# Date: 07.04.2023
# Description: KRY project 2 - Hybrid encryption of client-server communication


import socket
import sys
import secrets
import typing
import hashlib
from Crypto.PublicKey import RSA  # pip install crypto
from Crypto.Signature import pkcs1_15
from Crypto.Cipher import AES
import hashlib
from Crypto.Hash import MD5
from Crypto.Cipher import PKCS1_OAEP


def generate_session_key():
    session_key = secrets.token_bytes(32)
    return session_key


def RSA_encode(message, key):
    """RSA encryption of message using key"""
    e, n = key
    encoded_message = [pow(ord(char), e, n) for char in message]
    return encoded_message


def RSA_decode(encoded_message, private_key):
    d, n = private_key
    # make it suitable for long numbers
    message = [chr(pow(char, d, n)) for char in encoded_message]
    return ''.join(message)


def encrypt_session_key(session_key, public_key_path):
    """RSA encryption of session key using public key"""
    with open(public_key_path, 'r') as f:
        public_key_str = f.read().split()
        e, n = int(public_key_str[0]), int(public_key_str[1])

    encoded_session_key = RSA_encode(session_key.hex(), (e, n))
    return encoded_session_key


def decrypt_session_key(encoded_session_key, private_key_path):
    """RSA decryption of encoded session key using private key"""
    with open(private_key_path, 'r') as f:
        private_key_str = f.read().split()
        d, n = int(private_key_str[0]), int(private_key_str[1])

    session_key_hex = RSA_decode(encoded_session_key, (d, n))
    session_key = bytes.fromhex(session_key_hex)
    return session_key


def add_checksum(message: str, hash: typing.List[int]):
    """Adds checksum to the message"""
    checksum = ' '.join(str(i) for i in hash)
    return message + '|' + checksum


def pad_hash(hash):
    """Pads the hash using custom OAEP-like padding"""
    hash_len = len(hash)
    padded_hash = bytearray()
    for i in range(16 - hash_len):
        padded_hash.append(0)
    padded_hash.extend(hash)
    padded_hash.extend(secrets.token_bytes(16 - hash_len))
    return padded_hash


def server_mode(port):
    HOST = '127.0.0.1'
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((HOST, port))
    server_socket.listen()

    # waiting for client to connect
    client_socket, client_address = server_socket.accept()

    # client connected
    while True:
        try:
            # Receive data from client
            data = client_socket.recv(4096)
            data = data.decode()
            print(f"Received data from client {client_address}: {data}")
            if not data:
                print(f"Client {client_address} disconnected")
                break

            # Convert received data to dictionary
            received_data = eval(data)

            # Decrypt session key using private key
            with open('cert/id_rsa', 'rb') as f:
                private_key = RSA.import_key(f.read())

            cipher_rsa = PKCS1_OAEP.new(private_key)
            session_key = cipher_rsa.decrypt(received_data["session_key"])

            # Decrypt the encrypted message using AES
            cipher = AES.new(session_key, AES.MODE_EAX,
                             nonce=received_data["nonce"])
            plaintext = cipher.decrypt_and_verify(
                received_data["ciphertext"], received_data["tag"])

            # Extract the MD5 hash and message from the plaintext
            md5_hash = plaintext[:16]
            message = plaintext[16:]

            # Verify the MD5 hash
            if md5_hash == hashlib.md5(message).digest():
                print(f"Client {client_address} sent: {message.decode()}")
            else:
                print(f"Client {client_address} sent an invalid message")

        except ConnectionResetError:
            print(f"Client {client_address} disconnected unexpectedly")
            break

    server_socket.close()


def client_mode(port):
    HOST = '127.0.0.1'
    # Create socket and connect to server
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((HOST, port))

    # Generate session key
    session_key = secrets.token_bytes(32)

    while True:
        message = input("Enter message: ")

        if message == "":
            break

        # Calculate the MD5 hash of the message
        print("1.) Calculating MD5 hash of message...")
        md5_hash = hashlib.md5(message.encode()).digest()

        # pad the hash
        print("2.) Padding MD5 hash...")
        md5_hash = pad_hash(md5_hash)
        # Add the MD5 hash to the message

        # encode padded hash using private key and custom RSA_encode
        with open('cert/id_rsa', 'rb') as f:
            private_key = RSA.import_key(f.read())
        d, n = private_key.d, private_key.n
        print("3.) Encoding MD5 hash...")
        encoded_MD5 = RSA_encode(md5_hash.hex(), (d, n))

        # add encoded MD5 hash to message
        # print("4.) Adding encoded MD5 hash to message...")
        # message = add_checksum(message, encoded_MD5)
        message = message.encode()

        # Add the session key to the message
        print("4.) Generating session key...")
        session_key = generate_session_key()

        # create dictionary from message, encoded MD5 hash, and session key
        AES_input = {"message": message, "encoded_MD5": encoded_MD5,
                     "session_key": session_key}

        # Encrypt AES_input using AES and send it to the server
        print("5.) Encrypting message...")
        cipher = AES.new(session_key, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(AES_input["message"])

        # Encrypt session key using public key
        with open('cert/id_rsa.pub', 'rb') as f:
            public_key = RSA.import_key(f.read())
        cipher_rsa = PKCS1_OAEP.new(public_key)
        encoded_session_key = cipher_rsa.encrypt(AES_input["session_key"])

        # create dictionary from ciphertext, tag, and encoded session key
        AES_output = {"ciphertext": ciphertext, "tag": tag,
                      "session_key": encoded_session_key,
                      "nonce": cipher.nonce}

        # send dictionary to server
        print("6.) Sending packet (encoded data + MD5 + encoded session key) server...")
        print(f"AES input: {AES_output}")
        client_socket.send(str(AES_output).encode())

    client_socket.close()


def generate_rsa_keys():
    key = RSA.generate(2048)

    # RSA private key
    with open('cert/id_rsa', 'wb') as f:
        f.write(key.export_key(format='PEM'))

    # RSA public key
    with open('cert/id_rsa.pub', 'wb') as f:
        f.write(key.publickey().export_key(format='PEM'))


if __name__ == '__main__':
    generate_rsa_keys()

    no_args = len(sys.argv)

    if no_args != 3:
        print("Wrong usage of arguments: python3 kry.py TYPE=s/c PORT=number")
        sys.exit()

    mode = sys.argv[1].split('=')[1]  # s = server, c = client
    port = int(sys.argv[2].split('=')[1])

    if mode == 's':
        server_mode(port)

    elif mode == 'c':
        client_mode(port)
    else:
        print("Wrong usage of arguments: python3 kry.py TYPE=s/c PORT=number")
        sys.exit()

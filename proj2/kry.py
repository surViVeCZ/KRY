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
from Crypto.Random import get_random_bytes


def generate_session_key():
    session_key = get_random_bytes(16)  # 16 bytes = 128 bits
    return session_key


def RSA_encode(message, key):
    """RSA encryption of message using key"""
    message_int = int.from_bytes(message, byteorder='big')
    ciphertext = key._encrypt(message_int)
    return ciphertext


def RSA_decode(ciphertext: int, private_key):
    """RSA decryption of ciphertext using private_key"""
    message_int = private_key._decrypt(ciphertext)
    message_int = int(message_int)
    message = message_int.to_bytes((message_int.bit_length() + 7) // 8, 'big')
    return message


def encrypt_session_key(session_key, public_key_path):
    """RSA encryption of session key using public key"""
    with open(public_key_path, 'rb') as f:
        public_key = RSA.import_key(f.read(), passphrase=None)

    encoded_session_key = RSA_encode(session_key, public_key)
    return encoded_session_key


def decrypt_session_key(encoded_session_key: int, private_key_path):
    """RSA decryption of encoded session key using private key"""
    with open(private_key_path, 'rb') as f:
        private_key = RSA.import_key(f.read(), passphrase=None)

    session_key = RSA_decode(encoded_session_key, private_key)
    return session_key


def add_checksum(message: bytes, hash: typing.List[int]):
    """Adds checksum to the message"""
    message = message + str(hash).encode()
    return message


def pad_hash(hash):
    """Pads the hash using custom OAEP-like padding
    This function pads the hash with zeros to make its
    length equal to 16 bytes, and then adds random bytes
    to the end to fill up the remaining space. You can
    use this function to pad the MD5 hash before adding it to the message."""
    hash_len = len(hash)
    padded_hash = bytearray()
    for i in range(16 - hash_len):
        padded_hash.append(0)
    padded_hash.extend(hash)
    padded_hash.extend(get_random_bytes(16 - hash_len))
    return padded_hash


def server_mode(port):
    HOST = '127.0.0.1'
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((HOST, port))
    server_socket.listen()

    # Load private key
    with open('cert/id_rsa', 'rb') as f:
        private_key = RSA.import_key(f.read())

    # waiting for client to connect
    client_socket, client_address = server_socket.accept()

    # client connected
    while True:
        try:
            # receive data from client in while loop, until it reaches end
            data = b''
            while True:
                packet = client_socket.recv(4096)
                if not packet:
                    break
                data += packet
            data = data.decode()

            # Convert received data to dictionary
            # check for empty string
            if data == "":
                break
            received_data = eval(data)
            print(received_data)

            # Decrypt session key using private key
            encoded_session_key = received_data["session_key"]
            session_key = decrypt_session_key(
                encoded_session_key, 'cert/id_rsa')

            # remove padding
            session_key = session_key[-16:]

            # Decrypt ciphertext and obtain signed MD5 hash without MAC check
            ciphertext = received_data["ciphertext"]
            tag = received_data["tag"]
            nonce = received_data["nonce"]
            cipher = AES.new(session_key, AES.MODE_EAX, nonce=nonce)
            decrypted_message = cipher.decrypt(ciphertext)
            print(f'Decrypted message: {decrypted_message}')

            # Verify the MD5 hash of the message
            received_md5 = received_data["encoded_MD5"]
            print(f'Encoded MD5: {received_md5}')
            print(type(received_md5))
            # load public key
            with open('cert/id_rsa.pub', 'rb') as f:
                public_key = RSA.import_key(f.read())
            received_md5 = public_key._encrypt(received_md5)
            received_md5_bytes = received_md5.to_bytes(255, 'big')
            recv_md5_cut = received_md5_bytes[-16:]
            # received_md5 = RSA_decode(received_md5, private_key)

            md5_hash = hashlib.md5(decrypted_message).digest()

            print(f'Expected MD5: {recv_md5_cut}')
            print(f'Received MD5: {md5_hash}')

            if recv_md5_cut != md5_hash:
                print("Error: Received message is corrupted or tampered with.")
                break

            # If verification is successful, print the message
            print("Received message: " + decrypted_message.decode())

        except ConnectionResetError:
            print(f"Client {client_address} disconnected unexpectedly")
            break

    server_socket.close()


def client_mode(port):
    HOST = '127.0.0.1'
    # Create socket and connect to server
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((HOST, port))

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
        # encoded_MD5 = RSA_encode(md5_hash, private_key)

        md5_int = int.from_bytes(md5_hash, byteorder='big')
        encoded_MD5 = private_key._decrypt(md5_int)
        encoded_MD5 = int(encoded_MD5)

        # add encoded MD5 hash to message
        # print("4.) Adding encoded MD5 hash to message...")
        # message = add_checksum(message, encoded_MD5)
        message = message.encode()

        # Add the session key to the message
        print("5.) Generating session key...")
        session_key = generate_session_key()
        # print(f"Session key: {session_key.hex()}")

        # encrypt session key using public key
        encoded_session_key = encrypt_session_key(
            session_key, 'cert/id_rsa.pub')
        # print(f"Encoded session key: {encoded_session_key}")

        # Encrypt AES_input using AES and send it to the server
        print("6.) Encrypting message...")
        cipher = AES.new(session_key, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(message)

        # create dictionary from ciphertext, tag, and encoded session key
        AES_output = {"ciphertext": ciphertext, "tag": tag,
                      "session_key": encoded_session_key,
                      "nonce": cipher.nonce, "encoded_MD5": encoded_MD5}

        # send dictionary to server
        print("7.) Sending packet (encoded data + MD5 + encoded session key) server...")
        print(f"AES input: {AES_output}")
        client_socket.send(str(AES_output).encode())

    client_socket.close()


def generate_rsa_keys():
    key = RSA.generate(2048)

    # Write id_rsa and id_rsa.pub to files, create them if they don't exist
    with open('cert/id_rsa', 'wb') as f:
        f.write(key.export_key('PEM'))
    with open('cert/id_rsa.pub', 'wb') as f:
        f.write(key.publickey().export_key('PEM'))


if __name__ == '__main__':
    generate_rsa_keys()

    no_args = len(sys.argv)

    if no_args != 3:
        print("Wrong usage of arguments: python3 kry.py TYPE=s/c PORT=number")
        sys.exit()

    try:
        port = int(sys.argv[2])
    except ValueError:
        print("Invalid port number")
        exit()

    if sys.argv[1] == 's':
        server_mode(port)
    elif sys.argv[1] == 'c':
        client_mode(port)
    else:
        print("Wrong usage of arguments: python3 kry.py TYPE=s/c PORT=number")
        sys.exit()

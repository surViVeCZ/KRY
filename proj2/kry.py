# Date: 07.04.2023
# Description: KRY project 2 - Hybrid encryption of client-server communication


import socket
import sys
import secrets
from Crypto.PublicKey import RSA  # pip install crypto
from Crypto.Signature import pkcs1_15
from Crypto.Cipher import AES
import hashlib
from Crypto.Hash import MD5
from Crypto.Cipher import PKCS1_OAEP

# Generates random numbers
session_key = secrets.token_bytes(32)


def RSA_encode(message, key):
    """RSA encryption of message using key"""
    e, n = key
    encoded_message = [pow(ord(char), e, n) for char in message]
    return encoded_message


def RSA_decode(encoded_message, key):
    """RSA decryption of message using key"""
    d, n = key
    decoded_message = ''.join([chr(pow(char, d, n))
                              for char in encoded_message])
    return decoded_message


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


def add_checksum(message):
    """Adds an MD5 checksum to the message"""
    md5_hash = hashlib.md5(message.encode()).hexdigest()
    return message + md5_hash


def pad_hash(hash):
    """Pads the hash using PKCS#1 OAEP"""
    with open('cert/id_rsa.pub', 'r') as f:
        public_key_str = f.read()
        public_key = RSA.import_key(public_key_str)
        cipher_rsa = PKCS1_OAEP.new(public_key)
        padded_hash = cipher_rsa.encrypt(hash)
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
            session_key = cipher_rsa.decrypt(
                received_data["encoded_session_key"])

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
        md5_hash = hashlib.md5(message.encode()).digest()

        # pad the hash
        public_key_str = open('cert/id_rsa.pub', 'r').read()
        md5_hash = pad_hash(md5_hash)
        # Add the MD5 hash to the message
        message = add_checksum(message)

        # Encrypt the MD5 hash and message using AES
        cipher = AES.new(session_key, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(
            md5_hash + message.encode())

        # Encode session key using server's public key
        with open('cert/id_rsa.pub', 'rb') as f:
            public_key = RSA.import_key(f.read())

        cipher_rsa = PKCS1_OAEP.new(public_key)
        encoded_session_key = cipher_rsa.encrypt(session_key)

        # Create data packet with encrypted message, session key, and nonce
        data = {
            "encoded_session_key": encoded_session_key,
            "nonce": cipher.nonce,
            "ciphertext": ciphertext,
            "tag": tag
        }
        print(f"Sending data to server: {data}")

        # Convert data packet to byte string and send to server
        client_socket.send(bytes(str(data).encode()))

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

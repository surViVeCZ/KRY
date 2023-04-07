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


def add_checksum(message):
    """Adds an MD5 checksum to the message"""
    md5_hash = hashlib.md5(message.encode()).hexdigest()
    return message + md5_hash


def pad_hash(hash):
    # Pad the hash using OAEP
    with open('cert/id_rsa.pub', 'rb') as f:
        public_key = f.read()
    cipher_rsa = PKCS1_OAEP.new(RSA.import_key(public_key))
    return cipher_rsa.encrypt(hash)


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
            message = client_socket.recv(1024).decode()
            if not message:
                print(f"Client {client_address} disconnected")
                break

            # Hash the message
            md5_hash = MD5.new(message.encode())

            # Padding the hash
            padded_hash = pad_hash(md5_hash.digest())

            # Encrypting the hash and session key with AES
            cipher = AES.new(session_key, AES.MODE_EAX)
            nonce = cipher.nonce
            ciphertext, tag = cipher.encrypt_and_digest(
                padded_hash + session_key)

            print(f"Received message from client: {message}")
            response = {
                "message": f"Data received: {message}",
                "nonce": nonce,
                "ciphertext": ciphertext,
                "tag": tag
            }
            client_socket.send(str(response).encode())

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

        # Hash the message
        md5_hash = MD5.new(message.encode())

        # Padding the hash
        padded_hash = pad_hash(md5_hash.digest())

        if message == "":
            break
        # add the hash to the message
        message = add_checksum(message)

        # Encrypting the hash and session key with AES
        cipher = AES.new(session_key, AES.MODE_EAX)
        nonce = cipher.nonce
        ciphertext, tag = cipher.encrypt_and_digest(
            padded_hash + session_key + message.encode())

        # send the encrypted hash, session key, and message to server
        data = {
            "message": message.encode(),
            "nonce": nonce,
            "ciphertext": ciphertext,
            "tag": tag
        }
        client_socket.send(str(data).encode())

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

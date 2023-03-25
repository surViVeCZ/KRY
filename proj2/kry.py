# Date: 25.3.2023
# Description: KRY project 2 - Hybrid encryption of client-server communication


import socket
import sys
import secrets
from Crypto.PublicKey import RSA  # pip install crypto
import os
from Crypto.Signature import pkcs1_15
import hashlib
# pip install pycryptodome

AES_KEY = secrets.token_bytes(16)  # AES key for encryption and decryption


def server_mode(port):
    HOST = '127.0.0.1'
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((HOST, port))
    server_socket.listen()

    # waiting for client to connect
    client_socket, client_address = server_socket.accept()

    # client connected
    while True:
        message = client_socket.recv(1024).decode()
        if not message:
            print(f"Client {client_address} disconnected")
            break

        # Compute MD5 checksum of message
        checksum = md5_checksum(message)

        # Sign checksum with private key
        with open('cert/id_rsa', 'rb') as f:
            private_key = RSA.import_key(f.read())

        #signature = private_key.sign(checksum.encode(), '')

        # Append signature to message
        #signed_message = f"{message} {signature}"

        print(f"Received message from client: {message}")
        response = f"Data recieved: {message}"
        client_socket.send(response.encode())

    server_socket.close()


def client_mode(port):
    HOST = '127.0.0.1'
    # Create socket and connect to server
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((HOST, port))
    while True:
        message = input("Enter message: ")

        # get md5 checksum of message
        checksum = md5_checksum(message)

        with open('cert/id_rsa', 'rb') as f:
            private_key = RSA.import_key(f.read())

        #!NEFUNGUJE
        # sign checksum with private key
        # signature = private_key.sign(checksum.encode(), '')

        client_socket.send(message.encode())
        # enter to exit
        if message == "":
            break

        # get response from server
        response = client_socket.recv(1024).decode()
        print(f"Server response: {response}")

    client_socket.close()


# MD5 checksum for message
def md5_checksum(message):
    return hashlib.md5(message.encode()).hexdigest()


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

# Date: 25.3.2023
# Author: Bc. Petr Pouč
# login: xpoucp01
# Description: KRY project 2 - Hybrid encryption of client-server communication


import socket
import sys
import secrets
from Crypto.PublicKey import RSA  # pip install crypto
import os


def server_mode(port):
    HOST = '127.0.0.1'
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((HOST, port))
    server_socket.listen()

    # waiting for client to connect
    client_socket, client_address = server_socket.accept()

    # client connected
    while True:
        # get message
        message = client_socket.recv(1024).decode()
        if not message:
            print(f"Client {client_address} disconnected")
            break

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

        # send message
        client_socket.send(message.encode())
        # enter to exit
        if message == "":
            break

        # get response from server
        response = client_socket.recv(1024).decode()
        print(f"Server response: {response}")

    client_socket.close()


def generate_AES128():
    # AES using same key for both encryption and decryption
    key = secrets.token_bytes(16)
    print(key)


def generate_rsa_keys():
    key = RSA.generate(2048)

    # RSA private key
    with open('cert/id_rsa', 'wb') as f:
        f.write(key.export_key(format='PEM'))

    # RSA public key
    with open('cert/id_rsa.pub', 'wb') as f:
        f.write(key.publickey().export_key(format='PEM'))


if __name__ == '__main__':
    generate_AES128()
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

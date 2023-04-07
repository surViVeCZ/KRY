import socket
import sys
import secrets
from Crypto.PublicKey import RSA  # pip install crypto
from Crypto.Signature import pkcs1_15
from Crypto.Cipher import AES
import hashlib


from Crypto.Signature import pkcs1_15
from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Hash import MD5
import socket
import sys
import secrets
# Generates random numbers
session_key = secrets.token_bytes(32)


def add_checksum(message):
    """Adds an MD5 checksum to the message"""
    md5_hash = hashlib.md5(message.encode()).hexdigest()
    return message + md5_hash


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
            with open('cert/id_rsa', 'rb') as f:
                private_key = f.read()
            padder = pkcs1_15.new(RSA.import_key(private_key))
            padded_hash = padder.sign(md5_hash)

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

        # Sign the hash
        with open('cert/id_rsa', 'rb') as f:
            private_key = f.read()
        signed_md5 = pkcs1_15.new(RSA.import_key(private_key)).sign(md5_hash)

        if message == "":
            break
        # add the hash to the message
        message = add_checksum(message)

        # Encrypting the hash and session key with AES
        cipher = AES.new(session_key, AES.MODE_EAX)
        nonce = cipher.nonce
        ciphertext, tag = cipher.encrypt_and_digest(
            signed_md5 + session_key)

        # send the encrypted hash, session key, and message to server
        data = {
            "message": message.encode(),
            "nonce": nonce,
            "ciphertext": ciphertext,
            "tag": tag
        }
        client_socket.send(str(data).encode())

        # get response from server
        # response = eval(client_socket.recv(1024).decode())
        # print(f"Server response: {response['message']}")

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

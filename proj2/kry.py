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

        # Sign checksum with private key
        with open('cert/id_rsa', 'rb') as f:
            private_key = RSA.import_key(f.read())

        # Hash the message
        md5_hash = MD5.new(message.encode())

        # Padding the hash
        padder = pkcs1_15.new(private_key)
        padded_hash = padder.sign(md5_hash)

        # Encrypting the hash with AES
        key = secrets.token_bytes(16)
        cipher = AES.new(key, AES.MODE_EAX)
        nonce = cipher.nonce
        ciphertext, tag = cipher.encrypt_and_digest(padded_hash)

        print(f"Received message from client: {message}")
        response = {
            "message": f"Data received: {message}",
            "key": key,
            "nonce": nonce,
            "ciphertext": ciphertext,
            "tag": tag
        }
        client_socket.send(str(response).encode())

    server_socket.close()


def client_mode(port):
    HOST = '127.0.0.1'
    # Create socket and connect to server
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((HOST, port))
    while True:
        message = input("Enter message: ")

        with open('cert/id_rsa', 'rb') as f:
            private_key = RSA.import_key(f.read())

        # Hash the message
        md5_hash = MD5.new(message.encode())

        # signed mg5 hash
        signed_md5 = pkcs1_15.new(private_key).sign(md5_hash)
        print(signed_md5)

        # Encrypting the hash with AES
        key = secrets.token_bytes(16)
        cipher = AES.new(key, AES.MODE_EAX)
        nonce = cipher.nonce
        ciphertext, tag = cipher.encrypt_and_digest(signed_md5)

        # send the encrypted hash and message to server
        data = {
            "message": message.encode(),
            "key": key,
            "nonce": nonce,
            "ciphertext": ciphertext,
            "tag": tag
        }
        client_socket.send(str(data).encode())

        # enter to exit
        if message == "":
            break

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

# Date: 12.04.2023
# Description: KRY project 2 - Hybrid encryption of client-server communication
# Author: Bc. Petr Pouč
# Login: xpoucp01

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

def generate_rsa_key_pair():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key


def generate_session_key():
    session_key = get_random_bytes(16)  # 16 bytes = 128 bits
    return session_key


def RSA_encode(message, key):
    message_int = int.from_bytes(message, byteorder='big')
    ciphertext = key._encrypt(message_int)
    return ciphertext


def RSA_decode(ciphertext: int, private_key):
    message_int = private_key._decrypt(ciphertext)
    message_int = int(message_int)
    message = message_int.to_bytes((message_int.bit_length() + 7) // 8, 'big')
    return message


def encrypt_session_key(session_key, public_key_path):
    with open(public_key_path, 'rb') as f:
        public_key = RSA.import_key(f.read(), passphrase=None)

    encoded_session_key = RSA_encode(session_key, public_key)
    return encoded_session_key


def decrypt_session_key(encoded_session_key: int, private_key_path):
    with open(private_key_path, 'rb') as f:
        private_key = RSA.import_key(f.read(), passphrase=None)

    session_key = RSA_decode(encoded_session_key, private_key)
    return session_key


def add_checksum(message: bytes, hash: typing.List[int]):
    message = message + str(hash).encode()
    return message


def pad_hash(hash):
    # Get the current length of the hash
    current_length = len(hash)

    # Calculate the number of bytes needed for padding
    padding_length = 255 - current_length

    # Generate the padding random bytes
    padding = get_random_bytes(padding_length)

    # Append the padding bytes to the hash
    padded_hash = hash + padding

    return padded_hash


def remove_padding(padded_hash):
    # Remove the padding bytes from the hash
    hash = padded_hash[-16:]

    return hash


def server_mode(port):
    HOST = '127.0.0.1'
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((HOST, port))
    server_socket.listen()

    # waiting for client to connect
    client_socket, client_address = server_socket.accept()

    # client connected
    while True:
        print("s: \"Client has joined\"")
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

            # Decrypt session key using private key
            encoded_session_key = received_data["session_key"]
            print(f's: RSA_AES_key=<{encoded_session_key}>')
            session_key = decrypt_session_key(
                encoded_session_key, 'cert/reciever_id_rsa')

            ciphertext = received_data["ciphertext"]
            print(f's: AES_cipher=<{received_data}>')

            # remove padding
            session_key = session_key[-16:]
            print(f's: AES_key=<{session_key}>')

            # Decrypt ciphertext and obtain signed MD5 hash without MAC check
            tag = received_data["tag"]
            nonce = received_data["nonce"]
            cipher = AES.new(session_key, AES.MODE_EAX, nonce=nonce)
            print(f's: AES_cipher {cipher}')
            decrypted_message = cipher.decrypt(ciphertext)

            # Verify the MD5 hash of the message
            received_md5 = received_data["encoded_MD5"]

            print(f's: plaintext=<{decrypted_message.decode()}>')

            # load public key
            with open('cert/sender_id_rsa.pub', 'rb') as f:
                public_key = RSA.import_key(f.read())
            received_md5 = public_key._encrypt(received_md5)
            received_md5_bytes = received_md5.to_bytes(
                (received_md5.bit_length() + 7) // 8, 'big')
            # first 16 bytes are the hash
            recv_md5_cut = received_md5_bytes[:16]
            # received_md5 = RSA_decode(received_md5, private_key)

            print(f's: MD5=<{received_md5}>')

            md5_hash = hashlib.md5(decrypted_message).digest()

            print(f'Expected MD5: {recv_md5_cut}')
            print(f'Received MD5: {md5_hash}\n')

            if recv_md5_cut != md5_hash:
                print("The integrity of the report has been compromised.")
                # send NACK
                client_socket.sendall(b'NACK')
                break

            # If verification is successful, print the message
            print("s: The integrity of the message has not been compromised")
            # send ACK
            client_socket.sendall(b'ACK')

        except ConnectionResetError:
            print(f"s: Client {client_address} disconnected unexpectedly")
            break

    print("Closing connection...")
    server_socket.close()


def client_mode(port):
    HOST = '127.0.0.1'
    # Create socket and connect to server
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((HOST, port))
    print("c: Successfully connected to server")
    
    #load piblic sender key, private sender key and public key reciever
    with open('cert/sender_id_rsa', 'rb') as f:
            private_key = RSA.import_key(f.read())
    with open('cert/sender_id_rsa.pub', 'rb') as f:
            public_key = RSA.import_key(f.read())
    with open('cert/reciever_id_rsa.pub', 'rb') as f:
            public_key_reciever = RSA.import_key(f.read())
    #print public sender key, private sender key and public key reciever
    print(f'c: RSA_public_key_sender=<{public_key}>')
    print(f'c: RSA_private_key_sender=<{private_key}>')
    print(f'c: RSA_public_key_reciever=<{public_key_reciever}>')


    while True:
        message = input("c: Enter input: ")

        if message == "":
            break

        # Calculate the MD5 hash of the message
        md5_hash = hashlib.md5(message.encode()).digest()

        # session key(AES key)
        session_key = generate_session_key()
        print(f"c: AES_key<{session_key}>")
        print(f"c: AES_key_padding={pad_hash(session_key)}")

        # pad the hash
        print(f"c: MD5=<{md5_hash}>")
        md5_hash = pad_hash(md5_hash)
        print(f"c: MD5_padding=<{md5_hash}>")
     
        md5_int = int.from_bytes(md5_hash, 'big')
        # encode padded hash using private key and custom RSA_encode
        encoded_MD5 = private_key._decrypt(md5_int)
        encoded_MD5 = int(encoded_MD5)
        print(f"c: RSA_MD5_hash=<{encoded_MD5}>")

        message = message.encode()

        # encrypt session key using public key
        encoded_session_key = encrypt_session_key(
            session_key, 'cert/reciever_id_rsa.pub')
        # print(f"Encoded session key: {encoded_session_key}")

        # Encrypt message + md5 hash + session key using AES
        cipher = AES.new(session_key, AES.MODE_EAX)
        
        #TODO: add md5 hash to message
        ciphertext, tag = cipher.encrypt_and_digest(message)

        # create dictionary from ciphertext, tag, and encoded session key
        AES_output = {"ciphertext": ciphertext, "tag": tag,
                      "session_key": encoded_session_key,
                      "nonce": cipher.nonce, "encoded_MD5": encoded_MD5}

        print(f"c: AES_cipher={cipher}")
        print(f"c: RSA_AES_key={encoded_session_key}")
        #cipher text = encodeded message + hash + encoded key
        print(f"c: ciphertext={ciphertext}")
        try:
            client_socket.send(str(AES_output).encode())
            print("c: The message was successfully delivered")
        except ConnectionResetError:
            print("c: The message was sent again")
            break

    client_socket.close()


def generate_rsa_keys():
    key = RSA.generate(2048)

    # Write id_rsa and id_rsa.pub to files, create them if they don't exist
    with open('cert/sender_id_rsa', 'wb') as f:
        f.write(key.export_key('PEM'))
    with open('cert/sender_id_rsa.pub', 'wb') as f:
        f.write(key.publickey().export_key('PEM'))
    with open('cert/reciever_id_rsa', 'wb') as f:
        f.write(key.export_key('PEM'))
    with open('cert/reciever_id_rsa.pub', 'wb') as f:
        f.write(key.publickey().export_key('PEM'))


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
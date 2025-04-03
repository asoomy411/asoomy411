import socket
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

HOST = '127.0.0.1'
PORT = 12345

def load_public_key():
    with open("keys/public_key.pem", "rb") as f:
        return serialization.load_pem_public_key(f.read())

def encrypt_key(aes_key, public_key):
    return public_key.encrypt(
        aes_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

def encrypt_message(message, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    encrypted_msg = encryptor.update(message.encode()) + encryptor.finalize()
    return iv, encrypted_msg

def decrypt_message(ciphertext, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

def start_client():
    public_key = load_public_key()
    aes_key = os.urandom(32)

    encrypted_key = encrypt_key(aes_key, public_key)

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((HOST, PORT))
    print("[+] Connected to server.")

    client_socket.send(encrypted_key)
    print("[+] AES Key sent.")

    while True:
        msg = input("You: ")
        iv, encrypted_msg = encrypt_message(msg, aes_key)
        client_socket.send(iv)
        client_socket.send(encrypted_msg)

        iv = client_socket.recv(16)
        ciphertext = client_socket.recv(1024)
        plaintext = decrypt_message(ciphertext, aes_key, iv)
        print("[Server]:", plaintext.decode())

    client_socket.close()

if __name__ == "__main__":
    start_client()

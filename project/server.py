import socket
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

HOST = '0.0.0.0'
PORT = 12345

def load_private_key():
    with open("keys/private_key.pem", "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)

def decrypt_key(encrypted_key, private_key):
    return private_key.decrypt(
        encrypted_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

def decrypt_message(ciphertext, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

def start_server():
    private_key = load_private_key()

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((HOST, PORT))
    server_socket.listen(1)
    print(f"[+] Server is listening on port {PORT}")

    conn, addr = server_socket.accept()
    print(f"[+] Connected by {addr}")

    encrypted_key = conn.recv(256)
    aes_key = decrypt_key(encrypted_key, private_key)
    print("[+] AES Key received and decrypted.")

    while True:
        iv = conn.recv(16)
        ciphertext = conn.recv(1024)
        plaintext = decrypt_message(ciphertext, aes_key, iv)
        print("[Client]:", plaintext.decode())

        msg = input("You: ").encode()
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
        encryptor = cipher.encryptor()
        encrypted_msg = encryptor.update(msg) + encryptor.finalize()
        conn.send(iv + encrypted_msg)

    conn.close()

if __name__ == "__main__":
    start_server()

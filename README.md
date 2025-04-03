# 🔐 Secure Chat Project (Client-Server Communication)

This project demonstrates a secure chatting system using **asymmetric encryption (RSA)** for key exchange and **symmetric encryption (AES)** for secure communication between a client and a server. Developed in Python as part of the **Programming for Cybersecurity** course.

---

## 🧠 Project Idea

The goal is to simulate a real-world secure chat system:

1. **Client** connects to **Server** via TCP.
2. Client reads the **RSA public key** from the server.
3. Client generates a random **AES key** and encrypts it with RSA.
4. Server decrypts the AES key using its private RSA key.
5. All further messages are encrypted and decrypted using the AES key.

---

## 🔧 Technologies Used

- Python 3.x
- `socket` – for network communication
- `cryptography` – for encryption (RSA and AES)
- `os` – to generate keys and IVs
- `threading` (optional) – to handle concurrent sending and receiving

---

## 🔐 Encryption Flow

| Stage                | Type            | Algorithm | Purpose                             |
|---------------------|------------------|-----------|-------------------------------------|
| Key Exchange         | Asymmetric       | RSA       | Securely send AES key to server     |
| Chat Communication   | Symmetric        | AES (CFB) | Encrypt/decrypt messages in real time |

---

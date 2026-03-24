# Crypto Chat

A multi-user python chat room that compares the performance overhead of AES vs RSA encryption in real-time. 

## How it works
- **AES-256 (Symmetric):** Fast, low overhead. The server generates a master group key and securely distributes it to new participants using their RSA public keys when they join. 
- **RSA-2048 (Asymmetric):** High overhead. Sending a message in RSA mode will manually chunk and encrypt the payload individually for every single connected user using their public keys.
- **Metrics:** Real-time logging of encryption/decryption speeds, byte sizes, and overhead percentages natively in the UI.

## Setup
Make sure you have the `cryptography` package installed:
```bash
pip install cryptography
```

## Running
1. Start the server:
```bash
python chat_server.py
```
*(You can type `quit` in the server terminal at any time to cleanly shut it down).*

2. Start one or more clients in different terminals:
```bash
python chat_client.py
```

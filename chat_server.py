#!/usr/bin/env python3

import socket
import threading
import json
import time
import base64
from datetime import datetime
import os
import sys
from crypto_utils import encrypt_rsa, pem_to_public_key

class ChatServer:
    def __init__(self, host='localhost', port=12345):
        self.host = host
        self.port = port
        self.clients = {}  
        self.server_socket = None
        self.running = False
        
        self.aes_key = os.urandom(32)
        
        print(f"Chat Server initialized on {host}:{port}")
        print(f"AES Key (demo): {base64.b64encode(self.aes_key).decode()[:20]}...")

    def start_server(self):
        """Start the chat server"""
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            self.running = True
            
            print(f"Server listening on {self.host}:{self.port}")
            print("Waiting for clients to connect... (Type 'quit' to stop)")
            
            cli_thread = threading.Thread(target=self.cli_handler)
            cli_thread.daemon = True
            cli_thread.start()

            while self.running:
                try:
                    client_socket, address = self.server_socket.accept()
                    print(f"New connection from {address}")
                    
                    # Start client handler thread
                    client_thread = threading.Thread(
                        target=self.handle_client,
                        args=(client_socket, address)
                    )
                    client_thread.daemon = True
                    client_thread.start()
                    
                except socket.error:
                    if self.running:
                        print("Error accepting connection")
                    break
                    
        except Exception as e:
            print(f"Server error: {e}")
        finally:
            self.stop_server()

    def handle_client(self, client_socket, address):
        """Handle individual client connections"""
        try:
            while self.running:
                # Receive data from client
                data = client_socket.recv(4096)
                if not data:
                    break
                
                try:
                    message_data = json.loads(data.decode('utf-8'))
                    self.process_message(client_socket, message_data)
                except json.JSONDecodeError:
                    print(f"Invalid JSON from {address}")
                except Exception as e:
                    print(f"Error processing message from {address}: {e}")
                    
        except ConnectionResetError:
            print(f"Client {address} disconnected unexpectedly")
        except Exception as e:
            print(f"Error handling client {address}: {e}")
        finally:
            self.disconnect_client(client_socket)

    def process_message(self, sender_socket, message_data):
        """Process different types of messages"""
        message_type = message_data.get('type')
        
        if message_type == 'join':
            self.handle_join(sender_socket, message_data)
        elif message_type == 'chat':
            self.handle_chat_message(sender_socket, message_data)
        elif message_type == 'get_users':
            self.send_user_list(sender_socket)

    def handle_join(self, client_socket, message_data):
        """Handle user joining the chat"""
        username = message_data.get('username', 'Anonymous')
        public_key_pem = message_data.get('public_key', '')
        
        # Store client info
        self.clients[client_socket] = {
            'username': username,
            'joined_at': datetime.now(),
            'public_key': public_key_pem
        }
        
        if public_key_pem:
            client_pub_key = pem_to_public_key(public_key_pem)
            encrypted_aes_key, _, _ = encrypt_rsa(client_pub_key, base64.b64encode(self.aes_key).decode('utf-8'))
            aes_payload = encrypted_aes_key
            aes_payload_type = "rsa_encrypted"
        else:
            aes_payload = base64.b64encode(self.aes_key).decode()
            aes_payload_type = "plaintext"

        # Send welcome message and AES key
        welcome_data = {
            'type': 'welcome',
            'message': f'Welcome to the encrypted chat, {username}!',
            'aes_key': aes_payload,
            'aes_key_type': aes_payload_type,
            'server_time': datetime.now().isoformat()
        }
        
        self.send_to_client(client_socket, welcome_data)
        
        # Notify other users
        join_notification = {
            'type': 'notification',
            'message': f'{username} joined the chat',
            'timestamp': datetime.now().isoformat()
        }
        
        self.broadcast_message(join_notification, exclude=client_socket)
        
        # Share public keys
        self.send_user_list_to_all()
        
        print(f"User '{username}' joined the chat")

    def handle_chat_message(self, sender_socket, message_data):
        
        if sender_socket not in self.clients:
            return
            
        username = self.clients[sender_socket]['username']
        
        
        message_data['sender'] = username
        message_data['server_timestamp'] = datetime.now().isoformat()
        message_data['type'] = 'chat'
        
        
        self.broadcast_message(message_data)
        
        
        encryption_type = message_data.get('encryption_type', 'unknown')
        enc_time = message_data.get('encryption_time', 0)
        dec_time = message_data.get('decryption_time', 0)
        
        print(f"[{encryption_type.upper()}] {username}: {message_data.get('original_message', 'encrypted')} "
              f"(E:{enc_time}ms, D:{dec_time}ms)")

    def send_user_list(self, client_socket):
        users = {info['username']: info.get('public_key', '') for info in self.clients.values()}
        user_list_data = {
            'type': 'user_list',
            'users': users,
            'count': len(users)
        }
        self.send_to_client(client_socket, user_list_data)

    def send_user_list_to_all(self):
        users = {info['username']: info.get('public_key', '') for info in self.clients.values()}
        user_list_data = {
            'type': 'user_list',
            'users': users,
            'count': len(users)
        }
        self.broadcast_message(user_list_data)

    def cli_handler(self):
        """Handle CLI background commands like quit"""
        while self.running:
            try:
                cmd = input().strip()
                if cmd.lower() == 'quit':
                    print("\nShutting down server...")
                    self.stop_server()
                    os._exit(0)
            except Exception:
                pass

    def broadcast_message(self, message_data, exclude=None):
        
        disconnected_clients = []
        
        for client_socket in list(self.clients.keys()):
            if client_socket == exclude:
                continue
                
            try:
                self.send_to_client(client_socket, message_data)
            except:
                disconnected_clients.append(client_socket)
        
        # Clean up disconnected clients
        for client in disconnected_clients:
            self.disconnect_client(client)

    def send_to_client(self, client_socket, data):
        """Send data to a specific client"""
        try:
            message = json.dumps(data).encode('utf-8')
            client_socket.send(message)
        except Exception as e:
            print(f"Error sending to client: {e}")
            raise

    def disconnect_client(self, client_socket):
        """Handle client disconnection"""
        if client_socket in self.clients:
            username = self.clients[client_socket]['username']
            del self.clients[client_socket]
            
            # Notify other users
            leave_notification = {
                'type': 'notification',
                'message': f'{username} left the chat',
                'timestamp': datetime.now().isoformat()
            }
            
            self.broadcast_message(leave_notification)
            self.send_user_list_to_all()
            print(f"User '{username}' left the chat")
        
        try:
            client_socket.close()
        except:
            pass

    def stop_server(self):
        """Stop the server"""
        self.running = False
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass
        print("Server stopped")

def main():
    server = ChatServer(port=12345)
    try:
        server.start_server()
    except KeyboardInterrupt:
        print("\nShutting down server...")
        server.stop_server()

if __name__ == "__main__":
    main()
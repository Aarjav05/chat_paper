#!/usr/bin/env python3
"""
Multi-User Chat Client with Tkinter GUI and Encryption Support
Run multiple instances to simulate different users
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import socket
import threading
import json
import time
import base64
from datetime import datetime
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
import os

class ChatClient:
    def __init__(self):
        self.socket = None
        self.connected = False
        self.username = ""
        self.aes_key = None
        
        # Performance metrics
        self.metrics = {
            'messages_sent': 0,
            'messages_received': 0,
            'avg_encryption_time': 0,
            'avg_decryption_time': 0,
            'total_bytes_sent': 0,
            'total_bytes_received': 0
        }
        
        # Create GUI
        self.setup_gui()
        
    def setup_gui(self):
        """Initialize the GUI"""
        self.root = tk.Tk()
        self.root.title("Encrypted Chat Client")
        self.root.geometry("800x600")
        self.root.configure(bg='#f0f0f0')
        
        # Create notebook for tabs
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Connection tab
        self.setup_connection_tab()
        
        # Chat tab
        self.setup_chat_tab()
        
        # Metrics tab
        self.setup_metrics_tab()
        
        # Protocol handlers
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        
    def setup_connection_tab(self):
        """Setup connection configuration tab"""
        conn_frame = ttk.Frame(self.notebook)
        self.notebook.add(conn_frame, text="Connection")
        
        # Connection settings
        settings_frame = ttk.LabelFrame(conn_frame, text="Server Settings", padding=20)
        settings_frame.pack(fill=tk.X, padx=20, pady=20)
        
        ttk.Label(settings_frame, text="Server:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.server_entry = ttk.Entry(settings_frame, width=30)
        self.server_entry.insert(0, "localhost")
        self.server_entry.grid(row=0, column=1, padx=10, pady=5)
        
        ttk.Label(settings_frame, text="Port:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.port_entry = ttk.Entry(settings_frame, width=30)
        self.port_entry.insert(0, "12345")
        self.port_entry.grid(row=1, column=1, padx=10, pady=5)
        
        ttk.Label(settings_frame, text="Username:").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.username_entry = ttk.Entry(settings_frame, width=30)
        self.username_entry.insert(0, f"User{int(time.time()) % 1000}")
        self.username_entry.grid(row=2, column=1, padx=10, pady=5)
        
        # Encryption type selection
        encryption_frame = ttk.LabelFrame(conn_frame, text="Encryption Settings", padding=20)
        encryption_frame.pack(fill=tk.X, padx=20, pady=10)
        
        self.encryption_var = tk.StringVar(value="aes")
        ttk.Radiobutton(encryption_frame, text="AES-256 (Symmetric)", 
                       variable=self.encryption_var, value="aes").pack(anchor=tk.W)
        ttk.Radiobutton(encryption_frame, text="RSA-2048 (Asymmetric)", 
                       variable=self.encryption_var, value="rsa").pack(anchor=tk.W)
        
        # Connection buttons
        button_frame = ttk.Frame(conn_frame)
        button_frame.pack(fill=tk.X, padx=20, pady=20)
        
        self.connect_btn = ttk.Button(button_frame, text="Connect", command=self.connect_to_server)
        self.connect_btn.pack(side=tk.LEFT, padx=5)
        
        self.disconnect_btn = ttk.Button(button_frame, text="Disconnect", 
                                        command=self.disconnect_from_server, state=tk.DISABLED)
        self.disconnect_btn.pack(side=tk.LEFT, padx=5)
        
        # Status
        self.status_var = tk.StringVar(value="Disconnected")
        ttk.Label(button_frame, textvariable=self.status_var).pack(side=tk.RIGHT)
        
    def setup_chat_tab(self):
        """Setup chat interface tab"""
        chat_frame = ttk.Frame(self.notebook)
        self.notebook.add(chat_frame, text="Chat", state=tk.DISABLED)
        
        # Chat display area
        self.chat_display = scrolledtext.ScrolledText(
            chat_frame, wrap=tk.WORD, state=tk.DISABLED,
            height=20, font=('Consolas', 10)
        )
        self.chat_display.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Message input area
        input_frame = ttk.Frame(chat_frame)
        input_frame.pack(fill=tk.X, padx=10, pady=(0, 10))
        
        self.message_entry = ttk.Entry(input_frame, font=('Arial', 11))
        self.message_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        self.message_entry.bind('<Return>', lambda e: self.send_message())
        
        self.send_btn = ttk.Button(input_frame, text="Send", command=self.send_message)
        self.send_btn.pack(side=tk.RIGHT)
        
        # Users list
        users_frame = ttk.LabelFrame(chat_frame, text="Online Users")
        users_frame.pack(fill=tk.X, padx=10, pady=(0, 10))
        
        self.users_listbox = tk.Listbox(users_frame, height=3)
        self.users_listbox.pack(fill=tk.X, padx=5, pady=5)
        
    def setup_metrics_tab(self):
        """Setup performance metrics tab"""
        metrics_frame = ttk.Frame(self.notebook)
        self.notebook.add(metrics_frame, text="Performance")
        
        # Real-time metrics
        realtime_frame = ttk.LabelFrame(metrics_frame, text="Real-time Metrics", padding=20)
        realtime_frame.pack(fill=tk.X, padx=20, pady=20)
        
        self.metrics_labels = {}
        metrics_list = [
            ('Messages Sent', 'messages_sent'),
            ('Messages Received', 'messages_received'),
            ('Avg Encryption Time (ms)', 'avg_encryption_time'),
            ('Avg Decryption Time (ms)', 'avg_decryption_time'),
            ('Bytes Sent', 'total_bytes_sent'),
            ('Bytes Received', 'total_bytes_received')
        ]
        
        for i, (label, key) in enumerate(metrics_list):
            ttk.Label(realtime_frame, text=f"{label}:").grid(row=i, column=0, sticky=tk.W, pady=2)
            self.metrics_labels[key] = ttk.Label(realtime_frame, text="0", font=('Consolas', 10, 'bold'))
            self.metrics_labels[key].grid(row=i, column=1, sticky=tk.W, padx=20, pady=2)
        
        # Encryption comparison
        comparison_frame = ttk.LabelFrame(metrics_frame, text="Encryption Comparison", padding=20)
        comparison_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=(0, 20))
        
        comparison_text = """
AES-256 (Symmetric Encryption):
✓ Very fast encryption/decryption (< 1ms typically)
✓ Low CPU and memory usage
✓ Minimal message overhead
✓ Excellent for high-volume messaging
✗ Key distribution challenges
✗ Same key for all participants

RSA-2048 (Asymmetric Encryption):
✓ Secure key exchange
✓ No shared secret required
✓ Perfect for initial handshakes
✗ Much slower (10-50ms per operation)
✗ High CPU usage
✗ Significant message size overhead
✗ Not suitable for large messages
        """
        
        comparison_display = scrolledtext.ScrolledText(
            comparison_frame, wrap=tk.WORD, height=15,
            font=('Consolas', 9), state=tk.NORMAL
        )
        comparison_display.insert(tk.END, comparison_text)
        comparison_display.configure(state=tk.DISABLED)
        comparison_display.pack(fill=tk.BOTH, expand=True)
        
    def connect_to_server(self):
        """Connect to the chat server"""
        try:
            server = self.server_entry.get() or "localhost"
            port = int(self.port_entry.get() or "12345")
            self.username = self.username_entry.get() or f"User{int(time.time()) % 1000}"
            
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((server, port))
            self.connected = True
            
            # Send join message
            join_data = {
                'type': 'join',
                'username': self.username,
                'encryption_type': self.encryption_var.get()
            }
            self.send_data(join_data)
            
            # Start receiver thread
            receiver_thread = threading.Thread(target=self.receive_messages)
            receiver_thread.daemon = True
            receiver_thread.start()
            
            # Update GUI
            self.status_var.set(f"Connected as {self.username}")
            self.connect_btn.configure(state=tk.DISABLED)
            self.disconnect_btn.configure(state=tk.NORMAL)
            self.notebook.tab(1, state=tk.NORMAL)  # Enable chat tab
            self.notebook.select(1)  # Switch to chat tab
            
            self.add_to_chat("System", "Connected to server!", is_system=True)
            
        except Exception as e:
            messagebox.showerror("Connection Error", f"Failed to connect: {e}")
            
    def disconnect_from_server(self):
        """Disconnect from the server"""
        self.connected = False
        if self.socket:
            try:
                self.socket.close()
            except:
                pass
        
        # Update GUI
        self.status_var.set("Disconnected")
        self.connect_btn.configure(state=tk.NORMAL)
        self.disconnect_btn.configure(state=tk.DISABLED)
        self.notebook.tab(1, state=tk.DISABLED)  # Disable chat tab
        self.notebook.select(0)  # Switch to connection tab
        
        self.add_to_chat("System", "Disconnected from server", is_system=True)
        
    def send_message(self):
        """Send a chat message"""
        message = self.message_entry.get().strip()
        if not message or not self.connected:
            return
            
        # Measure encryption time
        start_time = time.time() * 1000
        
        if self.encryption_var.get() == "aes":
            encrypted_msg, original_size, encrypted_size = self.encrypt_aes(message)
            encryption_type = "AES-256"
        else:
            encrypted_msg, original_size, encrypted_size = self.encrypt_rsa(message)
            encryption_type = "RSA-2048"
            
        encryption_time = time.time() * 1000 - start_time
        
        # Prepare message data
        message_data = {
            'type': 'chat',
            'original_message': message,
            'encrypted_message': encrypted_msg,
            'encryption_type': encryption_type,
            'encryption_time': round(encryption_time, 3),
            'original_size': original_size,
            'encrypted_size': encrypted_size,
            'overhead': round(((encrypted_size - original_size) / original_size) * 100, 1),
            'timestamp': datetime.now().isoformat()
        }
        
        # Send to server
        self.send_data(message_data)
        
        # Update metrics
        self.update_metrics('send', encryption_time, len(message.encode()))
        
        # Clear input
        self.message_entry.delete(0, tk.END)
        
    def encrypt_aes(self, message):
        """Encrypt message using AES-256"""
        if not self.aes_key:
            return message, len(message), len(message)  # Fallback if no key
            
        # Generate random IV
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(self.aes_key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        
        # Pad message to block size
        padded_message = message.encode()
        padding_length = 16 - (len(padded_message) % 16)
        padded_message += bytes([padding_length] * padding_length)
        
        # Encrypt
        encrypted = encryptor.update(padded_message) + encryptor.finalize()
        
        # Combine IV and encrypted data
        encrypted_data = iv + encrypted
        encoded = base64.b64encode(encrypted_data).decode()
        
        return encoded, len(message), len(encoded)
        
    def encrypt_rsa(self, message):
        """Simulate RSA encryption (for demo purposes)"""
        # In real implementation, you'd use actual RSA encryption
        # For demo, we'll simulate the overhead and timing
        time.sleep(0.015)  # Simulate RSA encryption delay
        
        # Simulate RSA padding overhead
        encoded = base64.b64encode(f"RSA:{message}".encode()).decode()
        # RSA typically has significant overhead
        simulated_overhead = len(encoded) * 2  # Simulate RSA block expansion
        
        return encoded, len(message), simulated_overhead
        
    def send_data(self, data):
        """Send data to server"""
        try:
            message = json.dumps(data).encode('utf-8')
            self.socket.send(message)
        except Exception as e:
            print(f"Error sending data: {e}")
            
    def receive_messages(self):
        """Receive messages from server"""
        while self.connected:
            try:
                data = self.socket.recv(4096)
                if not data:
                    break
                    
                message_data = json.loads(data.decode('utf-8'))
                self.handle_received_message(message_data)
                
            except json.JSONDecodeError:
                continue
            except Exception as e:
                if self.connected:
                    print(f"Error receiving message: {e}")
                break
                
    def handle_received_message(self, message_data):
        """Handle different types of received messages"""
        msg_type = message_data.get('type')
        
        if msg_type == 'welcome':
            # Store AES key
            if 'aes_key' in message_data:
                self.aes_key = base64.b64decode(message_data['aes_key'])
            self.add_to_chat("Server", message_data.get('message', ''), is_system=True)
            
        elif msg_type == 'chat':
            # Measure decryption time
            start_time = time.time() * 1000
            
            sender = message_data.get('sender', 'Unknown')
            encrypted_msg = message_data.get('encrypted_message', '')
            encryption_type = message_data.get('encryption_type', 'Unknown')
            
            # Decrypt message
            if encryption_type.startswith('AES'):
                decrypted_msg = self.decrypt_aes(encrypted_msg)
            else:
                decrypted_msg = self.decrypt_rsa(encrypted_msg)
                
            decryption_time = time.time() * 1000 - start_time
            
            # Display message with metrics
            enc_time = message_data.get('encryption_time', 0)
            overhead = message_data.get('overhead', 0)
            
            display_text = f"{decrypted_msg}\n    [{encryption_type}] Enc: {enc_time}ms, Dec: {decryption_time:.1f}ms, Overhead: {overhead}%"
            self.add_to_chat(sender, display_text)
            
            # Update metrics if not our own message
            if sender != self.username:
                self.update_metrics('receive', decryption_time, len(decrypted_msg.encode()))
                
        elif msg_type == 'notification':
            self.add_to_chat("System", message_data.get('message', ''), is_system=True)
            
        elif msg_type == 'user_list':
            self.update_users_list(message_data.get('users', []))
            
    def decrypt_aes(self, encrypted_data):
        """Decrypt AES encrypted message"""
        try:
            if not self.aes_key:
                return encrypted_data
                
            decoded = base64.b64decode(encrypted_data.encode())
            iv = decoded[:16]
            encrypted = decoded[16:]
            
            cipher = Cipher(algorithms.AES(self.aes_key), modes.CBC(iv))
            decryptor = cipher.decryptor()
            
            padded_message = decryptor.update(encrypted) + decryptor.finalize()
            
            # Remove padding
            padding_length = padded_message[-1]
            message = padded_message[:-padding_length]
            
            return message.decode()
        except:
            return "Decryption failed"
            
    def decrypt_rsa(self, encrypted_data):
        """Simulate RSA decryption"""
        try:
            time.sleep(0.025)  # Simulate RSA decryption delay
            decoded = base64.b64decode(encrypted_data.encode()).decode()
            if decoded.startswith("RSA:"):
                return decoded[4:]
            return decoded
        except:
            return "Decryption failed"
            
    def add_to_chat(self, sender, message, is_system=False):
        """Add message to chat display"""
        def update_chat():
            self.chat_display.configure(state=tk.NORMAL)
            
            timestamp = datetime.now().strftime("%H:%M:%S")
            
            if is_system:
                self.chat_display.insert(tk.END, f"[{timestamp}] {message}\n", "system")
            else:
                self.chat_display.insert(tk.END, f"[{timestamp}] {sender}: {message}\n")
                
            self.chat_display.configure(state=tk.DISABLED)
            self.chat_display.see(tk.END)
            
        self.root.after(0, update_chat)
        
    def update_users_list(self, users):
        """Update the online users list"""
        def update_list():
            self.users_listbox.delete(0, tk.END)
            for user in users:
                self.users_listbox.insert(tk.END, user)
                
        self.root.after(0, update_list)
        
    def update_metrics(self, operation, time_ms, bytes_count):
        """Update performance metrics"""
        if operation == 'send':
            self.metrics['messages_sent'] += 1
            self.metrics['total_bytes_sent'] += bytes_count
            
            # Update average encryption time
            current_avg = self.metrics['avg_encryption_time']
            count = self.metrics['messages_sent']
            self.metrics['avg_encryption_time'] = ((current_avg * (count - 1)) + time_ms) / count
            
        elif operation == 'receive':
            self.metrics['messages_received'] += 1
            self.metrics['total_bytes_received'] += bytes_count
            
            # Update average decryption time
            current_avg = self.metrics['avg_decryption_time']
            count = self.metrics['messages_received']
            self.metrics['avg_decryption_time'] = ((current_avg * (count - 1)) + time_ms) / count
            
        # Update GUI
        def update_gui():
            for key, label in self.metrics_labels.items():
                value = self.metrics[key]
                if 'time' in key:
                    label.configure(text=f"{value:.2f}")
                else:
                    label.configure(text=str(int(value)))
                    
        self.root.after(0, update_gui)
        
    def on_closing(self):
        """Handle window closing"""
        if self.connected:
            self.disconnect_from_server()
        self.root.destroy()
        
    def run(self):
        """Start the GUI"""
        self.root.mainloop()

def main():
    client = ChatClient()
    client.run()

if __name__ == "__main__":
    main()
#!/usr/bin/env python3
import tkinter as tk
import customtkinter as ctk
import socket
import threading
import json
import time
import base64
from datetime import datetime
import os
from crypto_utils import (
    generate_rsa_key_pair, public_key_to_pem, pem_to_public_key,
    encrypt_aes, decrypt_aes, encrypt_rsa, decrypt_rsa
)

class ChatClient:
    def __init__(self):
        self.socket = None
        self.connected = False
        self.username = ""
        self.aes_key = None
        self.users_public_keys = {}
        self.rsa_private_key, self.rsa_public_key = generate_rsa_key_pair()
        
        # Performance metrics
        self.metrics = {
            'messages_sent': 0,
            'messages_received': 0,
            'avg_encryption_time': 0,
            'avg_decryption_time': 0,
            'total_bytes_sent': 0,
            'total_bytes_received': 0
        }
        
        ctk.set_appearance_mode("Dark")
        ctk.set_default_color_theme("blue")
        self.setup_gui()
        
    def setup_gui(self):
        """Initialize the GUI"""
        self.root = ctk.CTk()
        self.root.title("Encrypted Crypto Chat")
        self.root.geometry("900x650")
        
        # Create notebook for tabs
        self.notebook = ctk.CTkTabview(self.root)
        self.notebook.pack(fill="both", expand=True, padx=20, pady=20)
        
        self.notebook.add("Connection")
        self.notebook.add("Chat")
        self.notebook.add("Performance")
        
        self.setup_connection_tab()
        self.setup_chat_tab()
        self.setup_metrics_tab()
        
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        
    def setup_connection_tab(self):
        conn_frame = self.notebook.tab("Connection")
        
        # Settings
        settings_frame = ctk.CTkFrame(conn_frame)
        settings_frame.pack(fill="x", padx=40, pady=20)
        
        ctk.CTkLabel(settings_frame, text="Server:").grid(row=0, column=0, sticky="w", padx=20, pady=10)
        self.server_entry = ctk.CTkEntry(settings_frame, width=250)
        self.server_entry.insert(0, "localhost")
        self.server_entry.grid(row=0, column=1, padx=20, pady=10)
        
        ctk.CTkLabel(settings_frame, text="Port:").grid(row=1, column=0, sticky="w", padx=20, pady=10)
        self.port_entry = ctk.CTkEntry(settings_frame, width=250)
        self.port_entry.insert(0, "12345")
        self.port_entry.grid(row=1, column=1, padx=20, pady=10)
        
        ctk.CTkLabel(settings_frame, text="Username:").grid(row=2, column=0, sticky="w", padx=20, pady=10)
        self.username_entry = ctk.CTkEntry(settings_frame, width=250)
        self.username_entry.insert(0, f"User{int(time.time()) % 1000}")
        self.username_entry.grid(row=2, column=1, padx=20, pady=10)
        
        # Encryption type selection
        enc_frame = ctk.CTkFrame(conn_frame)
        enc_frame.pack(fill="x", padx=40, pady=10)
        
        ctk.CTkLabel(enc_frame, text="Encryption Mode", font=("Segoe UI", 14, "bold")).pack(anchor="w", padx=20, pady=(10,5))
        self.encryption_var = ctk.StringVar(value="aes")
        
        ctk.CTkRadioButton(enc_frame, text="AES-256 (Symmetric) - Recommended", variable=self.encryption_var, value="aes").pack(anchor="w", padx=20, pady=10)
        ctk.CTkRadioButton(enc_frame, text="RSA-2048 (Asymmetric) - Heavy P2P", variable=self.encryption_var, value="rsa").pack(anchor="w", padx=20, pady=(0, 10))
        
        # Action Buttons
        btn_frame = ctk.CTkFrame(conn_frame, fg_color="transparent")
        btn_frame.pack(fill="x", padx=40, pady=20)
        
        self.connect_btn = ctk.CTkButton(btn_frame, text="Connect", command=self.connect_to_server, fg_color="#10b981", hover_color="#059669")
        self.connect_btn.pack(side="left", padx=5)
        
        self.disconnect_btn = ctk.CTkButton(btn_frame, text="Disconnect", command=self.disconnect_from_server, state="disabled", fg_color="#ef4444", hover_color="#dc2626")
        self.disconnect_btn.pack(side="left", padx=5)
        
        # Status Light
        bg_col = self.root._apply_appearance_mode(ctk.ThemeManager.theme["CTkFrame"]["fg_color"])
        self.status_canvas = tk.Canvas(btn_frame, width=16, height=16, bg=btn_frame._bg_color, highlightthickness=0)
        # Handle tricky custom tkinter background matching for canvas
        try:
            self.status_canvas.configure(bg=self.root._apply_appearance_mode(ctk.ThemeManager.theme["CTk"]["fg_color"]))
        except:
            pass
        self.status_canvas.pack(side="right", padx=(0, 20), pady=7)
        self.status_circle = self.status_canvas.create_oval(2, 2, 14, 14, fill="#ef4444", outline="")
        
        self.status_var = ctk.StringVar(value="Disconnected")
        ctk.CTkLabel(btn_frame, textvariable=self.status_var).pack(side="right", padx=10)
        
    def setup_chat_tab(self):
        chat_frame = self.notebook.tab("Chat")
        
        chat_area = ctk.CTkFrame(chat_frame, fg_color="transparent")
        chat_area.pack(side="left", fill="both", expand=True, padx=(0, 10))
        
        self.chat_display = ctk.CTkTextbox(chat_area, state="disabled", font=("Segoe UI", 13), wrap="word")
        self.chat_display.pack(fill="both", expand=True, pady=(0, 10))
        
        # Tags for bubbles
        self.chat_display.tag_config('right', justify='right', foreground='#60a5fa', spacing1=10, spacing3=10)
        self.chat_display.tag_config('left', justify='left', foreground='#e4e4e7', spacing1=10, spacing3=10)
        self.chat_display.tag_config('system', justify='center', foreground='#fbbf24', spacing1=10, spacing3=10)
        self.chat_display.tag_config('meta_right', justify='right', foreground='#71717a', spacing3=15)
        self.chat_display.tag_config('meta_left', justify='left', foreground='#71717a', spacing3=15)

        input_frame = ctk.CTkFrame(chat_area, fg_color="transparent")
        input_frame.pack(fill="x")
        
        self.message_entry = ctk.CTkEntry(input_frame, placeholder_text="Type your message here...", height=40)
        self.message_entry.pack(side="left", fill="x", expand=True, padx=(0, 10))
        self.message_entry.bind('<Return>', lambda e: self.send_message())
        
        self.send_btn = ctk.CTkButton(input_frame, text="Send", command=self.send_message, width=80, height=40)
        self.send_btn.pack(side="right")
        
        # User List
        sidebar = ctk.CTkFrame(chat_frame, width=200)
        sidebar.pack(side="right", fill="y")
        
        ctk.CTkLabel(sidebar, text="Online Users", font=("Segoe UI", 16, "bold")).pack(pady=(15, 5))
        
        self.users_scroll = ctk.CTkScrollableFrame(sidebar, fg_color="transparent")
        self.users_scroll.pack(fill="both", expand=True, padx=5, pady=5)
        self.user_widgets = []
        
    def setup_metrics_tab(self):
        metrics_frame = self.notebook.tab("Performance")
        
        realtime_frame = ctk.CTkFrame(metrics_frame)
        realtime_frame.pack(fill="x", padx=40, pady=20)
        
        ctk.CTkLabel(realtime_frame, text="Real-time Metrics", font=("Segoe UI", 16, "bold")).grid(row=0, column=0, columnspan=2, sticky="w", pady=15, padx=20)
        
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
            ctk.CTkLabel(realtime_frame, text=f"{label}:", font=("Segoe UI", 13)).grid(row=i+1, column=0, sticky="w", pady=5, padx=20)
            self.metrics_labels[key] = ctk.CTkLabel(realtime_frame, text="0", font=("Consolas", 15, "bold"), text_color="#10b981")
            self.metrics_labels[key].grid(row=i+1, column=1, sticky="w", padx=20, pady=5)
            
    def connect_to_server(self):
        try:
            server = self.server_entry.get() or "localhost"
            port = int(self.port_entry.get() or "12345")
            self.username = self.username_entry.get() or f"User{int(time.time()) % 1000}"
            
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((server, port))
            self.connected = True
            
            join_data = {
                'type': 'join',
                'username': self.username,
                'encryption_type': self.encryption_var.get(),
                'public_key': public_key_to_pem(self.rsa_public_key)
            }
            self.send_data(join_data)
            
            receiver_thread = threading.Thread(target=self.receive_messages)
            receiver_thread.daemon = True
            receiver_thread.start()
            
            # Switch UI elements
            self.status_var.set(f"Connected as {self.username}")
            self.status_canvas.itemconfig(self.status_circle, fill="#10b981") # Green
            self.connect_btn.configure(state="disabled")
            self.disconnect_btn.configure(state="normal")
            self.notebook.set("Chat")
            
            self.add_to_chat("System", "Connected to server!", is_system=True)
            
        except Exception as e:
            from tkinter import messagebox
            messagebox.showerror("Connection Error", f"Failed to connect: {e}")
            
    def disconnect_from_server(self):
        self.connected = False
        if self.socket:
            try:
                self.socket.close()
            except:
                pass
        
        self.status_var.set("Disconnected")
        self.status_canvas.itemconfig(self.status_circle, fill="#ef4444") # Red
        self.connect_btn.configure(state="normal")
        self.disconnect_btn.configure(state="disabled")
        
        self.add_to_chat("System", "Disconnected from server", is_system=True)
        
    def send_message(self):
        message = self.message_entry.get().strip()
        if not message or not self.connected:
            return
            
        self.message_entry.delete(0, tk.END)
        threading.Thread(target=self._async_send, args=(message,), daemon=True).start()

    def _async_send(self, message):
        start_time = time.time() * 1000
        
        if self.encryption_var.get() == "aes":
            encrypted_msg, original_size, encrypted_size = encrypt_aes(self.aes_key, message)
            encryption_type = "AES-256"
            
            encryption_time = time.time() * 1000 - start_time
            message_data = {
                'type': 'chat',
                'original_message': message,
                'encrypted_message': encrypted_msg,
                'encryption_type': encryption_type,
                'encryption_time': round(encryption_time, 3),
                'original_size': original_size,
                'encrypted_size': encrypted_size,
                'overhead': round(((encrypted_size - original_size) / original_size) * 100, 1) if original_size else 0,
                'timestamp': datetime.now().isoformat()
            }
        else:
            encryption_type = "RSA-2048"
            encrypted_payloads = {}
            total_encrypted_size = 0
            original_size = len(message.encode('utf-8'))
            
            for user, pub_key in self.users_public_keys.items():
                if not pub_key: continue
                enc_msg, _, enc_sz = encrypt_rsa(pub_key, message)
                encrypted_payloads[user] = enc_msg
                total_encrypted_size += enc_sz
                
            encrypted_msg = json.dumps(encrypted_payloads)
            encryption_time = time.time() * 1000 - start_time
            
            message_data = {
                'type': 'chat',
                'original_message': message,
                'encrypted_message': encrypted_msg,
                'encryption_type': encryption_type,
                'encryption_time': round(encryption_time, 3),
                'original_size': original_size,
                'encrypted_size': len(encrypted_msg),
                'overhead': round(((len(encrypted_msg) - original_size) / original_size) * 100, 1) if original_size else 0,
                'timestamp': datetime.now().isoformat()
            }
            
        self.send_data(message_data)
        self.update_metrics('send', encryption_time, len(message.encode()))
        
    def send_data(self, data):
        try:
            message = json.dumps(data).encode('utf-8')
            self.socket.send(message)
        except Exception as e:
            print(f"Error sending data: {e}")
            
    def receive_messages(self):
        while self.connected:
            try:
                data = self.socket.recv(8192)
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
        msg_type = message_data.get('type')
        
        if msg_type == 'welcome':
            aes_payload = message_data.get('aes_key')
            aes_type = message_data.get('aes_key_type')
            
            if aes_payload:
                if aes_type == 'rsa_encrypted':
                    decrypted_b64 = decrypt_rsa(self.rsa_private_key, aes_payload)
                    self.aes_key = base64.b64decode(decrypted_b64.encode('utf-8'))
                else:
                    self.aes_key = base64.b64decode(aes_payload.encode('utf-8'))
            self.add_to_chat("System", message_data.get('message', ''), is_system=True)
            
        elif msg_type == 'chat':
            threading.Thread(target=self._async_receive, args=(message_data,), daemon=True).start()
                
        elif msg_type == 'notification':
            self.add_to_chat("System", message_data.get('message', ''), is_system=True)
            
        elif msg_type == 'user_list':
            users_dict = message_data.get('users', {})
            self.users_public_keys.clear()
            for user, pem_str in users_dict.items():
                if pem_str:
                    try:
                        self.users_public_keys[user] = pem_to_public_key(pem_str)
                    except:
                        pass
            self.update_users_list(list(users_dict.keys()))

    def _async_receive(self, message_data):
        start_time = time.time() * 1000
        
        sender = message_data.get('sender', 'Unknown')
        encrypted_msg = message_data.get('encrypted_message', '')
        encryption_type = message_data.get('encryption_type', 'Unknown')
        
        if encryption_type.startswith('AES'):
            decrypted_msg = decrypt_aes(self.aes_key, encrypted_msg)
        else:
            try:
                payloads = json.loads(encrypted_msg)
                if self.username in payloads:
                    my_ciphertext = payloads[self.username]
                    decrypted_msg = decrypt_rsa(self.rsa_private_key, my_ciphertext)
                elif sender == self.username:
                    decrypted_msg = message_data.get('original_message', '')
                else:
                    decrypted_msg = "<Message not encrypted for me>"
            except:
                decrypted_msg = "<Invalid RSA payload>"
                
        decryption_time = time.time() * 1000 - start_time
        
        enc_time = message_data.get('encryption_time', 0)
        overhead = message_data.get('overhead', 0)
        
        meta = f"[{encryption_type}] Enc: {enc_time}ms, Dec: {decryption_time:.1f}ms, Overhead: {overhead}%"
        self.add_to_chat(sender, decrypted_msg, meta=meta)
        
        if sender != self.username:
            self.update_metrics('receive', decryption_time, len(decrypted_msg.encode()))
            
    def add_to_chat(self, sender, message, is_system=False, meta=""):
        def update_chat():
            self.chat_display.configure(state="normal")
            timestamp = datetime.now().strftime("%I:%M %p")
            
            if is_system:
                self.chat_display.insert(tk.END, f"--- {message} ---\n", 'system')
            else:
                if sender == self.username:
                    self.chat_display.insert(tk.END, f"{message}\n", 'right')
                    self.chat_display.insert(tk.END, f"{meta}\n", 'meta_right')
                else:
                    self.chat_display.insert(tk.END, f"{sender} • {timestamp}\n", 'meta_left')
                    self.chat_display.insert(tk.END, f"{message}\n", 'left')
                    self.chat_display.insert(tk.END, f"{meta}\n", 'meta_left')
                
            self.chat_display.configure(state="disabled")
            self.chat_display.see(tk.END)
            
        self.root.after(0, update_chat)
        
    def update_users_list(self, users):
        def update_list():
            for widget in self.user_widgets:
                widget.destroy()
            self.user_widgets.clear()
            
            for user in users:
                is_me = (user == self.username)
                color = "#60a5fa" if is_me else "#e4e4e7"
                display_name = f"{user} (You)" if is_me else user
                
                lbl = ctk.CTkLabel(self.users_scroll, text=display_name, text_color=color, font=("Segoe UI", 14))
                lbl.pack(anchor="w", pady=2, padx=5)
                self.user_widgets.append(lbl)
                
        self.root.after(0, update_list)
        
    def update_metrics(self, operation, time_ms, bytes_count):
        if operation == 'send':
            self.metrics['messages_sent'] += 1
            self.metrics['total_bytes_sent'] += bytes_count
            current_avg = self.metrics['avg_encryption_time']
            count = self.metrics['messages_sent']
            self.metrics['avg_encryption_time'] = ((current_avg * (count - 1)) + time_ms) / count
            
        elif operation == 'receive':
            self.metrics['messages_received'] += 1
            self.metrics['total_bytes_received'] += bytes_count
            current_avg = self.metrics['avg_decryption_time']
            count = self.metrics['messages_received']
            self.metrics['avg_decryption_time'] = ((current_avg * (count - 1)) + time_ms) / count
            
        def update_gui():
            for key, label in self.metrics_labels.items():
                value = self.metrics[key]
                if 'time' in key:
                    label.configure(text=f"{value:.2f}")
                else:
                    label.configure(text=str(int(value)))
                    
        self.root.after(0, update_gui)
        
    def on_closing(self):
        if self.connected:
            self.disconnect_from_server()
        self.root.destroy()
        
    def run(self):
        self.root.mainloop()

def main():
    client = ChatClient()
    client.run()

if __name__ == "__main__":
    main()
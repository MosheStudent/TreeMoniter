import socket
import json
import tkinter as tk
from tkinter import filedialog, messagebox
import struct
from encryption import Encryption
from config import HOST, PORT, ENCRYPTION_KEY

class FileClient:
    def __init__(self, host=HOST, port=PORT, key=ENCRYPTION_KEY):
        self.host = host
        self.port = port
        self.encryption = Encryption(key)
        self.socket = None
        self.root = tk.Tk()
        self.root.title("File Client")
        self.connection_status = tk.StringVar(value="Disconnected")
        self.setup_gui()
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

    def connect(self):
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.host, self.port))
            self.connection_status.set("Connected")
            messagebox.showinfo("Success", "Connected to server")
            self.list_files()  # Auto-list files on connect
            return True
        except ConnectionRefusedError:
            self.connection_status.set("Disconnected")
            messagebox.showerror("Connection Error", "Server is not running or unreachable")
            return False
        except Exception as e:
            self.connection_status.set("Disconnected")
            messagebox.showerror("Connection Error", f"Failed to connect: {str(e)}")
            return False

    def send_message(self, request):
        if not self.socket:
            messagebox.showerror("Error", "Not connected to server")
            print("Error: Attempted to send message without a connection")
            return False
        data = self.encryption.encrypt(json.dumps(request))
        length = struct.pack('>I', len(data))
        try:
            self.socket.sendall(length + data)
            return True
        except (BrokenPipeError, ConnectionResetError, AttributeError) as e:
            self.connection_status.set("Disconnected")
            messagebox.showerror("Error", f"Connection to server lost: {str(e)}")
            self.socket = None
            print(f"Error sending message: {e}")
            return False

    def receive_message(self):
        if not self.socket:
            print("Error: Attempted to receive message without a connection")
            return None
        try:
            raw_msglen = self.recvall(4)
            if not raw_msglen:
                print("Error: No length prefix received")
                return None
            msglen = struct.unpack('>I', raw_msglen)[0]
            encrypted_data = self.recvall(msglen)
            if not encrypted_data:
                print("Error: No data received")
                return None
            decrypted_data = self.encryption.decrypt(encrypted_data).decode()
            response = json.loads(decrypted_data)
            print(f"Received response: {response}")  # Debug log
            return response
        except (json.JSONDecodeError, UnicodeDecodeError, struct.error, AttributeError) as e:
            messagebox.showerror("Error", f"Failed to process server response: {str(e)}")
            self.connection_status.set("Disconnected")
            self.socket = None
            print(f"Error receiving message: {e}")
            return None

    def recvall(self, n):
        data = bytearray()
        while len(data) < n:
            packet = self.socket.recv(n - len(data))
            if not packet:
                print("Error: Connection closed during receive")
                return None
            data.extend(packet)
        return data

    def list_files(self):
        if not self.socket:
            messagebox.showerror("Error", "Not connected to server")
            print("Error: List files attempted without connection")
            return
        if not self.send_message({'command': 'list'}):
            return
        response = self.receive_message()
        if response:
            if response.get('status') == 'success':
                self.file_list.delete(0, tk.END)
                files = response.get('files', [])
                if not files:
                    self.file_list.insert(tk.END, "(No files available)")
                else:
                    for file in files:
                        self.file_list.insert(tk.END, file)
                print(f"Displayed files: {files}")
            else:
                error_msg = response.get('message', 'Failed to list files')
                messagebox.showerror("Error", error_msg)
                print(f"Server error: {error_msg}")
        else:
            messagebox.showerror("Error", "No response from server")
            print("Error: No response received for list command")

    def download_file(self):
        if not self.socket:
            messagebox.showerror("Error", "Not connected to server")
            print("Error: Download attempted without connection")
            return
        selected = self.file_list.curselection()
        if not selected:
            messagebox.showerror("Error", "No file selected")
            print("Error: No file selected for download")
            return
        filename = self.file_list.get(selected[0])
        if filename == "(No files available)":
            messagebox.showerror("Error", "No files available to download")
            print("Error: Attempted to download placeholder text")
            return
        if self.send_message({'command': 'download', 'filename': filename}):
            response = self.receive_message()
            if response and response.get('status') == 'success':
                save_path = filedialog.asksaveasfilename(defaultextension=".*", initialfile=filename)
                if save_path:
                    try:
                        with open(save_path, 'wb') as f:
                            f.write(bytes.fromhex(response['data']))
                        messagebox.showinfo("Success", "File downloaded successfully")
                        print(f"Downloaded file: {filename} to {save_path}")
                    except Exception as e:
                        messagebox.showerror("Error", f"Failed to save file: {str(e)}")
                        print(f"Error saving file {filename}: {e}")
                else:
                    messagebox.showinfo("Info", "Download cancelled")
                    print("Download cancelled by user")
            else:
                error_msg = response.get('message', 'Failed to download file') if response else "No response from server"
                messagebox.showerror("Error", error_msg)
                print(f"Download error: {error_msg}")

    def delete_file(self):
        if not self.socket:
            messagebox.showerror("Error", "Not connected to server")
            print("Error: Delete attempted without connection")
            return
        selected = self.file_list.curselection()
        if not selected:
            messagebox.showerror("Error", "No file selected")
            print("Error: No file selected for delete")
            return
        filename = self.file_list.get(selected[0])
        if filename == "(No files available)":
            messagebox.showerror("Error", "No files available to delete")
            print("Error: Attempted to delete placeholder text")
            return
        if self.send_message({'command': 'delete', 'filename': filename}):
            response = self.receive_message()
            if response and response.get('status') == 'success':
                messagebox.showinfo("Success", "File deleted successfully")
                self.list_files()
                print(f"Deleted file: {filename}")
            else:
                error_msg = response.get('message', 'Failed to delete file') if response else "No response from server"
                messagebox.showerror("Error", error_msg)
                print(f"Delete error: {error_msg}")

    def setup_gui(self):
        tk.Label(self.root, text="Server Status:").pack(pady=5)
        tk.Label(self.root, textvariable=self.connection_status, font=("Arial", 12, "bold")).pack(pady=5)
        tk.Button(self.root, text="Connect", command=self.connect).pack(pady=5)
        tk.Button(self.root, text="List Files", command=self.list_files).pack(pady=5)
        tk.Button(self.root, text="Download File", command=self.download_file).pack(pady=5)
        tk.Button(self.root, text="Delete File", command=self.delete_file).pack(pady=5)
        self.file_list = tk.Listbox(self.root, width=50)
        self.file_list.pack(pady=5)

    def on_closing(self):
        if self.socket:
            try:
                self.socket.close()
                print("Socket closed")
            except Exception as e:
                print(f"Error closing socket: {e}")
        self.root.destroy()

    def run(self):
        self.root.mainloop()

if __name__ == '__main__':
    client = FileClient()
    client.run()
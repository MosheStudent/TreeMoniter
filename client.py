import socket
import json
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
import struct
from encryption import Encryption
from config import HOST, PORT, ENCRYPTION_KEY

import os

class FileClient:
    def __init__(self, host=HOST, port=PORT, key=ENCRYPTION_KEY):
        self.host = host
        self.port = port
        self.encryption = Encryption(key)
        self.socket = None
        self.root = tk.Tk()
        self.root.title("File Client")
        self.connection_status = tk.StringVar(value="Disconnected")
        self.current_path = tk.StringVar(value="/") # To keep track of the current directory
        self.setup_gui()
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

    def connect(self):
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.host, self.port))
            self.connection_status.set("Connected")
            messagebox.showinfo("Success", "Connected to server")
            self.list_files(self.current_path.get())  # List the initial path
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
            print(f"Received response: {response}")
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

    def list_files(self, path_to_list=None): # Added path_to_list parameter
        if not self.socket:
            messagebox.showerror("Error", "Not connected to server")
            print("Error: List files attempted without connection")
            return

        if path_to_list is None:
            path_to_list = simpledialog.askstring("List Directory", "Enter path to list (e.g., C:\\, /home/user/, /):", initialvalue=self.current_path.get())
            if not path_to_list:
                return

        self.current_path.set(path_to_list)
        self.path_label.config(text=f"Current Directory: {self.current_path.get()}")

        if not self.send_message({'command': 'list', 'path': path_to_list}): # Send the path
            return
        response = self.receive_message()
        if response:
            if response.get('status') == 'success':
                self.file_list.delete(0, tk.END)
                files = response.get('files', [])
                if not files:
                    self.file_list.insert(tk.END, "(No files or directories available in this path)")
                else:
                    for file in files:
                        self.file_list.insert(tk.END, file)
                print(f"Displayed items: {files}")
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

        selected_item = self.file_list.get(selected[0])
        # Extract the actual name by removing "(FILE)" or "(DIR)"
        if selected_item.endswith(" (FILE)"):
            item_name = selected_item[:-7]
        elif selected_item.endswith(" (DIR)"):
            messagebox.showerror("Error", "Cannot download a directory. Please select a file.")
            return
        else: # Fallback for items without specific tags (e.g., initial list)
            item_name = selected_item

        if item_name == "(No files or directories available in this path)":
            messagebox.showerror("Error", "No files available to download")
            print("Error: Attempted to download placeholder text")
            return

        # Construct the full path on the server
        server_filepath = os.path.join(self.current_path.get(), item_name)

        if self.send_message({'command': 'download', 'filepath': server_filepath}): # Send the full path
            response = self.receive_message()
            if response and response.get('status') == 'success':
                # Suggest the original filename for saving
                save_path = filedialog.asksaveasfilename(defaultextension=".*", initialfile=os.path.basename(server_filepath))
                if save_path:
                    try:
                        with open(save_path, 'wb') as f:
                            f.write(bytes.fromhex(response['data']))
                        messagebox.showinfo("Success", "File downloaded successfully")
                        print(f"Downloaded file: {server_filepath} to {save_path}")
                    except Exception as e:
                        messagebox.showerror("Error", f"Failed to save file: {str(e)}")
                        print(f"Error saving file {server_filepath}: {e}")
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

        selected_item = self.file_list.get(selected[0])
        if selected_item.endswith(" (FILE)"):
            item_name = selected_item[:-7]
        elif selected_item.endswith(" (DIR)"):
            messagebox.showerror("Error", "Cannot delete a directory directly with this command. Please select a file.")
            return
        else:
            item_name = selected_item

        if item_name == "(No files or directories available in this path)":
            messagebox.showerror("Error", "No files available to delete")
            print("Error: Attempted to delete placeholder text")
            return

        # Construct the full path on the server
        server_filepath = os.path.join(self.current_path.get(), item_name)

        if messagebox.askyesno("Confirm Delete", f"Are you sure you want to delete {server_filepath} on the server? This cannot be undone!"):
            if self.send_message({'command': 'delete', 'filepath': server_filepath}): # Send the full path
                response = self.receive_message()
                if response and response.get('status') == 'success':
                    messagebox.showinfo("Success", "File deleted successfully")
                    self.list_files(self.current_path.get()) # Refresh current directory list
                    print(f"Deleted file: {server_filepath}")
                else:
                    error_msg = response.get('message', 'Failed to delete file') if response else "No response from server"
                    messagebox.showerror("Error", error_msg)
                    print(f"Delete error: {error_msg}")
        else:
            messagebox.showinfo("Info", "Delete operation cancelled.")


    def go_to_parent_directory(self):
        current_path = self.current_path.get()
        parent_path = os.path.dirname(current_path)
        if parent_path == current_path: # Already at the root
            messagebox.showinfo("Info", "Already at the root directory.")
            return
        self.list_files(parent_path)

    def open_selected_directory(self):
        selected = self.file_list.curselection()
        if not selected:
            messagebox.showerror("Error", "No item selected")
            return
        selected_item = self.file_list.get(selected[0])
        if selected_item.endswith(" (DIR)"):
            dir_name = selected_item[:-6] # Remove " (DIR)"
            new_path = os.path.join(self.current_path.get(), dir_name)
            self.list_files(new_path)
        else:
            messagebox.showinfo("Info", "Selected item is not a directory.")


    def setup_gui(self):
        tk.Label(self.root, text="Server Status:").pack(pady=5)
        tk.Label(self.root, textvariable=self.connection_status, font=("Arial", 12, "bold")).pack(pady=5)
        tk.Button(self.root, text="Connect", command=self.connect).pack(pady=5)

        self.path_label = tk.Label(self.root, textvariable=self.current_path, font=("Arial", 10))
        self.path_label.pack(pady=2)

        # Frame for navigation buttons
        nav_frame = tk.Frame(self.root)
        nav_frame.pack(pady=5)
        tk.Button(nav_frame, text="List Current Dir", command=lambda: self.list_files(self.current_path.get())).pack(side=tk.LEFT, padx=2)
        tk.Button(nav_frame, text="Change Dir", command=self.list_files).pack(side=tk.LEFT, padx=2) # Will prompt for new path
        tk.Button(nav_frame, text="Go Up", command=self.go_to_parent_directory).pack(side=tk.LEFT, padx=2)
        tk.Button(nav_frame, text="Open Dir", command=self.open_selected_directory).pack(side=tk.LEFT, padx=2)


        tk.Button(self.root, text="Download File", command=self.download_file).pack(pady=5)
        tk.Button(self.root, text="Delete File", command=self.delete_file).pack(pady=5)

        self.file_list = tk.Listbox(self.root, width=80, height=20) # Increased width/height
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

import socket
import json

import tkinter as tk
from client_gui import FileClientGUI

import struct
from encryption import Encryption
from config import HOST, PORT, ENCRYPTION_KEY

import os

from cross_platform import to_network_path, safe_path_join

class FileClient:
    def __init__(self, host=HOST, port=PORT, key=ENCRYPTION_KEY):
        self.host = host #ip of server
        self.port = port #port of server

        self.encryption = Encryption(key)
        self.file_client_gui = FileClientGUI(self)

        self.socket = None
        self.root = self.file_client_gui.root  # Access the root window from the GUI class

        self.connection_status = self.file_client_gui.connection_status  # Access the connection status from the GUI class
        self.current_path = self.file_client_gui.current_path # To keep track of the current directory

    def connect(self):
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM) #tcp, ip
            self.socket.connect((self.host, self.port))
            self.connection_status.set("Connected")
            self.file_client_gui.info_message("Connection Status", "Connected to server successfully")
            self.list_files(self.current_path.get())  # List the initial path
            return True
        except ConnectionRefusedError:
            self.connection_status.set("Disconnected")
            self.file_client_gui.error_message("Error", "Connection refused. Is the server running?")
            return False
        except Exception as e:
            self.connection_status.set("Disconnected")
            self.file_client_gui.error_message("Error", f"Failed to connect to server: {str(e)}")
            return False

    def send_message(self, request):
        if not self.socket:
            self.file_client_gui.error_message("Error", "Not connected to server")
            print("Error: Attempted to send message without a connection")
            return False
        data = self.encryption.encrypt(json.dumps(request))
        length = struct.pack('>I', len(data))
        try:
            self.socket.sendall(length + data)
            return True
        except (BrokenPipeError, ConnectionResetError, AttributeError) as e:
            self.connection_status.set("Disconnected")
            self.file_client_gui.error_message("Error", f"Failed to send message: {str(e)}")
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
            self.file_client_gui.error_message("Error", f"Failed to receive message: {str(e)}")
            self.connection_status.set("Disconnected")
            self.socket = None
            print(f"Error receiving message: {e}")
            return None

    def recvall(self, n): #recv all bytes in once packet
        data = bytearray()
        while len(data) < n:
            packet = self.socket.recv(n - len(data))
            if not packet:
                print("Error: Connection closed during receive")
                return None
            data.extend(packet)
        return data

    def list_files(self, path_to_list=None): 
        if not self.socket:
            self.file_client_gui.error_message("Error", "Not connected to server")
            print("Error: List files attempted without connection")
            return

        if path_to_list is None:
            path_to_list = self.file_client_gui.ask_for_directory()
            if not path_to_list:
                return

        network_path = to_network_path(path_to_list)
        self.current_path.set(path_to_list)
        self.path_label.config(text=f"Current Directory: {self.current_path.get()}")

        if not self.send_message({'command': 'list', 'path': network_path}): # Send the path
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
                self.file_client_gui.error_message("Error", error_msg)
                print(f"Server error: {error_msg}")
        else:
            self.file_client_gui.error_message("Error", "No response received from server")
            print("Error: No response received for list command")

    def download_file(self):
        if not self.socket:
            self.file_client_gui.error_message("Error", "Not connected to server")
            print("Error: Download attempted without connection")
            return
        selected = self.file_list.curselection()
        if not selected:
            self.file_client_gui.error_message("Error", "No file selected for download")
            print("Error: No file selected for download")
            return

        selected_item = self.file_list.get(selected[0])
        # Extract the actual name by removing "(FILE)" or "(DIR)"
        if selected_item.endswith(" (FILE)"):
            item_name = selected_item[:-7]
        elif selected_item.endswith(" (DIR)"):
            self.file_client_gui.error_message("Error", "Cannot download a directory. Please select a file.")
            return
        else: # Fallback for items without specific tags 
            item_name = selected_item

        if item_name == "(No files or directories available in this path)":
            self.file_client_gui.error_message("Error", "No files available to download")
            print("Error: Attempted to download placeholder text")
            return

        # Construct the full path on the server
        local_full_path = safe_path_join(self.current_path.get(), item_name)
        server_filepath = to_network_path(local_full_path)

        if self.send_message({'command': 'download', 'filepath': server_filepath}): # Send the full path
            response = self.receive_message()
            if response and response.get('status') == 'success':
                # Suggest the original filename for saving
                save_path = self.file_client_gui.save_file_dialog(server_filepath) #changes to base name in the module
                if save_path:
                    try:
                        with open(save_path, 'wb') as f:
                            f.write(bytes.fromhex(response['data']))
                        self.file_client_gui.info_message("Success", f"File downloaded successfully to {save_path}")
                        print(f"Downloaded file: {server_filepath} to {save_path}")
                    except Exception as e:
                        self.file_client_gui.error_message("Error", f"Failed to save file: {str(e)}")
                        print(f"Error saving file {server_filepath}: {e}")
                else:
                    self.file_client_gui.info_message("Info", "Download cancelled by user")
                    print("Download cancelled by user")
            else:
                error_msg = response.get('message', 'Failed to download file') if response else "No response from server"
                self.file_client_gui.error_message("Error", error_msg)
                print(f"Download error: {error_msg}")

    def delete_file(self):
        if not self.socket:
            self.file_client_gui.error_message("Error", "Not connected to server")
            print("Error: Delete attempted without connection")
            return
        selected = self.file_list.curselection()
        if not selected:
            self.file_client_gui.error_message("Error", "No file selected for delete")
            print("Error: No file selected for delete")
            return

        selected_item = self.file_list.get(selected[0])
        if selected_item.endswith(" (FILE)"):
            item_name = selected_item[:-7]
        elif selected_item.endswith(" (DIR)"):
            self.file_client_gui.error_message("Error", "Cannot delete a directory. Please select a file.")
            return
        else:
            item_name = selected_item

        if item_name == "(No files or directories available in this path)":
            self.file_client_gui.error_message("Error", "No files available to delete")
            print("Error: Attempted to delete placeholder text")
            return

        # Construct the full path on the server
        local_full_path = safe_path_join(self.current_path.get(), item_name)
        server_filepath = to_network_path(local_full_path)

        if self.file_client_gui.yes_no_message("Confirm Delete", f"Are you sure you want to delete '{item_name}'? This action cannot be undone."):
            if self.send_message({'command': 'delete', 'filepath': server_filepath}): # Send the full path
                response = self.receive_message()
                if response and response.get('status') == 'success':
                    self.file_client_gui.info_message("Success", f"File '{item_name}' deleted successfully.")
                    self.list_files(self.current_path.get()) # Refresh current directory list
                    print(f"Deleted file: {server_filepath}")
                else:
                    error_msg = response.get('message', 'Failed to delete file') if response else "No response from server"
                    self.file_client_gui.error_message("Error", error_msg)
                    print(f"Delete error: {error_msg}")
        else:
            self.file_client_gui.info_message("Info", "Delete operation cancelled by user")


    def go_to_parent_directory(self):
        current_path = self.current_path.get()
        parent_path = os.path.dirname(current_path)
        if parent_path == current_path: # Already at the root
            self.file_client_gui.info_message("Info", "Already at the root directory")
            return
        self.list_files(parent_path)

    def open_selected_directory(self):
        selected = self.file_list.curselection()
        if not selected:
            self.file_client_gui.error_message("Error", "No directory selected")
            return
        selected_item = self.file_list.get(selected[0])
        if selected_item.endswith(" (DIR)"):
            dir_name = selected_item[:-6] # Remove " (DIR)"
            new_path = os.path.join(self.current_path.get(), dir_name)
            self.list_files(new_path)
        else:
            self.file_client_gui.info_message("Info", "Selected item is not a directory")

    def run(self):
        self.root.mainloop()

if __name__ == '__main__':
    client = FileClient()
    client.run()

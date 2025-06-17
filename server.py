import socket
import os
import json
import threading
from encryption import Encryption
from config import HOST, PORT, ENCRYPTION_KEY
from messaging import MessageHandler

from cross_platform import get_root, from_network_path, to_network_path
class FileServer:
    def __init__(self, host=HOST, port=PORT, key=ENCRYPTION_KEY):
        self.host = host
        self.port = port
        self.encryption = Encryption(key)
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.message_handler = MessageHandler(self.encryption)


        # Thread lock for synchronizing file system operations
        self.file_lock = threading.Lock()

        self.pathSlash = get_root()


    def start(self):
        try:
            self.socket.bind((self.host, self.port))
            self.socket.listen()
            print(f"Server listening on {self.host}:{self.port}")
            while True:
                conn, addr = self.socket.accept()
                # Create a new thread for each client
                client_thread = threading.Thread(target=self.handle_client, args=(conn, addr))
                client_thread.start()
                print(f"Started thread {client_thread.name} for client {addr}")
        except Exception as e:
            print(f"Server error: {e}")
        finally:
            self.socket.close()


    def handle_client(self, conn, addr):
        thread_name = threading.current_thread().name
        print(f"[{thread_name}] Connected to {addr}")
        try:
            while True:
                encrypted_data = self.message_handler.receive_message(conn)
                if not encrypted_data:
                    break
                try:
                    data = json.loads(self.encryption.decrypt(encrypted_data).decode())
                except (json.JSONDecodeError, UnicodeDecodeError) as e:
                    print(f"[{thread_name}] Invalid data from {addr}: {e}")
                    self.message_handler.send_message(conn, {'status': 'error', 'message': f'Invalid data format: {e}'})
                    break

                command = data.get('command')
                if not command:
                    self.message_handler.send_message(conn, {'status': 'error', 'message': 'No command specified'})
                    break

                if command == 'list':
                    directory_to_list = data.get('path', to_network_path(self.pathSlash))
                    try:
                        local_path = from_network_path(directory_to_list)
                        abs_path = os.path.abspath(local_path)
                        # No lock needed for listing, as os.listdir is thread-safe (reading operation is safe)
                        files_and_dirs = os.listdir(abs_path)
                        files_list = []
                        for item in files_and_dirs:
                            full_item_path = os.path.join(abs_path, item)
                            if os.path.isfile(full_item_path):
                                files_list.append(item + " (FILE)")
                            elif os.path.isdir(full_item_path):
                                files_list.append(item + " (DIR)")
                        print(f"[{thread_name}] Listing contents of {abs_path}: {files_list}")
                        response = {'files': files_list, 'status': 'success'}
                    except FileNotFoundError:
                        response = {'status': 'error', 'message': 'Directory not found'}
                    except PermissionError:
                        response = {'status': 'error', 'message': 'Permission denied to list this directory'}
                    except Exception as e:
                        print(f"[{thread_name}] Failed to list directory {directory_to_list}: {e}")
                        response = {'status': 'error', 'message': f'Failed to list directory: {str(e)}'}
                    if not self.message_handler.send_message(conn, response):
                        break

                elif command == 'download':
                    filepath = data.get('filepath')
                    if not filepath:
                        response = {'status': 'error', 'message': 'No filepath provided'}
                    else:
                        try:
                            local_path = from_network_path(filepath)
                            abs_filepath = os.path.abspath(local_path)
                            
                            # Use lock to ensure thread-safe file reading
                            with self.file_lock:
                                if not os.path.exists(abs_filepath):
                                    response = {'status': 'error', 'message': 'File not found'}
                                elif not os.path.isfile(abs_filepath):
                                    response = {'status': 'error', 'message': 'Path is not a file'}
                                else:
                                    with open(abs_filepath, 'rb') as f:
                                        file_data = f.read()
                                    response = {'data': file_data.hex(), 'status': 'success'}
                        except PermissionError:
                            response = {'status': 'error', 'message': 'Permission denied to download this file'}
                        except Exception as e:
                            response = {'status': 'error', 'message': f'Download error: {str(e)}'}
                    if not self.message_handler.send_message(conn, response):
                        break

                elif command == 'delete':
                    filepath = data.get('filepath')
                    if not filepath:
                        response = {'status': 'error', 'message': 'No filepath provided'}
                    else:
                        try:
                            local_path = from_network_path(filepath)
                            abs_filepath = os.path.abspath(local_path)
                            # Use lock to ensure thread-safe file deletion
                            with self.file_lock:
                                if not os.path.exists(abs_filepath):
                                    response = {'status': 'error', 'message': 'File not found'}
                                elif not os.path.isfile(abs_filepath):
                                    response = {'status': 'error', 'message': 'Path is not a file'}
                                else:
                                    os.remove(abs_filepath)
                                    response = {'status': 'success'}
                        except PermissionError:
                            response = {'status': 'error', 'message': 'Permission denied to delete this file'}
                        except Exception as e:
                            response = {'status': 'error', 'message': f'Delete error: {str(e)}'}
                    if not self.message_handler.send_message(conn, response):
                        break

                else:
                    self.message_handler.send_message(conn, {'status': 'error', 'message': 'Invalid command'})
                    break

        except (ConnectionResetError, BrokenPipeError):
            print(f"[{thread_name}] Client {addr} disconnected")
        except Exception as e:
            print(f"[{thread_name}] Error handling client {addr}: {e}")
        finally:
            conn.close()
            print(f"[{thread_name}] Connection to {addr} closed")

if __name__ == '__main__':
    server = FileServer()
    server.start()
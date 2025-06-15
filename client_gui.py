import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
import os

class FileClientGUI:
    def __init__(self, client):
        self.client = client

        self.root = tk.Tk()
        self.root.title("File Client")

        self.connection_status = tk.StringVar(value="Disconnected")
        self.current_path = tk.StringVar(value="/")

        self.client.connection_status = self.connection_status
        self.client.current_path = self.current_path

        self.setup_gui()
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

    
    def setup_gui(self):
        tk.Label(self.root, text="Server Status:").pack(pady=5)
        tk.Label(self.root, textvariable=self.connection_status, font=("Arial", 12, "bold")).pack(pady=5)
        tk.Button(self.root, text="Connect", command=self.client.connect).pack(pady=5)

        self.client.path_label = tk.Label(self.root, textvariable=self.current_path, font=("Arial", 10))
        self.client.path_label.pack(pady=2)

        nav_frame = tk.Frame(self.root)
        nav_frame.pack(pady=5)
        tk.Button(nav_frame, text="List Current Dir", command=lambda: self.client.list_files(self.current_path.get())).pack(side=tk.LEFT, padx=2)
        tk.Button(nav_frame, text="Change Dir", command=self.client.list_files).pack(side=tk.LEFT, padx=2)
        tk.Button(nav_frame, text="Go Up", command=self.client.go_to_parent_directory).pack(side=tk.LEFT, padx=2)
        tk.Button(nav_frame, text="Open Dir", command=self.client.open_selected_directory).pack(side=tk.LEFT, padx=2)

        tk.Button(self.root, text="Download File", command=self.client.download_file).pack(pady=5)
        tk.Button(self.root, text="Delete File", command=self.client.delete_file).pack(pady=5)

        self.client.file_list = tk.Listbox(self.root, width=80, height=20)
        self.client.file_list.pack(pady=5)

    def error_message(self, header, message):
        messagebox.showerror(header, message)

    def info_message(self, header, message):
        messagebox.showinfo(header, message)

    def yes_no_message(self, header, message):
        return messagebox.askyesno(header, message)
    
    def ask_for_directory(self):
        return simpledialog.askstring("Change Directory", "Enter directory path:", initialvalue=self.current_path.get())
    
    def save_file_dialog(self, file_path):
        return filedialog.asksaveasfilename(defaultextension=".*", initialfile=os.path.basename(os.path.join(file_path)))

    def on_closing(self):
        if self.client.socket:
            try:
                self.client.socket.close()
            except Exception as e:
                print(f"Error closing socket: {e}")
        self.root.destroy()


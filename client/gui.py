import tkinter as tk
from tkinter import messagebox, ttk, scrolledtext, filedialog
import threading
import os
import socket
import time # Import time for sleep

# Import from server.config as it's the central configuration
# Make sure your project structure allows this import (e.g., you're running from the project root)
# If not, you might need to adjust the import path, or copy the config values directly.
try:
    from server.config import SERVER_IP, KNOCK_SEQUENCE, TARGET_PORT, PASSWORD
except ImportError:
    # Fallback if server.config cannot be imported directly (e.g., running gui.py from client/ dir)
    print("Warning: Could not import from server.config. Using default hardcoded values.")
    SERVER_IP = '127.0.0.1'
    KNOCK_SEQUENCE = [10001, 10002, 10003] # Example sequence
    TARGET_PORT = 2121
    PASSWORD = 'mysecurepassword'


# Assuming client.client.py is in the 'client' directory relative to gui.py
from client.client import PortKnockingClient

class PortKnockingGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Port Knocking Client")
        # Set initial size, but allow resizing
        self.root.geometry("750x950") # Increased height slightly more
        self.root.resizable(True, True) # Allow window to be resizable horizontally and vertically
        self.root.configure(bg='#f0f0f0')
        
        # Variables
        self.server_ip = tk.StringVar(value=SERVER_IP)
        self.target_port = tk.StringVar(value=str(TARGET_PORT))
        self.knock_sequence = tk.StringVar(value=",".join(map(str, KNOCK_SEQUENCE)))
        self.password = tk.StringVar(value=PASSWORD)
        self.status = tk.StringVar(value="Ready")
        self.ftp_connected = False
        self.client = None  # PortKnockingClient instance
        self.ftp_socket = None # Persistent socket for FTP connection

        # Style configuration
        self.style = ttk.Style()
        self.style.configure('TFrame', background='#f0f0f0')
        self.style.configure('TLabel', background='#f0f0f0', font=('Arial', 10))
        self.style.configure('TButton', font=('Arial', 10, 'bold')) # Make buttons bolder
        self.style.configure('TEntry', font=('Arial', 10))
        self.style.configure('Success.TLabel', foreground='green', font=('Arial', 10, 'bold'))
        self.style.configure('Error.TLabel', foreground='red', font=('Arial', 10, 'bold'))
        
        # Create widgets
        self.create_widgets()
        self.set_ftp_controls_state(tk.DISABLED) # Initially disable FTP controls

    def create_widgets(self):
        # Main container
        main_frame = ttk.Frame(self.root, padding="15")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Connection Settings Frame
        settings_frame = ttk.LabelFrame(main_frame, text="Connection Settings", padding="10")
        settings_frame.pack(fill=tk.X, pady=5)
        
        # Grid layout for settings
        settings_frame.columnconfigure(1, weight=1) # Make entry fields expand

        # Server IP
        ttk.Label(settings_frame, text="Server IP:").grid(row=0, column=0, sticky=tk.W, pady=5)
        ttk.Entry(settings_frame, textvariable=self.server_ip, width=30).grid(row=0, column=1, sticky=(tk.W, tk.E), pady=5)
        
        # Target Port
        ttk.Label(settings_frame, text="Target Port:").grid(row=1, column=0, sticky=tk.W, pady=5)
        ttk.Entry(settings_frame, textvariable=self.target_port, width=30).grid(row=1, column=1, sticky=(tk.W, tk.E), pady=5)
        
        # Knock Sequence
        ttk.Label(settings_frame, text="Knock Sequence (comma-separated):").grid(row=2, column=0, sticky=tk.W, pady=5)
        ttk.Entry(settings_frame, textvariable=self.knock_sequence, width=30).grid(row=2, column=1, sticky=(tk.W, tk.E), pady=5)
        
        # Password
        ttk.Label(settings_frame, text="Password:").grid(row=3, column=0, sticky=tk.W, pady=5)
        ttk.Entry(settings_frame, textvariable=self.password, show="*", width=30).grid(row=3, column=1, sticky=(tk.W, tk.E), pady=5)
        
        # Connect Button
        connect_frame = ttk.Frame(main_frame)
        connect_frame.pack(fill=tk.X, pady=10)
        self.connect_button = ttk.Button(connect_frame, text="Connect", command=self.start_connection, style='TButton')
        self.connect_button.pack()
        
        # Status
        status_frame = ttk.Frame(main_frame)
        status_frame.pack(fill=tk.X, pady=5)
        ttk.Label(status_frame, text="Status:").pack(side=tk.LEFT)
        self.status_label = ttk.Label(status_frame, textvariable=self.status)
        self.status_label.pack(side=tk.LEFT, padx=5)
        
        # Console Output
        console_frame = ttk.LabelFrame(main_frame, text="Connection Log", padding="10")
        console_frame.pack(fill=tk.BOTH, expand=True)
        
        self.console_output = scrolledtext.ScrolledText(
            console_frame, 
            state='disabled', 
            height=10, # Reduced height to make space for FTP
            wrap=tk.WORD,
            font=('Consolas', 10))
        self.console_output.pack(fill=tk.BOTH, expand=True)
        
        # FTP Commands (only visible when connected)
        self.ftp_frame = ttk.LabelFrame(main_frame, text="FTP Commands", padding="10")
        
        # File list
        self.file_list = tk.Listbox(self.ftp_frame, height=8, font=('Consolas', 10), bg='#ffffff', fg='#333333', selectbackground='#a0c0ff', selectforeground='white')
        self.file_list.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # Command input
        self.ftp_command_entry = ttk.Entry(self.ftp_frame, width=70, font=('Arial', 10))
        self.ftp_command_entry.pack(fill=tk.X, pady=(0,5))
        self.ftp_command_entry.bind("<Return>", self.send_ftp_command) # Bind Enter key
        
        # Command buttons container frame for better layout
        self.ftp_button_frame = ttk.Frame(self.ftp_frame)
        self.ftp_button_frame.pack(fill=tk.X, pady=5)
        
        self.send_cmd_button = ttk.Button(self.ftp_button_frame, text="Send Command", command=self.send_ftp_command)
        self.send_cmd_button.pack(side=tk.LEFT, padx=(0, 5))
        
        self.refresh_button = ttk.Button(self.ftp_button_frame, text="Refresh Files", command=self.refresh_files)
        self.refresh_button.pack(side=tk.LEFT, padx=5)
        
        self.download_button = ttk.Button(self.ftp_button_frame, text="Download Selected", command=self.download_file)
        self.download_button.pack(side=tk.LEFT, padx=5)
        
        self.upload_button = ttk.Button(self.ftp_button_frame, text="Upload File", command=self.upload_file)
        self.upload_button.pack(side=tk.LEFT, padx=5)

        self.disconnect_button = ttk.Button(self.ftp_button_frame, text="Disconnect FTP", command=self.disconnect_ftp)
        self.disconnect_button.pack(side=tk.RIGHT, padx=5) # Place disconnect button on the right
        
        # Initially hide FTP frame
        self.ftp_frame.pack_forget()

    def set_ftp_controls_state(self, state):
        """Enables or disables all FTP-related controls."""
        self.ftp_command_entry.config(state=state)
        for widget in self.ftp_button_frame.winfo_children():
            widget.config(state=state)

    def log_to_console(self, message, is_error=False):
        """Logs messages to the main console output, with optional error styling."""
        self.console_output.config(state='normal')
        self.console_output.insert(tk.END, message + "\n")
        
        if is_error:
            self.console_output.tag_add("error", "end-2c linestart", "end-1c")
            self.console_output.tag_config("error", foreground="red", font=('Consolas', 10, 'bold'))
        
        self.console_output.config(state='disabled')
        self.console_output.see(tk.END)
    
    def start_connection(self):
        """Initiates the port knocking and subsequent TCP connection."""
        if self.ftp_connected:
            messagebox.showinfo("Already Connected", "You are already connected to the FTP server. Please disconnect first.")
            return

        self.connect_button.config(state='disabled') # Disable connect button during connection attempt
        self.status.set("Connecting...")
        self.status_label.config(style='TLabel')
        self.log_to_console("Starting connection attempt...")
        
        try:
            sequence_str = self.knock_sequence.get()
            if not sequence_str:
                raise ValueError("Knock sequence cannot be empty.")
            sequence = [int(p.strip()) for p in sequence_str.split(",") if p.strip()]
            if not sequence:
                raise ValueError("Knock sequence is invalid. Please provide comma-separated numbers.")
            
            target_port = int(self.target_port.get())
            if not (1 <= target_port <= 65535):
                raise ValueError("Target port must be between 1 and 65535.")

            self.client = PortKnockingClient(
                server_ip=self.server_ip.get(),
                sequence=sequence,
                target_port=target_port,
                password=self.password.get(),
                log_callback=self.log_to_console # Pass GUI logger to client
            )
            
            # Start the knocking and connection in a separate thread
            threading.Thread(target=self.initiate_knock_and_connect, daemon=True).start()
        
        except ValueError as e:
            messagebox.showerror("Input Error", f"Invalid input: {str(e)}")
            self.status.set("Input error")
            self.status_label.config(style='Error.TLabel')
            self.log_to_console(f"Error: {str(e)}", is_error=True)
            self.connect_button.config(state='normal') # Re-enable button on input error
        except Exception as e:
            messagebox.showerror("Error", f"An unexpected error occurred: {str(e)}")
            self.status.set("Error")
            self.status_label.config(style='Error.TLabel')
            self.log_to_console(f"Error: {str(e)}", is_error=True)
            self.connect_button.config(state='normal') # Re-enable button on error

    def initiate_knock_and_connect(self):
        """Threaded function to perform knocking and establish TCP connection."""
        try:
            # Step 1: Send the knock sequence
            knock_success = self.client.run() # client.run() now just calls send_knock()
            
            if not knock_success:
                self.root.after(0, lambda: self.status.set("Knock sequence failed"))
                self.root.after(0, lambda: self.status_label.config(style='Error.TLabel'))
                self.root.after(0, lambda: self.log_to_console("Knock sequence failed during transmission.", is_error=True))
                return
            
            self.root.after(0, lambda: self.log_to_console("Knock sequence sent. Waiting for server to process and attempting TCP connection..."))
            time.sleep(1.5) # Give server a moment to process knocks and open port

            # Step 2: Establish TCP connection to the target port
            self.ftp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.ftp_socket.settimeout(5) # Set a timeout for connection attempt
            self.ftp_socket.connect((self.server_ip.get(), int(self.target_port.get())))
            
            # Step 3: Verify authentication (read initial server response)
            initial_response_data = ""
            # Read until newline for the initial response
            while "\n" not in initial_response_data:
                chunk = self.ftp_socket.recv(1024).decode('utf-8')
                if not chunk: # Server disconnected
                    raise ConnectionError("Server disconnected unexpectedly during initial response.")
                initial_response_data += chunk
            initial_response = initial_response_data.strip()

            self.root.after(0, lambda: self.log_to_console(f"Server's initial response: {initial_response}"))

            if "successful" not in initial_response.lower():
                self.root.after(0, lambda: self.status.set("Authentication denied"))
                self.root.after(0, lambda: self.status_label.config(style='Error.TLabel'))
                self.root.after(0, lambda: self.log_to_console(f"Server denied connection: {initial_response}", is_error=True))
                self.ftp_socket.close()
                self.ftp_socket = None
                return

            # If successful, update GUI and enable FTP controls
            def on_success():
                self.status.set("Connection successful! FTP Ready.")
                self.status_label.config(style='Success.TLabel')
                self.log_to_console("Connection established and authenticated. FTP session ready.")
                self.ftp_frame.pack(fill=tk.BOTH, expand=True) # Show FTP frame
                self.set_ftp_controls_state(tk.NORMAL) # Enable FTP controls
                self.ftp_connected = True
                self.refresh_files() # Refresh file list automatically
            
            self.root.after(0, on_success)
            
        except socket.timeout as e:
            self.root.after(0, lambda e=e: self.status.set("Connection timeout"))
            self.root.after(0, lambda e=e: self.status_label.config(style='Error.TLabel'))
            self.root.after(0, lambda e=e: self.log_to_console(f"Failed to connect to target port: Connection timed out. Error: {e}", is_error=True))
        except ConnectionRefusedError as e:
            self.root.after(0, lambda e=e: self.status.set("Connection refused"))
            self.root.after(0, lambda e=e: self.status_label.config(style='Error.TLabel'))
            self.root.after(0, lambda e=e: self.log_to_console(f"Failed to connect to target port: Connection refused (port might be closed or firewall active). Error: {e}", is_error=True))
        except Exception as e:
            def on_error(e_arg):
                self.status.set(f"Error: {str(e_arg)}")
                self.status_label.config(style='Error.TLabel')
                self.log_to_console(f"An error occurred during connection: {str(e_arg)}", is_error=True)
                self.ftp_connected = False
                self.set_ftp_controls_state(tk.DISABLED)
                if self.ftp_socket:
                    self.ftp_socket.close()
                    self.ftp_socket = None
            self.root.after(0, lambda e_arg=e: on_error(e_arg))
        finally:
            self.root.after(0, lambda: self.connect_button.config(state='normal')) # Always re-enable connect button

    def disconnect_ftp(self):
        """Closes the FTP connection and resets GUI state."""
        if self.ftp_connected and self.ftp_socket:
            try:
                # Send QUIT command to server (optional but good practice)
                self.ftp_socket.sendall(b"QUIT\n")
                self.log_to_console("Sent QUIT command to server.")
                time.sleep(0.5) # Give server a moment to process the QUIT command
                self.ftp_socket.close()
                self.ftp_socket = None
                self.ftp_connected = False
                self.status.set("Disconnected.")
                self.status_label.config(style='TLabel')
                self.log_to_console("FTP session closed.")
                self.ftp_frame.pack_forget() # Hide FTP frame
                self.set_ftp_controls_state(tk.DISABLED)
            except Exception as e:
                self.log_to_console(f"Error closing FTP connection: {e}", is_error=True)
        else:
            self.log_to_console("Not currently connected to FTP.")

    def send_ftp_command(self, event=None): # event=None for button click
        """Sends a generic FTP command entered in the entry field."""
        if not self.ftp_connected or not self.ftp_socket:
            messagebox.showwarning("Not Connected", "Please connect first.")
            return

        command = self.ftp_command_entry.get().strip()
        if not command:
            self.log_to_console("No command entered.", is_error=True)
            return

        self.log_to_console(f"Client: {command}")
        self.ftp_command_entry.delete(0, tk.END) # Clear input after sending

        def _send_and_receive():
            try:
                self.ftp_socket.sendall(f'{command}\n'.encode('utf-8'))
                
                # For generic commands, read until newline for response
                response_data = ""
                self.ftp_socket.settimeout(10.0) # Timeout for reading response
                while "\n" not in response_data:
                    chunk = self.ftp_socket.recv(4096).decode('utf-8')
                    if not chunk: # Server disconnected
                        self.root.after(0, lambda: self.log_to_console("Server disconnected unexpectedly during command response.", is_error=True))
                        break
                    response_data += chunk
                
                full_response = response_data.strip()
                if full_response:
                    self.root.after(0, lambda: self.log_to_console(f"Server response:\n{full_response}"))
                else:
                    self.root.after(0, lambda: self.log_to_console("No response from server or empty response."))
                    
                # If it was a LIST command, refresh the file list
                if command.upper() == 'LIST':
                    self.root.after(0, self.refresh_files)

            except Exception as e:
                self.root.after(0, lambda e=e: self.log_to_console(f"Error sending command: {e}", is_error=True))
                self.root.after(0, lambda e=e: messagebox.showerror("Command Error", f"Failed to send command: {e}"))
                
        threading.Thread(target=_send_and_receive, daemon=True).start()

    def refresh_files(self):
        """Requests and displays the list of files from the server."""
        if not self.ftp_connected or not self.ftp_socket:
            messagebox.showwarning("Not Connected", "Please connect first.")
            return
        
        self.file_list.delete(0, tk.END) # Clear current list
        self.log_to_console("Requesting file list from server...")

        def _refresh():
            try:
                self.ftp_socket.settimeout(5.0) # Timeout for initial response from server
                self.ftp_socket.sendall(b'LIST\n')
                
                # Wait for server's READY_TO_LIST signal
                response_data = ""
                while "\n" not in response_data:
                    chunk = self.ftp_socket.recv(1024).decode('utf-8')
                    if not chunk: # Server disconnected
                        self.root.after(0, lambda: self.log_to_console("Server disconnected unexpectedly during LIST ready signal.", is_error=True))
                        return
                    response_data += chunk
                response = response_data.strip()

                if "READY_TO_LIST" not in response:
                    self.root.after(0, lambda: self.log_to_console(f"Server not ready for LIST: {response}", is_error=True))
                    return

                files_data = ""
                # Loop to read file names until END_OF_LIST marker
                self.ftp_socket.settimeout(10.0) # Longer timeout for receiving the full list
                while True:
                    chunk = self.ftp_socket.recv(4096).decode('utf-8', errors='ignore')
                    if not chunk: # Server disconnected
                        self.root.after(0, lambda: self.log_to_console("Server disconnected during file list reception.", is_error=True))
                        break
                    
                    files_data += chunk
                    if "END_OF_LIST" in files_data:
                        # Extract data before the marker
                        files_data = files_data.split("END_OF_LIST")[0]
                        break # End of list reception

                parsed_files = [f.strip() for f in files_data.split("\n") if f.strip()]
                
                if parsed_files:
                    for file_name in parsed_files:
                        self.root.after(0, lambda f=file_name: self.file_list.insert(tk.END, f))
                    self.root.after(0, lambda: self.log_to_console("File list refreshed successfully."))
                else:
                    self.root.after(0, lambda: self.log_to_console("No files found on server or empty response.", is_error=True))

            except socket.timeout as e:
                self.root.after(0, lambda: self.log_to_console(f"Error refreshing files (timeout): {e}", is_error=True))
            except Exception as e:
                self.root.after(0, lambda: messagebox.showerror("Error", f"Failed to refresh files: {e}"))
                self.root.after(0, lambda: self.log_to_console(f"Error refreshing files: {e}", is_error=True))
        
        threading.Thread(target=_refresh, daemon=True).start()
    
    def download_file(self):
        """Downloads the selected file from the server."""
        if not self.ftp_connected or not self.ftp_socket:
            messagebox.showwarning("Not Connected", "Please connect first.")
            return
        
        selection = self.file_list.curselection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select a file to download.")
            return
        
        filename = self.file_list.get(selection[0])
        
        # Open a "Save As" dialog on the client machine
        save_path = filedialog.asksaveasfilename(title="Save File As", initialfile=filename)
        if not save_path:
            return # User cancelled the dialog
        
        self.log_to_console(f"Attempting to download '{filename}' to '{save_path}'...")

        def _download():
            try:
                self.ftp_socket.sendall(f'GET {filename}\n'.encode('utf-8'))
                
                # Read initial server response (e.g., "File not found" or "READY_TO_RECEIVE_FILE")
                self.ftp_socket.settimeout(5.0) # Timeout for initial response from server
                initial_response_data = ""
                while "\n" not in initial_response_data:
                    chunk = self.ftp_socket.recv(1024).decode('utf-8')
                    if not chunk: # Server disconnected
                        self.root.after(0, lambda: self.log_to_console("Server disconnected unexpectedly during GET ready signal.", is_error=True))
                        break
                    initial_response_data += chunk
                initial_response = initial_response_data.strip()
                
                self.root.after(0, lambda: self.log_to_console(f"Server response for GET: {initial_response}"))

                if "File not found" in initial_response:
                    self.root.after(0, lambda: messagebox.showerror("Download Error", f"File '{filename}' not found on server."))
                    self.root.after(0, lambda: self.log_to_console(f"Download failed: File '{filename}' not found on server.", is_error=True))
                    return
                elif "READY_TO_RECEIVE_FILE" not in initial_response:
                    self.root.after(0, lambda: messagebox.showerror("Download Error", f"Server not ready for file transfer: {initial_response}"))
                    self.root.after(0, lambda: self.log_to_console(f"Download failed: Server not ready. Response: {initial_response}", is_error=True))
                    return

                # If server is ready, proceed to receive file data
                with open(save_path, 'wb') as f:
                    self.ftp_socket.settimeout(60.0) # Longer timeout for actual file transfer chunks (e.g., for large files)
                    bytes_received = 0
                    buffer = b"" # Use a buffer to detect the end marker reliably
                    while True:
                        data = self.ftp_socket.recv(4096)
                        if not data:
                            self.root.after(0, lambda: self.log_to_console(f"Server disconnected unexpectedly during download of '{filename}'.", is_error=True))
                            break # Server finished sending or connection closed
                        
                        buffer += data
                        if b"FILE_TRANSFER_COMPLETE" in buffer:
                            # Write data up to the marker, then break
                            f.write(buffer.split(b"FILE_TRANSFER_COMPLETE")[0])
                            break
                        else:
                            f.write(buffer)
                            buffer = b"" # Clear buffer after writing
                        
                        bytes_received += len(data) # This count will be inflated by buffer until marker is found
                
                # Reset timeout for next command
                self.ftp_socket.settimeout(10.0) 

                self.root.after(0, lambda: self.log_to_console(f"File '{filename}' downloaded successfully to '{save_path}'."))
                self.root.after(0, lambda: messagebox.showinfo("Download Complete", f"File '{filename}' downloaded successfully."))
            except socket.timeout as e:
                self.root.after(0, lambda: self.log_to_console(f"Download of '{filename}' timed out. Transfer incomplete. Error: {e}", is_error=True))
            except Exception as e:
                self.root.after(0, lambda: messagebox.showerror("Error", f"Failed to download file: {e}"))
                self.root.after(0, lambda: self.log_to_console(f"Error downloading file: {e}", is_error=True))
        
        threading.Thread(target=_download, daemon=True).start()
    
    def upload_file(self):
        """Uploads a selected local file to the server."""
        if not self.ftp_connected or not self.ftp_socket:
            messagebox.showwarning("Not Connected", "Please connect first.")
            return
            
        # Open a "Open File" dialog on the client machine
        file_path = filedialog.askopenfilename(title="Select File to Upload")
        if not file_path:
            return # User cancelled the dialog
        
        # Extract just the filename for the server
        filename = os.path.basename(file_path)
        
        self.log_to_console(f"Attempting to upload '{filename}' from '{file_path}'...")

        def _upload():
            try:
                # Send the upload command
                self.ftp_socket.sendall(f'PUT {filename}\n'.encode('utf-8'))
                
                # Wait for server's readiness message
                self.ftp_socket.settimeout(5.0) # Timeout for server's ready message
                ready_response_data = ""
                while "\n" not in ready_response_data:
                    chunk = self.ftp_socket.recv(1024).decode('utf-8')
                    if not chunk: # Server disconnected
                        self.root.after(0, lambda: self.log_to_console("Server disconnected unexpectedly during PUT ready signal.", is_error=True))
                        break
                    ready_response_data += chunk
                ready_response = ready_response_data.strip()

                self.root.after(0, lambda: self.log_to_console(f"Server response for PUT: {ready_response}"))

                if "READY_TO_UPLOAD_FILE" not in ready_response:
                    self.root.after(0, lambda: messagebox.showerror("Upload Error", f"Server not ready to receive file: {ready_response}"))
                    self.root.after(0, lambda: self.log_to_console(f"Upload failed: Server not ready. Response: {ready_response}", is_error=True))
                    return

                # If server is ready, proceed to send file data
                with open(file_path, 'rb') as f:
                    self.ftp_socket.settimeout(60.0) # Longer timeout for actual file transfer chunks
                    bytes_sent = 0
                    while True:
                        data = f.read(4096) # Read in chunks
                        if not data:
                            break # End of file
                        self.ftp_socket.sendall(data)
                        bytes_sent += len(data)
                
                # Send explicit end-of-file marker
                self.ftp_socket.sendall(b"END_OF_FILE\n")
                self.root.after(0, lambda: self.log_to_console(f"Sent END_OF_FILE marker for '{filename}'."))

                # Server sends a confirmation message after receiving the file
                self.ftp_socket.settimeout(10.0) # Give server time to send final confirmation
                final_response_data = ""
                while "\n" not in final_response_data:
                    chunk = self.ftp_socket.recv(1024).decode('utf-8')
                    if not chunk: # Server disconnected
                        self.root.after(0, lambda: self.log_to_console("Server disconnected unexpectedly during final upload confirmation.", is_error=True))
                        break
                    final_response_data += chunk
                final_response = final_response_data.strip()

                self.root.after(0, lambda: self.log_to_console(f"Server's final upload response: {final_response}"))
                
                if "File uploaded successfully" in final_response:
                    self.root.after(0, lambda: self.log_to_console(f"File '{filename}' uploaded successfully."))
                    self.root.after(0, lambda: messagebox.showinfo("Upload Complete", f"File '{filename}' uploaded successfully."))
                    self.root.after(0, self.refresh_files) # Refresh file list after successful upload
                else:
                    self.root.after(0, lambda: messagebox.showerror("Upload Error", f"Upload failed or unexpected server response: {final_response}"))
                    self.root.after(0, lambda: self.log_to_console(f"Upload failed: {final_response}", is_error=True))

            except socket.error as e:
                self.root.after(0, lambda: self.log_to_console(f"Socket error during upload: {e}. Connection might be lost.", is_error=True))
                self.root.after(0, self.disconnect_ftp) # Attempt to clean up by disconnecting
            except Exception as e:
                self.root.after(0, lambda: messagebox.showerror("Error", f"Failed to upload file: {e}"))
                self.root.after(0, lambda: self.log_to_console(f"Error uploading file: {e}", is_error=True))
        
        threading.Thread(target=_upload, daemon=True).start()


def main():
    root = tk.Tk()
    app = PortKnockingGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
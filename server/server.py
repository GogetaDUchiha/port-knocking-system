import socket
import threading
import time
from datetime import datetime
from collections import defaultdict
import os
import re
# Import all necessary configurations, including encryption functions
from server.config import (
    SERVER_IP, KNOCK_SEQUENCE, TARGET_PORT, TIMEOUT, COOLDOWN, RATE_LIMIT,
    BLOCKLIST_FILE, LOGFILE, PASSWORD, encrypt_message, decrypt_message,
    MAX_FAILED_ATTEMPTS
)

class PortKnockingServer:
    def __init__(self):
        os.makedirs('logs', exist_ok=True)
        os.makedirs('server_files', exist_ok=True) # Directory for server-side files
        
        self.knock_sequence = KNOCK_SEQUENCE
        self.target_port = TARGET_PORT
        self.timeout = TIMEOUT
        self.cooldown = COOLDOWN
        self.rate_limit = RATE_LIMIT
        self.max_failed_attempts = MAX_FAILED_ATTEMPTS

        self.active_connections = set() # IPs that have successfully knocked and are authenticated
        self.knock_status = defaultdict(list) # Stores received knocks per IP: [{'pos': ..., 'time': ..., 'password': ...}]
        self.failed_attempts_count = defaultdict(int) # Counts consecutive failed attempts for an IP
        self.blocked_ips = self.load_blocklist()
        self.rate_limits = defaultdict(float) # Stores last request timestamp for rate limiting per IP
        self.sequence_length = len(KNOCK_SEQUENCE)

        self.running = True
        self.log_lock = threading.Lock()
        self.block_lock = threading.Lock()

        # Start listener threads for knock sequence ports
        for port in self.knock_sequence:
            threading.Thread(target=self.listen_port, args=(port,), daemon=True).start()

        # Start listener thread for the target port (FTP)
        threading.Thread(target=self.listen_target_port, daemon=True).start()
        
        # Start cleanup thread for old knock status and rate limits
        threading.Thread(target=self.cleanup_thread, daemon=True).start()

        self.log_event(f"✅ Server started. Knock sequence: {self.knock_sequence} ➡️ Target port: {self.target_port}")

    def load_blocklist(self):
        """Loads blocked IPs from the blocklist file."""
        try:
            with open(f'logs/{BLOCKLIST_FILE}', 'r') as f:
                return set(line.strip() for line in f if line.strip())
        except FileNotFoundError:
            return set()

    def save_blocklist(self):
        """Saves current blocked IPs to the blocklist file."""
        with self.block_lock: # Ensure thread-safe access
            with open(f'logs/{BLOCKLIST_FILE}', 'w') as f:
                for ip in self.blocked_ips:
                    f.write(f"{ip}\n")

    def log_event(self, event):
        """Logs events to console and a log file with a timestamp."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] {event}\n"
        with self.log_lock: # Ensure thread-safe logging
            print(log_entry.strip())
            with open(f'logs/{LOGFILE}', 'a') as f:
                f.write(log_entry)

    def is_blocked(self, ip):
        """Checks if an IP is currently in the blocklist."""
        with self.block_lock:
            return ip in self.blocked_ips

    def block_ip(self, ip):
        """Adds an IP to the blocklist and saves it."""
        with self.block_lock:
            if ip not in self.blocked_ips:
                self.blocked_ips.add(ip)
                self.save_blocklist()
                self.log_event(f"❌ Blocked IP: {ip} due to too many failed attempts.")
            self.failed_attempts_count.pop(ip, None) # Clear attempts after blocking

    def check_rate_limit(self, ip):
        """Checks if an IP is exceeding the rate limit."""
        now = time.time()
        if ip in self.rate_limits and now - self.rate_limits[ip] < self.rate_limit:
            return False
        self.rate_limits[ip] = now
        return True

    def inspect_packet(self, data):
        """
        Performs basic packet inspection.
        Attempts to decrypt and validate the format of the payload.
        """
        try:
            if not data:
                return False
            decrypted_payload = decrypt_message(data.decode('utf-8')) # Decrypt the message
            if decrypted_payload is None: # Decryption failed
                return False
            # Check for expected format: "port:password"
            return re.match(r'^\d+:.+$', decrypted_payload) is not None
        except Exception as e:
            self.log_event(f"Packet inspection error: {e}")
            return False

    def listen_port(self, port):
        """Listens for UDP knock packets on a specific port."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1.0) # Set a timeout to allow checking self.running periodically
        try:
            sock.bind((SERVER_IP, port))
            self.log_event(f"👂 Listening for knocks on UDP port {port}")
        except socket.error as e:
            self.log_event(f"Failed to bind UDP port {port}: {e}. This port might be in use.")
            return # Exit thread if bind fails

        while self.running:
            try:
                data, addr = sock.recvfrom(1024)
                ip = addr[0]

                if self.is_blocked(ip):
                    self.log_event(f"Blocked IP {ip} attempted to knock on port {port}. Ignoring.")
                    continue

                if not self.check_rate_limit(ip):
                    self.log_event(f"⚠️ Rate limit exceeded for IP: {ip} on port {port}. Ignoring.")
                    self.handle_failed_attempt(ip) # Rate limit violation counts as a failed attempt
                    continue

                if not self.inspect_packet(data):
                    self.log_event(f"🛑 Suspicious or malformed packet from {ip} on port {port}.")
                    self.handle_failed_attempt(ip)
                    continue

                try:
                    decrypted_payload = decrypt_message(data.decode('utf-8'))
                    if decrypted_payload is None: # Decryption failed
                        raise ValueError("Decryption failed")

                    port_num_str, received_password = decrypted_payload.split(':', 1)
                    port_num = int(port_num_str)

                    if port_num != port: # Verify the port in payload matches the listening port
                        self.log_event(f"Mismatched port in payload ({port_num}) from {ip} on port {port}. Expected {port}.")
                        self.handle_failed_attempt(ip)
                        continue
                    
                    # Password check for the knock itself (optional, but adds security)
                    if received_password != PASSWORD:
                        self.log_event(f"Incorrect password in knock payload from {ip} on port {port}.")
                        self.handle_failed_attempt(ip)
                        continue

                    self.handle_knock(ip, port, received_password)

                except ValueError as ve:
                    self.log_event(f"Invalid knock payload from {ip} on port {port}: {str(ve)}")
                    self.handle_failed_attempt(ip)
                except Exception as e:
                    self.log_event(f"Error processing knock from {ip} on port {port}: {str(e)}")
                    self.handle_failed_attempt(ip)

            except socket.timeout:
                # Timeout occurred, continue loop to check self.running
                continue
            except Exception as e:
                self.log_event(f"Error in UDP listener on port {port}: {str(e)}")
        sock.close()
        self.log_event(f"UDP listener on port {port} stopped.")

    def handle_knock(self, ip, port, password):
        """Processes a received knock, checking sequence and timing."""
        now = time.time()
        # Filter out old knocks for this IP that are outside the timeout window
        self.knock_status[ip] = [knock for knock in self.knock_status[ip] if now - knock['time'] < self.timeout]

        try:
            sequence_pos = self.knock_sequence.index(port)
        except ValueError:
            # This port is not part of the defined sequence
            self.log_event(f"Received knock on non-sequence port {port} from {ip}. Ignoring.")
            self.handle_failed_attempt(ip)
            self.knock_status.pop(ip, None) # Clear status for this IP on non-sequence knock
            return

        # Check if this knock is in the correct order for the current sequence progress
        expected_next_pos = len(self.knock_status[ip])
        if sequence_pos != expected_next_pos:
            self.log_event(f"Incorrect knock order from {ip}. Expected port at position {expected_next_pos}, but got {port} at position {sequence_pos}.")
            self.handle_failed_attempt(ip)
            self.knock_status.pop(ip, None) # Reset sequence for this IP on order mismatch
            return

        self.knock_status[ip].append({
            'pos': sequence_pos,
            'time': now,
            'password': password # Store password from this knock
        })

        self.log_event(f"🔔 Received correct knock #{sequence_pos + 1} ({port}) from {ip}")

        if len(self.knock_status[ip]) == self.sequence_length:
            self.validate_sequence(ip)

    def validate_sequence(self, ip):
        """Validates the complete knock sequence and grants access if successful."""
        knocks = sorted(self.knock_status[ip], key=lambda k: k['pos'])
        
        # Check if all sequence positions are present and in order (redundant with handle_knock, but good final check)
        sequence_correct = all(knock['pos'] == i for i, knock in enumerate(knocks))
        
        # Verify that all passwords sent in the knock sequence match the configured PASSWORD
        passwords_match = all(knock['password'] == PASSWORD for knock in knocks)
        
        if sequence_correct and passwords_match:
            self.active_connections.add(ip)
            self.log_event(f"✅ Authentication successful for {ip}. Target port {self.target_port} opened for this IP for {self.cooldown} seconds.")
            self.failed_attempts_count.pop(ip, None) # Reset failed attempts on success
            # Schedule automatic removal from active_connections after cooldown
            threading.Timer(self.cooldown, self.deactivate_connection, args=(ip,)).start()
        else:
            self.log_event(f"❌ Authentication failed for {ip} - {'sequence incorrect' if not sequence_correct else 'passwords mismatch'}.")
            self.handle_failed_attempt(ip)
        
        self.knock_status.pop(ip, None) # Always clear knock status after validation attempt

    def deactivate_connection(self, ip):
        """Removes an IP from active_connections after the cooldown period."""
        if ip in self.active_connections:
            self.active_connections.remove(ip)
            self.log_event(f"IP {ip} removed from active connections after cooldown period.")

    def handle_failed_attempt(self, ip):
        """Increments failed attempt count for an IP and blocks it if threshold is reached."""
        self.failed_attempts_count[ip] += 1
        self.log_event(f"Failed attempt {self.failed_attempts_count[ip]} for IP: {ip}")
        if self.failed_attempts_count[ip] >= self.max_failed_attempts:
            self.block_ip(ip)

    def sanitize_filename(self, filename):
        """Basic sanitization to prevent directory traversal."""
        # Remove any path separators and '..'
        sanitized = os.path.basename(filename).replace('..', '').replace('/', '').replace('\\', '')
        return sanitized

    def handle_ftp_client(self, conn, ip):
        """Handles the FTP-like commands for an authenticated client."""
        self.log_event(f"Starting FTP session for {ip}")
        try:
            conn.sendall(b"Authentication successful. Welcome to FTP service!\n")
            
            while self.running: # Continue session as long as server is running
                conn.settimeout(30.0) # Increase timeout for command reception
                try: # <--- This try block for command processing
                    command_full = ""
                    # Read command until newline
                    while "\n" not in command_full:
                        chunk = conn.recv(1024).decode('utf-8')
                        if not chunk: # Client disconnected
                            self.log_event(f"Client {ip} disconnected from FTP session.")
                            return # Exit thread gracefully
                        command_full += chunk
                    command_full = command_full.strip() # Remove newline and any extra whitespace

                    if not command_full: # Empty command, just continue
                        continue 

                    self.log_event(f"Received FTP command from {ip}: '{command_full}'")

                    if command_full.upper() == 'LIST':
                        try:
                            # Send a ready signal for the list first
                            conn.sendall(b"READY_TO_LIST\n") 
                            # Give client a moment to switch to receiving mode
                            time.sleep(0.05) 

                            files = os.listdir('server_files')
                            # Filter out directories (optional, but good for listing files)
                            files_only = [f for f in files if os.path.isfile(os.path.join('server_files', f))]
                            
                            # Send each file name on a new line, then an END_OF_LIST marker
                            for file_name in files_only:
                                conn.sendall(f"{file_name}\n".encode('utf-8'))
                            
                            conn.sendall(b"END_OF_LIST\n") # Explicit marker for end of list
                            self.log_event(f"Sent file list to {ip} with END_OF_LIST marker.")
                        except Exception as e:
                            conn.sendall(f"Error listing files: {e}\n".encode('utf-8'))
                            self.log_event(f"Error sending file list to {ip}: {e}")

                    elif command_full.upper().startswith('GET '):
                        requested_filename = command_full[4:].strip()
                        filename = self.sanitize_filename(requested_filename)
                        filepath = os.path.join('server_files', filename)

                        if not os.path.exists(filepath) or not os.path.isfile(filepath):
                            conn.sendall(b"File not found.\n")
                            self.log_event(f"File '{requested_filename}' not found for GET from {ip}.")
                            continue

                        try:
                            # Send a confirmation/ready message before sending file data
                            conn.sendall(b"READY_TO_RECEIVE_FILE\n") 
                            time.sleep(0.1) # Small delay to ensure client processes ready signal

                            with open(filepath, 'rb') as f:
                                while True:
                                    chunk = f.read(4096)
                                    if not chunk:
                                        break
                                    conn.sendall(chunk)
                            
                            # Send a final marker after file transfer
                            conn.sendall(b"FILE_TRANSFER_COMPLETE\n")
                            self.log_event(f"Sent file '{filename}' to {ip} and sent FILE_TRANSFER_COMPLETE.")
                        except Exception as e:
                            conn.sendall(f"Error sending file: {e}\n".encode('utf-8'))
                            self.log_event(f"Error sending file '{filename}' to {ip}: {e}")

                    elif command_full.upper().startswith('PUT '):
                        requested_filename = command_full[4:].strip()
                        filename = self.sanitize_filename(requested_filename)
                        filepath = os.path.join('server_files', filename)

                        self.log_event(f"Preparing to receive file '{filename}' from {ip}.")
                        conn.sendall(b"READY_TO_UPLOAD_FILE\n") # Signal client to start sending
                        
                        try:
                            # Set a longer timeout for receiving file data, specifically
                            conn.settimeout(60.0) # Increased timeout for large files

                            with open(filepath, 'wb') as f:
                                buffer = b"" # Use a buffer to accumulate chunks until the marker is found
                                while True:
                                    chunk = conn.recv(4096)
                                    if not chunk: # Client finished sending or disconnected
                                        self.log_event(f"Client {ip} disconnected during upload of '{filename}'.")
                                        break
                                    
                                    buffer += chunk
                                    # Check for the END_OF_FILE marker within the buffer
                                    if b"END_OF_FILE" in buffer:
                                        # Write data before the marker
                                        f.write(buffer.split(b"END_OF_FILE")[0])
                                        break # End of file transfer
                                    else:
                                        f.write(buffer) # Write current buffer content
                                        buffer = b"" # Clear buffer after writing (unless it contained partial marker)
                            
                            # Restore general command timeout
                            conn.settimeout(30.0) 

                            conn.sendall(b"File uploaded successfully.\n")
                            self.log_event(f"Received file '{filename}' from {ip}.")
                        except socket.timeout:
                            self.log_event(f"File upload from {ip} timed out for '{filename}'. Transfer incomplete.")
                            conn.sendall(b"File upload timed out.\n")
                        except Exception as e:
                            conn.sendall(f"Error receiving file: {e}\n".encode('utf-8'))
                            self.log_event(f"Error receiving file '{filename}' from {ip}: {e}")
                
                    elif command_full.upper() in ['EXIT', 'QUIT']:
                        self.log_event(f"Client {ip} requested to exit FTP session.")
                        conn.sendall(b"Goodbye.\n")
                        break # Exit FTP session loop
                    
                    else:
                        conn.sendall(b"Unknown command. Supported: LIST, GET <filename>, PUT <filename>, EXIT/QUIT.\n".encode('utf-8'))
                        self.log_event(f"Unknown command from {ip}: '{command_full}'")
    
                except socket.timeout: # <--- Corrected indentation: This handles timeout for recv in the inner loop
                    self.log_event(f"Client {ip} timed out waiting for FTP command or during file transfer. Disconnecting.")
                    break # Timeout on recv, disconnect
                except Exception as e: # <--- Corrected indentation: This handles other errors in the inner loop
                    self.log_event(f"Error in command handling for {ip}: {str(e)}")
                    break # Break out of loop on other errors

        except Exception as e: # <--- This handles errors from the outer try block (e.g., initial sendall)
            self.log_event(f"Unexpected error in FTP session for {ip}: {str(e)}")
        finally:
            self.log_event(f"Closing FTP connection for {ip}.")
            conn.close()
            # If the IP is still in active_connections (e.g., cooldown not expired), remove it
            if ip in self.active_connections:
                self.active_connections.remove(ip)

    def listen_target_port(self):
        """Listens for TCP connections on the target port."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) # Allow reuse of address
        sock.settimeout(1.0) # Set a timeout for accept to allow checking self.running periodically
        try:
            sock.bind((SERVER_IP, self.target_port))
            sock.listen(5)
            self.log_event(f"🌐 Listening on TCP target port {self.target_port} for client connections.")
        except socket.error as e:
            self.log_event(f"Failed to bind TCP target port {self.target_port}: {e}. This port might be in use.")
            return # Exit thread if bind fails

        while self.running:
            try:
                conn, addr = sock.accept()
                ip = addr[0]
                
                if self.is_blocked(ip):
                    self.log_event(f"Blocked IP {ip} attempted to connect to target port. Denying.")
                    conn.sendall(b"Connection denied: Your IP is blocked.\n")
                    conn.close()
                    continue
                    
                if not self.check_rate_limit(ip):
                    self.log_event(f"Rate-limited IP {ip} attempted to connect to target port. Denying.")
                    conn.sendall(b"Connection denied: Rate limit exceeded.\n")
                    conn.close()
                    continue

                if ip in self.active_connections:
                    # Handle this client in a new thread to allow concurrent connections
                    threading.Thread(target=self.handle_ftp_client, args=(conn, ip), daemon=True).start()
                else:
                    self.log_event(f"Connection denied from {ip} on target port (not authenticated or authentication expired).")
                    conn.sendall(b"Connection denied. No valid knock sequence received or authentication expired.\n")
                    conn.close()
                    self.handle_failed_attempt(ip) # Direct access to target port counts as failed attempt

            except socket.timeout:
                # Timeout occurred, continue loop to check self.running
                continue
            except Exception as e:
                self.log_event(f"Error in target port listener: {str(e)}")
        sock.close()
        self.log_event(f"TCP target port listener on {self.target_port} stopped.")

    def cleanup_thread(self):
        """Periodically cleans up expired knock statuses and rate limit entries."""
        while self.running:
            now = time.time()
            # Clean up expired knock sequences
            for ip in list(self.knock_status.keys()):
                self.knock_status[ip] = [
                    knock for knock in self.knock_status[ip] 
                    if now - knock['time'] < self.timeout
                ]
                if not self.knock_status[ip]:
                    self.log_event(f"Expired knock sequence for {ip}. Clearing status.")
                    # If a sequence expires before completion, it's a failed attempt
                    self.handle_failed_attempt(ip) 
                    self.knock_status.pop(ip, None)
            
            # Clean up old rate limit entries (if no activity for a while)
            for ip in list(self.rate_limits.keys()):
                if now - self.rate_limits[ip] > self.rate_limit * 10: # Clear after 10 times the rate limit window
                    self.rate_limits.pop(ip, None)
            
            time.sleep(10) # Run cleanup every 10 seconds

    def stop(self):
        """Stops the server and all listening threads."""
        self.running = False
        self.log_event("Server shutting down. Attempting to close sockets...")
        # To unblock listening sockets, you can try connecting to them briefly
        # This forces them out of blocking `accept()` or `recvfrom()` calls.
        try:
            # Connect to UDP knock ports
            for port in self.knock_sequence:
                socket.socket(socket.AF_INET, socket.SOCK_DGRAM).sendto(b'stop', (SERVER_IP, port))
            # Connect to TCP target port
            dummy_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            dummy_sock.connect((SERVER_IP, self.target_port))
            dummy_sock.close()
        except Exception as e:
            self.log_event(f"Error during dummy connection for shutdown: {e}")
        self.log_event("Server stopped.")

if __name__ == "__main__":
    server = PortKnockingServer()
    try:
        # Keep the main thread alive to allow daemon threads to run
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nShutting down server...")
        server.stop()
import socket
import time
# Import from server.config as it's the central config
from server.config import SERVER_IP, KNOCK_SEQUENCE, TARGET_PORT, PASSWORD, encrypt_message

class PortKnockingClient:
    def __init__(self, server_ip=SERVER_IP, sequence=KNOCK_SEQUENCE, target_port=TARGET_PORT, password=PASSWORD, log_callback=None):
        self.server_ip = server_ip
        self.sequence = sequence
        self.target_port = target_port
        self.password = password
        self.log_callback = log_callback # Callback to log messages to GUI console

    def _log(self, message):
        """Internal logging function that uses the provided callback or prints to console."""
        if self.log_callback:
            self.log_callback(message)
        else:
            print(message)

    def send_knock(self):
        """
        Sends the UDP knock sequence to the server.
        Uses encryption for the message payload.
        Returns True if all knocks are sent without immediate socket errors, False otherwise.
        """
        self._log("🔐 Sending knock sequence...")
        for port in self.sequence:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                    sock.settimeout(1) # Short timeout for sending UDP
                    message = f"{port}:{self.password}"
                    encrypted_message = encrypt_message(message) # Encrypt the message
                    sock.sendto(encrypted_message.encode('utf-8'), (self.server_ip, port))
                    self._log(f"🔑 Knocked on port {port}")
            except Exception as e:
                self._log(f"❌ Error knocking on port {port}: {e}")
                return False # Indicate failure if any knock fails
            time.sleep(0.1) # Small delay between knocks
        self._log("✅ Knock sequence sent.")
        return True

    def run(self):
        """
        This method is primarily for the GUI to initiate the knocking process.
        It only sends the knock sequence. The GUI will handle the subsequent TCP connection.
        """
        return self.send_knock()

# No __main__ block needed here as this is a module used by the GUI.
# The previous __main__ block was for a command-line client.
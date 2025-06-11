import os

# --- Encryption/Decryption (Simple XOR for demonstration) ---
# In a real-world scenario, use a strong, industry-standard encryption like AES.
# This XOR cipher is for conceptual demonstration only.
ENCRYPTION_KEY = b'supersecretkey12345' # IMPORTANT: Use a strong, random key in production!

def xor_cipher(data, key):
    """Applies XOR cipher to bytes data with a given key."""
    return bytes([_a ^ _b for _a, _b in zip(data, key * (len(data) // len(key) + 1))])

def encrypt_message(message):
    """Encrypts a string message using XOR cipher and returns hex string."""
    return xor_cipher(message.encode('utf-8'), ENCRYPTION_KEY).hex()

def decrypt_message(encrypted_hex):
    """Decrypts a hex string message using XOR cipher and returns string."""
    try:
        return xor_cipher(bytes.fromhex(encrypted_hex), ENCRYPTION_KEY).decode('utf-8')
    except Exception as e:
        # Handle cases where decryption fails (e.g., invalid hex, wrong key)
        print(f"Decryption error: {e}")
        return None # Return None or raise a specific error

# --- Network Configuration ---
SERVER_IP = '127.0.0.1'  # Use '0.0.0.0' to listen on all available interfaces
KNOCK_SEQUENCE = [10001, 10002, 10003]  # Example knock sequence ports
TARGET_PORT = 2121       # The port that opens after successful knocking (e.g., for FTP)
PASSWORD = 'mysecurepassword' # Shared password for authentication

# --- Security Parameters ---
TIMEOUT = 5             # Time in seconds to complete the knock sequence
COOLDOWN = 60           # Time in seconds an IP stays authenticated on target port
RATE_LIMIT = 0.05       # Changed from 3.5. Allow a packet every 0.05 seconds from the same IP.
                        # This allows the client's 0.1s delay between knocks to pass.
MAX_FAILED_ATTEMPTS = 3 # Number of failed attempts before an IP is blocked


# --- Logging and Blocklist Files ---
BLOCKLIST_FILE = 'blocked_ips.txt'
LOGFILE = 'server_events.log'
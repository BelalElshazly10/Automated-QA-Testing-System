# modules/encryption/aes.py

import os
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64

# ----------------------------------------------------------
# Configuration
# ----------------------------------------------------------
# Key must be 32 bytes for AES-256
AES_KEY = "12345678901234567890123456789012".encode()


  # convert to bytes

if len(AES_KEY) != 32:
    raise RuntimeError("AES_KEY must be exactly 32 bytes for AES-256.")


# ----------------------------------------------------------
# Encrypt
# ----------------------------------------------------------
def encrypt(plaintext: str) -> str:
    """
    Returns base64 encoded ciphertext:
    IV + ciphertext
    """

    data = plaintext.encode()

    # random IV
    iv = get_random_bytes(16)

    cipher = AES.new(AES_KEY, AES.MODE_CBC, iv)

    ciphertext = cipher.encrypt(pad(data, AES.block_size))

    combined = iv + ciphertext

    return base64.b64encode(combined).decode()


# ----------------------------------------------------------
# Decrypt
# ----------------------------------------------------------
def decrypt(token: str) -> str:
    """
    Reverse encryption:
    Extract IV + ciphertext
    """

    combined = base64.b64decode(token)

    iv = combined[:16]
    ciphertext = combined[16:]

    cipher = AES.new(AES_KEY, AES.MODE_CBC, iv)

    decrypted = unpad(cipher.decrypt(ciphertext), AES.block_size)

    return decrypted.decode()

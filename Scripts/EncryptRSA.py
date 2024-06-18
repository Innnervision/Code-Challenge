from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
import os

# Load public key
with open("public_key.pem", "rb") as pub_file:
    public_key = serialization.load_pem_public_key(pub_file.read())

# Generate AES key
aes_key = os.urandom(32)  # 256-bit AES key

# Encrypt the AES key with the RSA public key
encrypted_aes_key = public_key.encrypt(
    aes_key,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

# Encrypt the file using AES
file_path = "AMD image file (1).jpg"
with open(file_path, "rb") as f:
    plaintext = f.read()

iv = os.urandom(16)  # Initialization vector for AES
cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
encryptor = cipher.encryptor()
ciphertext = encryptor.update(plaintext) + encryptor.finalize()

# Save the encrypted AES key and ciphertext to a file
encrypted_file_path = "encrypted_file.bin"
with open(encrypted_file_path, "wb") as enc_file:
    enc_file.write(encrypted_aes_key + iv + ciphertext)

print(f"File encrypted and saved to '{encrypted_file_path}'")

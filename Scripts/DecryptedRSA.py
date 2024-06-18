from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Load private key
with open("private_key.pem", "rb") as priv_file:
    private_key = serialization.load_pem_private_key(priv_file.read(), password=None)

# Read the encrypted file
encrypted_file_path = "encrypted_file.bin"
with open(encrypted_file_path, "rb") as enc_file:
    encrypted_aes_key = enc_file.read(256)  # RSA 2048-bit key size
    iv = enc_file.read(16)  # AES block size
    ciphertext = enc_file.read()

# Decrypt the AES key with the RSA private key
aes_key = private_key.decrypt(
    encrypted_aes_key,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

# Decrypt the file using AES
cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
decryptor = cipher.decryptor()
decrypted_text = decryptor.update(ciphertext) + decryptor.finalize()

# Save the decrypted file
decrypted_file_path = "decrypted_image_file.jpg"
with open(decrypted_file_path, "wb") as dec_file:
    dec_file.write(decrypted_text)

print(f"File decrypted and saved to '{decrypted_file_path}'")

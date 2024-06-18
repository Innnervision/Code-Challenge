from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization

# Load public key
with open("public_key.pem", "rb") as pub_file:
    public_key = serialization.load_pem_public_key(pub_file.read())

# Load private key
with open("private_key.pem", "rb") as priv_file:
    private_key = serialization.load_pem_private_key(priv_file.read(), password=None)

# Encrypt the file
with open("AMD image file (1).JPG", "rb") as f:
    plaintext = f.read()

ciphertext = public_key.encrypt(
    plaintext,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

# Save the encrypted file
encrypted_file_path = "encrypted_file.bin"
with open(encrypted_file_path, "wb") as enc_file:
    enc_file.write(ciphertext)

print(f"File encrypted and saved to '{encrypted_file_path}'")

# Decrypt the file
with open(encrypted_file_path, "rb") as enc_file:
    ciphertext = enc_file.read()

decrypted_text = private_key.decrypt(
    ciphertext,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

# Save the decrypted file
decrypted_file_path = "decrypted_image_file.jpg"
with open(decrypted_file_path, "wb") as dec_file:
    dec_file.write(decrypted_text)

print(f"File decrypted and saved to '{decrypted_file_path}'")

import hashlib

# File path
file_path = "AMD image file (1).JPG"  # Replace with the actual image file path

# Calculate SHA-256 hash
sha256_hash = hashlib.sha256()

with open(file_path, "rb") as f:
    for byte_block in iter(lambda: f.read(4096), b""):
        sha256_hash.update(byte_block)

hash_hex = sha256_hash.hexdigest()
print(f"SHA-256 hash of the file: {hash_hex}")

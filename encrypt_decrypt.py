from Crypto.Cipher import AES, DES
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from base64 import b64encode, b64decode

# AES Encryption
def aes_encrypt(plain_text, password):
    key = pad(password.encode(), AES.block_size)
    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    cipher_text = cipher.encrypt(pad(plain_text.encode(), AES.block_size))
    return b64encode(iv + cipher_text).decode('utf-8')

# AES Decryption
def aes_decrypt(cipher_text, password):
    raw = b64decode(cipher_text)
    key = pad(password.encode(), AES.block_size)
    iv = raw[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plain_text = unpad(cipher.decrypt(raw[AES.block_size:]), AES.block_size)
    return plain_text.decode('utf-8')

# RSA Encryption
def rsa_encrypt(plain_text, public_key):
    cipher = RSA.import_key(public_key)
    encrypted_data = cipher.encrypt(plain_text.encode(), 32)
    return b64encode(encrypted_data[0]).decode('utf-8')

# RSA Decryption
def rsa_decrypt(cipher_text, private_key):
    raw = b64decode(cipher_text)
    cipher = RSA.import_key(private_key)
    decrypted_data = cipher.decrypt(raw)
    return decrypted_data.decode('utf-8')

# Example usage
if __name__ == "__main__":
    # AES usage
    password = "mypassword"
    message = "This is a secret message."
    encrypted = aes_encrypt(message, password)
    print(f"Encrypted (AES): {encrypted}")
    decrypted = aes_decrypt(encrypted, password)
    print(f"Decrypted (AES): {decrypted}")

    # RSA usage (for demo purpose, usually RSA keys should be generated and stored securely)
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    encrypted = rsa_encrypt(message, public_key)
    print(f"Encrypted (RSA): {encrypted}")
    decrypted = rsa_decrypt(encrypted, private_key)
    print(f"Decrypted (RSA): {decrypted}")

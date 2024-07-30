# Pinnacle_labs
Pinnacle labs Cybersecurity Internship


# Encryption and Decryption Helper Tool

This simple Python tool helps you to encrypt and decrypt messages using various encryption algorithms such as AES and RSA.

## Features

- AES encryption and decryption with a custom password.
- RSA encryption and decryption with auto-generated keys for the session.

## Requirements

- pycryptodome (`pip install pycryptodome`)

## Usage

Simply run the `encrypt_decrypt.py` script. It is set up to demonstrate AES and RSA encryption and decryption with example messages.

For AES encryption:
```python
password = "yourpassword"
message = "Your secret message"
encrypted = aes_encrypt(message, password)
print(f"Encrypted (AES): {encrypted}")

For AES decryption:

python

decrypted = aes_decrypt(encrypted, password)
print(f"Decrypted (AES): {decrypted}")

For RSA encryption and decryption, the script will handle key generation and show you the encrypted and decrypted messages.

Note: RSA encryption and decryption require key management, which is beyond the scope of this simple example.
Disclaimer

This tool is for educational purposes only. Use it responsibly and ethically.

vbnet


Remember to replace the placeholder strings such as "yourpassword" and "Your secret message" with actual secure values when you use the script. Additionally, RSA key management should be handled securely, which is not covered in this simple example script. Always make sure to comply with legal requirements and best practices when handling encryption in real-world applications.


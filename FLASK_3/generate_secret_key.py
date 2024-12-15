"""
Date: 11/17/2024
Author: Gokhan Unal
Please run this file only if you don't
see the secret.key file in the project's
root folder. Run it once please.
"""
from cryptography.fernet import Fernet

# Generate the key and save it to a file
key = Fernet.generate_key()
with open('secret.key', 'wb') as key_file:
    key_file.write(key)

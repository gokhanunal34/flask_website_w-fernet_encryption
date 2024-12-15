"""
Date: 11/27/2024
Author: Gokhan Unal
Please run this file only if you don't
see the hmac.key file in the project's
root folder. Run it once please.
"""
import os

# Generate a secure random key
hmac_key = os.urandom(32)  # 256 bits random hmac key creation

# Save the key to a .key file
with open('hmac_key.key', 'wb') as key_file:
    key_file.write(hmac_key)

print("HMAC key generated & saved to 'hmac_key.key'")

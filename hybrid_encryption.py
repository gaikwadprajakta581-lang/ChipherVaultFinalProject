from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import os

KEY_FOLDER = "keys"


def encrypt_aes_key(aes_key, filename):

    with open("keys/public.pem", "rb") as f:
        public_key = RSA.import_key(f.read())

    cipher = PKCS1_OAEP.new(public_key)

    encrypted_key = cipher.encrypt(aes_key)

    key_path = os.path.join(KEY_FOLDER, filename + ".key")

    with open(key_path, "wb") as f:
        f.write(encrypted_key)


def decrypt_aes_key(filename):

    with open("keys/private.pem", "rb") as f:
        private_key = RSA.import_key(f.read())

    cipher = PKCS1_OAEP.new(private_key)

    key_path = os.path.join(KEY_FOLDER, filename + ".key")

    with open(key_path, "rb") as f:
        encrypted_key = f.read()

    aes_key = cipher.decrypt(encrypted_key)

    return aes_key
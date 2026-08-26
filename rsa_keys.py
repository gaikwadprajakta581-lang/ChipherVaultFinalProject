from Crypto.PublicKey import RSA
import os

KEY_FOLDER = "keys"

if not os.path.exists(KEY_FOLDER):
    os.makedirs(KEY_FOLDER)


def generate_keys():

    key = RSA.generate(2048)

    private_key = key.export_key()

    public_key = key.publickey().export_key()

    with open("keys/private.pem", "wb") as f:
        f.write(private_key)

    with open("keys/public.pem", "wb") as f:
        f.write(public_key)

    return True
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

def encrypt_file(input_file, output_file):

    # Generate a new AES-256 key for this file
    key = get_random_bytes(32)

    # Generate cipher
    cipher = AES.new(key, AES.MODE_EAX)

    # Read original file
    with open(input_file, "rb") as file:
        data = file.read()

    # Encrypt data
    ciphertext, tag = cipher.encrypt_and_digest(data)

    # Save encrypted file
    with open(output_file, "wb") as file:
        file.write(cipher.nonce)
        file.write(tag)
        file.write(ciphertext)

    print("================================")
    print("Encryption Successful")
    print("Input File :", input_file)
    print("Output File:", output_file)
    print("================================")

    # Return AES key
    return key
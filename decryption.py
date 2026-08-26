from Crypto.Cipher import AES

def decrypt_file(input_file, output_file, key):

    with open(input_file, "rb") as file:
        nonce = file.read(16)
        tag = file.read(16)
        ciphertext = file.read()

    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)

    data = cipher.decrypt_and_verify(ciphertext, tag)

    with open(output_file, "wb") as file:
        file.write(data)

    print("================================")
    print("Decryption Successful")
    print("Output File :", output_file)
    print("================================")
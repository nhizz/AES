from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

def generate_key():
    return get_random_bytes(16)  # 16 bytes for AES-128 key

def encrypt(key, plaintext):
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
    return cipher.iv + ciphertext

def decrypt(key, ciphertext):
    iv = ciphertext[:AES.block_size]
    ciphertext = ciphertext[AES.block_size:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_data = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return decrypted_data.decode()

def main():
    # Generate a dynamic key for encryption and decryption
    key = generate_key()

    # Data to be encrypted
    message = "This a key test lol fuck u faggot"

    # Encryption
    encrypted_message = encrypt(key, message)
    print("Encrypted:", encrypted_message.hex())

    # Decryption
    decrypted_message = decrypt(key, encrypted_message)
    print("Decrypted:", decrypted_message)

if __name__ == "__main__":
    main()

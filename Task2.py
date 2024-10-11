# Diffie-Hellman key exchange
# TASK 1 MODIFICATION

import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad 
def power(base, exponent, modulus):
    return pow(base, exponent, modulus)

def sha256_truncate(secret):
    # Hash the secret to a 16-byte value
    return hashlib.sha256(secret.to_bytes(128, 'big')).digest()[:16]

def encrypt_message(message, key, iv):
    # Generate a random initialization vector (IV)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    # Hash the message
    padded_message = pad(message.encode('utf-8'), AES.block_size)
    # Encrypt the padded message
    encrypted_message = cipher.encrypt(padded_message)
    return encrypted_message

def main():
    # Public parameters
    q = int("B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371", 16)
    alpha = int("A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31266FEA1E5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28AD662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5",16)

    print(f"The value of q: {q}")
    print(f"The value of alpha: {alpha}")

    # Alice's private and public keys
    XA = 6 # Alice's private key
    YA = power(alpha, XA, q) # Alice's public key
    print(f"Alice's private key XA: {XA}")
    print(f"Alice's public key YA: {YA}")

    # Bob's private and public keys
    XB = 15 # Bob's private key
    YB = power(alpha, XB, q) # Bob's public key
    print(f"Bob's private key XB: {XB}")
    print(f"Bob's public key YB: {YB}")

    #Generate the shared secret key
    K_Alice = power(YB, XA, q) # Alice's calculation of the shared secret
    K_Bob = power(YA, XB, q) # Bob's calculation of the shared secret


    print(f"The shared secret key K_Alice: {K_Alice}")
    print(f"The shared secret key K_Bob: {K_Bob}")

    symmetric_key = sha256_truncate(K_Alice) # Truncate the shared secret to a 16-byte value
    print(f"The symmetric key: {symmetric_key.hex()}")

    message = "Hello, world!"
    iv = b'0123456789abcdef'  # 16-byte IV
    encrypted_message = encrypt_message(message, symmetric_key, iv)
    print(f"The encrypted message: {encrypted_message.hex()}")
    # decrypted_message = AES.new(symmetric_key, AES.MODE_CBC, iv).decrypt(encrypted_message)
   
if __name__ == "__main__":
    main()


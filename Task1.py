import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os

# Global parameters (Public values)
q = int("B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371", 16)
# alpha = int("A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31266FEA1E5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28AD662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5",16)

def generate_private_key():
    """Generates a random private key for Diffie-Hellman."""
    return int.from_bytes(os.urandom(16), 'big') % q

def compute_public_key(private_key, base, mod):
    """Computes the public key using the base and modulus."""
    return pow(base, private_key, mod)

def compute_shared_secret(public_key, private_key, mod):
    """Computes the shared secret using the other party's public key."""
    return pow(public_key, private_key, mod)

def derive_key(secret):
    """Derives a 16-byte symmetric key from the shared secret using SHA256."""
    return hashlib.sha256(secret.to_bytes(128, 'big')).digest()[:16]

def encrypt_message(message, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_message = pad(message.encode('utf-8'), AES.block_size)  # Pads the message to fit the block size
    return cipher.encrypt(padded_message)

def decrypt_message(encrypted_message, key, iv):
    """Decrypts the AES-CBC encrypted message."""
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_padded_message = cipher.decrypt(encrypted_message)
    return unpad(decrypted_padded_message, AES.block_size).decode('utf-8')

def mitm_generator_attack():
    # Mallory sets alpha to 1
    alpha = 1

    # Alice's private and public keys
    XA = generate_private_key()
    YA = compute_public_key(XA, alpha, q)
    
    # Bob's private and public keys
    XB = generate_private_key()
    YB = compute_public_key(XB, alpha, q)

    # Shared secrets, since Mallory made alph = 1, shared secret will always be 1
    shared_secret_Alice = compute_shared_secret(YB, XA, q)
    shared_secret_Bob = compute_shared_secret(YA, XB, q)

    # Check if shared secrets match
    assert shared_secret_Alice == shared_secret_Bob, "Shared secrets do not match!"

    # Derive the symmetric key
    symmetric_key = derive_key(shared_secret_Alice)

    # Example message encryption/decryption
    iv = os.urandom(16)  # 16-byte IV
    message_Alice = "This is Alice's message!"
    encrypted_message_Alice = encrypt_message(message_Alice, symmetric_key, iv)
    print(f"Encrypted message from Alice: {encrypted_message_Alice.hex()}")

    decrypted_message_Bob = decrypt_message(encrypted_message_Alice, symmetric_key, iv)
    print(f"Decrypted message by Bob: {decrypted_message_Bob}")

    message_Bob = "This is Bob's message!"
    encrypted_message_Bob = encrypt_message(message_Bob, symmetric_key, iv)
    print(f"Encrypted message from Bob: {encrypted_message_Bob.hex()}")

    decrypted_message_Alice = decrypt_message(encrypted_message_Bob, symmetric_key, iv)
    print(f"Decrypted message by Alice: {decrypted_message_Alice}")

    # Mallory intercepts and decrypts the message
    decrypted_message_Mallory = decrypt_message(encrypted_message_Alice, 1, iv)
    print(f"Decrypted message by Mallory: {decrypted_message_Mallory}")

    
if __name__ == "__main__":
    mitm_generator_attack()
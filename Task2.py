import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os

# Global parameters (Public values)
q = int("B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371", 16)
alpha = int("A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31266FEA1E5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28AD662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5",16)

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
    """Encrypts the message using AES-CBC."""
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_message = pad(message.encode('utf-8'), AES.block_size)
    return cipher.encrypt(padded_message)

def decrypt_message(encrypted_message, key, iv):
    """Decrypts the AES-CBC encrypted message."""
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_padded_message = cipher.decrypt(encrypted_message)
    return unpad(decrypted_padded_message, AES.block_size).decode('utf-8')

def mitm_key_fixing_attack():
    # Alice's private and public keys
    XA = generate_private_key()
    YA = compute_public_key(XA, alpha, q)

    # Bob's private and public keys
    XB = generate_private_key()
    YB = compute_public_key(XB, alpha, q)

    # Mallory intercepts and modifies the communication:
    # - Sends q instead of YA to Bob
    # - Sends q instead of YB to Alice
    Mallory_YA_to_Bob = q
    Mallory_YB_to_Alice = q

    # Now both Alice and Bob compute their shared secrets, but due to Mallory's modification:
    shared_secret_Alice = compute_shared_secret(Mallory_YB_to_Alice, XA, q)
    shared_secret_Bob = compute_shared_secret(Mallory_YA_to_Bob, XB, q)

    # Derive keys from shared secrets (which are now both 0 since anything raised to q mod q is 0)
    symmetric_key_Alice = derive_key(shared_secret_Alice)
    symmetric_key_Bob = derive_key(shared_secret_Bob)

    # Encryption and Decryption
    iv = b'0123456789abcdef'  # 16-byte IV
    message_Alice = "this is alice's mesg"
    encrypted_message_Alice = encrypt_message(message_Alice, symmetric_key_Alice, iv)
    print(f"Encrypted message from Alice: {encrypted_message_Alice.hex()}")

    decrypted_message_Bob = decrypt_message(encrypted_message_Alice, symmetric_key_Bob, iv)
    print(f"Decrypted message by Bob: {decrypted_message_Bob}")

    # Mallory can now decrypt both messages because they have the same symmetric key (derived from 0)
    decrypted_message_Mallory_Alice = decrypt_message(encrypted_message_Alice, symmetric_key_Alice, iv)
    print(f"Decrypted message by Mallory (Alice's message): {decrypted_message_Mallory_Alice}")

    message_Bob = "This is bob's mesg"
    encrypted_message_Bob = encrypt_message(message_Bob, symmetric_key_Bob, iv)
    print(f"Encrypted message from Bob: {encrypted_message_Bob.hex()}")

    decrypted_message_Alice = decrypt_message(encrypted_message_Bob, symmetric_key_Alice, iv)
    print(f"Decrypted message by Alice: {decrypted_message_Alice}")

    decrypted_message_Mallory_Bob = decrypt_message(encrypted_message_Bob, symmetric_key_Bob, iv)
    print(f"Decrypted message by Mallory (Bob's message): {decrypted_message_Mallory_Bob}")

if __name__ == "__main__":
    mitm_key_fixing_attack()

def mitm_generator_attack(alpha_value):
    # Alice's private and public keys
    XA = generate_private_key()
    YA = compute_public_key(XA, alpha_value, q)

    # Bob's private and public keys
    XB = generate_private_key()
    YB = compute_public_key(XB, alpha_value, q)

    # Both Alice and Bob compute shared secrets using tampered alpha
    shared_secret_Alice = compute_shared_secret(YB, XA, q)
    shared_secret_Bob = compute_shared_secret(YA, XB, q)

    # Derive the symmetric key
    symmetric_key_Alice = derive_key(shared_secret_Alice)
    symmetric_key_Bob = derive_key(shared_secret_Bob)

    # Example message encryption/decryption
    iv = b'0123456789abcdef'  # 16-byte IV
    message_Alice = "this is alice's msg !"
    encrypted_message_Alice = encrypt_message(message_Alice, symmetric_key_Alice, iv)
    print(f"Encrypted message from Alice: {encrypted_message_Alice.hex()}")

    decrypted_message_Bob = decrypt_message(encrypted_message_Alice, symmetric_key_Bob, iv)
    print(f"Decrypted message by Bob: {decrypted_message_Bob}")

    # Mallory can decrypt this by knowing how alpha was tampered
    decrypted_message_Mallory_Alice = decrypt_message(encrypted_message_Alice, symmetric_key_Alice, iv)
    print(f"Decrypted message by Mallory (Alice's message): {decrypted_message_Mallory_Alice}")

if __name__ == "__main__":
    print("Setting alpha to 1:")
    mitm_generator_attack(1)

    print("\nSetting alpha to q:")
    mitm_generator_attack(q)

    print("\nSetting alpha to q-1:")
    mitm_generator_attack(q-1)

import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# Requirement: Implement key generation
from sympy import isprime, mod_inverse, randprime


def generate_prime(bits):
    """Generate a prime number of approximately 'bits' bits."""
    return randprime(2**(bits-1), 2**bits)

# Requirement: Implement encryption
def encrypt(public_key, message):
    """Encrypt a message using RSA."""
    n, e = public_key
    return pow(message, e, n)
# Requirement: Implement decryption


def decrypt(private_key, ciphertext):
    """Decrypt a ciphertext using RSA."""
    n, d = private_key
    return pow(ciphertext, d, n)
# Requirement: Convert ASCII string to hex, then to integer


def string_to_int(message):
    """Convert an ASCII string to an integer via hex."""
    hex_string = message.encode().hex()
    return int(hex_string, 16)


def int_to_string(number):
    """Convert an integer back to an ASCII string."""
    hex_string = hex(number)[2:]  # Remove '0x' prefix
    if len(hex_string) % 2 != 0:
        hex_string = '0' + hex_string  # Ensure even length
    return bytes.fromhex(hex_string).decode()


def power(base, exponent, modulus):
    return pow(base, exponent, modulus)


def sha256_truncate(secret):
    # Hash the secret to a 16-byte value
    return hashlib.sha256(secret.to_bytes(128, 'big')).digest()[:16]


def encrypt_message(message, key, iv):
    """Encrypts the message using AES-CBC."""
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_message = pad(message.encode('utf-8'), AES.block_size)
    return cipher.encrypt(padded_message)


def decrypt_message(encrypted_message, key, iv):
    # Decrypt the message
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_message = cipher.decrypt(encrypted_message)
    # Remove padding
    return (unpad(decrypted_message, AES.block_size)).decode()


def main():
    # Public parameters
    q = int("B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371", 16)
    alpha = int("A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31266FEA1E5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28AD662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5", 16)

    print(f"The value of q: {q}")
    print(f"The value of alpha: {alpha}")

def diffie_hellman_protocol():
    # Alice's private and public keys
    XA = 6  # Alice's private key
    YA = power(alpha, XA, q)  # Alice's public key
    print(f"Alice's private key XA: {XA}")
    print(f"Alice's public key YA: {YA}")

    # Bob's private and public keys
    XB = 15  # Bob's private key
    YB = power(alpha, XB, q)  # Bob's public key
    print(f"Bob's private key XB: {XB}")
    print(f"Bob's public key YB: {YB}")

    # Generate the shared secret key
    # Alice's calculation of the shared secret, uses Bob's public key + her private key to calculate
    K_Alice = power(YB, XA, q)
    # Bob's calculation of the shared secret, uses Alice's public key + her private key to calculate
    K_Bob = power(YA, XB, q)

    # Derive the symmetric key
    symmetric_key = derive_key(shared_secret_Alice)

    # Truncate the shared secret to a 16-byte value
    symmetric_key = sha256_truncate(K_Alice)
    print(f"The symmetric key: {symmetric_key.hex()}")

    message = "Hello, world!"
    iv = b'0123456789abcdef'  # 16-byte IV
    encrypted_message = encrypt_message(message, symmetric_key, iv)
    print(f"The encrypted message: {encrypted_message.hex()}")
    decrypted_message = AES.new(
        symmetric_key, AES.MODE_CBC, iv).decrypt(encrypted_message)
    print(f"The decrypted message: {decrypted_message.decode()}")


if __name__ == "__main__":
    main()

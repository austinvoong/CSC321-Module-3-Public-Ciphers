import random
from Crypto.Util.number import getPrime

# Requirement: Implement modular inverse (using Extended Euclidean Algorithm)
def mod_inverse(a, m):
    """Compute the modular inverse of a modulo m using the extended Euclidean algorithm."""
    def egcd(a, b):
        if a == 0:
            return b, 0, 1
        else:
            g, y, x = egcd(b % a, a)
            return g, x - (b // a) * y, y

    g, x, _ = egcd(a, m)
    if g != 1:
        raise Exception('Modular inverse does not exist')
    else:
        return x % m

# Requirement: Generate prime numbers for RSA
def generate_prime(bits):
    """Generate a prime number of approximately 'bits' bits."""
    return getPrime(bits)

# Requirement: Implement key generation
def generate_keypair(bits):
    """Generate RSA public and private keys."""
    p = generate_prime(bits // 2)
    q = generate_prime(bits // 2)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537  # Requirement: Use the value e=65537
    d = mod_inverse(e, phi)
    return ((n, e), (n, d))

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

# Requirement: Convert an integer back to a string
def int_to_string(number):
    """Convert an integer back to an ASCII string."""
    hex_string = hex(number)[2:]  # Remove '0x' prefix
    if len(hex_string) % 2 != 0:
        hex_string = '0' + hex_string  # Ensure even length
    return bytes.fromhex(hex_string).decode()

# Example usage
def main():
    # Generate RSA keys
    bits = 2048
    public_key, private_key = generate_keypair(bits)
    print(f"Public key: {public_key}")
    print(f"Private key: {private_key}")

    # Encrypt a message
    message = "Hello, RSA!"
    message_int = string_to_int(message)
    ciphertext = encrypt(public_key, message_int)
    print(f"Ciphertext: {ciphertext}")

    # Decrypt the message
    decrypted_int = decrypt(private_key, ciphertext)
    decrypted_message = int_to_string(decrypted_int)
    print(f"Decrypted message: {decrypted_message}")

if __name__ == "__main__":
    main()

import random
from Crypto.Util.number import getPrime


def generate_prime(bits): 
    return getPrime(bits) #need to support upto 2048 bits 

def mod_inverse(a, m): #Computes the modular multiplicative inverse of m
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

def generate_keypair(bits): #Generate RSA public and private keys
    p = generate_prime(bits // 2)
    q = generate_prime(bits // 2)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537  # Asgn req need to use the value e=65537
    d = mod_inverse(e, phi)
    return ((n, e), (n, d))


def encrypt(public_key, message): #Encrypt a message using RSA
    n, e = public_key
    return pow(message, e, n)

def decrypt(private_key, ciphertext): #Decrypt a ciphertext using RSA
    n, d = private_key
    return pow(ciphertext, d, n)

def string_to_int(message): #Convert an ASCII string to an integer via hex
    hex_string = message.encode().hex()
    return int(hex_string, 16)

def int_to_string(number): #Convert integer back to ASCII string
    hex_string = hex(number)[2:]  # rmv '0x' prefix
    if len(hex_string) % 2 != 0:
        hex_string = '0' + hex_string  # even length
    return bytes.fromhex(hex_string).decode()

# demonstrating a successful RSA malleability attack Acc to hints 
print("\n\n***** successful RSA malleability attack *****")

def test_rsa():
    #RSA Key Generation
    bits = 1024
    public_key, private_key = generate_keypair(bits)
    n, e = public_key
    _, d = private_key

    #if you want to view the public and private keys
    # print(f"Public key: (n={n}, e={e})")
    # print(f"Private key: (n={n}, d={d})")

    # Alice picks a random value s and computes c = s^e mod n
    s = random.randint(2, n - 1) #range selected to avoid trivial values
    c = pow(s, e, n)
    print(f"\nAlice picks random s = {s}")

    #if you want to view the random s
    # print(f"\nAlice picks random s = {s} and computes c = {c}")


    # Mallory Modifies c
    # Mallory intercepts c and computes c' = c * (factor^e mod n)
    factor = random.randint(2, n - 1)
    c_prime = (c * pow(factor, e, n)) % n

    #if you want to view the mallory's modified c 
    # print(f"Mallory modifies c to c' = {c_prime} using factor = {factor}")

    # Bob decrypts c' to recover s' (Bob thinks this is s)
    s_prime = pow(c_prime, d, n)
    # print(f"Bob decrypts c' to get s' = {s_prime}")

    # Mallory recovers s by dividing s' by factor (mod n)
    s_mallory = (s_prime * mod_inverse(factor, n)) % n
    print(f"Mallory recovers the original s = {s_mallory}")

    # Verify that Mallory's recovered s matches Alice's original s
    assert s == s_mallory, "Mallory successfully recovered the original s!"
    print("Mallory successfully recovered the original s!")

if __name__ == "__main__":
    test_rsa()

print("\n\n***** Signature Malleability Attack *****")
def signature_malleability():
    # Generate RSA keypair
    public_key, private_key = generate_keypair(1024)
    n, e = public_key
    _, d = private_key

    # Alice signs m1 & m2
    m1 = random.randint(2, n - 1)
    m2 = random.randint(2, n - 1)
    s1 = pow(m1, d, n)  # Sign for m1
    s2 = pow(m2, d, n)  # Sign for m2

    # Mallory creates a valid signature
    m3 = (m1 * m2) % n
    s3 = (s1 * s2) % n  # Sign for m3
    print(f"\nMallory's new message (m3 = m1 * m2 mod n): {m3}")
    print(f"Mallory's forged signature for m3: {s3}")

    # Legitness of Mallory's forged signature
    def verify(public_key, message, signature):
        n, e = public_key
        return pow(signature, e, n) == message

    is_valid = verify(public_key, m3, s3)
    print(f"\nSignature 3 is valid: {is_valid}")

if __name__ == "__main__":
    signature_malleability()

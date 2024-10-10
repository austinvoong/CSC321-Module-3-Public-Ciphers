# Diffie-Hellman key exchange

def power(base, exponent, modulus):
    return pow(base, exponent, modulus)

def main():
    # Public parameters
    q = 37
    alpha = 5
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

if __name__ == "__main__":
    main()


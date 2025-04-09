#!/usr/bin/env python3
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
from hashlib import sha256

# --- Weak Vigenère Functions ---
def vigenere_encrypt(plaintext, key):
    ciphertext = ""
    key = key.upper()
    plaintext = plaintext.upper()
    key_length = len(key)
    for i, letter in enumerate(plaintext):
        if letter.isalpha():
            shift = ord(key[i % key_length]) - ord('A')
            ciphertext += chr(((ord(letter) - ord('A') + shift) % 26) + ord('A'))
        else:
            ciphertext += letter
    return ciphertext

def vigenere_decrypt(ciphertext, key):
    plaintext = ""
    key = key.upper()
    ciphertext = ciphertext.upper()
    key_length = len(key)
    for i, letter in enumerate(ciphertext):
        if letter.isalpha():
            shift = ord(key[i % key_length]) - ord('A')
            plaintext += chr(((ord(letter) - ord('A') - shift) % 26) + ord('A'))
        else:
            plaintext += letter
    return plaintext

# --- Weak AES Functions ---
def weak_aes_encrypt(data_bytes, aes_key):
    # Use fixed IV (all zeros) for intentional weakness
    iv = b'\x00' * 16
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(data_bytes, AES.block_size))
    return ciphertext, iv

def weak_aes_decrypt(ciphertext, aes_key, iv):
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return decrypted

def derive_key_from_passphrase(passphrase):
    return sha256(passphrase.encode('utf-8')).digest()[:16]

# --- Weak RSA Functions ---
def weak_rsa_setup():
    # Generate a small RSA key (1024-bit) for competition purposes
    rsa_key = RSA.generate(1024)
    return rsa_key, rsa_key.publickey()

def rsa_encrypt(data, rsa_public_key):
    from Crypto.Cipher import PKCS1_OAEP
    cipher_rsa = PKCS1_OAEP.new(rsa_public_key)
    return cipher_rsa.encrypt(data)

def rsa_decrypt(encrypted_data, rsa_private_key):
    from Crypto.Cipher import PKCS1_OAEP
    cipher_rsa = PKCS1_OAEP.new(rsa_private_key)
    return cipher_rsa.decrypt(encrypted_data)

# --- Combined Weak Three-Layer Encryption ---
def weak_three_layer_encrypt(plaintext, vigenere_key, aes_passphrase, rsa_public_key):
    # Layer 1: Weak Vigenère encryption
    layer1_text = vigenere_encrypt(plaintext, vigenere_key)
    layer1_bytes = layer1_text.encode('utf-8')
    
    # Layer 2: Weak AES encryption with derived key and fixed IV
    aes_key = derive_key_from_passphrase(aes_passphrase)
    ciphertext_aes, iv = weak_aes_encrypt(layer1_bytes, aes_key)
    
    # Layer 3: RSA encryption of the AES key and IV (using a small RSA key)
    # Here we simply send the derived key and IV; a contestant might attempt RSA factoring.
    key_iv = aes_key + iv
    encrypted_key_iv = rsa_encrypt(key_iv, rsa_public_key)
    
    return {
        'rsa': encrypted_key_iv,
        'aes': ciphertext_aes,
        'vigenere': layer1_text,
        'aes_key': aes_key,
        'iv': iv
    }

def weak_three_layer_decrypt(ciphertext_dict, vigenere_key, aes_passphrase, rsa_private_key):
    # Recover RSA part to extract AES key and IV
    key_iv = rsa_decrypt(ciphertext_dict['rsa'], rsa_private_key)
    aes_key = key_iv[:16]
    iv = key_iv[16:]
    
    # Decrypt AES ciphertext
    decrypted_layer1_bytes = weak_aes_decrypt(ciphertext_dict['aes'], aes_key, iv)
    layer1_text = decrypted_layer1_bytes.decode('utf-8')
    
    # Decrypt Vigenère ciphertext
    plaintext = vigenere_decrypt(layer1_text, vigenere_key)
    return plaintext

if __name__ == "__main__":
    # Setup weak RSA for the challenge
    rsa_private, rsa_public = weak_rsa_setup()
    
    # Use intentionally weak keys and passphrase
    vigenere_key = "ABC"  # Very short Vigenère key
    aes_passphrase = "weakpass123"  # Passphrase from which the AES key is derived
    plaintext = "THISISASECRETMESSAGEFORCRYPTOCOMPETITION"
    
    # Encrypt using the intentionally weak three-layer scheme
    encrypted = weak_three_layer_encrypt(plaintext, vigenere_key, aes_passphrase, rsa_public)
    print("Encrypted Data:")
    print("RSA Part (hex):", encrypted['rsa'].hex())
    print("AES Part (hex):", encrypted['aes'].hex())
    print("Vigenère Part:", encrypted['vigenere'])
    
    # In a real crypto challenge, contestants might be provided the ciphertext and
    # be expected to exploit the weaknesses.
    decrypted = weak_three_layer_decrypt(encrypted, vigenere_key, aes_passphrase, rsa_private)
    print("\nRecovered Plaintext:", decrypted)

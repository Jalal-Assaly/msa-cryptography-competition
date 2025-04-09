#!/usr/bin/env python3
"""
Three-Layered Cryptographic Challenge Example

Layer 1: Vigenère Cipher (classical encryption)
Layer 2: AES Encryption (symmetric encryption)
Layer 3: RSA Encryption (asymmetric encryption wrapping the AES key+IV)
"""
import os
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes


def dump_order_data(order_name, keys, texts, decrypted_texts=None, base_dir="output"):
    """
    Dumps keys, texts, and optionally decrypted texts for a specific encryption/decryption order into separate folders.
    """
    order_dir = os.path.join(base_dir, order_name)
    keys_dir = os.path.join(order_dir, "keys")
    texts_dir = os.path.join(order_dir, "texts")
    decrypted_dir = os.path.join(order_dir, "decrypted") if decrypted_texts else None

    # Create directories
    os.makedirs(keys_dir, exist_ok=True)
    os.makedirs(texts_dir, exist_ok=True)
    if decrypted_dir:
        os.makedirs(decrypted_dir, exist_ok=True)

    # Dump keys
    try:
        with open(os.path.join(keys_dir, "keys.txt"), 'w', encoding='utf-8') as f:
            f.write("=== Keys ===\n")
            f.write(f"Vigenère Key: {keys['vigenere_key']}\n")
            f.write(f"AES Key (hex): {keys['aes_key'].hex()}\n")
            f.write(f"IV (hex): {keys['iv'].hex()}\n")
            f.write(f"RSA Private Key (PEM):\n{keys['rsa_private_key'].export_key().decode('utf-8')}\n")
            f.write(f"RSA Public Key (PEM):\n{keys['rsa_public_key'].export_key().decode('utf-8')}\n")
        print(f"Keys dumped to '{keys_dir}/keys.txt'.")
    except Exception as e:
        print(f"Error dumping keys for {order_name}: {e}")

    # Dump texts
    try:
        with open(os.path.join(texts_dir, "vigenere.txt"), 'w', encoding='utf-8') as f:
            f.write(texts['vigenere'])
        with open(os.path.join(texts_dir, "aes.hex"), 'w', encoding='utf-8') as f:
            f.write(texts['aes'].hex())
        with open(os.path.join(texts_dir, "rsa.hex"), 'w', encoding='utf-8') as f:
            f.write(texts['rsa'].hex())
        print(f"Texts dumped to '{texts_dir}'.")
    except Exception as e:
        print(f"Error dumping texts for {order_name}: {e}")

    # Dump decrypted texts
    if decrypted_texts:
        try:
            with open(os.path.join(decrypted_dir, "vigenere_decrypted.txt"), 'w', encoding='utf-8') as f:
                f.write(decrypted_texts['vigenere'])
            with open(os.path.join(decrypted_dir, "aes_decrypted.txt"), 'w', encoding='utf-8') as f:
                f.write(decrypted_texts['aes'])
            with open(os.path.join(decrypted_dir, "final_plaintext.txt"), 'w', encoding='utf-8') as f:
                f.write(decrypted_texts['plaintext'])
            print(f"Decrypted texts dumped to '{decrypted_dir}'.")
        except Exception as e:
            print(f"Error dumping decrypted texts for {order_name}: {e}")





def encrypt_order_1(plaintext, vigenere_key, rsa_public_key):
    """
    Order 1: Vigenère -> AES -> RSA
    """
    # Layer 1: Vigenère encryption
    layer1_text = vigenere_encrypt(plaintext, vigenere_key)
    layer1_bytes = layer1_text.encode('utf-8')

    # Layer 2: AES encryption
    aes_key = get_random_bytes(16)
    iv = get_random_bytes(16)
    ciphertext_aes = aes_encrypt(layer1_bytes, aes_key, iv)

    # Layer 3: RSA encryption of AES key + IV
    key_iv = aes_key + iv
    encrypted_key_iv = rsa_encrypt(key_iv, rsa_public_key)

    return {'rsa': encrypted_key_iv, 'aes': ciphertext_aes, 'aes_key': aes_key, 'iv': iv, 'vigenere': layer1_text}


def encrypt_order_2(plaintext, aes_key, iv, rsa_public_key, vigenere_key):
    """
    Order 2: AES -> Vigenère -> RSA
    """
    # Layer 1: AES encryption
    plaintext_bytes = plaintext.encode('utf-8')
    ciphertext_aes = aes_encrypt(plaintext_bytes, aes_key, iv)

    # Layer 2: Vigenère encryption
    layer2_text = vigenere_encrypt(ciphertext_aes.hex(), vigenere_key)

    # Layer 3: RSA encryption of AES key + IV
    key_iv = aes_key + iv
    encrypted_key_iv = rsa_encrypt(key_iv, rsa_public_key)

    return {'rsa': encrypted_key_iv, 'aes': ciphertext_aes, 'aes_key': aes_key, 'iv': iv, 'vigenere': layer2_text}


def encrypt_order_3(plaintext, rsa_public_key, vigenere_key):
    """
    Order 3: RSA -> Vigenère -> AES
    """
    # Layer 1: RSA encryption of plaintext
    plaintext_bytes = plaintext.encode('utf-8')
    encrypted_rsa = rsa_encrypt(plaintext_bytes, rsa_public_key)

    # Layer 2: Vigenère encryption
    layer2_text = vigenere_encrypt(encrypted_rsa.hex(), vigenere_key)

    # Layer 3: AES encryption
    aes_key = get_random_bytes(16)
    iv = get_random_bytes(16)
    ciphertext_aes = aes_encrypt(layer2_text.encode('utf-8'), aes_key, iv)

    return {'rsa': encrypted_rsa, 'aes': ciphertext_aes, 'aes_key': aes_key, 'iv': iv, 'vigenere': layer2_text}


def decrypt_order_1(ciphertext_dict, vigenere_key, rsa_private_key):
    """
    Decrypt Order 1: RSA -> AES -> Vigenère
    """
    # Layer 1: RSA decryption to recover AES key + IV
    key_iv = rsa_decrypt(ciphertext_dict['rsa'], rsa_private_key)
    aes_key = key_iv[:16]
    iv = key_iv[16:]

    # Layer 2: AES decryption to recover Vigenère ciphertext
    decrypted_layer1_bytes = aes_decrypt(ciphertext_dict['aes'], aes_key, iv)
    layer1_text = decrypted_layer1_bytes.decode('utf-8')

    # Layer 3: Vigenère decryption to recover plaintext
    original_plaintext = vigenere_decrypt(layer1_text, vigenere_key)
    return original_plaintext


def decrypt_order_2(ciphertext_dict, vigenere_key, rsa_private_key):
    """
    Decrypt Order 2: RSA -> Vigenère -> AES
    """
    # Layer 1: RSA decryption to recover AES key + IV
    key_iv = rsa_decrypt(ciphertext_dict['rsa'], rsa_private_key)
    aes_key = key_iv[:16]
    iv = key_iv[16:]

    # Layer 2: Vigenère decryption to recover AES ciphertext
    decrypted_layer2_text = vigenere_decrypt(ciphertext_dict['vigenere'], vigenere_key)
    ciphertext_aes = bytes.fromhex(decrypted_layer2_text)

    # Layer 3: AES decryption to recover plaintext
    decrypted_plaintext_bytes = aes_decrypt(ciphertext_aes, aes_key, iv)
    return decrypted_plaintext_bytes.decode('utf-8')


def decrypt_order_3(ciphertext_dict, vigenere_key, rsa_private_key):
    """
    Decrypt Order 3: AES -> Vigenère -> RSA
    """
    # Layer 1: AES decryption to recover Vigenère ciphertext
    decrypted_layer1_bytes = aes_decrypt(ciphertext_dict['aes'], ciphertext_dict['aes_key'], ciphertext_dict['iv'])
    layer1_text = decrypted_layer1_bytes.decode('utf-8')

    # Layer 2: Vigenère decryption to recover RSA ciphertext
    decrypted_layer2_text = vigenere_decrypt(layer1_text, vigenere_key)
    rsa_ciphertext = bytes.fromhex(decrypted_layer2_text)

    # Layer 3: RSA decryption to recover plaintext
    original_plaintext = rsa_decrypt(rsa_ciphertext, rsa_private_key)
    return original_plaintext.decode('utf-8')


# -----------------------------
# Layer 1: Vigenère Cipher Code
# -----------------------------
def vigenere_encrypt(plaintext, key):
    ciphertext = ""
    key = key.upper()
    plaintext = plaintext.upper()
    key_length = len(key)
    for i, letter in enumerate(plaintext):
        if letter.isalpha():
            shift = ord(key[i % key_length]) - ord('A')
            new_char = chr(((ord(letter) - ord('A') + shift) % 26) + ord('A'))
            ciphertext += new_char
        else:
            ciphertext += letter  # non-alphabetic characters are not encrypted
    return ciphertext

def vigenere_decrypt(ciphertext, key):
    plaintext = ""
    key = key.upper()
    ciphertext = ciphertext.upper()
    key_length = len(key)
    for i, letter in enumerate(ciphertext):
        if letter.isalpha():
            shift = ord(key[i % key_length]) - ord('A')
            new_char = chr(((ord(letter) - ord('A') - shift) % 26) + ord('A'))
            plaintext += new_char
        else:
            plaintext += letter
    return plaintext

# -----------------------------------
# Layer 2: AES Encryption (symmetric)
# -----------------------------------
def aes_encrypt(data_bytes, aes_key, iv):
    cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)
    ciphertext = cipher_aes.encrypt(pad(data_bytes, AES.block_size))
    return ciphertext

def aes_decrypt(ciphertext, aes_key, iv):
    cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)
    decrypted = unpad(cipher_aes.decrypt(ciphertext), AES.block_size)
    return decrypted

# ----------------------------------------------------------
# Layer 3: RSA Encryption (asymmetric encryption of AES key+IV)
# ----------------------------------------------------------
def rsa_encrypt(data, rsa_public_key):
    cipher_rsa = PKCS1_OAEP.new(rsa_public_key)
    encrypted_data = cipher_rsa.encrypt(data)
    return encrypted_data

def rsa_decrypt(encrypted_data, rsa_private_key):
    cipher_rsa = PKCS1_OAEP.new(rsa_private_key)
    data = cipher_rsa.decrypt(encrypted_data)
    return data

# ---------------------------------------------
# Combined Three-Layer Encryption and Decryption
# ---------------------------------------------
def three_layer_encrypt(plaintext, vigenere_key, rsa_public_key):
    # Layer 1: Vigenère encryption
    layer1_text = vigenere_encrypt(plaintext, vigenere_key)
    print("Layer 1 (Vigenère Encrypted):", layer1_text)
    
    # Convert to bytes (using UTF-8 encoding)
    layer1_bytes = layer1_text.encode('utf-8')
    
    # Layer 2: AES encryption
    aes_key = get_random_bytes(16)  # AES-128; alternatively use 24 or 32 bytes for AES-192/256
    iv = get_random_bytes(16)
    ciphertext_aes = aes_encrypt(layer1_bytes, aes_key, iv)
    print("Layer 2 (AES Ciphertext in hex):", ciphertext_aes.hex())
    
    # Layer 3: RSA encryption of the AES key concatenated with iv
    key_iv = aes_key + iv
    encrypted_key_iv = rsa_encrypt(key_iv, rsa_public_key)
    print("Layer 3 (RSA Encrypted AES Key+IV in hex):", encrypted_key_iv.hex())
    
    # Final output: return both RSA encrypted AES key+IV and the AES ciphertext
    return {'rsa': encrypted_key_iv, 'aes': ciphertext_aes, 'aes_key': aes_key, 'iv': iv}

def three_layer_decrypt(ciphertext_dict, vigenere_key, rsa_private_key):
    # Extract RSA part and AES ciphertext
    encrypted_key_iv = ciphertext_dict['rsa']
    ciphertext_aes = ciphertext_dict['aes']
    
    # Layer 3 Decryption: RSA decrypt to recover AES key and IV
    key_iv = rsa_decrypt(encrypted_key_iv, rsa_private_key)
    aes_key = key_iv[:16]
    iv = key_iv[16:]
    
    # Layer 2 Decryption: AES decryption to recover the Vigenère ciphertext (as bytes)
    decrypted_layer1_bytes = aes_decrypt(ciphertext_aes, aes_key, iv)
    layer1_text = decrypted_layer1_bytes.decode('utf-8')
    print("Recovered Layer 1 (Vigenère Ciphertext):", layer1_text)
    
    # Layer 1 Decryption: Vigenère decryption to recover the original plaintext
    original_plaintext = vigenere_decrypt(layer1_text, vigenere_key)
    return original_plaintext

# ---------------------------------------------
# Dump Keys to File
# ---------------------------------------------
def dump_keys_to_file(rsa_private_key, rsa_public_key, aes_key, iv, vigenere_key, output_file="keys_dump.txt"):
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write("=== Keys Dump ===\n")
            f.write(f"Vigenère Key: {vigenere_key}\n")
            f.write(f"AES Key (hex): {aes_key.hex()}\n")
            f.write(f"IV (hex): {iv.hex()}\n")
            f.write(f"RSA Private Key (PEM):\n{rsa_private_key.export_key().decode('utf-8')}\n")
            f.write(f"RSA Public Key (PEM):\n{rsa_public_key.export_key().decode('utf-8')}\n")
        print(f"Keys successfully dumped to '{output_file}'.")
    except Exception as e:
        print(f"Error dumping keys to file: {e}")


# ---------------------------
# Example Usage of the Script
# ---------------------------
if __name__ == "__main__":
    # Generate RSA key pair (for demonstration purposes)
    rsa_key = RSA.generate(2048)
    rsa_private = rsa_key
    rsa_public = rsa_key.publickey()

    # Define your plaintext and Vigenère key
    plaintext = "This is the secret message that must be revealed!"
    vigenere_key = "CRYPTO"

    # AES key and IV for Order 2
    aes_key = get_random_bytes(16)
    iv = get_random_bytes(16)

    print("Original Plaintext:", plaintext)

    # Encrypt and Decrypt using Order 1
    encrypted_data_1 = encrypt_order_1(plaintext, vigenere_key, rsa_public)
    decrypted_plaintext_1 = decrypt_order_1(encrypted_data_1, vigenere_key, rsa_private)
    print("\nDecrypted Plaintext (Order 1):", decrypted_plaintext_1)

    # Dump Order 1 Data
    dump_order_data(
        "order_1",
        keys={
            "vigenere_key": vigenere_key,
            "aes_key": encrypted_data_1['aes_key'],
            "iv": encrypted_data_1['iv'],
            "rsa_private_key": rsa_private,
            "rsa_public_key": rsa_public,
        },
        texts={
            "vigenere": encrypted_data_1['vigenere'],
            "aes": encrypted_data_1['aes'],
            "rsa": encrypted_data_1['rsa'],
        },
        decrypted_texts={
            "vigenere": encrypted_data_1['vigenere'],
            "aes": encrypted_data_1['aes'].decode('utf-8', errors='replace'),
            "plaintext": decrypted_plaintext_1,
        }
    )

    # Encrypt and Decrypt using Order 2
    encrypted_data_2 = encrypt_order_2(plaintext, aes_key, iv, rsa_public, vigenere_key)
    decrypted_plaintext_2 = decrypt_order_2(encrypted_data_2, vigenere_key, rsa_private)
    print("\nDecrypted Plaintext (Order 2):", decrypted_plaintext_2)

    # Dump Order 2 Data
    dump_order_data(
        "order_2",
        keys={
            "vigenere_key": vigenere_key,
            "aes_key": aes_key,
            "iv": iv,
            "rsa_private_key": rsa_private,
            "rsa_public_key": rsa_public,
        },
        texts={
            "vigenere": encrypted_data_2['vigenere'],
            "aes": encrypted_data_2['aes'],
            "rsa": encrypted_data_2['rsa'],
        },
        decrypted_texts={
            "vigenere": encrypted_data_2['vigenere'],
            "aes": encrypted_data_2['aes'].decode('utf-8', errors='replace'),
            "plaintext": decrypted_plaintext_2,
        }
    )

    # Encrypt and Decrypt using Order 3
    encrypted_data_3 = encrypt_order_3(plaintext, rsa_public, vigenere_key)
    decrypted_plaintext_3 = decrypt_order_3(encrypted_data_3, vigenere_key, rsa_private)
    print("\nDecrypted Plaintext (Order 3):", decrypted_plaintext_3)

    # Dump Order 3 Data
    dump_order_data(
        "order_3",
        keys={
            "vigenere_key": vigenere_key,
            "aes_key": encrypted_data_3['aes_key'],
            "iv": encrypted_data_3['iv'],
            "rsa_private_key": rsa_private,
            "rsa_public_key": rsa_public,
        },
        texts={
            "vigenere": encrypted_data_3['vigenere'],
            "aes": encrypted_data_3['aes'],
            "rsa": encrypted_data_3['rsa'],
        },
        decrypted_texts={
            "vigenere": encrypted_data_3['vigenere'],
            "aes": encrypted_data_3['aes'].decode('utf-8', errors='replace'),
            "plaintext": decrypted_plaintext_3,
        }
    )
def encrypt_message(message, e, n):
    """
    Encrypts the message using fixed RSA parameters with block size = 1 byte.
    """
    block_size = 1
    encrypted_blocks = []
    for char in message:
        m = ord(char)
        c = pow(m, e, n)
        encrypted_blocks.append(c)
    cipher_block_size = (n.bit_length() + 7) // 8
    encrypted_bytes = b''.join(c.to_bytes(cipher_block_size, byteorder='big') for c in encrypted_blocks)
    return encrypted_bytes.hex()


def decrypt_message(ciphertext_hex, d, n):
    """
    Decrypts a hex-encoded ciphertext that was produced by encrypt_message.
    """
    cipher_block_size = (n.bit_length() + 7) // 8
    ciphertext_bytes = bytes.fromhex(ciphertext_hex)
    blocks = [int.from_bytes(ciphertext_bytes[i:i + cipher_block_size], byteorder='big')
              for i in range(0, len(ciphertext_bytes), cipher_block_size)]
    plaintext = ''.join(chr(pow(c, d, n)) for c in blocks)
    return plaintext


def main():
    n = 3233
    print("Welcome to the RSA tool.")
    #print(f"The fixed modulus (n) is: {n}")

    mode = input("Enter mode (encrypt/decrypt): ").strip().lower()

    if mode == 'encrypt':
        try:
            e = int(input("Enter the public exponent (e): ").strip())
        except ValueError:
            print("Invalid input for e. It must be an integer.")
            return
        
        input_path = input("Enter the path of the plaintext file: ").strip()
        output_path = input("Enter the path of the ciphertext file: ").strip()
        try:
            with open(input_path, "r", encoding="utf-8") as infile:
                plaintext = infile.read()
        except Exception as ex:
            print(f"Error reading input file: {ex}")
            return

        ciphertext = encrypt_message(plaintext, e, n)
        try:
            with open(output_path, "w", encoding="utf-8") as outfile:
                outfile.write(ciphertext)
            print("Encryption completed. Check the output file.")
        except Exception as ex:
            print(f"Error writing output file: {ex}")

    elif mode == 'decrypt':
        try:
            d = int(input("Enter the private exponent (d): ").strip())
        except ValueError:
            print("Invalid input for d. It must be an integer.")
            return

        input_path = input("Enter the path of the ciphertext file: ").strip()
        output_path = input("Enter the path of the plaintext file: ").strip()
        try:
            with open(input_path, "r", encoding="utf-8") as infile:
                ciphertext_hex = infile.read()
        except Exception as ex:
            print(f"Error reading input file: {ex}")
            return

        plaintext = decrypt_message(ciphertext_hex, d, n)
        try:
            with open(output_path, "w", encoding="utf-8") as outfile:
                outfile.write(plaintext)
            print("Decryption completed. Check the output file.")
        except Exception as ex:
            print(f"Error writing output file: {ex}")
    else:
        print("Invalid mode selected.")


if __name__ == "__main__":
    main()

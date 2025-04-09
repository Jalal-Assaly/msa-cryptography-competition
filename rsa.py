def encrypt_message(hex_plaintext: str, e: int, n: int) -> str:
    plaintext_bytes = bytes.fromhex(hex_plaintext)
    block_length = (n.bit_length() + 7) // 8
    ciphertext = []

    for byte in plaintext_bytes:
        m = byte
        c = pow(m, e, n)
        ciphertext.append(c.to_bytes(block_length, 'big'))

    encrypted_bytes = b''.join(ciphertext)
    return encrypted_bytes.hex()


def decrypt_message(hex_ciphertext: str, d: int, n: int) -> str:
    encrypted_bytes = bytes.fromhex(hex_ciphertext)
    block_length = (n.bit_length() + 7) // 8
    plaintext_bytes = []

    for i in range(0, len(encrypted_bytes), block_length):
        encrypted_block = encrypted_bytes[i:i + block_length]
        c = int.from_bytes(encrypted_block, 'big')
        m = pow(c, d, n)

        try:
            byte = m.to_bytes(1, 'big')  # only works if m < 256
        except OverflowError:
            # If the decrypted value doesn't fit in 1 byte, it's likely due to wrong keys
            byte = b'?'

        plaintext_bytes.append(byte)

    decrypted_bytes = b''.join(plaintext_bytes)
    return decrypted_bytes.hex()


def rsa_encrypt_file(e: int, n: int, input_file="texts/input.txt", output_file="texts/rsa-encrypted.txt"):
    try:
        with open(input_file, "r", encoding="utf-8") as infile:
            plaintext = infile.read()
    except FileNotFoundError:
        print(f"Error: File '{input_file}' not found.")
        return

    encrypted_hex = encrypt_message(plaintext, e, n)

    with open(output_file, "w", encoding="utf-8") as outfile:
        outfile.write(encrypted_hex)

    print(f"Encrypted result saved to '{output_file}'.")


def rsa_decrypt_file(d: int, n: int, input_file="texts/rsa-encrypted.txt", output_file="texts/rsa-decrypted.txt"):
    try:
        with open(input_file, "r", encoding="utf-8") as infile:
            ciphertext_hex = infile.read().strip()
    except FileNotFoundError:
        print(f"Error: File '{input_file}' not found.")
        return

    plaintext = decrypt_message(ciphertext_hex, d, n)

    with open(output_file, "w", encoding="utf-8") as outfile:
        outfile.write(plaintext)

    print(f"Decrypted result saved to '{output_file}'.")


def main():
    print("=== RSA Cipher ===")

    mode = input("Enter mode (encrypt/decrypt): ").strip().lower()

    if mode == 'encrypt':
        key_input = input("Enter public key (e n) separated by space: ").strip().split()
        if len(key_input) != 2:
            print("Invalid public key format.")
            return
        e, n = map(int, key_input)
    elif mode == 'decrypt':
        key_input = input("Enter private key (d n) separated by space: ").strip().split()
        if len(key_input) != 2:
            print("Invalid private key format.")
            return
        d, n = map(int, key_input)
    else:
        print("Invalid mode selected.")
        return

    input_path = input("Enter input file path: ").strip()
    output_path = input("Enter output file path: ").strip()

    try:
        if mode == 'encrypt':
            rsa_encrypt_file(e, n, input_path, output_path)
        else:
            rsa_decrypt_file(d, n, input_path, output_path)
    except Exception as err:
        print(f"Error during {mode}ion: {err}")


if __name__ == "__main__":
    main()

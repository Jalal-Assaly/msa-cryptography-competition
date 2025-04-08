def autokey_encrypt(hex_plaintext: str, initial_key: int) -> str:
    plaintext_bytes = bytes.fromhex(hex_plaintext)

    ciphertext = bytearray()
    key_stream = [initial_key]
    key_index = 0

    for byte in plaintext_bytes:
        k = key_stream[key_index]
        encrypted = (byte + k) % 256
        ciphertext.append(encrypted)
        key_stream.append(byte)
        key_index += 1

    return ciphertext.hex()


def autokey_decrypt(hex_ciphertext: str, initial_key: int) -> str:
    ciphertext_bytes = bytes.fromhex(hex_ciphertext)

    plaintext = bytearray()
    key_stream = [initial_key]
    key_index = 0

    for byte in ciphertext_bytes:
        k = key_stream[key_index]
        decrypted = (byte - k + 256) % 256
        plaintext.append(decrypted)
        key_stream.append(decrypted)
        key_index += 1

    return plaintext.hex()


def autokey_encrypt_file(initial_key, input_file="texts/input.txt", output_file="texts/autokey-encrypted.txt"):
    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            hex_text = f.read().strip()
    except FileNotFoundError:
        print(f"Error: File '{input_file}' not found.")
        return

    encrypted = autokey_encrypt(hex_text, initial_key)

    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(encrypted)

    print(f"Encrypted result saved to '{output_file}'.")


def autokey_decrypt_file(initial_key, input_file="texts/autokey-encrypted.txt", output_file="texts/autokey-decrypted.txt"):
    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            hex_text = f.read().strip()
    except FileNotFoundError:
        print(f"Error: File '{input_file}' not found.")
        return

    decrypted = autokey_decrypt(hex_text, initial_key)

    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(decrypted)

    print(f"Decrypted result saved to '{output_file}'.")


def main():
    print("=== Autokey Cipher (Standalone Mode) ===")

    mode = input("Type 'E' to encrypt or 'D' to decrypt: ").strip().upper()
    if mode not in ('E', 'D'):
        print("Invalid mode. Use 'E' or 'D'.")
        return

    try:
        initial_key = int(input("Enter initial numeric key (0–255): ").strip()) % 256
    except ValueError:
        print("Invalid numeric key.")
        return

    input_path = input("Enter input file path: ").strip()
    output_path = input("Enter output file path: ").strip()

    if mode == 'E':
        autokey_encrypt_file(initial_key, input_path, output_path)
    else:
        autokey_decrypt_file(initial_key, input_path, output_path)


if __name__ == "__main__":
    main()

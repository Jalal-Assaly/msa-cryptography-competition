import os

def format_text(text, preserve_format=False):
    if preserve_format:
        return text
    return ''.join(filter(str.isalpha, text)).upper()


def letter_to_num(c):
    return ord(c.upper()) - ord('A')


def num_to_letter(n, original_char='A'):
    base = ord('A') if original_char.isupper() else ord('a')
    return chr(n + base)


def autokey_encrypt(plaintext, initial_key, preserve_format=False):
    formatted = format_text(plaintext, preserve_format)
    ciphertext = ''
    key_stream = [initial_key]
    key_index = 0

    for i, char in enumerate(formatted):
        if char.isalpha():
            p_val = letter_to_num(char)
            k_val = key_stream[key_index]
            c_val = (p_val + k_val) % 26
            new_char = num_to_letter(c_val, char)
            ciphertext += new_char
            key_stream.append(p_val)
            key_index += 1
        else:
            ciphertext += char if preserve_format else ''
    return ciphertext


def autokey_decrypt(ciphertext, initial_key, preserve_format=False):
    formatted = format_text(ciphertext, preserve_format)
    plaintext = ''
    key_stream = [initial_key]
    key_index = 0

    for i, char in enumerate(formatted):
        if char.isalpha():
            c_val = letter_to_num(char)
            k_val = key_stream[key_index]
            p_val = (c_val - k_val + 26) % 26
            new_char = num_to_letter(p_val, char)
            plaintext += new_char
            key_stream.append(p_val)
            key_index += 1
        else:
            plaintext += char if preserve_format else ''
    return plaintext


def process_file(input_file, output_file, initial_key, mode, preserve_format=False):
    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            text = f.read()
    except FileNotFoundError:
        print(f"Error: File '{input_file}' not found.")
        return

    if mode == 'E':
        result = autokey_encrypt(text, initial_key, preserve_format)
        label = "Encrypted"
    else:
        result = autokey_decrypt(text, initial_key, preserve_format)
        label = "Decrypted"

    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(f"{label} Text:\n{result}\n")

    print(f"{label} result saved to '{output_file}'.")


def main():
    print("=== Autokey Cipher – Flexible Edition ===")
    mode = input("Type 'E' to encrypt or 'D' to decrypt: ").strip().upper()
    if mode not in ('E', 'D'):
        print("Invalid mode. Use 'E' or 'D'.")
        return

    batch = input("Do you want to process multiple files? (y/n): ").strip().lower() == 'y'

    try:
        initial_key = int(input("Enter initial numeric key (0–25): ").strip()) % 26
    except ValueError:
        print("Invalid numeric key.")
        return

    preserve = input("Preserve formatting (spaces, punctuation, case)? (y/n): ").strip().lower() == 'y'

    if batch:
        count = int(input("How many files? "))
        for i in range(count):
            print(f"\n--- File {i+1} ---")
            input_file = input("Input file: ").strip()
            output_file = input("Output file: ").strip()
            process_file(input_file, output_file, initial_key, mode, preserve)
    else:
        input_file = input("Input file: ").strip()
        output_file = input("Output file: ").strip()
        process_file(input_file, output_file, initial_key, mode, preserve)


if __name__ == "__main__":
    main()

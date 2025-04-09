from rsa import rsa_encrypt_file, rsa_decrypt_file
from autokey import autokey_encrypt_file, autokey_decrypt_file
from aes import aes_encrypt_file, aes_decrypt_file


def convert_plaintext_to_hex(input_path: str, output_path: str):
    try:
        with open(input_path, 'r', encoding='utf-8') as f:
            plain_text = f.read()
    except FileNotFoundError:
        print(f"Error: File '{input_path}' not found.")
        return False

    hex_text = plain_text.encode('utf-8').hex()

    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(hex_text)

    print(f"Converted plaintext to hex and saved to '{output_path}'.")
    return True


def hex_to_plaintext(hex_string: str) -> str:
    try:
        return bytes.fromhex(hex_string).decode('utf-8', errors='replace')
    except ValueError:
        return "[Invalid hex input]"


def write_to_output_file(file_path: str, is_encryption: bool):
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read().strip()
    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found.")
        return

    output_path = "texts/output.txt"
    result = content if is_encryption else hex_to_plaintext(content)

    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(result)

    print(f"Final result written to '{output_path}'.")


def get_encrypt_decrypt_functions(name: str, mode: str, keys: dict):
    if name == "autokey":
        return (
            lambda inp, out: autokey_encrypt_file(keys['autokey'], inp, out),
            lambda inp, out: autokey_decrypt_file(keys['autokey'], inp, out)
        ) if mode == 'encrypt' else (
            lambda inp, out: autokey_decrypt_file(keys['autokey'], inp, out),
            lambda inp, out: autokey_encrypt_file(keys['autokey'], inp, out)
        )
    elif name == "rsa":
        return (
            lambda inp, out: rsa_encrypt_file(keys['rsa'][0], keys['rsa'][1], inp, out),
            lambda inp, out: rsa_decrypt_file(keys['rsa'][0], keys['rsa'][1], inp, out)
        ) if mode == 'encrypt' else (
            lambda inp, out: rsa_decrypt_file(keys['rsa'][0], keys['rsa'][1], inp, out),
            lambda inp, out: rsa_encrypt_file(keys['rsa'][0], keys['rsa'][1], inp, out)
        )
    elif name == "aes":
        return (
            lambda inp, out: aes_encrypt_file(keys['aes'], inp, out),
            lambda inp, out: aes_decrypt_file(keys['aes'], inp, out)
        ) if mode == 'encrypt' else (
            lambda inp, out: aes_decrypt_file(keys['aes'], inp, out),
            lambda inp, out: aes_encrypt_file(keys['aes'], inp, out)
        )


def run_custom_pipeline(order: list, keys: dict, mode: str):
    file_prefix = "texts"
    current_file = f"{file_prefix}/input-hex.txt" if mode == "encrypt" else f"{file_prefix}/{order[0]}-encrypted.txt"

    for i, algo in enumerate(order):
        encrypt_fn, _ = get_encrypt_decrypt_functions(algo, 'encrypt', keys)
        decrypt_fn, _ = get_encrypt_decrypt_functions(algo, 'decrypt', keys)

        input_file = current_file
        next_file = f"{file_prefix}/{algo}-{'encrypted' if mode == 'encrypt' else 'decrypted'}.txt"

        if mode == 'encrypt':
            encrypt_fn(input_file, next_file)
        else:
            decrypt_fn(input_file, next_file)

        current_file = next_file

    write_to_output_file(current_file, is_encryption=(mode == 'encrypt'))


def interactive_execute():
    print("=== Custom Encryption Pipeline ===")
    mode = input("Enter mode (encrypt/decrypt): ").strip().lower()
    if mode not in ('encrypt', 'decrypt'):
        print("Invalid mode. Use 'encrypt' or 'decrypt'.")
        return

    order = input("Enter algorithm order separated by commas (e.g., autokey,rsa,aes): ").strip().lower().split(',')
    if set(order) - {'aes', 'rsa', 'autokey'}:
        print("Invalid algorithm names. Valid options: aes, rsa, autokey")
        return

    keys = {}

    if 'rsa' in order:
        key_type = 'public' if mode == 'encrypt' else 'private'
        rsa_key = (
            int(input(f"Enter RSA {key_type} key part 1: ").strip()),
            int(input(f"Enter RSA {key_type} key part 2: ").strip())
        )
        keys['rsa'] = rsa_key

    if 'aes' in order:
        aes_key = input("Enter a 16-character AES key: ").encode()
        if len(aes_key) != 16:
            print("Error: AES key must be exactly 16 bytes.")
            return
        keys['aes'] = aes_key

    if 'autokey' in order:
        autokey_key = int(input("Enter Autokey numeric key (0–255): ").strip()) % 256
        keys['autokey'] = autokey_key

    if mode == 'encrypt':
        if not convert_plaintext_to_hex("texts/input.txt", "texts/input-hex.txt"):
            return

    run_custom_pipeline(order if mode == 'encrypt' else order[::-1], keys, mode)


if __name__ == "__main__":
    interactive_execute()

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
    """
    Writes the final result to 'texts/output.txt'.
    If it's decryption, convert from hex to readable text.
    """
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


def autokey_rsa_aes_encrypt(rsa_public_key, aes_key, autokey_initial_key):
    """
    Encrypts the file using Autokey → RSA → AES.
    """
    autokey_encrypt_file(
        initial_key=autokey_initial_key,
        input_file="texts/input-hex.txt",
        output_file="texts/autokey-encrypted.txt"
    )

    rsa_encrypt_file(
        e=rsa_public_key[0],
        n=rsa_public_key[1],
        input_file="texts/autokey-encrypted.txt",
        output_file="texts/rsa-encrypted.txt"
    )

    aes_encrypt_file(
        key=aes_key,
        input_file="texts/rsa-encrypted.txt",
        output_file="texts/aes-encrypted.txt"
    )

    print("\nAutokey + RSA + AES encryption completed.")
    write_to_output_file("texts/aes-encrypted.txt", is_encryption=True)


def autokey_rsa_aes_decrypt(rsa_private_key, aes_key, autokey_initial_key):
    """
    Decrypts the file using AES → RSA → Autokey.
    """
    aes_decrypt_file(
        key=aes_key,
        input_file="texts/aes-encrypted.txt",
        output_file="texts/aes-decrypted.txt"
    )

    rsa_decrypt_file(
        d=rsa_private_key[0],
        n=rsa_private_key[1],
        input_file="texts/aes-decrypted.txt",
        output_file="texts/rsa-decrypted.txt"
    )

    autokey_decrypt_file(
        initial_key=autokey_initial_key,
        input_file="texts/rsa-decrypted.txt",
        output_file="texts/autokey-decrypted.txt"
    )

    print("\nAES + RSA + Autokey decryption completed.")
    write_to_output_file("texts/autokey-decrypted.txt", is_encryption=False)


def autokey_rsa_aes_execute():
    print("=== Autokey → RSA → AES Encryption / AES → RSA → Autokey Decryption ===")
    mode = input("Enter mode (encrypt/decrypt): ").strip().lower()

    if mode == "encrypt":
        rsa_public_key = (
            int(input("Enter RSA public key 'e': ").strip()),
            int(input("Enter RSA public key 'n': ").strip())
        )

        aes_key = input("Enter a 16-character AES key: ").encode()
        if len(aes_key) != 16:
            print("Error: AES key must be exactly 16 bytes.")
            return

        autokey_initial_key = int(input("Enter Autokey initial numeric key (0–255): ").strip()) % 256

        print("\n--- Converting plaintext to hex ---")
        if not convert_plaintext_to_hex("texts/input.txt", "texts/input-hex.txt"):
            return

        autokey_rsa_aes_encrypt(rsa_public_key, aes_key, autokey_initial_key)

    elif mode == "decrypt":
        rsa_private_key = (
            int(input("Enter RSA private key 'd': ").strip()),
            int(input("Enter RSA private key 'n': ").strip())
        )

        aes_key = input("Enter the 16-character AES key used for encryption: ").encode()
        if len(aes_key) != 16:
            print("Error: AES key must be exactly 16 bytes.")
            return

        autokey_initial_key = int(input("Enter Autokey initial numeric key used during encryption (0–255): ").strip()) % 256

        autokey_rsa_aes_decrypt(rsa_private_key, aes_key, autokey_initial_key)

    else:
        print("Invalid mode. Use 'encrypt' or 'decrypt'.")


if __name__ == "__main__":
    autokey_rsa_aes_execute()

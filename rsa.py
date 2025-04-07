def encrypt_message(message, e, n):
    block_length = (n.bit_length() + 7) // 8
    ciphertext = []
    for char in message:
        m = ord(char)
        c = pow(m, e, n)
        ciphertext.append(c.to_bytes(block_length, 'big'))

    encrypted_bytes = b''.join(ciphertext)
    return encrypted_bytes.hex()  # Return as hex string

def decrypt_message(ciphertext_hex, d, n):
    encrypted_bytes = bytes.fromhex(ciphertext_hex)
    block_length = (n.bit_length() + 7) // 8
    plaintext = []

    for i in range(0, len(encrypted_bytes), block_length):
        encrypted_block = encrypted_bytes[i:i + block_length]
        c = int.from_bytes(encrypted_block, 'big')
        m = pow(c, d, n)
        plaintext.append(chr(m))

    return ''.join(plaintext)


def main():
    mode = input("Enter mode (encrypt/decrypt): ").strip().lower()

    if mode == 'encrypt':
        key_input = input("Enter public key (e n) separated by space: ")
        parts = key_input.split()
        if len(parts) != 2:
            print("Invalid public key format.")
            return
        e = int(parts[0])
        n = int(parts[1])
    elif mode == 'decrypt':
        key_input = input("Enter private key (d n) separated by space: ")
        parts = key_input.split()
        if len(parts) != 2:
            print("Invalid private key format.")
            return
        d = int(parts[0])
        n = int(parts[1])
    else:
        print("Invalid mode selected. Exiting.")
        return

    input_path = input("Enter the path of the input text file: ").strip()
    output_path = input("Enter the path of the output text file: ").strip()

    try:
        with open(input_path, "r", encoding="utf-8") as infile:
            data = infile.read()
    except Exception as e:
        print(f"Error reading input file: {e}")
        return

    try:
        if mode == 'encrypt':
            result = encrypt_message(data, e, n)
        else:
            result = decrypt_message(data, d, n)
    except Exception as e:
        print(f"Error during {mode}ion: {e}")
        return

    try:
        with open(output_path, "w", encoding="utf-8") as outfile:
            outfile.write(result)
        print("Operation completed. Check the output file.")
    except Exception as e:
        print(f"Error writing to output file: {e}")


if __name__ == "__main__":
    main()

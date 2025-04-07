import base64

def message_to_blocks(message, block_size):
    message_bytes = message.encode('utf-8')
    blocks = []
    for i in range(0, len(message_bytes), block_size):
        block = message_bytes[i:i+block_size]
        blocks.append(int.from_bytes(block, byteorder='big'))
    return blocks

def blocks_to_message(blocks, original_block_size):
    message_bytes = bytearray()
    for block in blocks:
        # Calculate the byte size of the block from the modulus
        byte_len = (block.bit_length() + 7) // 8
        block_bytes = block.to_bytes(byte_len, byteorder='big')
        message_bytes.extend(block_bytes)
    return message_bytes.decode('utf-8', errors='ignore')

def encrypt_message(message, e, n):
    block_size = (n.bit_length() - 1) // 8  # block size in bytes
    blocks = message_to_blocks(message, block_size)
    encrypted_blocks = [pow(m, e, n) for m in blocks]

    # Base64 encoding of the encrypted ciphertext
    encrypted_block_bytes = []
    cipher_block_size = (n.bit_length() + 7) // 8  # size needed to store encrypted ints
    for c in encrypted_blocks:
        encrypted_block_bytes.append(c.to_bytes(cipher_block_size, byteorder='big'))

    # Combine all encrypted blocks and encode as base64
    ciphertext_bytes = b''.join(encrypted_block_bytes)
    return f"{block_size}\n" + base64.b64encode(ciphertext_bytes).decode('ascii')

def decrypt_message(ciphertext_b64, d, n):
    # Split the base64 encoded ciphertext and original block size
    lines = ciphertext_b64.strip().split('\n', 1)
    original_block_size = int(lines[0])
    b64_data = lines[1]

    # Decode the base64 data into the ciphertext bytes
    ciphertext_bytes = base64.b64decode(b64_data)

    # Calculate how many bytes we need per encrypted block
    cipher_block_size = (n.bit_length() + 7) // 8

    # Split the ciphertext into individual encrypted blocks
    blocks = [int.from_bytes(ciphertext_bytes[i:i+cipher_block_size], byteorder='big')
              for i in range(0, len(ciphertext_bytes), cipher_block_size)]
    
    # Decrypt each block
    decrypted_blocks = [pow(c, d, n) for c in blocks]

    # Convert decrypted blocks back to the original message
    return blocks_to_message(decrypted_blocks, original_block_size)

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

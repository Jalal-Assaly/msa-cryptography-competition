import base64

def encrypt_message(message, e, n):
    """
    Encrypts the message by converting each character to its ASCII value and
    performing RSA encryption: c = m^e mod n.

    Args:
        message (str): The plaintext message.
        e (int): Public exponent.
        n (int): Modulus.

    Returns:
        str: A Base64-encoded string of encrypted integers (with padding and newlines removed).
    """
    # Calculate fixed block length based on n
    block_length = (n.bit_length() + 7) // 8
    ciphertext = []
    for char in message:
        m = ord(char)
        c = pow(m, e, n)  # RSA encryption: c = m^e mod n
        # Convert to fixed-length bytes with leading zeros if needed
        ciphertext.append(c.to_bytes(block_length, 'big'))
    
    # Combine all encrypted blocks and encode in Base64
    encrypted_bytes = b''.join(ciphertext)
    encoded = base64.b64encode(encrypted_bytes).decode('utf-8')
    return encoded.replace('=', '').replace('\n', '')

def decrypt_message(ciphertext, d, n):
    """
    Decrypts the ciphertext by converting the Base64-encoded string back to integers and characters.
    Performs RSA decryption: m = c^d mod n.

    Args:
        ciphertext (str): A Base64-encoded string of encrypted integers.
        d (int): Private exponent.
        n (int): Modulus.

    Returns:
        str: The decrypted plaintext message.
    """
    # Reintroduce Base64 padding if needed
    missing_padding = len(ciphertext) % 4
    if missing_padding:
        ciphertext += '=' * (4 - missing_padding)
    
    encrypted_bytes = base64.b64decode(ciphertext)
    
    # Determine the fixed block length used during encryption
    block_length = (n.bit_length() + 7) // 8
    plaintext = []
    i = 0
    while i < len(encrypted_bytes):
        encrypted_block = encrypted_bytes[i:i + block_length]
        i += block_length
        
        c = int.from_bytes(encrypted_block, 'big')  # Convert bytes to integer
        m = pow(c, d, n)  # RSA decryption: m = c^d mod n
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

    # Get file paths from the user
    input_path = input("Enter the path of the input text file: ").strip()
    output_path = input("Enter the path of the output text file: ").strip()

    # Read data from the input file
    try:
        with open(input_path, "r", encoding="utf-8") as infile:
            data = infile.read()
    except Exception as e:
        print(f"Error reading input file: {e}")
        return

    # Encrypt or decrypt based on the chosen mode
    try:
        if mode == 'encrypt':
            result = encrypt_message(data, e, n)
        else:
            result = decrypt_message(data, d, n)
    except Exception as e:
        print(f"Error during {mode}ion: {e}")
        return

    # Write the result to the output file
    try:
        with open(output_path, "w", encoding="utf-8") as outfile:
            outfile.write(result)
        print("Operation completed. Check the output file.")
    except Exception as e:
        print(f"Error writing to output file: {e}")

if __name__ == "__main__":
    main()

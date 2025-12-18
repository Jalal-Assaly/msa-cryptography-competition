# Cryptography Competition Project

This project was conducted at MSA University as part of a cryptography competition for students to try and crack an encrypted code using cryptography techniques such as cryptanalysis and also new AI practices. It provides implementations of three cryptographic algorithms: AES, a byte-based Autokey cipher, and a textbook RSA. It allows users to encrypt and decrypt files by creating a custom pipeline, chaining these algorithms in any desired order.

-   **Encryption:** The process of converting plaintext (unencrypted data) into ciphertext (encrypted data).
-   **Decryption:** The reverse process of converting ciphertext back into plaintext.
-   **Key:** A piece of information used by a cipher (an algorithm for performing encryption or decryption) to transform the data.

## Implemented Algorithms

This project includes three ciphers, each with a distinct approach to encryption.

### Autokey Cipher

The Autokey cipher is a polyalphabetic substitution cipher. Unlike a simple Caesar cipher that uses a fixed key, the Autokey cipher uses a key that incorporates the plaintext itself. This implementation is a byte-oriented variant:

-   An initial integer key (0-255) is used to encrypt the first byte of the message.
-   For each subsequent byte, the *previous plaintext byte* is used as the key.
-   This makes the key stream dependent on the message being encrypted, which can be more secure than a simple repeating key.

### RSA

RSA (Rivest–Shamir–Adleman) is a widely used public-key cryptosystem. It uses a pair of keys: a public key for encryption and a private key for decryption.

-   **Public Key:** Shared with everyone, it allows anyone to encrypt a message.
-   **Private Key:** Kept secret, it is the only key that can decrypt messages encrypted with the public key.

This implementation is a "textbook" version that processes each byte of the input individually. While demonstrating the core mathematical principles of RSA (modular exponentiation), it is not intended for secure, real-world use as it lacks modern security features like cryptographic padding.

### AES (Advanced Encryption Standard)

AES is a symmetric-key block cipher and a U.S. government standard. It is one of the most secure and widely used encryption algorithms in the world.

-   **Symmetric Key:** The same key is used for both encryption and decryption.
-   **Block Cipher:** It operates on fixed-size blocks of data (16 bytes for AES-128).

This project provides a from-scratch implementation of **AES-128 in CBC (Cipher Block Chaining) mode**. In CBC mode, each block of plaintext is XORed with the previous ciphertext block before being encrypted. This ensures that even if the original plaintext contains identical blocks, the resulting ciphertext blocks will be different. A random Initialization Vector (IV) is used for the first block to ensure uniqueness.

## Project Structure

The project is organized into several key files:

```
├── main.py                 # Main interactive script to run encryption/decryption pipelines
├── aes.py                  # AES-128 CBC implementation
├── autokey.py              # Autokey cipher implementation
├── rsa.py                  # Textbook RSA implementation
└── texts/
    ├── input.txt           # Plaintext input for encryption
    ├── output.txt          # Final output (encrypted or decrypted)
    ├── input-hex.txt       # Intermediate hex representation of input.txt
    ├── aes-encrypted.txt   # Intermediate encrypted files
    ├── rsa-encrypted.txt
    └── autokey-encrypted.txt
    ├── aes-decrypted.txt   # Intermediate decrypted files
    ├── rsa-decrypted.txt
    └── autokey-decrypted.txt
```

## How to Use

The project is designed to be run interactively from the command line.

1.  **Prepare Input:** Place the text you want to encrypt in `texts/input.txt`.

2.  **Run the Main Script:**
    ```bash
    python main.py
    ```

3.  **Follow the Prompts:** The script will guide you through the process:
    -   **Mode:** Enter `encrypt` or `decrypt`.
    -   **Algorithm Order:** Specify the order of algorithms as a comma-separated list (e.g., `autokey,rsa,aes`).
        -   During decryption, the script will automatically reverse this order.
    -   **Keys:** Provide the necessary keys for each algorithm you selected.
        -   **Autokey:** An integer between 0 and 255.
        -   **AES:** A 16-character string.
        -   **RSA:** Two integers for the public key (`e` and `n`) or private key (`d` and `n`), separated by a space.

4.  **View Output:**
    -   For **encryption**, the final encrypted hex string will be saved in `texts/output.txt`.
    -   For **decryption**, the final decrypted plaintext will be saved in `texts/output.txt`.

Intermediate files for each step of the pipeline are stored in the `texts/` directory, allowing you to trace the transformation of data at each stage.

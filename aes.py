import os
from Crypto.Util.Padding import pad, unpad

# AES Constants
SBOX = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
]
INV_SBOX = [SBOX.index(x) for x in range(256)]
RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]
Nb, Nk, Nr = 4, 4, 10

# --- Helper Functions ---
def sub_bytes(state): return [[SBOX[b] for b in row] for row in state]
def inv_sub_bytes(state): return [[INV_SBOX[b] for b in row] for row in state]
def shift_rows(state): return [state[0], state[1][1:] + state[1][:1], state[2][2:] + state[2][:2], state[3][3:] + state[3][:3]]
def inv_shift_rows(state): return [state[0], state[1][-1:] + state[1][:-1], state[2][-2:] + state[2][:-2], state[3][-3:] + state[3][:-3]]
def xtime(a): return ((a << 1) ^ 0x1B) & 0xFF if a & 0x80 else a << 1

def mix_columns(state):
    for i in range(4):
        a = state[0][i], state[1][i], state[2][i], state[3][i]
        t = a[0] ^ a[1] ^ a[2] ^ a[3]
        state[0][i] ^= t ^ xtime(a[0] ^ a[1])
        state[1][i] ^= t ^ xtime(a[1] ^ a[2])
        state[2][i] ^= t ^ xtime(a[2] ^ a[3])
        state[3][i] ^= t ^ xtime(a[3] ^ a[0])
    return state

def inv_mix_columns(state):
    def mul(a, b):
        p = 0
        for _ in range(8):
            if b & 1: p ^= a
            hi_bit = a & 0x80
            a = (a << 1) & 0xFF
            if hi_bit: a ^= 0x1B
            b >>= 1
        return p
    for i in range(4):
        a = [state[r][i] for r in range(4)]
        state[0][i] = mul(a[0], 0x0e) ^ mul(a[1], 0x0b) ^ mul(a[2], 0x0d) ^ mul(a[3], 0x09)
        state[1][i] = mul(a[0], 0x09) ^ mul(a[1], 0x0e) ^ mul(a[2], 0x0b) ^ mul(a[3], 0x0d)
        state[2][i] = mul(a[0], 0x0d) ^ mul(a[1], 0x09) ^ mul(a[2], 0x0e) ^ mul(a[3], 0x0b)
        state[3][i] = mul(a[0], 0x0b) ^ mul(a[1], 0x0d) ^ mul(a[2], 0x09) ^ mul(a[3], 0x0e)
    return state

def add_round_key(state, key): return [[s ^ k for s, k in zip(sr, kr)] for sr, kr in zip(state, key)]

def key_expansion(key):
    key_symbols = list(key)
    key_schedule = [key_symbols[i:i+4] for i in range(0, len(key_symbols), 4)]
    for i in range(Nk, Nb * (Nr + 1)):
        temp = key_schedule[i-1][:]
        if i % Nk == 0:
            temp = [SBOX[b] for b in temp[1:] + temp[:1]]
            temp[0] ^= RCON[i // Nk - 1]
        key_schedule.append([a ^ b for a, b in zip(key_schedule[i - Nk], temp)])
    return [key_schedule[4*i:4*(i+1)] for i in range(Nr + 1)]

def bytes_to_matrix(b): return [list(b[i::4]) for i in range(4)]
def matrix_to_bytes(m): return bytes(sum(zip(*m), ()))
def xor_blocks(a, b): return bytes(i ^ j for i, j in zip(a, b))

def encrypt_block(block, key_schedule):
    state = bytes_to_matrix(block)
    state = add_round_key(state, key_schedule[0])
    for rnd in range(1, Nr):
        state = mix_columns(shift_rows(sub_bytes(state)))
        state = add_round_key(state, key_schedule[rnd])
    state = add_round_key(shift_rows(sub_bytes(state)), key_schedule[Nr])
    return matrix_to_bytes(state)

def decrypt_block(block, key_schedule):
    state = bytes_to_matrix(block)
    state = add_round_key(state, key_schedule[Nr])
    for rnd in range(Nr - 1, 0, -1):
        state = inv_mix_columns(add_round_key(inv_sub_bytes(inv_shift_rows(state)), key_schedule[rnd]))
    state = add_round_key(inv_sub_bytes(inv_shift_rows(state)), key_schedule[0])
    return matrix_to_bytes(state)

def encrypt_cbc(plaintext, key):
    iv = os.urandom(16)
    blocks = [pad(plaintext, 16)[i:i+16] for i in range(0, len(pad(plaintext, 16)), 16)]
    key_schedule = key_expansion(key)
    ciphertext = iv
    prev = iv
    for block in blocks:
        enc = encrypt_block(xor_blocks(block, prev), key_schedule)
        ciphertext += enc
        prev = enc
    return ciphertext

def decrypt_cbc(ciphertext, key):
    iv, ciphertext = ciphertext[:16], ciphertext[16:]
    blocks = [ciphertext[i:i+16] for i in range(0, len(ciphertext), 16)]
    key_schedule = key_expansion(key)
    plaintext = b''
    prev = iv
    for block in blocks:
        dec = xor_blocks(decrypt_block(block, key_schedule), prev)
        plaintext += dec
        prev = block
    try:
        return unpad(plaintext, 16)
    except ValueError:
        return plaintext  # Return raw if padding invalid


def aes_encrypt(hex_plaintext: str, key: bytes) -> str:
    plaintext_bytes = bytes.fromhex(hex_plaintext)
    ciphertext = encrypt_cbc(plaintext_bytes, key)
    return ciphertext.hex()


def aes_decrypt(hex_ciphertext: str, key: bytes) -> str:
    ciphertext_bytes = bytes.fromhex(hex_ciphertext)
    decrypted_bytes = decrypt_cbc(ciphertext_bytes, key)
    return decrypted_bytes.hex()


# === Modular Interface ===
def aes_encrypt_file(key: bytes, input_file="texts/input.txt", output_file="texts/aes-encrypted.txt"):
    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            hex_plaintext = f.read().strip()
    except FileNotFoundError:
        print(f"Error: File '{input_file}' not found.")
        return

    encrypted_hex = aes_encrypt(hex_plaintext, key)

    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(encrypted_hex)

    print(f"Encrypted result saved to '{output_file}'.")


def aes_decrypt_file(key: bytes, input_file="texts/aes-encrypted.txt", output_file="texts/aes-decrypted.txt"):
    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            hex_ciphertext = f.read().strip()
    except (FileNotFoundError, ValueError):
        print("Error: Could not load or decode encrypted hex.")
        return

    decrypted_hex = aes_decrypt(hex_ciphertext, key)

    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(decrypted_hex)

    print(f"Decrypted result saved to '{output_file}'.")


# === CLI Entry Point ===
def main():
    print("=== AES-128 CBC Mode ===")
    mode = input("Encrypt or Decrypt? (E/D): ").strip().upper()
    key_input = input("Enter a 16-character key: ").encode()
    if len(key_input) != 16:
        print("Error: Key must be exactly 16 bytes.")
        return

    input_path = input("Input file path: ").strip()
    output_path = input("Output file path: ").strip()

    if mode == 'E':
        aes_encrypt_file(key=key_input, input_file=input_path, output_file=output_path)
    elif mode == 'D':
        aes_decrypt_file(key=key_input, input_file=input_path, output_file=output_path)
    else:
        print("Invalid mode. Use 'E' or 'D'.")


if __name__ == "__main__":
    main()

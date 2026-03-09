from __future__ import annotations

import base64
import os
from pathlib import Path
from typing import Final

from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


CAESAR_SHIFT: Final[int] = 3
VIGENERE_KEY: Final[str] = "SKYKEY"
AES_PASSPHRASE: Final[str] = "Sky21-AES-Password-2026"
SALT_SIZE: Final[int] = 16
IV_SIZE: Final[int] = 16
PBKDF2_ITERATIONS: Final[int] = 200_000
AES_KEY_SIZE: Final[int] = 32  # AES-256


def caesar_transform(text: str, shift: int) -> str:
    result: list[str] = []
    for ch in text:
        if 'A' <= ch <= 'Z':
            offset = ord('A')
            result.append(chr((ord(ch) - offset + shift) % 26 + offset))
        elif 'a' <= ch <= 'z':
            offset = ord('a')
            result.append(chr((ord(ch) - offset + shift) % 26 + offset))
        else:
            result.append(ch)
    return ''.join(result)


def vigenere_transform(text: str, key: str, encrypt: bool = True) -> str:
    result: list[str] = []
    key = key.upper()
    key_index = 0

    for ch in text:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            key_shift = ord(key[key_index % len(key)]) - ord('A')
            if not encrypt:
                key_shift = -key_shift
            result.append(chr((ord(ch) - base + key_shift) % 26 + base))
            key_index += 1
        else:
            result.append(ch)
    return ''.join(result)


def derive_key(passphrase: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=AES_KEY_SIZE,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(passphrase.encode('utf-8'))


def aes_encrypt(data: bytes, passphrase: str) -> bytes:
    salt = os.urandom(SALT_SIZE)
    iv = os.urandom(IV_SIZE)
    key = derive_key(passphrase, salt)

    padder = padding.PKCS7(128).padder()
    padded = padder.update(data) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()

    return base64.b64encode(salt + iv + ciphertext)


def aes_decrypt(token: bytes, passphrase: str) -> bytes:
    decoded = base64.b64decode(token)
    salt = decoded[:SALT_SIZE]
    iv = decoded[SALT_SIZE:SALT_SIZE + IV_SIZE]
    ciphertext = decoded[SALT_SIZE + IV_SIZE:]

    key = derive_key(passphrase, salt)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


def write_text(path: Path, text: str) -> None:
    path.write_text(text, encoding='utf-8')


def main() -> None:
    base_dir = Path(__file__).resolve().parent
    input_file = base_dir / 'passwd.txt'
    output_dir = base_dir / 'outputs'
    output_dir.mkdir(exist_ok=True)

    plaintext = input_file.read_text(encoding='utf-8')

    caesar_encrypted = caesar_transform(plaintext, CAESAR_SHIFT)
    caesar_decrypted = caesar_transform(caesar_encrypted, -CAESAR_SHIFT)

    vigenere_encrypted = vigenere_transform(plaintext, VIGENERE_KEY, encrypt=True)
    vigenere_decrypted = vigenere_transform(vigenere_encrypted, VIGENERE_KEY, encrypt=False)

    aes_encrypted = aes_encrypt(plaintext.encode('utf-8'), AES_PASSPHRASE)
    aes_decrypted = aes_decrypt(aes_encrypted, AES_PASSPHRASE).decode('utf-8')

    write_text(output_dir / 'caesar_encrypted.txt', caesar_encrypted)
    write_text(output_dir / 'caesar_decrypted.txt', caesar_decrypted)
    write_text(output_dir / 'vigenere_encrypted.txt', vigenere_encrypted)
    write_text(output_dir / 'vigenere_decrypted.txt', vigenere_decrypted)
    write_text(output_dir / 'aes_encrypted.txt', aes_encrypted.decode('utf-8'))
    write_text(output_dir / 'aes_decrypted.txt', aes_decrypted)

    print('Encryption and decryption completed successfully.')
    print(f'Input file: {input_file}')
    print(f'Output folder: {output_dir}')
    print(f'Caesar verified: {caesar_decrypted == plaintext}')
    print(f'Vigenere verified: {vigenere_decrypted == plaintext}')
    print(f'AES verified: {aes_decrypted == plaintext}')


if __name__ == '__main__':
    main()

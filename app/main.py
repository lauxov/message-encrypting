from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import secrets
import hmac
import base64
import winsound
import os
import time
import msvcrt
import colorama
from colorama import Fore, Style
import pyperclip

colorama.init()

KEY_LENGTH = 32
BLOCK_SIZE = 16
ITERATIONS = 100000

def pad(text):
    padding_size = BLOCK_SIZE - len(text) % BLOCK_SIZE
    padding = bytes([padding_size] * padding_size)
    return text + padding

def unpad(padded):
    padding_size = padded[-1]
    if not all(padding == padding_size for padding in padded[-padding_size:]):
        raise ValueError("Incorrect padding")
    return padded[:-padding_size]

def encrypt(plain_text, password):
    backend = default_backend()
    salt = secrets.token_bytes(KEY_LENGTH)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LENGTH,
        salt=salt,
        iterations=ITERATIONS,
        backend=backend
    )
    key = kdf.derive(password.encode())
    nonce = secrets.token_bytes(KEY_LENGTH // 2)
    aesgcm = AESGCM(key)
    padded_text = pad(plain_text.encode())
    cipher_text = aesgcm.encrypt(nonce, padded_text, None)
    hmac_key = secrets.token_bytes(KEY_LENGTH)
    hmac_digest = hmac.new(hmac_key, nonce + cipher_text, "sha3_256").digest()
    return base64.urlsafe_b64encode(salt + hmac_key + nonce + cipher_text + hmac_digest).decode()

def decrypt(cipher_text, password):
    backend = default_backend()
    data = base64.urlsafe_b64decode(cipher_text.encode())
    salt = data[:KEY_LENGTH]
    hmac_key = data[KEY_LENGTH:(KEY_LENGTH * 2)]
    nonce = data[(KEY_LENGTH * 2):(KEY_LENGTH * 2) + (KEY_LENGTH // 2)]
    cipher_text = data[(KEY_LENGTH * 2) + (KEY_LENGTH // 2):-32]
    hmac_digest = data[-32:]
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LENGTH,
        salt=salt,
        iterations=ITERATIONS,
        backend=backend
    )
    key = kdf.derive(password.encode())
    hmac_verify = hmac.digest(hmac_key, nonce + cipher_text, "sha3_256")
    if not hmac.compare_digest(hmac_verify, hmac_digest):
        raise ValueError("HMAC verification failed")
    aesgcm = AESGCM(key)
    padded_text = aesgcm.decrypt(nonce, cipher_text, None)
    plain_text = unpad(padded_text)
    return plain_text.decode()

while True:
    mode = input("Select mode (Encrypt, Decrypt): ")
    print("Enter encryption key: ", end="", flush=True)
    password = ""
    while True:
        char = msvcrt.getch().decode("utf-8")
        if char == "\r":
            break
        elif char == "\b":
            if len(password) > 0:
                password = password[:-1]
                print("\b \b", end="", flush=True)
        else:
            password += char
            print("*", end="", flush=True)
    print()
    text = input("Enter text: ")

    if mode.lower() == "e" or mode.upper() == "E" or mode == "Encrypt":
        try:
            duration = 200
            freq = 460
            winsound.Beep(freq, duration)
            duration = 200
            freq = 440
            winsound.Beep(freq, duration)
            duration = 500
            freq = 420
            winsound.Beep(freq, duration)
            result = encrypt(text, password)
            print(f"Encrypted text: {result}")
            pyperclip.copy(result)
            print(Fore.GREEN + f"Copied to clipboard " + Style.RESET_ALL)
            duration = 500
            freq = 440
            winsound.Beep(freq, duration)
        except Exception as e:
            duration = 200
            freq = 240
            winsound.Beep(freq, duration)
            duration = 200
            freq = 240
            winsound.Beep(freq, duration)
            print(Fore.RED + f"Encryption failed: {e}" + Style.RESET_ALL)
    elif mode.lower() == "d" or mode.upper() == "D" or mode == "Decrypt":
        try:
            duration = 200
            freq = 460
            winsound.Beep(freq, duration)
            duration = 200
            freq = 440
            winsound.Beep(freq, duration)
            duration = 500
            freq = 420
            winsound.Beep(freq, duration)
            result = decrypt(text, password)
            print(f"Decrypted text: {result}")
            duration = 500
            freq = 440
            winsound.Beep(freq, duration)
        except Exception as e:
            duration = 200
            freq = 240
            winsound.Beep(freq, duration)
            duration = 200
            freq = 240
            winsound.Beep(freq, duration)
            print(Fore.RED + f"Decryption failed: {e}" + Style.RESET_ALL)
    else:
        duration = 200
        freq = 240
        winsound.Beep(freq, duration)
        duration = 200
        freq = 240
        winsound.Beep(freq, duration)
        print(Fore.RED + "Invalid mode selected." + Style.RESET_ALL)

    exit_choice = input("Exit (Y/N)? ")
    if exit_choice.lower() == "n":
        duration = 1000
        freq = 140
        winsound.Beep(freq, duration)
        os.system('cls')
        continue
    elif exit_choice.lower() == "y":
        duration = 1000
        freq = 140
        winsound.Beep(freq, duration)
        os.system('cls')
        break
    else:
        print("Invalid input, exiting...")
        break
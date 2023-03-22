import winsound
import os
import msvcrt
import colorama
from colorama import Fore, Style
import pyperclip
from functions.methods import encrypt, decrypt

colorama.init()

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

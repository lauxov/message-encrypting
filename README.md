# Video: https://youtu.be/fnI8AXTRE3o

This Python code implements an encryption and decryption tool using the AES-GCM (Galois/Counter Mode) authenticated encryption algorithm. The tool is designed to accept user input for either encryption or decryption, and uses a password entered by the user to encrypt or decrypt the data. The encrypted data is then copied to the system clipboard for easy sharing.

The tool uses the cryptography library for the implementation of the encryption algorithm and key derivation function. The PBKDF2HMAC function is used to derive a key from the password using the SHA256 hash function, with a randomly generated salt and a fixed number of iterations (100000 in this case). The AESGCM function is then used to encrypt and decrypt the data with the derived key and a randomly generated nonce.

To ensure data integrity, the encrypted data is also authenticated using HMAC-SHA3-256. A randomly generated HMAC key is used to compute the HMAC over the nonce and ciphertext, and the resulting digest is appended to the encrypted data. During decryption, the HMAC is verified before the ciphertext is decrypted to ensure that the data has not been tampered with.

The user interface is implemented using the msvcrt library for reading password input without echoing to the console, and the winsound library for playing sound effects during encryption and decryption. The colorama library is used to provide colored console output.

To use the tool, the user can run the script and select either encryption or decryption mode. They will then be prompted to enter a password (which is not displayed on the console), and the text to encrypt or decrypt. The tool will then display the result and copy the encrypted data to the system clipboard for easy sharing.

To learn more about AES-GCM, HMAC, and other cryptographic concepts used in this code, you can refer to resources such as the NIST Special Publication 800-38D for AES-GCM and RFC 2104 for HMAC.

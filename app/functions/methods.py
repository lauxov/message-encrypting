from settings import KEY_LENGTH, ITERATIONS
from functions.pads import unpad, pad
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import secrets
import hmac
import base64

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
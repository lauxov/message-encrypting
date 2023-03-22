from settings import BLOCK_SIZE

def pad(text):
    padding_size = BLOCK_SIZE - len(text) % BLOCK_SIZE
    padding = bytes([padding_size] * padding_size)
    return text + padding

def unpad(padded):
    padding_size = padded[-1]
    if not all(padding == padding_size for padding in padded[-padding_size:]):
        raise ValueError("Incorrect padding")
    return padded[:-padding_size]
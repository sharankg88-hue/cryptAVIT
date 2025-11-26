from flask import Flask, request, send_file, jsonify
from flask_cors import CORS
import tempfile
import os
import numpy as np
import soundfile as sf
from PIL import Image
import cv2
from moviepy.editor import VideoFileClip
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import serialization, hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# ---------------------------------------------
# CRYPTO FUNCTIONS
# ---------------------------------------------
def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048
    )
    public_key = private_key.public_key()

    priv = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )

    pub = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    return priv.decode(), pub.decode()


def encrypt_hybrid(message: str, public_pem: str):
    public_key = serialization.load_pem_public_key(
        public_pem.encode(), backend=default_backend()
    )

    aes_key = os.urandom(32)
    iv = os.urandom(16)

    padder = padding.PKCS7(128).padder()
    padded = padder.update(message.encode()) + padder.finalize()

    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    ciphertext = cipher.encryptor().update(padded) + cipher.encryptor().finalize()

    encrypted_aes_key = public_key.encrypt(
        aes_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    return encrypted_aes_key + iv + ciphertext


def decrypt_hybrid(packed: bytes, private_pem: str):
    private_key = serialization.load_pem_private_key(
        private_pem.encode(), password=None, backend=default_backend()
    )

    encrypted_aes_key = packed[:256]
    iv = packed[256:256 + 16]
    ciphertext = packed[256 + 16:]

    aes_key = private_key.decrypt(
        encrypted_aes_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    padded = cipher.decryptor().update(ciphertext) + cipher.decryptor().finalize()

    unpadder = padding.PKCS7(128).unpadder()
    return (unpadder.update(padded) + unpadder.finalize()).decode()

# ---------------------------------------------
# STEGANOGRAPHY HELPERS
# ---------------------------------------------
def pack_payload(payload: bytes):
    return len(payload).to_bytes(4, "big") + payload

def embed_bytes_in_image_file(in_path, payload, out_path):
    img = Image.open(in_path).convert("RGB")
    arr = np.array(img)
    flat = arr.reshape(-1)

    packed = pack_payload(payload)
    bits = np.array([int(b) for byte in packed for b in f"{byte:08b}"], dtype=np.uint8)

    flat[:len(bits)] = (flat[:len(bits)] & 0xFE) | bits

    stego = flat.reshape(arr.shape)
    Image.fromarray(stego).save(out_path)
    return out_path

def extract_bytes_from_image_file(in_path):
    img = Image.open(in_path).convert("RGB")
    flat = np.array(img).reshape(-1)

    header = flat[:32] & 1
    length = int("".join(str(b) for b in header), 2)

    total = 32 + length * 8
    bits = flat[32:total] & 1

    data = [
        int("".join(str(bit) for bit in bits[i:i+8]), 2)
        for i in range(0, len(bits), 8)
    ]

    return bytes(data)

# TEXT — zero width chars
ZW0 = "\u200B"
ZW1 = "\u200C"
DELIM = "\u200D"

def embed_bytes_in_text_file(in_path, payload, out_path):
    text = open(in_path, "r", encoding="utf-8").read()
    packed = pack_payload(payload)
    bits = ''.join(f"{b:08b}" for b in packed)
    hidden = ''.join(ZW0 if b == "0" else ZW1 for b in bits)
    open(out_path, "w", encoding="utf-8").write(text + DELIM + hidden)
    return out_path

def extract_bytes_from_text_file(in_path):
    content = open(in_path, "r", encoding="utf-8").read()
    hidden = content.split(DELIM)[-1]
    bits = ''.join("0" if c == ZW0 else "1" for c in hidden)
    length = int(bits[:32], 2)
    data_bits = bits[32:32 + length * 8]
    data = bytes(int(data_bits[i:i+8], 2) for i in range(0, len(data_bits), 8))
    return data

# ---------------------------------------------
# FLASK API
# ---------------------------------------------
app = Flask(__name__)
CORS(app)

@app.get("/generate_keys")
def api_generate_keys():
    priv, pub = generate_rsa_keys()
    return jsonify({"private_key": priv, "public_key": pub})

@app.post("/encrypt_embed")
def api_encrypt_embed():
    pubkey = request.form["public_key"]
    message = request.form["message"]
    media = request.files["media"]

    encrypted = encrypt_hybrid(message, pubkey)

    temp_in = tempfile.NamedTemporaryFile(delete=False).name
    temp_out = tempfile.NamedTemporaryFile(delete=False).name

    media.save(temp_in)
    name = media.filename.lower()

    if name.endswith((".png", ".jpg", ".jpeg")):
        outfile = temp_out + ".png"
        embed_bytes_in_image_file(temp_in, encrypted, outfile)

    elif name.endswith(".txt"):
        outfile = temp_out + ".txt"
        embed_bytes_in_text_file(temp_in, encrypted, outfile)

    else:
        return "Unsupported file", 400

    return send_file(outfile, as_attachment=True)

@app.post("/decrypt")
def api_decrypt():
    priv = request.form["private_key"]
    media = request.files["media"]

    temp_in = tempfile.NamedTemporaryFile(delete=False).name
    media.save(temp_in)
    name = media.filename.lower()

    if name.endswith((".png", ".jpg", ".jpeg")):
        payload = extract_bytes_from_image_file(temp_in)
    elif name.endswith(".txt"):
        payload = extract_bytes_from_text_file(temp_in)
    else:
        return "Unsupported file", 400

    message = decrypt_hybrid(payload, priv)
    return jsonify({"message": message})

@app.get("/")
def index():
    return "CryptAVIT Backend Running"

# ---------------------------------------------
# DEPLOY
# ---------------------------------------------
if __name__ == "__main__":
    app.run(debug=True)
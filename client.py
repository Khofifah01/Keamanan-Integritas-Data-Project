# File dari sisi client 
# Lengkapi file ini dengan proses-proses pembuatan private, public key, pembuatan pesan rahasia
# TIPS: Untuk private, public key bisa dibuat di sini lalu disimpan dalam file
# sebelum mengakses laman Swagger API
from fastapi import FastAPI
app = FastAPI()

from cryptography.hazmat.primitives.asymmetric import ec, padding,ed25519
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

from cryptography import x509
from cryptography.x509.oid import NameOID
import datetime
import os


# TODO: Lengkapi proses-proses pembuatan private dan public key
# untuk users yang disimulasikan

# Buat folder penyimpanan
os.makedirs("punkhazard-keys", exist_ok=True)

# USER 1
ed1_priv = ed25519.Ed25519PrivateKey.generate()
ed1_pub  = ed1_priv.public_key()

with open("punkhazard-keys/user1_priv.pem", "wb") as f:
    f.write(
        ed1_priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
    )

with open("punkhazard-keys/user1_pub.pem", "wb") as f:
    f.write(
        ed1_pub.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )

# USER 2
ed2_priv = ed25519.Ed25519PrivateKey.generate()
ed2_pub  = ed2_priv.public_key()

with open("punkhazard-keys/user2_priv.pem", "wb") as f:
    f.write(
        ed2_priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
    )

with open("punkhazard-keys/user2_pub.pem", "wb") as f:
    f.write(
        ed2_pub.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )


# TODO: Lengkapi proses-proses lain enkripsi simetrik (jika dibutuhkan)
# di mana pesan rahasia tersebut akan ditransmisikan
#
# Tulis code Anda di bawah ini
def encrypt_aes256(message: bytes):
    key = os.urandom(32)     # AES-256
    iv = os.urandom(16)      # CBC

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()

    # PKCS7 padding
    pad_len = 16 - (len(message) % 16)
    padded = message + bytes([pad_len]) * pad_len

    ciphertext = encryptor.update(padded) + encryptor.finalize()
    return key, iv, ciphertext

secret = b"Ini pesan rahasia dari client."
aes_key, aes_iv, aes_cipher = encrypt_aes256(secret)

with open("punkhazard-keys/secret.enc", "wb") as f:
    f.write(aes_cipher)

# SIGN PESAN (User 1 dan User 2)
# User 1 signature
sig1 = ed1_priv.sign(secret)
sig1_hex = sig1.hex()

with open("punkhazard-keys/user1_signature.hex", "w") as f:
    f.write(sig1_hex)

# User 2 signature
sig2 = ed2_priv.sign(secret)
sig2_hex = sig2.hex()

with open("punkhazard-keys/user2_signature.hex", "w") as f:
    f.write(sig2_hex)

print("USER 1 SIGNATURE HEX ")
print(sig1_hex)

print("USER 2 SIGNATURE HEX ")
print(sig2_hex)
print("Semua file tersimpan di folder punkhazard-keys")

import requests
from cryptography.hazmat.primitives import serialization


# KONFIGURASI

USER_ID = "Zahra Brillianty Putri"                    # nama user sesuai public key di server
PRIV_KEY = "punkhazard-keys/user1_priv.pem"   # private key user ini
PDF_PATH = "Soal-UAS-KID25.pdf"   # file PDF yang mau di-sign

API_URL = "http://localhost:8000/verify-pdf"



# LOAD PRIVATE KEY

try:
    with open(PRIV_KEY, "rb") as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=None
        )
except FileNotFoundError:
    print(f"[ERROR] Private key tidak ditemukan: {PRIV_KEY}")
    exit()
except Exception as e:
    print("[ERROR] Private key gagal dibaca:", str(e))
    exit()

# BACA PDF
try:
    with open(PDF_PATH, "rb") as f:
        pdf_bytes = f.read()
except FileNotFoundError:
    print(f"[ERROR] PDF tidak ditemukan: {PDF_PATH}")
    exit()


# SIGN FILE PDF (RAW)

signature = private_key.sign(pdf_bytes)
signature_hex = signature.hex()

print("Signature HEX:")
print(signature_hex)


# KIRIM KE SERVER
files = {
    "pdf": (PDF_PATH, pdf_bytes, "application/pdf")
}

data = {
    "user_id": USER_ID,
    "signature": signature_hex
}

print("\nMengirim ke server...")
try:
    resp = requests.post(API_URL, data=data, files=files)
    print("Server Response:")
    print(resp.json())
except Exception as e:
    print("[ERROR] Gagal mengirim ke API:", str(e))
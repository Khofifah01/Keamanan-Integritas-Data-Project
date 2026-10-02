# File utama API yang menjadi core logic dari layanan keamanan (security service) 
# Peran server dijelaskan pada soal
# TIPS: Gunakan file .txt sederhana untuk menyimpan data-data pengguna

from fastapi import FastAPI, HTTPException, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from typing import Optional, List
import os
from datetime import datetime
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.exceptions import InvalidSignature
import secrets

app = FastAPI(title="Security Service", version="1.0.0")

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ------------------------------------------
# UTILITIES
# ------------------------------------------
def create_tampered_message(msg: str):
    return msg + "_tampered"

def validate_token(user_id: str, token: str) -> bool:
    if not os.path.exists("data/tokens.txt"):
        return False
    with open("data/tokens.txt", "r") as f:
        for line in f:
            uid, tok = line.strip().split("|")
            if uid == user_id and tok == token:
                return True
    return False

# ------------------------------------------
# LOGIN / SECURE SESSION
# ------------------------------------------
@app.post("/login")
async def login(user_id: str = Form(...)):
    token = secrets.token_hex(16)
    os.makedirs("data", exist_ok=True)
    with open("data/tokens.txt", "a") as f:
        f.write(f"{user_id}|{token}\n")
    return {"message": "Login successful", "user": user_id, "token": token}

# ------------------------------------------
# HEALTH CHECK
# ------------------------------------------
@app.get("/health")
async def health_check():
    return {
        "status": "Security Service is running",
        "timestamp": datetime.now().isoformat()
    }

@app.get("/")
async def get_index() -> dict:
    return {"message": "Hello world! Please visit http://localhost:8080/docs for API UI."}

# ------------------------------------------
# UPLOAD PDF
# ------------------------------------------
@app.post("/upload-pdf")
async def upload_pdf(file: UploadFile = File(...)):
    fname = file.filename
    ctype = file.content_type
    
    try:
        contents = await file.read()
        os.makedirs("data", exist_ok=True)
        with open(f"data/{fname}", "wb") as f:
            f.write(contents)
    except Exception as e:
        return {"message": str(e)}
    
    return {"message": "File uploaded!", "filename": fname, "content-type": ctype}

# ------------------------------------------
# VERIFY PDF
# ------------------------------------------
@app.post("/verify-pdf")
async def verify_pdf(
    user_id: str = Form(...),
    signature: str = Form(...),
    pdf: UploadFile = File(...)
):
    pubkey_file = f"data/{user_id}_pub.pem"
    if not os.path.exists(pubkey_file):
        return {"message": "User not registered", "valid": False}

    with open(pubkey_file, "rb") as f:
        pubkey_pem = f.read()

    try:
        public_key = serialization.load_pem_public_key(pubkey_pem)
    except Exception as e:
        return {"message": "Invalid public key", "valid": False, "error": str(e)}

    try:
        pdf_bytes = await pdf.read()
    except Exception as e:
        return {"message": "Failed to read PDF", "error": str(e), "valid": False}

    try:
        sig_bytes = bytes.fromhex(signature)
    except:
        return {"message": "Invalid signature format (not hex)", "valid": False}

    try:
        public_key.verify(sig_bytes, pdf_bytes)
        return {"message": "PDF signature VALID", "user": user_id, "pdf_name": pdf.filename, "valid": True}
    except Exception as e:
        return {"message": "PDF signature INVALID", "user": user_id, "pdf_name": pdf.filename, "valid": False, "error": str(e)}

# ------------------------------------------
# STORE PUBLIC KEY
# ------------------------------------------
@app.post("/store")
async def store_pubkey(
    user_id: str = Form(...),
    pubkey: UploadFile = File(...),
    token: str = Form(...)
):
    if not validate_token(user_id, token):
        return {"message": "Invalid token", "user": user_id}

    msg = None
    try:
        keydata = await pubkey.read()
        keytext = keydata.decode()
        os.makedirs("data", exist_ok=True)

        try:
            serialization.load_pem_public_key(keytext.encode())
        except Exception:
            return {"message": "Invalid public key format", "user": user_id}

        pubkey_file = f"data/{user_id}_pub.pem"
        with open(pubkey_file, "w") as f:
            f.write(keytext)

        with open("data/keys.txt", "a") as f:
            f.write(f"{user_id}|{pubkey_file}\n")

        msg = "Public key stored successfully"

    except Exception as e:
        msg = f"Error: {str(e)}"

    return {"message": msg, "user": user_id}

# ------------------------------------------
# VERIFY SIGNATURE
# ------------------------------------------
@app.post("/verify")
async def verify(
    user_id: str = Form(...),
    token: str = Form(...),
    message: str = Form(...),
    signature: str = Form(...)
):
    if not validate_token(user_id, token):
        return {"message": "Invalid token", "valid": False}

    pubkey_file = f"data/{user_id}_pub.pem"
    if not os.path.exists(pubkey_file):
       return {"message": "User not registered", "valid": False}
    
    with open(pubkey_file, "r") as f:
        pubkey_pem = f.read()

    public_key = serialization.load_pem_public_key(pubkey_pem.encode())
    sig_bytes = bytes.fromhex(signature)
    tampered_message = create_tampered_message(message)

    try:
        public_key.verify(sig_bytes, message.encode())
        valid_original = True
        msg_text = "Signature VALID for original message"
    except InvalidSignature:
        valid_original = False
        msg_text = "Signature INVALID for original message"

    try:
        public_key.verify(sig_bytes, tampered_message.encode())
        valid_tampered = True
    except InvalidSignature:
        valid_tampered = False

    return {
        "message": msg_text,
        "user": user_id,
        "original_message": message,
        "tampered_message": tampered_message,
        "valid_original": valid_original,
        "valid_tampered": valid_tampered,
        "error": "" if valid_original else "Signature does not match"
    }

# ------------------------------------------
# RELAY MESSAGE
# ------------------------------------------
@app.post("/relay")
async def relay(
    sender: str = Form(...),
    receiver: str = Form(...),
    message: str = Form(...),
    token: str = Form(...)
):
    if not validate_token(sender, token):
        return {"message": "Invalid token", "delivered": False}

    registered = False
    if os.path.exists("data/keys.txt"):
        with open("data/keys.txt", "r") as f:
            for line in f:
                uid, _ = line.strip().split("|", 1)
                if uid == receiver:
                    registered = True
                    break
    if not registered:
        return {"message": "Receiver not registered", "delivered": False}

    # AES256 CBC encrypt message
    key = os.urandom(32)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    pad_len = 16 - (len(message.encode()) % 16)
    padded = message.encode() + bytes([pad_len]*pad_len)
    ciphertext = encryptor.update(padded) + encryptor.finalize()

    os.makedirs("data", exist_ok=True)
    with open("data/inbox.txt", "ab") as f:
        f.write(f"FROM:{sender}|TO:{receiver}|MSG:".encode() + ciphertext + b"\n")

    return {"message": "Message relayed securely", "from": sender, "to": receiver, "delivered": True}
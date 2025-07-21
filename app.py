import os
import base64
import hashlib
import hmac
from flask import Flask, render_template, request, send_file, after_this_request
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'Uploads'
app.config['PROCESSED_FOLDER'] = 'processed'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['PROCESSED_FOLDER'], exist_ok=True)

def derive_key(key_input: str, salt: bytes = None) -> tuple[bytes, bytes]:
    """Derive a 32-byte AES key from a user-provided key/password using PBKDF2HMAC."""
    if len(key_input) < 5:
        raise ValueError("Key/Password must be at least 5 characters long")
    if salt is None:
        salt = get_random_bytes(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # AES-256 key size
        salt=salt,
        iterations=100000,
    )
    key = kdf.derive(key_input.encode())
    return key, salt

def compute_hmac(data: bytes, key: bytes) -> bytes:
    """Compute HMAC for data integrity."""
    return hmac.new(key, data, hashlib.sha256).digest()

def encrypt_text(plain_text: str, key_input: str) -> str:
    """Encrypt text with a derived key."""
    try:
        aes_key, salt = derive_key(key_input)
        iv = get_random_bytes(16)
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        padded = pad(plain_text.encode(), AES.block_size)
        encrypted = cipher.encrypt(padded)
        hmac_value = compute_hmac(encrypted, aes_key)
        combined = salt + iv + hmac_value + encrypted
        return base64.b64encode(combined).decode()
    except Exception as e:
        raise ValueError(f"Encryption failed: {str(e)}")

def decrypt_text(cipher_text: str, key_input: str) -> str:
    """Decrypt text with a derived key."""
    try:
        combined = base64.b64decode(cipher_text)
        if len(combined) < 80:  # salt (16) + iv (16) + hmac (32) + data
            raise ValueError("Invalid ciphertext format")
        salt, iv, stored_hmac, encrypted = combined[:16], combined[16:32], combined[32:64], combined[64:]
        aes_key, _ = derive_key(key_input, salt)
        computed_hmac = compute_hmac(encrypted, aes_key)
        if not hmac.compare_digest(stored_hmac, computed_hmac):
            raise ValueError("Integrity check failed: Data tampered")
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        decrypted = unpad(cipher.decrypt(encrypted), AES.block_size)
        return decrypted.decode()
    except Exception as e:
        raise ValueError(f"Decryption failed: {str(e)}")

def encrypt_file(file_data: bytes, filename: str, key_input: str) -> bytes:
    """Encrypt file with a derived key."""
    try:
        aes_key, salt = derive_key(key_input)
        iv = get_random_bytes(16)
        ext = os.path.splitext(filename)[1].encode()[:16].ljust(16, b'\0')
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        padded = pad(ext + file_data, AES.block_size)
        encrypted = cipher.encrypt(padded)
        hmac_value = compute_hmac(encrypted, aes_key)
        combined = salt + iv + hmac_value + encrypted
        return combined
    except Exception as e:
        raise ValueError(f"File encryption failed: {str(e)}")

def decrypt_file(encrypted_data: bytes, key_input: str) -> tuple[bytes, bytes]:
    """Decrypt file with a derived key."""
    try:
        if len(encrypted_data) < 80:
            raise ValueError("Invalid file format")
        salt, iv, stored_hmac, encrypted = encrypted_data[:16], encrypted_data[16:32], encrypted_data[32:64], encrypted_data[64:]
        aes_key, _ = derive_key(key_input, salt)
        computed_hmac = compute_hmac(encrypted, aes_key)
        if not hmac.compare_digest(stored_hmac, computed_hmac):
            raise ValueError("Integrity check failed: Data tampered")
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        decrypted = unpad(cipher.decrypt(encrypted), AES.block_size)
        ext = decrypted[:16].rstrip(b'\0').decode()
        content = decrypted[16:]
        return ext, content
    except Exception as e:
        raise ValueError(f"File decryption failed: {str(e)}")

@app.route('/', methods=['GET', 'POST'])
def text_encrypt_decrypt():
    result = ""
    input_text = ""
    mode = "Encrypt"
    error = ""

    if request.method == 'POST':
        input_text = request.form['text']
        key_input = request.form['key_input']
        mode = request.form['mode']
        
        if not key_input:
            error = "Key/Password is required"
        else:
            try:
                if mode == 'Encrypt':
                    result = encrypt_text(input_text, key_input)
                else:
                    result = decrypt_text(input_text, key_input)
            except Exception as e:
                error = str(e)

    return render_template('index.html', result=result, input_text=input_text, mode=mode, error=error)

@app.route('/file', methods=['GET', 'POST'])
def handle_file():
    result_file = None
    operation = None
    error = ""

    if request.method == 'POST':
        file = request.files['file']
        key_input = request.form['key_input']
        operation = request.form['mode']
        
        if not key_input:
            error = "Key/Password is required"
        elif file:
            filename = secure_filename(file.filename)
            file_data = file.read()
            try:
                if len(file_data) > app.config['MAX_CONTENT_LENGTH']:
                    raise ValueError("File size exceeds 16MB limit")
                output_path = os.path.join(app.config['PROCESSED_FOLDER'], filename + ('.enc' if operation == 'Encrypt' else ''))
                if operation == 'Encrypt':
                    encrypted_data = encrypt_file(file_data, filename, key_input)
                    with open(output_path, 'wb') as f:
                        f.write(encrypted_data)
                else:
                    ext, decrypted_data = decrypt_file(file_data, key_input)
                    output_path = os.path.join(app.config['PROCESSED_FOLDER'], filename.replace('.enc', '') + ext)
                    with open(output_path, 'wb') as f:
                        f.write(decrypted_data)
                
                @after_this_request
                def cleanup(response):
                    try:
                        os.remove(output_path)
                    except:
                        pass
                    return response
                
                result_file = output_path
            except Exception as e:
                error = str(e)

    return render_template('file.html', result_file=result_file, operation=operation, error=error)

@app.route('/download/<filename>')
def download_file(filename):
    file_path = os.path.join(app.config['PROCESSED_FOLDER'], filename)
    return send_file(file_path, as_attachment=True)

if __name__ == '__main__':
    app.run(debug=True)

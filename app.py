import os
import base64
import hashlib
import hmac
import logging
from flask import Flask, render_template, request, send_file, after_this_request, abort
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from werkzeug.utils import secure_filename

# Configure logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'Uploads'
app.config['PROCESSED_FOLDER'] = 'processed'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['PROCESSED_FOLDER'], exist_ok=True)

def derive_key(key_input: str, salt: bytes = None) -> tuple[bytes, bytes]:
    """Derive a 32-byte AES key from a user-provided key/password using PBKDF2HMAC."""
    logger.debug(f"Deriving key for input: {key_input[:5]}... (length: {len(key_input)})")
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
        logger.debug("Starting text encryption")
        aes_key, salt = derive_key(key_input)
        iv = get_random_bytes(16)
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        padded = pad(plain_text.encode(), AES.block_size)
        encrypted = cipher.encrypt(padded)
        hmac_value = compute_hmac(encrypted, aes_key)
        combined = salt + iv + hmac_value + encrypted
        return base64.b64encode(combined).decode()
    except Exception as e:
        logger.error(f"Text encryption failed: {str(e)}")
        raise ValueError(f"Encryption failed: {str(e)}")

def decrypt_text(cipher_text: str, key_input: str) -> str:
    """Decrypt text with a derived key."""
    try:
        logger.debug("Starting text decryption")
        combined = base64.b64decode(cipher_text)
        if len(combined) < 80:
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
        logger.error(f"Text decryption failed: {str(e)}")
        raise ValueError(f"Decryption failed: {str(e)}")

def encrypt_file(file_data: bytes, filename: str, key_input: str) -> bytes:
    """Encrypt file with a derived key."""
    try:
        logger.debug(f"Encrypting file: {filename}, size: {len(file_data)} bytes")
        aes_key, salt = derive_key(key_input)
        iv = get_random_bytes(16)
        ext = os.path.splitext(filename)[1].encode()[:16].ljust(16, b'\0')
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        padded = pad(ext + file_data, AES.block_size)
        encrypted = cipher.encrypt(padded)
        hmac_value = compute_hmac(encrypted, aes_key)
        combined = salt + iv + hmac_value + encrypted
        logger.debug(f"File encrypted, output size: {len(combined)} bytes")
        return combined
    except Exception as e:
        logger.error(f"File encryption failed: {str(e)}")
        raise ValueError(f"File encryption failed: {str(e)}")

def decrypt_file(encrypted_data: bytes, key_input: str) -> tuple[bytes, bytes]:
    """Decrypt file with a derived key."""
    try:
        logger.debug(f"Decrypting file, input size: {len(encrypted_data)} bytes")
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
        logger.debug(f"File decrypted, extension: {ext}, content size: {len(content)} bytes")
        return ext, content
    except Exception as e:
        logger.error(f"File decryption failed: {str(e)}")
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
                logger.debug(f"Processing file: {filename}, operation: {operation}")
                if len(file_data) > app.config['MAX_CONTENT_LENGTH']:
                    raise ValueError("File size exceeds 16MB limit")
                output_filename = filename + ('.enc' if operation == 'Encrypt' else '')
                output_path = os.path.join(app.config['PROCESSED_FOLDER'], output_filename)
                if operation == 'Encrypt':
                    encrypted_data = encrypt_file(file_data, filename, key_input)
                    with open(output_path, 'wb') as f:
                        f.write(encrypted_data)
                    logger.debug(f"Encrypted file written to: {output_path}")
                else:
                    ext, decrypted_data = decrypt_file(file_data, key_input)
                    output_filename = filename.replace('.enc', '') + ext
                    output_path = os.path.join(app.config['PROCESSED_FOLDER'], output_filename)
                    with open(output_path, 'wb') as f:
                        f.write(decrypted_data)
                    logger.debug(f"Decrypted file written to: {output_path}")
                
                result_file = output_path
                
                # Delayed cleanup to ensure file is available for download
                @after_this_request
                def cleanup(response):
                    try:
                        if os.path.exists(output_path):
                            logger.debug(f"Cleaning up file: {output_path}")
                            os.remove(output_path)
                    except Exception as e:
                        logger.error(f"Cleanup failed: {str(e)}")
                    return response
                
            except Exception as e:
                logger.error(f"File operation error: {str(e)}")
                error = str(e)

    return render_template('file.html', result_file=result_file, operation=operation, error=error)

@app.route('/download/<filename>')
def download_file(filename):
    file_path = os.path.join(app.config['PROCESSED_FOLDER'], filename)
    logger.debug(f"Attempting to download: {file_path}")
    if not os.path.exists(file_path):
        logger.error(f"File not found: {file_path}")
        abort(404, description="File not found. It may have been deleted or not generated correctly.")
    try:
        return send_file(file_path, as_attachment=True)
    except Exception as e:
        logger.error(f"Download failed: {str(e)}")
        abort(500, description=f"Download failed: {str(e)}")

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), debug=False)

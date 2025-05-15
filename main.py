
from flask import Flask, render_template, request, send_file, make_response
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import os

app = Flask(__name__)
app.secret_key = get_random_bytes(16)

def validate_key_size(key):
    key_length = len(key.encode())
    valid_sizes = {16: 128, 24: 192, 32: 256}  # bytes: bits
    
    if key_length not in valid_sizes:
        return None, f"Invalid key length. Key must be 16, 24, or 32 bytes (currently {key_length} bytes). This corresponds to 128, 192, or 256 bits."
    
    return valid_sizes[key_length], None

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/encrypt', methods=['POST'])
def encrypt():
    try:
        file = request.files['file']
        key = request.form['key']
        
        key_size, error = validate_key_size(key)
        if error:
            return error, 400
            
        iv = get_random_bytes(16)
        cipher = AES.new(key.encode(), AES.MODE_CBC, iv)
        
        data = file.read()
        ct_bytes = cipher.encrypt(pad(data, AES.block_size))
        
        encrypted_data = iv + ct_bytes
        
        response = make_response(encrypted_data)
        response.headers['Content-Type'] = 'application/octet-stream'
        response.headers['Content-Disposition'] = f'attachment; filename=encrypted_{file.filename}'
        return response
        
    except Exception as e:
        return str(e), 400

@app.route('/decrypt', methods=['POST'])
def decrypt():
    try:
        file = request.files['file']
        key = request.form['key']
        
        key_size, error = validate_key_size(key)
        if error:
            return error, 400
            
        file_data = file.read()
        iv = file_data[:16]
        ct = file_data[16:]
        
        cipher = AES.new(key.encode(), AES.MODE_CBC, iv)
        pt = unpad(cipher.decrypt(ct), AES.block_size)
        
        response = make_response(pt)
        response.headers['Content-Type'] = 'application/octet-stream'
        response.headers['Content-Disposition'] = f'attachment; filename=decrypted_{file.filename}'
        return response
        
    except Exception as e:
        return str(e), 400

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)

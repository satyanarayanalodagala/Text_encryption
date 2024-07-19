from flask import Flask, render_template, request, redirect, url_for, flash
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from base64 import b64encode, b64decode
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)

def encrypt_text(plain_text, key):
    key = key.ljust(32)[:32].encode('utf-8')  # Ensure the key is 32 bytes
    iv = get_random_bytes(16)  # Generate a random IV
    cipher = AES.new(key, AES.MODE_CFB, iv=iv)
    encrypted_text = iv + cipher.encrypt(plain_text.encode('utf-8'))
    return b64encode(encrypted_text).decode('utf-8')

def decrypt_text(encrypted_text, key):
    key = key.ljust(32)[:32].encode('utf-8')  # Ensure the key is 32 bytes
    encrypted_text = b64decode(encrypted_text.encode('utf-8'))
    iv = encrypted_text[:16]
    cipher = AES.new(key, AES.MODE_CFB, iv=iv)
    decrypted_text = cipher.decrypt(encrypted_text[16:]).decode('utf-8')
    return decrypted_text

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        operation = request.form['operation']
        text = request.form['text']
        key = request.form['key']
        if operation == 'encrypt':
            result = encrypt_text(text, key)
            flash('Encrypted Text: {}'.format(result))
        elif operation == 'decrypt':
            try:
                result = decrypt_text(text, key)
                flash('Decrypted Text: {}'.format(result))
            except Exception as e:
                flash('Decryption failed: {}'.format(str(e)))
        return redirect(url_for('index'))
    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True)

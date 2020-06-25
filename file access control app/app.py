from flask import Flask, render_template, request
from werkzeug.utils import secure_filename
from cryptography.fernet import Fernet
import base64
import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from werkzeug.utils import secure_filename

UPLOAD_FOLDER = '/path/to/the/uploads'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

app = Flask(__name__)

pa = "pass phrase"


password_provided = pa
password = password_provided.encode()

salt = b'salt_'


def encrypt(fer, f):
    
    with open(f, 'rb') as d:
        data = d.read()
        print(data)
        encrypted = fer.encrypt(data)

    with open('enc_' + f, 'wb') as d:
        d.write(encrypted)
    return render_template('temp.html')


def decrypt_file(fer, f):
    with open(f, 'rb') as d:
        data = d.read()
        print(data)
        decrypted = fer.decrypt(data)
        print(decrypted)
    with open('dec_' + f.strip('enc_'), 'wb') as d:
        d.write(decrypted)
    return render_template('temp2.html')


@app.route('/uploader', methods=['GET', 'POST'])
def uploader():
    if request.method == 'POST':
        f = request.files['file']
        
        pa = request.form.get('text')
        password_provided = pa
        password = password_provided.encode()
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()


        )
        key = base64.urlsafe_b64encode(kdf.derive(password))
        fer = Fernet(key)
        f.save(secure_filename(f.filename))
       
        print(f.filename)
        if not f.filename.startswith('enc'):
            return encrypt(fer, f.filename)
        else:
            return decrypt_file(fer, f.filename)
    else:
        return render_template('home.html')


if __name__ == '__main__':
    app.run(debug=True)

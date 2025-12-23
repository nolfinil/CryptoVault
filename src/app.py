from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file
import os
import sys
import json
import time
import io
import base64
import qrcode
from werkzeug.utils import secure_filename

# Настраиваем пути относительно текущего файла (src/app.py)
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(current_dir)

# Папки keys и uploads
KEYS_DIR = os.path.join(os.path.dirname(current_dir), 'keys')
INBOX_FILE = "inbox.json"
UPLOADS_DIR = os.path.join(current_dir, 'uploads')

from auth.authentication import AuthModule
from messaging.encryption import MessagingModule
from files.file_encryption import FileEncryptionModule
from blockchain.ledger import BlockchainModule

app = Flask(__name__)
app.secret_key = 'SUPER_SECRET_KEY_FOR_DEMO'
app.config['UPLOAD_FOLDER'] = UPLOADS_DIR

# Создаем папки, если их нет
if not os.path.exists(UPLOADS_DIR):
    os.makedirs(UPLOADS_DIR)
if not os.path.exists(KEYS_DIR):
    os.makedirs(KEYS_DIR)

# Инициализация модулей
ledger = BlockchainModule(difficulty=2)
auth = AuthModule(blockchain_logger=ledger)
messenger = MessagingModule()
files = FileEncryptionModule(blockchain_logger=ledger)

def load_inbox():
    if not os.path.exists(INBOX_FILE): return []
    try:
        with open(INBOX_FILE, 'r') as f: return json.load(f)
    except: return []

def save_to_inbox(msg_data):
    inbox = load_inbox()
    inbox.append(msg_data)
    with open(INBOX_FILE, 'w') as f: json.dump(inbox, f, indent=4)

@app.route('/')
def index():
    if 'username' in session: return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        messenger.generate_keys()
        messenger.save_keys(username, KEYS_DIR)
        pub_key = messenger.get_public_key_pem()
        success, result = auth.register_user(username, password, pub_key)
        if success:
            qr = qrcode.make(result)
            buffered = io.BytesIO()
            qr.save(buffered, format="PNG")
            img_str = base64.b64encode(buffered.getvalue()).decode()
            secret = result.split('secret=')[1].split('&')[0]
            return render_template('register_success.html', username=username, qr_code=img_str, secret=secret)
        else:
            flash(f"Error: {result}")
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        totp = request.form['totp']
        success, result = auth.login(username, password, totp)
        if success:
            session['username'] = username
            if messenger.load_keys(username, KEYS_DIR): flash("Keys loaded successfully.")
            else: flash("Warning: Encryption keys not found.")
            ledger.mine_block()
            return redirect(url_for('dashboard'))
        else:
            flash(result)
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

@app.route('/dashboard')
def dashboard():
    if 'username' not in session: return redirect(url_for('login'))
    current_user = session['username']
    
    # Загрузка сообщений
    all_msgs = load_inbox()
    my_msgs = []
    for msg in all_msgs:
        if msg.get('to') == current_user:
            try:
                decrypted = messenger.decrypt_message(msg)
                msg['content'] = decrypted
                msg['status'] = 'Verified & Decrypted'
                msg['class'] = 'success'
            except Exception as e:
                msg['content'] = '[Encrypted Content]'
                msg['status'] = f'Decryption Failed: {str(e)}'
                msg['class'] = 'danger'
            my_msgs.append(msg)
            
    # Загрузка списка файлов
    user_files = []
    if os.path.exists(UPLOADS_DIR):
        user_files = [f for f in os.listdir(UPLOADS_DIR) if f.startswith(current_user + "_")]
    
    users = auth.get_all_users()
    return render_template('dashboard.html', username=current_user, messages=my_msgs, users=users, files=user_files)

@app.route('/send', methods=['POST'])
def send_message():
    if 'username' not in session: return redirect(url_for('login'))
    sender = session['username']
    recipient = request.form['recipient']
    text = request.form['message']
    recipient_pub = auth.get_user_pubkey(recipient)
    if not recipient_pub:
        flash("Recipient not found")
        return redirect(url_for('dashboard'))
    try:
        encrypted_pkg = messenger.send_message(recipient_pub, text)
        encrypted_pkg['to'] = recipient
        encrypted_pkg['from'] = sender
        encrypted_pkg['timestamp'] = time.time()
        save_to_inbox(encrypted_pkg)
        ledger.add_transaction(f"MSG: {sender} -> {recipient}")
        ledger.mine_block()
        flash("Message sent securely!")
    except Exception as e:
        flash(f"Error sending: {e}")
    return redirect(url_for('dashboard'))

# --- РОУТЫ ДЛЯ ФАЙЛОВ (ТЕПЕРЬ ТОЧНО ЕСТЬ) ---
@app.route('/encrypt_file', methods=['POST'])
def encrypt_file_route():
    if 'username' not in session: return redirect(url_for('login'))
    if 'file' not in request.files:
        flash('No file part')
        return redirect(url_for('dashboard'))
    file = request.files['file']
    password = request.form['password']
    if file.filename == '':
        flash('No selected file')
        return redirect(url_for('dashboard'))
    
    if file:
        filename = secure_filename(file.filename)
        # Добавляем имя юзера к файлу, чтобы не путать
        save_name = f"{session['username']}_{filename}"
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], save_name)
        file.save(filepath)
        
        try:
            enc_path = files.encrypt_file(filepath, password)
            os.remove(filepath) # Удаляем оригинал
            ledger.mine_block()
            flash(f"File encrypted: {os.path.basename(enc_path)}")
        except Exception as e:
            flash(f"Error: {e}")
            
    return redirect(url_for('dashboard'))

@app.route('/decrypt_file', methods=['POST'])
def decrypt_file_route():
    if 'username' not in session: return redirect(url_for('login'))
    filename = request.form['filename']
    password = request.form['password']
    
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    
    try:
        dec_path = files.decrypt_file(filepath, password)
        ledger.mine_block()
        return send_file(dec_path, as_attachment=True)
    except Exception as e:
        flash(f"Decryption failed: {e}")
        return redirect(url_for('dashboard'))

@app.route('/ledger')
def view_ledger():
    chain_data = json.loads(ledger.get_chain_dump())
    return render_template('ledger.html', chain=chain_data)

if __name__ == '__main__':
    app.run(debug=True, port=5000)
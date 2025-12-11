#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from flask import Flask, request, jsonify
from flask_cors import CORS
import sqlite3
import hashlib
import secrets
import datetime
import os
import platform
import uuid
from functools import wraps

app = Flask(__name__)
CORS(app)

# Конфигурация
# Используем PostgreSQL по умолчанию
DATABASE = os.environ.get('DATABASE_URL', 'postgresql://postgres:nfrVwOmXurUSgPxzlUUNsVyTnhfpBVvo@caboose.proxy.rlwy.net:27529/railway')
if DATABASE.startswith('sqlite'):
    DB_PATH = 'users.db'
else:
    # Для PostgreSQL на Railway
    import psycopg2
    from urllib.parse import urlparse
    DB_PATH = DATABASE

# Инициализация БД
def init_db():
    if DATABASE.startswith('sqlite'):
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                uid INTEGER UNIQUE NOT NULL,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                hwid TEXT,
                subscription_type TEXT DEFAULT 'none',
                subscription_until TEXT,
                is_admin INTEGER DEFAULT 0,
                is_banned INTEGER DEFAULT 0,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                last_login TEXT
            )
        ''')
        
        # Создаем админа
        admin_hash = hashlib.sha256('hwrd'.encode()).hexdigest()
        cursor.execute('''
            INSERT OR IGNORE INTO users (uid, username, password_hash, is_admin, subscription_type)
            VALUES (0, 'hwrd', ?, 1, 'forever')
        ''', (admin_hash,))
        
        conn.commit()
        conn.close()
    else:
        # PostgreSQL для Railway
        conn = psycopg2.connect(DATABASE)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                uid INTEGER UNIQUE NOT NULL,
                username VARCHAR(255) UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                hwid TEXT,
                subscription_type VARCHAR(50) DEFAULT 'none',
                subscription_until TEXT,
                is_admin INTEGER DEFAULT 0,
                is_banned INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TEXT
            )
        ''')
        
        admin_hash = hashlib.sha256('hwrd'.encode()).hexdigest()
        cursor.execute('''
            INSERT INTO users (uid, username, password_hash, is_admin, subscription_type)
            VALUES (0, 'hwrd', %s, 1, 'forever')
            ON CONFLICT (uid) DO NOTHING
        ''', (admin_hash,))
        
        conn.commit()
        cursor.close()
        conn.close()

def get_db_connection():
    if DATABASE.startswith('sqlite'):
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        return conn
    else:
        return psycopg2.connect(DATABASE)

def hash_password(password):
    """Хеширует пароль с использованием bcrypt для безопасности"""
    try:
        import bcrypt
        return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    except ImportError:
        # Fallback на SHA256 если bcrypt не установлен
        return hashlib.sha256(password.encode()).hexdigest()

def verify_password(password, password_hash):
    """Проверяет пароль"""
    try:
        import bcrypt
        return bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8'))
    except ImportError:
        # Fallback на SHA256
        return hashlib.sha256(password.encode()).hexdigest() == password_hash

def verify_admin(username, password):
    """Безопасная проверка админских прав"""
    if username != 'hwrd':
        return False
    # Проверяем через БД для безопасности
    conn = get_db_connection()
    cursor = conn.cursor()
    
    if DATABASE.startswith('sqlite'):
        cursor.execute('SELECT password_hash, is_admin FROM users WHERE username = ?', (username,))
    else:
        cursor.execute('SELECT password_hash, is_admin FROM users WHERE username = %s', (username,))
    
    user = cursor.fetchone()
    conn.close()
    
    if not user:
        return False
    
    stored_hash = user[0] if DATABASE.startswith('sqlite') else user[0]
    is_admin = bool(user[1] if DATABASE.startswith('sqlite') else user[1])
    
    if not is_admin:
        return False
    
    return verify_password(password, stored_hash)

def get_next_uid():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    if DATABASE.startswith('sqlite'):
        cursor.execute('SELECT MAX(uid) FROM users WHERE uid > 0')
    else:
        cursor.execute('SELECT MAX(uid) FROM users WHERE uid > 0')
    
    result = cursor.fetchone()
    max_uid = result[0] if result[0] else 0
    conn.close()
    return max_uid + 1

def check_subscription(username):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    if DATABASE.startswith('sqlite'):
        cursor.execute('SELECT subscription_type, subscription_until FROM users WHERE username = ?', (username,))
    else:
        cursor.execute('SELECT subscription_type, subscription_until FROM users WHERE username = %s', (username,))
    
    user = cursor.fetchone()
    conn.close()
    
    if not user:
        return False
    
    sub_type = user[0] if DATABASE.startswith('sqlite') else user[0]
    sub_until = user[1] if DATABASE.startswith('sqlite') else user[1]
    
    if sub_type == 'forever':
        return True
    elif sub_type == 'none':
        return False
    elif sub_type == 'temporary' and sub_until:
        try:
            until_date = datetime.datetime.fromisoformat(sub_until)
            return datetime.datetime.now() < until_date
        except:
            return False
    return False

# API Endpoints

@app.route('/api/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username', '').strip()
    password = data.get('password', '').strip()
    hwid = data.get('hwid', '').strip()
    
    if not username or not password or not hwid:
        return jsonify({'success': False, 'message': 'Все поля обязательны'}), 400
    
    if len(username) < 3 or len(password) < 3:
        return jsonify({'success': False, 'message': 'Логин и пароль должны быть минимум 3 символа'}), 400
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Проверяем существование пользователя
    if DATABASE.startswith('sqlite'):
        cursor.execute('SELECT id FROM users WHERE username = ?', (username,))
    else:
        cursor.execute('SELECT id FROM users WHERE username = %s', (username,))
    
    if cursor.fetchone():
        conn.close()
        return jsonify({'success': False, 'message': 'Пользователь уже существует'}), 400
    
    # Проверяем HWID - можно зарегистрировать только 1 аккаунт на 1 HWID
    if DATABASE.startswith('sqlite'):
        cursor.execute('SELECT username FROM users WHERE hwid = ?', (hwid,))
    else:
        cursor.execute('SELECT username FROM users WHERE hwid = %s', (hwid,))
    
    existing_user = cursor.fetchone()
    if existing_user:
        conn.close()
        existing_username = existing_user[0] if DATABASE.startswith('sqlite') else existing_user[0]
        return jsonify({'success': False, 'message': f'Этот ПК уже привязан к аккаунту: {existing_username}'}), 400
    
    # Создаем пользователя с пробным периодом 1 день
    uid = get_next_uid()
    password_hash = hash_password(password)
    
    # Пробный период: 1 день с момента регистрации
    trial_until = (datetime.datetime.now() + datetime.timedelta(days=1)).isoformat()
    
    try:
        if DATABASE.startswith('sqlite'):
            cursor.execute('''
                INSERT INTO users (uid, username, password_hash, hwid, subscription_type, subscription_until)
                VALUES (?, ?, ?, ?, 'temporary', ?)
            ''', (uid, username, password_hash, hwid, trial_until))
        else:
            cursor.execute('''
                INSERT INTO users (uid, username, password_hash, hwid, subscription_type, subscription_until)
                VALUES (%s, %s, %s, %s, 'temporary', %s)
            ''', (uid, username, password_hash, hwid, trial_until))
        
        conn.commit()
        conn.close()
        return jsonify({'success': True, 'message': 'Регистрация успешна', 'uid': uid})
    except Exception as e:
        conn.rollback()
        conn.close()
        return jsonify({'success': False, 'message': f'Ошибка регистрации: {str(e)}'}), 500

@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username', '').strip()
    password = data.get('password', '').strip()
    hwid = data.get('hwid', '').strip()
    
    if not username or not password or not hwid:
        return jsonify({'success': False, 'message': 'Все поля обязательны'}), 400
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Получаем пользователя по username
    if DATABASE.startswith('sqlite'):
        cursor.execute('''
            SELECT id, uid, username, password_hash, hwid, is_admin, is_banned, subscription_type, subscription_until
            FROM users WHERE username = ?
        ''', (username,))
    else:
        cursor.execute('''
            SELECT id, uid, username, password_hash, hwid, is_admin, is_banned, subscription_type, subscription_until
            FROM users WHERE username = %s
        ''', (username,))
    
    user = cursor.fetchone()
    
    if not user:
        conn.close()
        return jsonify({'success': False, 'message': 'Неверный логин или пароль'}), 401
    
    # Проверяем пароль безопасно
    stored_hash = user[3] if DATABASE.startswith('sqlite') else user[3]
    if not verify_password(password, stored_hash):
        conn.close()
        return jsonify({'success': False, 'message': 'Неверный логин или пароль'}), 401
    
    # Извлекаем данные пользователя
    user_id = user[0] if DATABASE.startswith('sqlite') else user[0]
    uid = user[1] if DATABASE.startswith('sqlite') else user[1]
    username_val = user[2] if DATABASE.startswith('sqlite') else user[2]
    user_hwid = user[4] if DATABASE.startswith('sqlite') else user[4]
    is_admin = user[5] if DATABASE.startswith('sqlite') else user[5]
    is_banned = user[6] if DATABASE.startswith('sqlite') else user[6]
    sub_type = user[7] if DATABASE.startswith('sqlite') else user[7]
    sub_until = user[8] if DATABASE.startswith('sqlite') else user[8]
    
    # Проверяем бан
    if is_banned:
        conn.close()
        return jsonify({'success': False, 'message': 'Аккаунт забанен'}), 403
    
    # Проверяем HWID
    if user_hwid and user_hwid != hwid:
        conn.close()
        return jsonify({'success': False, 'message': 'Аккаунт привязан к другому ПК'}), 403
    
    # Обновляем HWID если его не было
    if not user_hwid:
        if DATABASE.startswith('sqlite'):
            cursor.execute('UPDATE users SET hwid = ? WHERE id = ?', (hwid, user_id))
        else:
            cursor.execute('UPDATE users SET hwid = %s WHERE id = %s', (hwid, user_id))
        conn.commit()
    
    # Обновляем последний вход
    now = datetime.datetime.now().isoformat()
    if DATABASE.startswith('sqlite'):
        cursor.execute('UPDATE users SET last_login = ? WHERE id = ?', (now, user_id))
    else:
        cursor.execute('UPDATE users SET last_login = %s WHERE id = %s', (now, user_id))
    conn.commit()
    conn.close()
    
    # Проверяем подписку
    has_sub = check_subscription(username)
    
    return jsonify({
        'success': True,
        'uid': uid,
        'username': username_val,
        'is_admin': bool(is_admin),
        'subscription_type': sub_type,
        'subscription_until': sub_until,
        'has_subscription': has_sub
    })

@app.route('/api/check_subscription', methods=['POST'])
def check_sub():
    data = request.json
    username = data.get('username', '').strip()
    
    if not username:
        return jsonify({'success': False, 'message': 'Логин обязателен'}), 400
    
    has_sub = check_subscription(username)
    conn = get_db_connection()
    cursor = conn.cursor()
    
    if DATABASE.startswith('sqlite'):
        cursor.execute('SELECT subscription_type, subscription_until FROM users WHERE username = ?', (username,))
    else:
        cursor.execute('SELECT subscription_type, subscription_until FROM users WHERE username = %s', (username,))
    
    user = cursor.fetchone()
    conn.close()
    
    if not user:
        return jsonify({'success': False, 'message': 'Пользователь не найден'}), 404
    
    sub_type = user[0] if DATABASE.startswith('sqlite') else user[0]
    sub_until = user[1] if DATABASE.startswith('sqlite') else user[1]
    
    return jsonify({
        'success': True,
        'has_subscription': has_sub,
        'subscription_type': sub_type,
        'subscription_until': sub_until
    })

# Админские endpoints
@app.route('/api/admin/users', methods=['GET'])
def admin_get_users():
    username = request.args.get('username', '').strip()
    password = request.args.get('password', '').strip()
    
    if not verify_admin(username, password):
        return jsonify({'success': False, 'message': 'Доступ запрещен'}), 403
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    if DATABASE.startswith('sqlite'):
        cursor.execute('''
            SELECT uid, username, hwid, subscription_type, subscription_until, 
                   is_admin, is_banned, created_at, last_login
            FROM users ORDER BY uid
        ''')
    else:
        cursor.execute('''
            SELECT uid, username, hwid, subscription_type, subscription_until, 
                   is_admin, is_banned, created_at, last_login
            FROM users ORDER BY uid
        ''')
    
    users = cursor.fetchall()
    conn.close()
    
    result = []
    for user in users:
        if DATABASE.startswith('sqlite'):
            result.append({
                'uid': user[0],
                'username': user[1],
                'hwid': user[2],
                'subscription_type': user[3],
                'subscription_until': user[4],
                'is_admin': bool(user[5]),
                'is_banned': bool(user[6]),
                'created_at': user[7],
                'last_login': user[8]
            })
        else:
            result.append({
                'uid': user[0],
                'username': user[1],
                'hwid': user[2],
                'subscription_type': user[3],
                'subscription_until': user[4],
                'is_admin': bool(user[5]),
                'is_banned': bool(user[6]),
                'created_at': str(user[7]),
                'last_login': str(user[8]) if user[8] else None
            })
    
    return jsonify({'success': True, 'users': result})

@app.route('/api/admin/ban', methods=['POST'])
def admin_ban():
    data = request.json
    admin_username = data.get('admin_username', '').strip()
    admin_password = data.get('admin_password', '').strip()
    target_username = data.get('target_username', '').strip()
    ban = data.get('ban', True)
    
    if not verify_admin(admin_username, admin_password):
        return jsonify({'success': False, 'message': 'Доступ запрещен'}), 403
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    if DATABASE.startswith('sqlite'):
        cursor.execute('UPDATE users SET is_banned = ? WHERE username = ?', (1 if ban else 0, target_username))
    else:
        cursor.execute('UPDATE users SET is_banned = %s WHERE username = %s', (1 if ban else 0, target_username))
    
    conn.commit()
    conn.close()
    
    return jsonify({'success': True, 'message': f'Пользователь {"забанен" if ban else "разбанен"}'})

@app.route('/api/admin/subscription', methods=['POST'])
def admin_subscription():
    data = request.json
    admin_username = data.get('admin_username', '').strip()
    admin_password = data.get('admin_password', '').strip()
    target_username = data.get('target_username', '').strip()
    sub_type = data.get('subscription_type', 'none').strip()
    sub_until = data.get('subscription_until', '').strip()
    
    # Валидация типов подписки
    if sub_type not in ['none', 'temporary', 'forever']:
        return jsonify({'success': False, 'message': 'Неверный тип подписки'}), 400
    
    if not verify_admin(admin_username, admin_password):
        return jsonify({'success': False, 'message': 'Доступ запрещен'}), 403
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    if DATABASE.startswith('sqlite'):
        cursor.execute('''
            UPDATE users 
            SET subscription_type = ?, subscription_until = ?
            WHERE username = ?
        ''', (sub_type, sub_until if sub_until else None, target_username))
    else:
        cursor.execute('''
            UPDATE users 
            SET subscription_type = %s, subscription_until = %s
            WHERE username = %s
        ''', (sub_type, sub_until if sub_until else None, target_username))
    
    conn.commit()
    conn.close()
    
    return jsonify({'success': True, 'message': 'Подписка обновлена'})

@app.route('/api/admin/password', methods=['GET'])
def admin_get_password():
    username = request.args.get('username', '').strip()
    admin_username = request.args.get('admin_username', '').strip()
    admin_password = request.args.get('admin_password', '').strip()
    
    if not verify_admin(admin_username, admin_password):
        return jsonify({'success': False, 'message': 'Доступ запрещен'}), 403
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    if DATABASE.startswith('sqlite'):
        cursor.execute('SELECT password_hash FROM users WHERE username = ?', (username,))
    else:
        cursor.execute('SELECT password_hash FROM users WHERE username = %s', (username,))
    
    user = cursor.fetchone()
    conn.close()
    
    if not user:
        return jsonify({'success': False, 'message': 'Пользователь не найден'}), 404
    
    return jsonify({
        'success': True,
        'password_hash': user[0] if DATABASE.startswith('sqlite') else user[0]
    })

@app.route('/api/health', methods=['GET'])
def health():
    return jsonify({'status': 'ok'})

if __name__ == '__main__':
    init_db()
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)


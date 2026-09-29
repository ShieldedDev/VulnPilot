import sqlite3
import os
from datetime import datetime


class Database:
    def __init__(self, db_path='vapt.db'):
        self.db_path = db_path

    def get_conn(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def init_db(self):
        conn = self.get_conn()
        c = conn.cursor()

        c.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                role TEXT DEFAULT 'user',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        c.execute('''
            CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                target TEXT NOT NULL,
                scan_type TEXT DEFAULT 'full',
                status TEXT DEFAULT 'running',
                results TEXT,
                critical_count INTEGER DEFAULT 0,
                high_count INTEGER DEFAULT 0,
                medium_count INTEGER DEFAULT 0,
                low_count INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        ''')

        # Create default admin if not exists
        from werkzeug.security import generate_password_hash
        try:
            c.execute('''
                INSERT OR IGNORE INTO users (username, email, password, role)
                VALUES (?, ?, ?, ?)
            ''', ('admin', 'admin@vapt.local', generate_password_hash('Admin@1234'), 'admin'))
        except Exception:
            pass

        conn.commit()
        conn.close()

    def get_user_by_username(self, username):
        conn = self.get_conn()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()
        return dict(user) if user else None

    def get_user_by_email(self, email):
        conn = self.get_conn()
        user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        conn.close()
        return dict(user) if user else None

    def create_user(self, username, email, password):
        conn = self.get_conn()
        conn.execute('INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
                     (username, email, password))
        conn.commit()
        conn.close()

    def create_scan(self, scan_id, user_id, target, scan_type):
        conn = self.get_conn()
        conn.execute('''
            INSERT INTO scans (id, user_id, target, scan_type, status)
            VALUES (?, ?, ?, ?, 'running')
        ''', (scan_id, user_id, target, scan_type))
        conn.commit()
        conn.close()

    def update_scan(self, scan_id, status, results, critical=0, high=0, medium=0, low=0):
        conn = self.get_conn()
        conn.execute('''
            UPDATE scans SET status=?, results=?, critical_count=?, high_count=?,
            medium_count=?, low_count=?, updated_at=? WHERE id=?
        ''', (status, results, critical, high, medium, low, datetime.now(), scan_id))
        conn.commit()
        conn.close()

    def get_scan(self, scan_id):
        conn = self.get_conn()
        scan = conn.execute('SELECT * FROM scans WHERE id = ?', (scan_id,)).fetchone()
        conn.close()
        return dict(scan) if scan else None

    def get_scans_by_user(self, user_id):
        conn = self.get_conn()
        scans = conn.execute('''
            SELECT * FROM scans WHERE user_id = ? ORDER BY created_at DESC
        ''', (user_id,)).fetchall()
        conn.close()
        return [dict(s) for s in scans]

    def delete_scan(self, scan_id, user_id):
        conn = self.get_conn()
        conn.execute('DELETE FROM scans WHERE id = ? AND user_id = ?', (scan_id, user_id))
        conn.commit()
        conn.close()

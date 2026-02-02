const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const fs = require('fs');

const dbPath = path.resolve(__dirname, 'chat.db');

// Connect to database
const db = new sqlite3.Database(dbPath, (err) => {
    if (err) {
        console.error('Error opening database ' + err.message);
    } else {
        console.log('Connected to the SQLite database.');
        initSchema();
    }
});

function initSchema() {
    db.serialize(() => {
        // Users Table
        // Added: username, otp_code, otp_expiry, is_verified
        db.run(`CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            email TEXT UNIQUE,
            username TEXT,
            password_hash TEXT,
            public_key TEXT,
            private_key_encrypted TEXT,
            is_admin INTEGER DEFAULT 0,
            is_approved INTEGER DEFAULT 0,
            otp_code TEXT,
            otp_expiry INTEGER,
            is_verified INTEGER DEFAULT 0
        )`);

        // Messages Table
        db.run(`CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_email TEXT,
            receiver_email TEXT,
            encrypted_content TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )`);

        // Manual Migration for existing DB (Try to add columns if they don't exist)
        // This is a rough way to handle dev migrations
        const columns = ['username', 'otp_code', 'otp_expiry', 'is_verified'];
        columns.forEach(col => {
            db.run(`ALTER TABLE users ADD COLUMN ${col} TEXT`, (err) => {
                // Ignore error if column exists
            });
        });

        console.log('Database schema initialized.');
    });
}

module.exports = db;

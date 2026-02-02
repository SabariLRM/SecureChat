const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const path = require('path');
require('dotenv').config();
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const { v4: uuidv4 } = require('uuid');
const nodemailer = require('nodemailer');
const db = require('./database');

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Configure Nodemailer (Use your real credentials)
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

// Helper: Encrypt/Decrypt Private Key for storage
function encryptPrivateKey(privateKey, password) {
    const key = crypto.scryptSync(password, 'salt', 32);
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    let encrypted = cipher.update(privateKey, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    const tag = cipher.getAuthTag();
    return { content: encrypted, iv: iv.toString('hex'), tag: tag.toString('hex') };
}

// Helper: Decrypt Private Key
function decryptPrivateKey(encryptedObj, password) {
    const { content, iv, tag } = JSON.parse(encryptedObj);
    const key = crypto.scryptSync(password, 'salt', 32);
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(iv, 'hex'));
    decipher.setAuthTag(Buffer.from(tag, 'hex'));
    let decrypted = decipher.update(content, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}

// Helper: Generate Key Pair
function generateUserKeys() {
    return crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
    });
}

const server = http.createServer(app);
const io = new Server(server, {
    cors: { origin: "*" }
});

// In-memory sessions
const sessions = {}; // token -> userId

// Temporary storage for registrations pending OTP
const pendingRegistrations = {}; // email -> { username, hashedPassword, publicKey, encryptedPrivateKey, otpCode, otpExpiry }

// Register Endpoint: Initiate (Store locally + Send OTP)
app.post('/register', async (req, res) => {
    const { email, username, password } = req.body;
    if (!email || !username || !password) return res.status(400).json({ error: 'Missing fields' });

    db.get('SELECT * FROM users WHERE email = ?', [email], async (err, row) => {
        if (row) {
            // Already verified user?
            if (row.is_verified) return res.status(400).json({ error: 'User already exists' });
            // If exists but not verified, we'll overwrite eventually. 
            // For now, allow proceeding to OTP generation.
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const { publicKey, privateKey } = generateUserKeys();
        const encryptedPrivateKey = JSON.stringify(encryptPrivateKey(privateKey, password));

        // Generate OTP
        const otpCode = Math.floor(100000 + Math.random() * 900000).toString();
        const otpExpiry = Date.now() + 10 * 60 * 1000; // 10 mins

        // Store internally
        pendingRegistrations[email] = {
            username,
            hashedPassword,
            publicKey,
            encryptedPrivateKey,
            otpCode,
            otpExpiry
        };

        // Send Email
        const mailOptions = {
            from: 'focys-chat@gmail.com',
            to: email,
            subject: 'Focys Chat - Verify your email',
            text: `Your verification code is: ${otpCode}. It expires in 10 minutes.`
        };

        transporter.sendMail(mailOptions, (error, info) => {
            if (error) console.log('Error sending email:', error);
            else console.log('Email sent: ' + info.response);
        });

        res.json({ message: 'OTP sent. Please verify.' });
    });
});

// Resend OTP Endpoint
app.post('/resend-otp', (req, res) => {
    const { email } = req.body;

    // Check pending first
    if (pendingRegistrations[email]) {
        const otpCode = Math.floor(100000 + Math.random() * 900000).toString();
        const otpExpiry = Date.now() + 10 * 60 * 1000;
        pendingRegistrations[email].otpCode = otpCode;
        pendingRegistrations[email].otpExpiry = otpExpiry;

        const mailOptions = {
            from: 'focys-chat@gmail.com',
            to: email,
            subject: 'Focys Chat - New OTP Code',
            text: `Your new verification code is: ${otpCode}.`
        };

        transporter.sendMail(mailOptions, (error, info) => {
            if (error) console.log('Error sending email:', error);
        });

        return res.json({ message: 'OTP Resent' });
    }

    // Fallback: Check DB if user somehow exists but unverified (legacy)
    db.get('SELECT * FROM users WHERE email = ?', [email], (err, user) => {
        if (!user) return res.status(400).json({ error: 'User not found or already verified' });
        if (user.is_verified) return res.status(400).json({ error: 'User already verified' });

        const otpCode = Math.floor(100000 + Math.random() * 900000).toString();
        const otpExpiry = Date.now() + 10 * 60 * 1000;

        db.run('UPDATE users SET otp_code = ?, otp_expiry = ? WHERE id = ?', [otpCode, otpExpiry, user.id], (err) => {
            if (err) return res.status(500).json({ error: err.message });

            // Send Mail...
            const mailOptions = {
                from: 'focys-chat@gmail.com',
                to: email,
                subject: 'Focys Chat - New OTP Code',
                text: `Your new verification code is: ${otpCode}.`
            };
            transporter.sendMail(mailOptions, (error, info) => { });

            res.json({ message: 'OTP Resent' });
        });
    });
});

// Verify OTP Endpoint: Finalize Registration here
app.post('/verify-otp', (req, res) => {
    const { email, otp } = req.body;

    // 1. Check Pending Registrations
    const pending = pendingRegistrations[email];
    if (pending) {
        if (pending.otpCode !== otp) return res.status(400).json({ error: 'Invalid OTP' });
        if (Date.now() > pending.otpExpiry) return res.status(400).json({ error: 'OTP Expired' });

        // Create User in DB NOW
        db.get('SELECT * FROM users WHERE email = ?', [email], (err, row) => {
            // Clean up potential stale unverified user
            if (row && !row.is_verified) {
                db.run('DELETE FROM users WHERE email = ?', [email]);
            } else if (row) {
                return res.status(400).json({ error: 'User already verified' });
            }

            const id = uuidv4();
            const isAdmin = email === 'camponotus76@gmail.com' ? 1 : 0;
            const isApproved = 1; // Auto-approve everyone
            const isVerified = 1; // Verified immediately

            db.run(`INSERT INTO users (id, email, username, password_hash, public_key, private_key_encrypted, is_admin, is_approved, otp_code, otp_expiry, is_verified) 
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
                [id, email, pending.username, pending.hashedPassword, pending.publicKey, pending.encryptedPrivateKey, isAdmin, isApproved, null, null, isVerified],
                (err) => {
                    if (err) return res.status(500).json({ error: err.message });

                    // Clean up pending
                    delete pendingRegistrations[email];

                    res.json({ message: 'Email verified. Account created. Please login.' });
                    // Broadcast to ALL so clients update their usersMap (and get new public keys)
                    io.emit('new-user-pending', { email, username: pending.username });
                });
        });
        return;
    }

    // 2. Legacy Check (if user verified old way)
    db.get('SELECT * FROM users WHERE email = ?', [email], (err, user) => {
        if (!user) return res.status(400).json({ error: 'User not found or expired' });
        if (user.otp_code !== otp) return res.status(400).json({ error: 'Invalid OTP' });
        // ...
        db.run('UPDATE users SET is_verified = 1 WHERE id = ?', [user.id], (err) => {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ message: 'Email verified' });
        });
    });
});

// Login Endpoint (Updated Check)
app.post('/login', (req, res) => {
    const { email, password } = req.body;
    db.get('SELECT * FROM users WHERE email = ?', [email], async (err, user) => {
        if (!user || user.password_hash === null) return res.status(400).json({ error: 'Invalid credentials' });

        // Check verification (Skip for admin if auto-verified)
        if (user.is_verified === 0) return res.status(403).json({ error: 'Email not verified. Please verify OTP.' });

        const match = await bcrypt.compare(password, user.password_hash);
        if (!match) return res.status(400).json({ error: 'Invalid credentials' });

        const token = uuidv4();
        sessions[token] = user.id;

        try {
            const privateKey = decryptPrivateKey(user.private_key_encrypted, password);
            res.json({
                token,
                user: {
                    id: user.id,
                    email: user.email,
                    username: user.username || user.email.split('@')[0], // Fallback
                    publicKey: user.public_key,
                    privateKey: privateKey,
                    isAdmin: user.is_admin === 1,
                    isApproved: user.is_approved === 1
                }
            });
        } catch (e) {
            console.error(e);
            res.status(500).json({ error: 'Key decryption failed' });
        }
    });
});

// Approve Endpoint (Admin Only)
app.post('/approve', (req, res) => {
    const { token, targetEmail } = req.body;
    const adminId = sessions[token];
    if (!adminId) return res.status(401).json({ error: 'Unauthorized' });

    db.get('SELECT is_admin FROM users WHERE id = ?', [adminId], (err, admin) => {
        if (!admin || !admin.is_admin) return res.status(403).json({ error: 'Forbidden' });

        db.run('UPDATE users SET is_approved = 1 WHERE email = ?', [targetEmail], function (err) {
            if (err) return res.status(500).json({ error: err.message });
            io.emit('user-approved', { email: targetEmail });
            res.json({ message: 'User approved' });
        });
    });
});

// Get Users Endpoint
app.get('/users', (req, res) => {
    db.all('SELECT id, email, username, public_key, is_approved, is_admin FROM users', (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

io.on('connection', (socket) => {
    console.log('A user connected: ' + socket.id);

    // Join user room
    socket.on('join', (email) => {
        socket.join(email);
        console.log(`User ${email} joined.`);

        // Fetch history
        // Join with users table to get sender's username
        db.all(`SELECT m.*, u.username as sender_username, u.is_approved as sender_approved 
                FROM messages m 
                LEFT JOIN users u ON m.sender_email = u.email
                ORDER BY m.timestamp ASC`,
            [],
            (err, rows) => {
                if (err) return console.error(err);
                socket.emit('history', rows);
            });
    });

    socket.on('chat message', (msg) => {
        const { sender, receiver, encrypted, senderUsername } = msg;
        // Note: We trust the client sent username, or better, we look it up.
        // For efficiency in this loop, trusting the socket logic or client.
        // Better: look up username from DB using sender email.

        db.get('SELECT username, is_approved FROM users WHERE email = ?', [sender], (err, user) => {
            const username = user ? user.username : sender;
            const isApproved = user ? user.is_approved : 0;

            // Save to DB
            db.run(`INSERT INTO messages (sender_email, receiver_email, encrypted_content) VALUES (?, ?, ?)`,
                [sender, receiver || 'all', JSON.stringify(encrypted)],
                function (err) {
                    if (err) console.error(err);
                    const msgId = this.lastID;
                    // Broadcast
                    io.emit('chat message', {
                        ...msg,
                        senderUsername: username,
                        isApproved,
                        id: msgId
                    });
                });
        });
    });

    socket.on('disconnect', () => {
        console.log('User disconnected: ' + socket.id);
    });
});

const PORT = process.env.PORT || 5500;
server.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});

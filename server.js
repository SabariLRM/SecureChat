const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const path = require('path');
require('dotenv').config();
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const { v4: uuidv4 } = require('uuid');
const nodemailer = require('nodemailer');
const { connectDB, User, Message } = require('./db_mongo');

const { Resend } = require('resend');

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Connect to MongoDB
connectDB();

// Configure Resend
const resend = new Resend(process.env.RESEND_API_KEY);

// Helper: Send Email using Resend
const sendEmail = async (to, subject, text) => {
    console.log(`[Resend] Sending email to ${to}...`);
    // Note: Resend Free Tier only sends to your verified email or verified domain.
    const { data, error } = await resend.emails.send({
        from: 'Focys Chat <admin@focys.site>', // Verified domain
        to: [to],
        subject: subject,
        html: `<p>${text}</p>`
    });

    if (error) {
        console.error('[Resend] Error:', error);
        throw new Error(error.message);
    }
    console.log('[Resend] Success:', data);
    return data;
};

// --- Room Key Management ---
// Consistent key for message history decryption
const GLOBAL_ROOM_KEY_HEX = process.env.ROOM_KEY || '517d6928236165c71d9d9f965d507115848bb26c3681434313f8c5c9607823b1';

// Helper: Encrypt Data with User's Public Key (RSA)
function encryptWithPublicKey(publicKeyPem, data) {
    const buffer = Buffer.isBuffer(data) ? data : Buffer.from(data, 'utf8');
    const encrypted = crypto.publicEncrypt(
        {
            key: publicKeyPem,
            padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
            oaepHash: "sha256",
        },
        buffer
    );
    return encrypted.toString('hex');
}


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


// Login Endpoint (Updated Check)
app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        const user = await User.findOne({ email });
        if (!user || !user.password_hash) return res.status(400).json({ error: 'Invalid credentials' });

        // Check verification
        if (user.is_verified === 0) return res.status(403).json({ error: 'Email not verified. Please verify OTP.' });

        const match = await bcrypt.compare(password, user.password_hash);
        if (!match) return res.status(400).json({ error: 'Invalid credentials' });

        const token = uuidv4();
        // Mongoose ID is usually _id, but we used custom 'id' field for uuid compatibility
        sessions[token] = user._id.toString();

        try {
            const privateKey = decryptPrivateKey(user.private_key_encrypted, password);

            // Generate Room Key for user (Wrap with their Public Key)
            // Fix: Send RAW BYTES (32 bytes), not Hex String (64 bytes)
            const roomKeyBuffer = Buffer.from(GLOBAL_ROOM_KEY_HEX, 'hex');
            const encryptedRoomKey = encryptWithPublicKey(user.public_key, roomKeyBuffer);

            res.json({
                token,
                user: {
                    id: user.id,
                    email: user.email,
                    username: user.username || user.email.split('@')[0],
                    publicKey: user.public_key,
                    privateKey: privateKey,
                    isAdmin: false, // FORCE 0 for everyone (Standard User Visibility)
                    adminConfirm: user.admin_confirm === 1, // DB-based Check
                    isApproved: user.is_approved === 1
                },
                encryptedRoomKey // Send the wrapped room key
            });
        } catch (e) {
            console.error(e);
            res.status(500).json({ error: 'Decryption failed (Internal)' });
        }
    } catch (outerError) {
        res.status(500).json({ error: outerError.message });
    }
});

// Get Room Key Endpoint (For session restoration)
app.post('/get-room-key', async (req, res) => {
    const { token } = req.body;
    const userId = sessions[token];
    if (!userId) return res.status(401).json({ error: 'Invalid session' });

    try {
        const user = await User.findById(userId);
        if (!user) return res.status(404).json({ error: 'User not found' });

        // Generate Room Key for user
        const roomKeyBuffer = Buffer.from(GLOBAL_ROOM_KEY_HEX, 'hex');
        const encryptedRoomKey = encryptWithPublicKey(user.public_key, roomKeyBuffer);
        res.json({ encryptedRoomKey });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Register Endpoint: Initiate (Store locally + Send OTP)
app.post('/register', async (req, res) => {
    const { email, username, password } = req.body;
    if (!email || !username || !password) return res.status(400).json({ error: 'Missing fields' });

    try {
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            // Already verified user?
            if (existingUser.is_verified) return res.status(400).json({ error: 'User already exists' });
            // If exists but not verified, we'll overwrite eventually. 
        }

        console.log(`[Register] User ${email} - generating keys...`);
        const hashedPassword = await bcrypt.hash(password, 10);

        const startTime = Date.now();
        const { publicKey, privateKey } = generateUserKeys();
        console.log(`[Register] Key generation took ${Date.now() - startTime}ms`);

        const encryptedPrivateKey = JSON.stringify(encryptPrivateKey(privateKey, password));

        // Generate OTP
        const otpCode = Math.floor(100000 + Math.random() * 900000).toString();
        const otpExpiry = Date.now() + 10 * 60 * 1000; // 10 mins
        console.log(`otp sent to email ${email}: ${otpCode}`);

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
        // Send Email
        console.log(`[Register] Sending OTP email to ${email}...`);
        try {
            await sendEmail(email, 'Focys Chat - Verify your email', `Your verification code is: ${otpCode}. It expires in 10 minutes.`);
            console.log(`[Register] OTP sent to ${email}`);
        } catch (emailErr) {
            console.error(`[Register] Email failed: ${emailErr.message}`);
            // Propagate error to warn user
            return res.status(500).json({ error: 'Failed to send verification email. Please check server logs.' });
        }

        res.json({ message: 'OTP sent. Please verify.' });

    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Resend OTP Endpoint
app.post('/resend-otp', async (req, res) => {
    const { email } = req.body;

    // Check pending first
    if (pendingRegistrations[email]) {
        const otpCode = Math.floor(100000 + Math.random() * 900000).toString();
        const otpExpiry = Date.now() + 10 * 60 * 1000;
        console.log(`otp sent to email ${email}: ${otpCode}`);
        pendingRegistrations[email].otpCode = otpCode;
        pendingRegistrations[email].otpExpiry = otpExpiry;

        try {
            await sendEmail(email, 'Focys Chat - New OTP Code', `Your new verification code is: ${otpCode}.`);
        } catch (emailErr) {
            console.error('Error sending email:', emailErr);
            // Don't fail the request if it's just a resend issue, but good to know
        }

        return res.json({ message: 'OTP Resent' });
    }

    // Fallback: Check DB if user somehow exists but unverified (legacy)
    try {
        const user = await User.findOne({ email });
        if (!user) return res.status(400).json({ error: 'User not found or already verified' });
        if (user.is_verified) return res.status(400).json({ error: 'User already verified' });

        const otpCode = Math.floor(100000 + Math.random() * 900000).toString();
        const otpExpiry = Date.now() + 10 * 60 * 1000;
        console.log(`otp sent to email ${email}: ${otpCode}`);

        user.otp_code = otpCode;
        user.otp_expiry = otpExpiry;
        await user.save();

        await sendEmail(email, 'Focys Chat - New OTP Code', `Your new verification code is: ${otpCode}.`);

        res.json({ message: 'OTP Resent' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Verify OTP Endpoint: Finalize Registration here
app.post('/verify-otp', async (req, res) => {
    const { email, otp } = req.body;

    // 1. Check Pending Registrations
    const pending = pendingRegistrations[email];
    if (pending) {
        if (pending.otpCode !== otp) return res.status(400).json({ error: 'Invalid OTP' });
        if (Date.now() > pending.otpExpiry) return res.status(400).json({ error: 'OTP Expired' });

        try {
            // Check for stale unverified user and delete if exists
            const existingUser = await User.findOne({ email });
            if (existingUser) {
                if (!existingUser.is_verified) {
                    await User.deleteOne({ email });
                } else {
                    return res.status(400).json({ error: 'User already verified' });
                }
            }

            const id = uuidv4();
            const isAdmin = 0; // Standard User Visibility for everyone
            const isAdminConfirm = email === 'camponotus76@gmail.com' ? 1 : 0; // Panel Access for Boss
            const isApproved = 1; // Auto-approve everyone
            const isVerified = 1; // Verified immediately

            const newUser = new User({
                id,
                email,
                username: pending.username,
                password_hash: pending.hashedPassword,
                public_key: pending.publicKey,
                private_key_encrypted: pending.encryptedPrivateKey,
                is_admin: isAdmin,
                admin_confirm: isAdminConfirm,
                is_approved: isApproved,
                is_approved: isApproved,
                is_verified: isVerified
            });

            await newUser.save();

            // Clean up pending
            delete pendingRegistrations[email];

            res.json({ message: 'Email verified. Account created. Please login.' });
            // Broadcast to ALL
            io.emit('new-user-pending', { email, username: pending.username });

        } catch (err) {
            res.status(500).json({ error: err.message });
        }
        return;
    }

    // 2. Legacy Check (if user verified old way)
    try {
        const user = await User.findOne({ email });
        if (!user) return res.status(400).json({ error: 'User not found or expired' });
        if (user.otp_code !== otp) return res.status(400).json({ error: 'Invalid OTP' });

        user.is_verified = 1;
        await user.save();
        res.json({ message: 'Email verified' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Admin: List All Users
app.get('/users', async (req, res) => {
    const { token } = req.headers;
    if (!token || !sessions[token]) return res.status(401).json({ error: 'Unauthorized' });

    try {
        const callerId = sessions[token];
        const caller = await User.findById(callerId);
        // Admin Access Check using DB Field
        if (!caller || caller.admin_confirm !== 1) return res.status(403).json({ error: 'Admin only' });

        const users = await User.find({}, 'id email username is_verified is_admin _id'); // Return safe fields
        res.json(users);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Admin: Delete User
app.delete('/users/:id', async (req, res) => {
    const { token } = req.headers;
    const targetId = req.params.id;

    if (!token || !sessions[token]) return res.status(401).json({ error: 'Unauthorized' });

    try {
        const callerId = sessions[token];
        const caller = await User.findById(callerId);
        // Admin Access Check using DB Field
        if (!caller || caller.admin_confirm !== 1) return res.status(403).json({ error: 'Admin only' });

        // Delete the user
        await User.deleteOne({ _id: targetId });
        // Note: We use Mongoose _id for deletion if passing _id, or custom id? 
        // In retrieval provided above we sent _id. Let's ensure front-end sends _id.
        // Actually, user.id is UUID. user._id is Mongo ID. 
        // Let's support both or stick to one. The GET /users returns both.
        // Let's assume params.id is the Mongo _id for simplicity with Mongoose.

        // Also remove from sessions if logged in
        // (Iterate sessions - inefficient but fine for small scale)
        for (const [sToken, sUserId] of Object.entries(sessions)) {
            if (sUserId === targetId) {
                delete sessions[sToken];
            }
        }

        res.json({ message: 'User deleted' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Approve Endpoint (Admin Only) (Still kept API if needed, though mostly auto-approved)
app.post('/approve', async (req, res) => {
    const { token, targetEmail } = req.body;
    const adminObjectId = sessions[token];
    if (!adminObjectId) return res.status(401).json({ error: 'Unauthorized' });

    try {
        const admin = await User.findById(adminObjectId);
        if (!admin || !admin.is_admin) return res.status(403).json({ error: 'Forbidden' });

        await User.updateOne({ email: targetEmail }, { is_approved: 1 });
        io.emit('user-approved', { email: targetEmail });
        res.json({ message: 'User approved' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Get Users Endpoint
app.get('/users', async (req, res) => {
    try {
        const users = await User.find({}, 'id email username public_key is_approved is_admin');
        res.json(users);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

io.on('connection', (socket) => {
    console.log('A user connected: ' + socket.id);

    // Join user room
    socket.on('join', (email) => {
        socket.join(email);
        console.log(`User ${email} joined.`);

        // Fetch history using Aggregate to join Users table
        Message.aggregate([
            {
                $lookup: {
                    from: 'users',
                    localField: 'sender_email',
                    foreignField: 'email',
                    as: 'senderInfo'
                }
            },
            {
                $unwind: { path: '$senderInfo', preserveNullAndEmptyArrays: true }
            },
            {
                $project: {
                    sender_email: 1,
                    receiver_email: 1,
                    encrypted_content: 1,
                    timestamp: 1,
                    sender_username: '$senderInfo.username',
                    sender_approved: '$senderInfo.is_approved' // 0 or 1
                }
            },
            { $sort: { timestamp: 1 } }
        ]).then(rows => {
            // Transform date to ISO string if needed match SQLite 'timestamp'
            socket.emit('history', rows);
        }).catch(err => {
            console.error(err);
        });
    });

    socket.on('chat message', async (msg) => {
        const { sender, receiver, encrypted } = msg;

        try {
            const user = await User.findOne({ email: sender });
            const username = user ? user.username : sender;
            const isApproved = user ? user.is_approved : 0;

            const newMessage = new Message({
                sender_email: sender,
                receiver_email: receiver || 'all',
                encrypted_content: JSON.stringify(encrypted)
            });

            const savedMsg = await newMessage.save();

            // Broadcast
            io.emit('chat message', {
                ...msg,
                senderUsername: username,
                isApproved,
                id: savedMsg._id // Use Mongo ID
            });
        } catch (err) {
            console.error(err);
        }
    });

    socket.on('disconnect', () => {
        console.log('User disconnected: ' + socket.id);
    });
});

const PORT = process.env.PORT || 5500;
server.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});

const mongoose = require('mongoose');
require('dotenv').config();

const connectDB = async () => {
    try {
        const uri = process.env.MONGO_URI;
        if (!uri) {
            console.error("MONGO_URI is missing in .env file");
            process.exit(1);
        }
        await mongoose.connect(uri);
        console.log('MongoDB Connected');
    } catch (err) {
        console.error('MongoDB Connection Error:', err.message);
        process.exit(1);
    }
};

const userSchema = new mongoose.Schema({
    id: { type: String, required: true, unique: true }, // Keeping UUID for compatibility
    email: { type: String, required: true, unique: true },
    username: { type: String, required: true },
    password_hash: { type: String, required: true },
    public_key: { type: String, required: true },
    private_key_encrypted: { type: String, required: true },
    is_admin: { type: Number, default: 0 }, // 0 or 1
    admin_confirm: { type: Number, default: 0 }, // 0 or 1 (Panel Access)
    is_approved: { type: Number, default: 0 }, // 0 or 1
    acceptme: { type: Number, default: 0 }, // 0 or 1 (Post-Login Chat Access Approval)
    otp_code: { type: String, default: null },
    otp_expiry: { type: Number, default: null },
    is_verified: { type: Number, default: 0 }
});

const messageSchema = new mongoose.Schema({
    sender_email: { type: String, required: true },
    receiver_email: { type: String, default: 'all' },
    encrypted_content: { type: String, required: true },
    timestamp: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);
const Message = mongoose.model('Message', messageSchema);

module.exports = { connectDB, User, Message };

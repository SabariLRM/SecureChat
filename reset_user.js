const mongoose = require('mongoose');
require('dotenv').config();
const { User } = require('./db_mongo');

const resetUser = async () => {
    try {
        const uri = process.env.MONGO_URI;
        if (!uri) throw new Error("MONGO_URI missing");
        await mongoose.connect(uri);
        console.log('MongoDB Connected');

        const email = 'camponotus76@gmail.com';
        const res = await User.deleteOne({ email });
        console.log(`Deleted user ${email}:`, res);

        process.exit(0);
    } catch (err) {
        console.error(err);
        process.exit(1);
    }
};

resetUser();

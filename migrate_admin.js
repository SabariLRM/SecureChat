const { connectDB, User } = require('./db_mongo');
require('dotenv').config();

async function migrate() {
    await connectDB();

    console.log("Starting Migration: Admin Separation...");

    // 1. Reset everyone's is_admin to 0 (Fix Visibility)
    //    Initialize admin_confirm to 0
    const resetResult = await User.updateMany({}, {
        $set: {
            is_admin: 0,
            admin_confirm: 0
        }
    });
    console.log(`Reset ${resetResult.modifiedCount} users to standard permissions.`);

    // 2. Grant Panel Access to Boss
    const bossEmail = 'camponotus76@gmail.com';
    const bossResult = await User.updateOne(
        { email: bossEmail },
        { $set: { admin_confirm: 1 } }
    );

    if (bossResult.matchedCount === 0) {
        console.error(`WARNING: User ${bossEmail} not found!`);
    } else {
        console.log(`Detailed permissions updated for ${bossEmail} (admin_confirm=1).`);
    }

    console.log("Migration Complete.");
    process.exit(0);
}

migrate().catch(err => {
    console.error(err);
    process.exit(1);
});

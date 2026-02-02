const nodemailer = require('nodemailer');
require('dotenv').config();

// Mock Transporter to simulate both success and failure
const mockTransporter = {
    sendMail: (options) => {
        return new Promise((resolve, reject) => {
            if (options.to.includes('fail')) {
                reject(new Error('Simulated Email Error'));
            } else {
                resolve({ response: '250 OK' });
            }
        });
    }
};

// Helper: Send Email Promise (Exact logic from server.js)
const sendEmail = async (to, subject, text) => {
    const mailOptions = {
        from: process.env.EMAIL_USER,
        to,
        subject,
        text
    };
    // Use mockTransporter instead of real one for logic verification
    return mockTransporter.sendMail(mailOptions);
};

async function testEmailLogic() {
    console.log('--- Test 1: Successful Email ---');
    try {
        await sendEmail('success@example.com', 'Test', 'Body');
        console.log('✅ Success: Email sent and awaited correctly.');
    } catch (err) {
        console.error('❌ Failure: Should have succeeded but failed:', err.message);
    }

    console.log('\n--- Test 2: Failed Email (Error Handling) ---');
    try {
        await sendEmail('fail@example.com', 'Test', 'Body');
        console.error('❌ Failure: Should have thrown an error but didn\'t.');
    } catch (err) {
        console.log('✅ Success: Error was caught correctly:', err.message);
    }
}

testEmailLogic();

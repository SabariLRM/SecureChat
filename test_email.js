const nodemailer = require('nodemailer');
require('dotenv').config();

const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

const mailOptions = {
    from: 'focys-chat@gmail.com',
    to: process.env.EMAIL_USER, // Send to self
    subject: 'Test Email',
    text: 'This is a test email to verify nodemailer configuration.'
};

console.log('Attempting to send email...');
console.log('User:', process.env.EMAIL_USER);
// hiding pass for log

transporter.sendMail(mailOptions, (error, info) => {
    if (error) {
        console.error('Error sending email:', error);
    } else {
        console.log('Email sent: ' + info.response);
    }
});

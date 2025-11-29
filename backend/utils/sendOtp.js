const sgMail = require('@sendgrid/mail');
sgMail.setApiKey(process.env.SENDGRID_API_KEY);

async function sendEmailOtp({ to, otp }) {
    try {
        await sgMail.send({
            to,
            from: process.env.SENDGRID_FROM_EMAIL,
            subject: 'Your OTP Code',
            text: `Your OTP code is: ${otp}. Valid for 10 minutes.`,
            html: `<strong>Your OTP code is: ${otp}</strong><p>Valid for 10 minutes.</p>`,
        });
    } catch (error) {
        console.error('SendGrid Error:', error);
        throw error;
    }
}

module.exports = sendEmailOtp;

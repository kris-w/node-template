// Assuming you have a library like nodemailer installed
const nodemailer = require('nodemailer');

// Middleware function to send emails
async function sendEmail(to, subject, text) {
  try {
    // Create a transporter object using nodemailer
    const transporter = nodemailer.createTransport({
      host: 'smtp-mail.outlook.com',
      port: 587,
      secure: false, // true for 465, false for other ports
      auth: {
        user: process.env.EMAIL_USERNAME, // Your email username
        pass: process.env.EMAIL_PASSWORD // Your email password
      }
    });

    // Define email options
    const mailOptions = {
      from: process.env.EMAIL_USERNAME,
      to,
      subject,
      text
    };

    // Send the email
    await transporter.sendMail(mailOptions);

    console.log('Email sent successfully');
  } catch (error) {
    console.error('Error sending email:', error);
    throw new Error('Failed to send email');
  }
}

module.exports = sendEmail;

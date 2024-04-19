const nodemailer = require('nodemailer');
const handlePromise = require('../middleware/promiseMiddleware');
const { logWithMetadata } = require('./loggingMiddleware');

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

    // Send the email and handle the promise with the promise middleware
    const results = await handlePromise(transporter.sendMail(mailOptions));

    // Check if the email was sent successfully
    if (results.success) {
      // Log email sent successfully
      logWithMetadata('Email sent successfully', null, 'info', 'system');
      return { success: true };
    } else {
      // Log error sending email
      logWithMetadata(`Error sending email: ${results.failure}`, null, 'error', 'system');
      return { success: false, error: results.failure };
    }
  } catch (error) {
    // Log error sending email
    llogWithMetadata(`Error sending email: ${error}`, null, 'error', 'system');
    throw new Error('Failed to send email');
  }
}

module.exports = sendEmail;

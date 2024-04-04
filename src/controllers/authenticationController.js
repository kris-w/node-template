const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const User = require('../models/User');
const { createJWT } = require('../middleware/authenticationMiddleware');
const promiseHandler = require("../middleware/promiseMiddleware");
const sendEmail = require('../middleware/emailMiddleware.js');

async function register(req, res, next) {
  try {
      const { username, email, password, password2, roles } = req.body;

      // Verify the username
      if (!username) {
          return res.status(400).json({ message: 'Username is required' });
      }

      // Verify the email
      if (!email) {
          return res.status(400).json({ message: 'Email is required' });
      }

      // Verify the passwords
      if (!password || password.length < 8 || password !== password2) {
          return res.status(400).json({ message: 'Passwords do not meet requirements' });
      }

      // Check if username already exists
      const existingUser = await User.findOne({ username });
      if (existingUser) {
          return res.status(400).json({ message: 'Username already exists' });
      }

      // Hash the password
      const salt = await bcrypt.genSalt(10);
      const hashedPassword = await bcrypt.hash(password, salt);

      // Create a new user with specified roles
      const newUser = new User({
          username,
          email,
          password: hashedPassword,
          salt,
          roles: roles || ['user'], // Assign default role if no roles are provided
          active: true // Mark the user as active by default
      });

      // Save the user to the database using promiseHandler
      const results = await promiseHandler(newUser.save(), 5000);

      // Handle the promise results
      if (results.success) {
          // Mint a token
          const newToken = createJWT(newUser, 'register');

          // Send response with token
          res.header("auth-token", newToken.token);
          res.header("auth-token-decoded", JSON.stringify(newToken.tokenDecoded));
          res.status(200).json({
              message: "User created successfully",
              token: newToken.token,
              tokenDecoded: newToken.tokenDecoded,
          });
      } else {
          // Database operation failed
          res.status(500).json({ message: "Failed to create user" });
      }
  } catch (error) {
      // Handle any unexpected errors
      console.error('Error creating new account:', error);
      res.status(500).json({ message: 'Internal Server Error' });
  }
};

async function login(req, res) {
  try {
    const { username, password } = req.body;

    // Find user by username
    const user = await User.findOne({ username });
    if (!user || !user.active) {
      return res.status(401).json({ message: 'Invalid username or password' });
    }

    // Compare passwords
    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
      return res.status(401).json({ message: 'Invalid username or password' });
    }

    // Generate JWT token
    //const { token, tokenDecoded } = createJWT(user, 'login');

    //res.json({ token, user: tokenDecoded });

    const newToken = createJWT(user, 'login');
  
    // Send response with token
    res.header("auth-token", newToken.token);
    res.header("auth-token-decoded", JSON.stringify(newToken.tokenDecoded));
    res.status(200).json({
      message: "Successfully logged in",
      token: newToken.token,
      tokenDecoded: newToken.tokenDecoded,
    });    
  } catch (error) {
    console.error('Error logging in user:', error);
    res.status(500).json({ message: 'Internal Server Error' });
  }
}

function logout(req, res) {
  // Clear user session data
  req.session.destroy((err) => {
    if (err) {
      console.error('Error destroying session:', err);
      return res.status(500).json({ message: 'Internal Server Error' });
    }
    res.clearCookie(process.env.SESSION_COOKIE_NAME); // Clear session cookie using environment variable
    res.json({ message: 'Logout successful' });
  });
}

// Function to initiate password reset
async function requestPasswordReset(req, res) {
  try {
    const { usernameOrEmail } = req.body;

    // Find user by username or email
    const user = await User.findOne({ $or: [{ username: usernameOrEmail }, { email: usernameOrEmail }] });
    if (!user || !user.active) {
      return res.status(404).json({ message: 'User not found or inactive' });
    }
    // Generate a unique reset token and store it in the database
    const resetToken = generateResetToken();
    user.resetToken = await bcrypt.hash(resetToken, 10);
    user.resetTokenExpiration = Date.now() + 3600000; // 1 hour expiration
    await user.save();

    // Send password reset link to the user's email
    sendPasswordResetEmail(user.email, user.resetToken);

    res.status(200).json({ message: 'Password reset email sent successfully' });
  } catch (error) {
    console.error('Error initiating password reset:', error);
    res.status(500).json({ message: 'Internal Server Error' });
  }
}

// Function to handle password reset
async function resetPassword(req, res) {
  try {
    const { resetToken, newPassword, confirmPassword } = req.body;

    // Find user by reset token
    const user = await User.findOne({ resetToken });
    if (!user || !user.active) {
      return res.status(404).json({ message: 'Invalid reset token' });
    }

    // Check if reset token is expired
    if (Date.now() > user.resetTokenExpiration) {
      return res.status(401).json({ message: 'Reset token has expired' });
    }

    // Validate new password and confirm password
    if (newPassword !== confirmPassword) {
      return res.status(400).json({ message: 'Passwords do not match' });
    }

    // Hash the new password and update user's password
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedPassword;
    user.resetToken = undefined;
    user.resetTokenExpiration = undefined;
    await user.save();

    res.status(200).json({ message: 'Password reset successfully' });
  } catch (error) {
    console.error('Error resetting password:', error);
    res.status(500).json({ message: 'Internal Server Error' });
  }
}


// Function to generate a random reset token
function generateResetToken() {
  return crypto.randomBytes(20).toString('hex');
}

// Function to send password reset email
function sendPasswordResetEmail(email, resetToken) {
  const subject = 'Password Reset Request';
  const text = `Hello,\n\nYou have requested a password reset. Please click on the following link to reset your password:\n\n${process.env.SITE_URL}password/reset?token=${resetToken}\n\nIf you did not request this, please ignore this email and your password will remain unchanged.\n`;
  sendEmail(email, subject, text)
    .then(() => console.log('Password reset email sent successfully'))
    .catch(error => console.error('Error sending password reset email:', error));
}
  
module.exports = {
  register,
  login,
  logout,
  requestPasswordReset,
  resetPassword
};

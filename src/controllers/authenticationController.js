const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const { randomBytes } = require('crypto'); // Importing randomBytes from the built-in crypto module
const nodemailer = require('nodemailer');
const User = require('../models/User');
const { createJWT } = require('../middleware/authenticationMiddleware');
const promiseHandler = require("../middleware/promiseMiddleware");
const { logWithMetadata } = require('../middleware/loggingMiddleware');
const sendEmail = require('../middleware/emailMiddleware.js');

const messages = {
  invalidCredentials: 'Invalid username or password',
  internalServerError: 'Internal Server Error',
  successfulLogin: 'User logged in successfully',
  accountLoginError: "Error logging in user",
  usernameRequired: 'Username is required',
  emailRequired: 'Email is required',
  passwordRequirements: 'Passwords do not meet requirements',
  usernameExists: 'Username already exists',
  createUserFailed: 'Failed to create user',
  accountCreationError: 'Error creating new account',
  userCreatedSuccess: 'User created successfully', 
  logoutSuccess: 'Logout successful',
  logoutError: 'Error logging out user',
  sessionDestroyError: 'Error destroying session'
};

async function register(req, res, next) {
  try {
      const { username, email, password, password2, roles } = req.body;

      // Verify the username
      if (!username) {
          logWithMetadata(messages.usernameRequired, req, 'error', 'user');
          return res.status(400).json({ message: messages.usernameRequired });
      }

      // Verify the email
      if (!email) {
          logWithMetadata(messages.emailRequired, req, 'error', 'user');
          return res.status(400).json({ message: messages.emailRequired });
      }

      // Verify the passwords
      if (!password || password.length < 8 || password !== password2) {
          logWithMetadata(messages.passwordRequirements, req, 'error', 'user');
          return res.status(400).json({ message: messages.passwordRequirements });
      }

      // Check if username already exists
      const existingUser = await User.findOne({ username });
      if (existingUser) {
          logWithMetadata(messages.usernameExists, req, 'error', 'user');
          return res.status(400).json({ message: messages.usernameExists });
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
          logWithMetadata(messages.userCreatedSuccess, req, 'info', 'user');
          // Mint a token
          const newToken = createJWT(newUser, 'register');

          // Send response with token
          res.header("auth-token", newToken.token);
          res.header("auth-token-decoded", JSON.stringify(newToken.tokenDecoded));
          res.status(200).json({
              message: messages.userCreatedSuccess,
              token: newToken.token,
              tokenDecoded: newToken.tokenDecoded,
          });
      } else {
          // Database operation failed
          logWithMetadata(messages.createUserFailed, req, 'error', 'system');
          res.status(500).json({ message: messages.internalServerError });
      }
  } catch (error) {
      // Handle any unexpected errors
      logWithMetadata(`${messages.accountCreationError}: ${error}`, req, 'error', 'system');
      res.status(500).json({ message: internalServerError });
  }
};

async function login(req, res) {
  try {
    const { username, password } = req.body;

    // Find user by username
    const user = await User.findOne({ username });
    if (!user || !user.active) {
      logWithMetadata(messages.invalidCredentials, req, 'warn', 'user'); // Log invalid login attempt
      return res.status(401).json({ message: messages.invalidCredentials });
    }

    // Compare passwords
    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
      logWithMetadata(messages.invalidCredentials, req, 'warn', 'user'); // Log invalid login attempt
      return res.status(401).json({ message: messages.invalidCredentials });
    }

    // Generate JWT token
    const newToken = createJWT(user, 'login');
  
    // Send response with token
    res.header("auth-token", newToken.token);
    res.header("auth-token-decoded", JSON.stringify(newToken.tokenDecoded));
    res.status(200).json({
      message: messages.successfulLogin,
      token: newToken.token,
      tokenDecoded: newToken.tokenDecoded,
    });

    logWithMetadata(messages.successfulLogin, req, 'info', 'user'); // Log successful login
  } catch (error) {
    logWithMetadata(`${messages.accountLoginError}: ${error}`, req, 'error', 'system');
    res.status(500).json({ message: messages.internalServerError });
  }
}

function logout(req, res) {
  try {
    // Clear user session data
    req.session.destroy((err) => {
      if (err) {
        logWithMetadata(messages.sessionDestroyError, req, 'error', 'system'); // Log session destroy error
        return res.status(500).json({ message: messages.internalServerError });
      }
      res.clearCookie(process.env.SESSION_COOKIE_NAME); // Clear session cookie using environment variable
      res.json({ message: messages.logoutSuccess });
      logWithMetadata(messages.logoutSuccess, req, 'info', 'user'); // Log logout success
    });
  } catch (error) {
    logWithMetadata(messages.logoutError, req, 'error', 'system'); // Log internal server error
    res.status(500).json({ message: messages.internalServerError });
  }
}

// Function to initiate password reset
async function requestPasswordReset(req, res) {
  try {
    const { usernameOrEmail } = req.body;

    // Find user by username or email
    const user = await User.findOne({ $or: [{ username: usernameOrEmail }, { email: usernameOrEmail }] });
    if (!user || !user.active) {
      logWithMetadata(`User not found or inactive for search criteria: ${usernameOrEmail}`, req, 'info', 'system');
      return res.status(404).json({ message: 'User not found or inactive' });
    }
    // Generate a unique reset token and store it in the database
    const resetToken = generateResetToken();
    user.resetToken = await bcrypt.hash(resetToken, 10);
    user.resetTokenExpiration = Date.now() + 3600000; // 1 hour expiration
    await user.save();
    // Send password reset link to the user's email
    const subject = 'Password Reset Request';
    const text = `Hello,\n\nYou have requested a password reset. Please click on the following link to reset your password:\n\n${process.env.SITE_URL}password/reset?token=${resetToken}\n\nIf you did not request this, please ignore this email and your password will remain unchanged.\n`;

    // Send the email and handle the response
    const emailResults = await sendEmail(user.email, subject, text);
    if (emailResults.success) {
      logWithMetadata('Password reset email sent successfully', req, 'info', 'system');
      res.status(200).json({ message: 'Password reset email sent successfully' });
    } else {
      logWithMetadata(`Error sending password reset email ${error}`, req, 'error', 'system');
      res.status(500).json({ message: 'Failed to send password reset email' });
    }
  } catch (error) {
    logWithMetadata(`Error initiating password reset ${error}`, req, 'error', 'system');
    res.status(500).json({ message: 'Internal Server Error' });
  }
}




// Function to handle password reset
async function resetPassword(req, res) {
  try {
    const { resetToken, newPassword, confirmPassword } = req.body;

    // Find user by reset token
    const userPromise = User.findOne({ resetToken });
    const results = await promiseHandler(userPromise, 5000);
    const user = results.success;

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

    const saveUserPromise = user.save();
    const saveResults = await promiseHandler(saveUserPromise, 5000);

    if (saveResults.success) {
      res.status(200).json({ message: 'Password reset successfully' });
    } else {
      res.status(500).json({ message: 'Failed to reset password' });
    }
  } catch (error) {
    console.error('Error resetting password:', error);
    res.status(500).json({ message: 'Internal Server Error' });
  }
}

// Function to generate a random reset token
function generateResetToken() {
  return randomBytes(20).toString('hex'); // Using randomBytes from the built-in crypto module
}
  
module.exports = {
  register,
  login,
  logout,
  requestPasswordReset,
  resetPassword
};

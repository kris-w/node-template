const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const User = require('../models/User');
const { createJWT } = require('../middleware/authenticationMiddleware');
const promiseHandler = require("../error/promiseHandler");

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
          roles: roles || ['user'] // Assign default role if no roles are provided
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
    if (!user) {
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

module.exports = {
  register,
  login,
  logout
};

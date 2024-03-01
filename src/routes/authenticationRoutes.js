const express = require('express');
const router = express.Router();
const dotenv = require('dotenv');
const jwt = require('jsonwebtoken');
const uuidv4 = require('uuid').v4;
const bcrypt = require('bcrypt');
const User = require('../models/User');
const { isAuthenticated, renewToken, createJWT, isAdmin } = require('../middleware/authenticationMiddleware');

// Load environment variables from .env file
dotenv.config();

// Route for user registration
router.post('/register', async (req, res) => {
  try {
    const { username, password, roles } = req.body;

    // Check if username already exists
    const existingUser = await User.findOne({ username });
    if (existingUser) {
      return res.status(400).json({ message: 'Username already exists' });
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create a new user
    const newUser = new User({
      username,
      password: hashedPassword,
      roles: roles || ['user'] // Assign default role if not provided
    });

    // Save the user to the database
    await newUser.save();

    res.status(201).json({ message: 'User created successfully' });
  } catch (error) {
    console.error('Error registering user:', error);
    res.status(500).json({ message: 'Internal Server Error' });
  }
});

// Route for user login
router.post('/login', async (req, res) => {
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
    const { token, tokenDecoded } = createJWT(user, 'login');

    res.json({ token, user: tokenDecoded });
  } catch (error) {
    console.error('Error logging in user:', error);
    res.status(500).json({ message: 'Internal Server Error' });
  }
});

// Logout route
router.post('/logout', (req, res) => {
  // Clear user session data
  req.session.destroy((err) => {
    if (err) {
      console.error('Error destroying session:', err);
      return res.status(500).json({ message: 'Internal Server Error' });
    }
    res.clearCookie(process.env.SESSION_COOKIE_NAME); // Clear session cookie using environment variable
    res.json({ message: 'Logout successful' });
  });
});

// Route for accessing a protected resource
router.get('/protected', isAuthenticated, (req, res) => {
  // This route is protected and requires authentication
  res.json({ message: 'You have accessed a protected resource' });
});

// Route for accessing an admin resource
router.get('/admin', isAuthenticated, isAdmin, (req, res) => {
  // This route requires authentication and admin role
  res.json({ message: 'You have accessed an admin resource' });
});

// Route for renewing token
router.post('/renew', renewToken, (req, res) => {
  // Token renewal middleware will handle the renewal logic
  // If the token is renewed, the new token will be sent in the response headers
  res.sendStatus(204); // No content
});

module.exports = router;

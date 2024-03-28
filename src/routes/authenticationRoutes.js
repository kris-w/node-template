const express = require('express');
const router = express.Router();
const { isAuthenticated, renewToken, isAdmin } = require('../middleware/authenticationMiddleware');
const { register, login, logout, requestPasswordReset, resetPassword } = require('../controllers/authenticationController');

// Route for user registration
router.post('/register', register);

// Route for user login
router.post('/login', login);

// Logout route
router.post('/logout', logout);

// Route for requesting password reset
router.post('/password/reset/request', requestPasswordReset);

// Route for resetting password
router.post('/password/reset', resetPassword);

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

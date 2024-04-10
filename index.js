// Middleware
const express = require('express');
const dotenv = require('dotenv');
const mongoose = require('mongoose');
const session = require('express-session');
const { logger, logWithMetadata } = require('./src/middleware/loggingMiddleware');
const authMiddleware = require('./src/middleware/authenticationMiddleware');
const securityMiddleware = require('./src/middleware/securityMiddleware'); // Updated import

const app = express();

// Load environment variables from .env file
dotenv.config();

// Connect to MongoDB
mongoose.set('strictQuery', false);
mongoose.connect(process.env.MONGODB_URI)
  .then(() => {
    console.log('Connected to MongoDB');
  })
  .catch((error) => {
    console.error('Error connecting to MongoDB:', error);
    process.exit(1); // Exit the process if unable to connect to MongoDB
  });

// Middleware
app.use(express.json());
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
    cookie: {
      name: process.env.SESSION_COOKIE_NAME,
      secure: false, // recommended true for HTTPS
      maxAge: 24 * 60 * 60 * 1000 // 1 day
    }
  }));

app.use(securityMiddleware()); // Updated usage of securityMiddleware

// Custom request logging middleware using logWithMetadata
app.use((req, res, next) => {
  logWithMetadata(`${req.method} ${req.url}`, null, req); // Log request details with metadata
  next(); // Call next middleware
});

// Routes
const authRoutes = require('./src/routes/authenticationRoutes');
const userRoutes = require('./src/routes/userRoutes');

// Apply authentication middleware for all routes under /api/admin
app.use('/api/admin', authMiddleware.isAuthenticated, authMiddleware.isAdmin);

app.use('/api/auth', authRoutes);
app.use('/api/admin/users', userRoutes);

// Start server
const port = process.env.PORT || 3000;
app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});

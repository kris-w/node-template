// Middleware
const express = require('express');
const dotenv = require('dotenv');
const cors = require('cors');
const helmet = require('helmet');
const mongoose = require('mongoose');
const session = require('express-session');
const loggingMiddleware = require('./src/middleware/loggingMiddleware');
const authMiddleware = require('./src/middleware/authenticationMiddleware');
const [securityMiddleware, limiter] = require('./src/middleware/securityMiddleware');
const errorHandlingMiddleware = require('./src/middleware/errorHandlingMiddleware');

const app = express();

// Load environment variables from .env file
dotenv.config();

// Connect to MongoDB
mongoose.connect(process.env.MONGODB_URI)
  .then(() => {
    console.log('Connected to MongoDB');
  })
  .catch((error) => {
    console.error('Error connecting to MongoDB:', error);
    process.exit(1); // Exit the process if unable to connect to MongoDB
  });
  
  mongoose.set('strictQuery', false);

// Middleware
app.use(helmet());
app.use(cors({
  origin: 'http://localhost:5173' // Replace with your Vue.js application's domain
}));
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
app.use(loggingMiddleware); // Logging middleware
app.use(securityMiddleware);
app.use(limiter); // Apply rate limiting middleware


// Routes
const authRoutes = require('./src/routes/authenticationRoutes');
const userRoutes = require('./src/routes/userRoutes');

// Apply authentication middleware for all routes under /api/admin
app.use('/api/admin', authMiddleware.isAuthenticated, authMiddleware.isAdmin);

//const otherRoutes = require('./src/routes/otherRoutes');
app.use('/api/auth', authRoutes);
app.use('/api/admin/users', userRoutes);
//app.use('/api/other', authMiddleware.isAuthenticated, otherRoutes);

// Error handling middleware should be placed after all other middleware
app.use(errorHandlingMiddleware);

// Start server
const port = process.env.PORT || 3000;
app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});

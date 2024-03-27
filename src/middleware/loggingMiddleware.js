const dotenv = require('dotenv');
const winston = require('winston');
const winstonMongoDB = require('winston-mongodb');

// Load environment variables from .env file
dotenv.config();

// MongoDB URI from environment variable
const mongoUri = process.env.MONGODB_URI;

// Check if the MongoDB URI is provided
if (!mongoUri) {
    throw new Error('MongoDB URI is not provided in the environment variable MONGODB_URI');
}

// Configure Winston logger with console and MongoDB transports
const logger = winston.createLogger({
    level: 'info',
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.json()
    ),
    transports: [
        // Console transport
        new winston.transports.Console(),
        // MongoDB transport using the provided URI
        new winstonMongoDB.MongoDB({
            db: mongoUri,
            collection: 'app_logs',
            options: { useNewUrlParser: true, useUnifiedTopology: true }
        })
    ]
});

// Function to log messages with additional metadata and optional log level
function logWithMetadata(message, user = null, request = null, level = 'info') {
    // Additional metadata to include in log messages
    const metadata = {
        user: sanitizeUser(user),
        request: sanitizeRequest(request)
    };

    // Log the message with metadata using the specified log level
    logger.log(level, message, { metadata });
}

// Function to sanitize user information before logging
function sanitizeUser(user) {
    if (!user) return null;

    // Remove sensitive information from user object
    const sanitizedUser = { username: user.username }; // Retain only non-sensitive user data
    return sanitizedUser;
}

// Function to sanitize request information before logging
function sanitizeRequest(request) {
    if (!request) return null;

    // Remove sensitive information from request object
    const sanitizedRequest = {
        method: request.method,
        url: request.url,
        // Omit headers and body for privacy reasons
    };

    // Optionally log request body for POST and PUT requests
    if (request.method === 'POST' || request.method === 'PUT') {
        sanitizedRequest.body = request.body;
    }

    return sanitizedRequest;
}

module.exports = { logger, logWithMetadata };

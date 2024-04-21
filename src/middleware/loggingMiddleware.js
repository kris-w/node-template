// loggingMiddleware.js

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
function logWithMetadata(message, request = null, level = 'info', type = 'user') {
    const username = request && request.tokenDecoded ? request.tokenDecoded.username : null;
    // Additional metadata to include in log messages
    const metadata = {
        user: username,
        request: sanitizeRequest(request),
        type: type // Add a new field to indicate the type of activity
    };

    // Log the message with metadata using the specified log level
    logger.log(level, message, { metadata });
}

// Function to sanitize user information before logging
/*function sanitizeUser(user) {
    if (!user) return null;

    // Remove sensitive information from user object
    const sanitizedUser = { username: user.username }; // Retain only non-sensitive user data
    return sanitizedUser;
}*/

// Function to sanitize request information before logging
function sanitizeRequest(request) {
    if (!request) return null;

    // Remove sensitive information from request object
    const sanitizedRequest = {
        method: request.method,
        url: request.url,
        // Omit headers for privacy reasons
    };

    // Optionally log request body for POST and PUT requests
    if (request.method === 'POST' || request.method === 'PUT') {
        sanitizedRequest.body = sanitizeRequestBody(request.body);
    }

    return sanitizedRequest;
}

// Function to sanitize request body
function sanitizeRequestBody(body) {
    if (!body) return null;

    // Clone the body object to avoid modifying the original
    const sanitizedBody = { ...body };

    // Replace sensitive fields (e.g., password) with asterisks
    if (sanitizedBody.password) {
        sanitizedBody.password = '****';
    }

    if (sanitizedBody.password2) {
        sanitizedBody.password2 = '****';
    }

    // Add additional sensitive fields to sanitize if needed

    return sanitizedBody;
}

module.exports = { logger, logWithMetadata };

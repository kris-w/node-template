const { createLogger, transports, format } = require('winston');

// Create a logger instance
const logger = createLogger({
  transports: [
    new transports.Console({
      format: format.combine(
        format.colorize(),
        format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
        format.printf(info => `${info.timestamp} ${info.level}: ${info.message}`)
      )
    }),
    // You can add additional transports like file transport here
  ]
});

// Error handling middleware
const errorHandlingMiddleware = (err, req, res, next) => {
  // Log error details
  logger.error(`${err.status || 500} - ${err.message} - ${req.originalUrl} - ${req.method} - ${req.ip}`);

  // Send error response to the client
  res.status(err.status || 500).json({
    error: {
      message: err.message || 'Internal Server Error'
    }
  });
};

module.exports = errorHandlingMiddleware;

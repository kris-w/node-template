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

// Define logging middleware
const loggingMiddleware = (req, res, next) => {
  // Log request details
  logger.info(`${req.method} ${req.url}`);

  // Log request body (optional)
  logger.debug('Request body:', req.body);

  next();
};

module.exports = loggingMiddleware;

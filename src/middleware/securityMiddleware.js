const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cors = require('cors');

// Apply security middleware using Helmet
const securityMiddleware = () => {
  const helmetConfig = helmet({
    contentSecurityPolicy: false, // Disable default CSP to set a custom one
  });

  // Custom Content Security Policy
  const cspConfig = {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'", 'https://trusted-scripts.com'],
      styleSrc: ["'self'", "'unsafe-inline'", 'https://trusted-styles.com'],
      imgSrc: ["'self'", 'https://trusted-images.com'],
      // Add more directives as needed for other content types
    },
  };

  const middlewareStack = [
    helmetConfig,
    helmet.contentSecurityPolicy(cspConfig),
    cors({
      origin: 'http://localhost:5173', // Replace with your Vue.js application's domain
    }),
    rateLimit({
      windowMs: 15 * 60 * 1000, // 15 minutes
      max: 100, // limit each IP to 100 requests per windowMs
      message: 'Too many requests from this IP, please try again later.',
    }),
  ];

  // Conditionally apply HSTS based on environment variable
  const enableHSTS = process.env.ENABLE_HSTS === 'true';
  if (enableHSTS) {
    middlewareStack.unshift(helmet.hsts({
      maxAge: 31536000, // 1 year in seconds
      includeSubDomains: true,
      preload: true,
    }));
  }

  return middlewareStack;
};

module.exports = securityMiddleware;

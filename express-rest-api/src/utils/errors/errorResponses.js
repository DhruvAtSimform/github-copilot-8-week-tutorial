const logger = require('../logger');

/**
 * Send detailed error response in development environment
 *
 * Includes full error details, stack trace, and request information
 * to help developers debug issues.
 *
 * @param {Error} err - The error to send
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 */
const sendErrorDev = (err, req, res) => {
  return res.status(err.statusCode).json({
    status: err.status,
    error: {
      message: err.message,
      name: err.name,
      stack: err.stack,
      code: err.code,
    },
    request: {
      method: req.method,
      url: req.originalUrl,
    },
  });
};

/**
 * Send safe error response in production environment
 *
 * Only operational errors show detailed messages.
 * Programming errors return generic messages to avoid leaking sensitive information.
 *
 * @param {Error} err - The error to send
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 */
const sendErrorProd = (err, req, res) => {
  // Operational, trusted error: send message to client
  if (err.isOperational) {
    return res.status(err.statusCode).json({
      status: err.status,
      message: err.message,
    });
  }

  // Programming or unknown error: don't leak error details to client
  logger.error('NON-OPERATIONAL ERROR - CRITICAL', {
    error: err,
    stack: err.stack,
    url: req.originalUrl,
  });

  return res.status(500).json({
    status: 'error',
    message: 'Something went wrong. Please try again later.',
  });
};

module.exports = {
  sendErrorDev,
  sendErrorProd,
};

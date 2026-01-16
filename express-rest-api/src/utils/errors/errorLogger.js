const logger = require('../logger');
const { sanitizeRequestBody } = require('./sanitizer');

/**
 * Log comprehensive error information for debugging
 *
 * Includes error details, request context, and user information
 * while ensuring sensitive data is sanitized.
 *
 * @param {Error} err - The error to log
 * @param {Object} req - Express request object
 */
const logError = (err, req) => {
  const errorLog = {
    timestamp: new Date().toISOString(),
    errorInfo: {
      message: err.message,
      name: err.name,
      statusCode: err.statusCode || 500,
      code: err.code,
      isOperational: err.isOperational,
      stack: err.stack,
    },
    request: {
      method: req.method,
      url: req.originalUrl,
      baseUrl: req.baseUrl,
      ip: req.ip || req.connection?.remoteAddress,
      userAgent: req.get('user-agent'),
      body: sanitizeRequestBody(req.body),
      params: req.params,
      query: req.query,
      headers: {
        host: req.get('host'),
        referer: req.get('referer'),
        origin: req.get('origin'),
      },
      userId: req.user?.id || 'anonymous',
    },
  };

  // Log based on error severity
  if (err.statusCode >= 500 || !err.isOperational) {
    logger.error('Internal Server Error', errorLog);
  } else if (err.statusCode >= 400) {
    logger.warn('Client Error', errorLog);
  } else {
    logger.info('Error', errorLog);
  }
};

module.exports = { logError };

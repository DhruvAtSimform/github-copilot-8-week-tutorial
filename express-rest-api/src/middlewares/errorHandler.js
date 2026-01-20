const {
  AppError,
  transformError,
  logError,
  sendErrorDev,
  sendErrorProd,
} = require('../utils/errors');

/**
 * Global error handling middleware
 *
 * This middleware catches all errors thrown in the application and:
 * 1. Logs comprehensive error information for debugging
 * 2. Transforms known error types into operational errors
 * 3. Sends appropriate responses based on environment
 *
 * Must be registered after all routes.
 *
 * @param {Error} err - The error that was thrown
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} _next - Express next middleware function (unused)
 */
const errorHandler = (err, req, res, _next) => {
  // Set default values
  err.statusCode = err.statusCode || 500;
  err.status = err.status || 'error';

  // Log the error with full request context
  logError(err, req);

  // Transform specific error types into AppError
  const transformedError = transformError(err);

  // Send error response based on environment
  if (process.env.NODE_ENV === 'development') {
    sendErrorDev(transformedError, req, res);
  } else {
    sendErrorProd(transformedError, req, res);
  }
};

/**
 * Async error wrapper to eliminate try-catch blocks
 * Usage: router.get('/path', catchAsync(async (req, res) => { ... }))
 */
const catchAsync = (fn) => {
  return (req, res, next) => {
    // eslint-disable-next-line promise/no-callback-in-promise
    Promise.resolve(fn(req, res, next)).catch(next);
  };
};

module.exports = {
  errorHandler,
  AppError,
  catchAsync,
};

/**
 * Central export point for all error-related utilities
 *
 * This follows the barrel pattern for cleaner imports throughout the application.
 * Instead of importing from multiple files, consumers can import from this index.
 */

const AppError = require('./AppError');
const { transformError } = require('./errorTransformers');
const { logError } = require('./errorLogger');
const { sendErrorDev, sendErrorProd } = require('./errorResponses');
const { sanitizeRequestBody, sanitizeHeaders } = require('./sanitizer');

module.exports = {
  AppError,
  transformError,
  logError,
  sendErrorDev,
  sendErrorProd,
  sanitizeRequestBody,
  sanitizeHeaders,
};

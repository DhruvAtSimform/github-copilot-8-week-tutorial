/**
 * Central export point for all error-related utilities
 *
 * This follows the barrel pattern for cleaner imports throughout the application.
 * Instead of importing from multiple files, consumers can import from this index.
 */

import AppError from './AppError.js';
import { transformError } from './errorTransformers.js';
import { logError } from './errorLogger.js';
import { sendErrorDev, sendErrorProd } from './errorResponses.js';
import { sanitizeRequestBody, sanitizeHeaders } from './sanitizer.js';

export {
  AppError,
  transformError,
  logError,
  sendErrorDev,
  sendErrorProd,
  sanitizeRequestBody,
  sanitizeHeaders,
};

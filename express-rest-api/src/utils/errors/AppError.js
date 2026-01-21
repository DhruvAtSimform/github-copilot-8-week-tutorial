/**
 * Custom Application Error class for operational errors
 *
 * Operational errors are expected errors that can occur during normal application flow,
 * such as validation errors, authentication failures, or resource not found errors.
 * These errors are safe to show to the client.
 */
class AppError extends Error {
  /**
   * @param {string} message - Error message to display
   * @param {number} statusCode - HTTP status code
   * @param {boolean} isOperational - Whether this is an operational error (default: true)
   */
  constructor(message, statusCode, isOperational = true) {
    super(message);

    this.statusCode = statusCode;
    this.isOperational = isOperational;
    this.status = `${statusCode}`.startsWith('4') ? 'fail' : 'error';

    // Capture stack trace, excluding constructor call from it
    Error.captureStackTrace(this, this.constructor);
  }
}
export default AppError;

/**
 * Custom Application Error Class
 *
 * Extends the native Error class to provide:
 * - HTTP status codes
 * - Operational vs programming error distinction
 * - Stack trace capture
 * - Status classification (fail for 4xx, error for 5xx)
 *
 * Operational errors are expected errors that can occur during normal application flow,
 * such as validation errors, authentication failures, or resource not found errors.
 * These errors are safe to show to the client.
 *
 * @example
 * throw new AppError('User not found', 404);
 * throw new AppError('Invalid credentials', 401);
 * throw new AppError('Database connection failed', 500, false);
 */
class AppError extends Error {
  public readonly statusCode: number;
  public readonly status: string;
  public readonly isOperational: boolean;

  /**
   * Creates a new AppError instance
   * @param message - Error message to display
   * @param statusCode - HTTP status code (default: 500)
   * @param isOperational - Whether this is an operational error (default: true)
   */
  constructor(
    message: string,
    statusCode: number = 500,
    isOperational: boolean = true
  ) {
    super(message);

    this.statusCode = statusCode;
    this.isOperational = isOperational;
    this.status = `${statusCode}`.startsWith('4') ? 'fail' : 'error';

    // Capture stack trace, excluding constructor call from it
    Error.captureStackTrace(this, this.constructor);
  }
}

export default AppError;

import { Request, Response, NextFunction } from 'express';
import {
  AppError,
  transformError,
  logError,
  sendErrorDev,
  sendErrorProd,
} from '../utils/errors/index.js';

/**
 * Extended error interface with optional properties
 */
interface ExtendedError extends Error {
  statusCode?: number;
  status?: string;
}

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
 * @param err - The error that was thrown
 * @param req - Express request object
 * @param res - Express response object
 * @param _next - Express next middleware function (unused)
 */
const errorHandler = (
  err: Error | AppError,
  req: Request,
  res: Response,
  _next: NextFunction
): void => {
  const error = err as ExtendedError;

  // Set default values
  error.statusCode = error.statusCode || 500;
  error.status = error.status || 'error';

  // Log the error with full request context
  logError(error, req);

  // Transform specific error types into AppError
  const transformedError = transformError(error);

  // Send error response based on environment
  if (process.env.NODE_ENV === 'development') {
    sendErrorDev(transformedError, req, res);
  } else {
    sendErrorProd(transformedError, req, res);
  }
};

/**
 * Async error wrapper to eliminate try-catch blocks
 *
 * Wraps async route handlers to automatically catch rejected promises
 * and pass them to the error handling middleware.
 *
 * @param fn - Async route handler function
 * @returns Wrapped function that catches errors
 *
 * @example
 * router.get('/users', catchAsync(async (req, res) => {
 *   const users = await User.find();
 *   res.json({ status: 'success', data: users });
 * }));
 */
const catchAsync = (
  fn: (req: Request, res: Response, next: NextFunction) => Promise<void>
) => {
  return (req: Request, res: Response, next: NextFunction): void => {
    // eslint-disable-next-line promise/no-callback-in-promise
    fn(req, res, next).catch(next);
  };
};

export { errorHandler, AppError, catchAsync };

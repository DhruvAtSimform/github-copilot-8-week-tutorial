import { Request, Response } from 'express';
import logger from '../logger.js';
import AppError from './AppError.js';

/**
 * Error response interface
 */
interface ErrorResponse {
  status: string;
  error?: {
    message: string;
    name: string;
    stack?: string;
    code?: string | number;
  };
  message?: string;
  request?: {
    method: string;
    url: string;
  };
}

/**
 * Send detailed error response in development environment
 *
 * Includes full error details, stack trace, and request information
 * to help developers debug issues.
 *
 * @param err - The error to send
 * @param req - Express request object
 * @param res - Express response object
 */
const sendErrorDev = (
  err: Error | AppError,
  req: Request,
  res: Response
): void => {
  const appError = err as AppError;
  const statusCode = appError.statusCode || 500;
  const status = appError.status || 'error';

  const response: ErrorResponse = {
    status,
    error: {
      message: err.message,
      name: err.name,
      stack: err.stack,
      code: (err as Error & { code?: string | number }).code,
    },
    request: {
      method: req.method,
      url: req.originalUrl,
    },
  };

  res.status(statusCode).json(response);
};

/**
 * Send safe error response in production environment
 *
 * Only operational errors show detailed messages.
 * Programming errors return generic messages to avoid leaking sensitive information.
 *
 * @param err - The error to send
 * @param req - Express request object
 * @param res - Express response object
 */
const sendErrorProd = (
  err: Error | AppError,
  req: Request,
  res: Response
): void => {
  const appError = err as AppError;
  const statusCode = appError.statusCode || 500;
  const status = appError.status || 'error';

  // Operational, trusted error: send message to client
  if (appError.isOperational) {
    const response: ErrorResponse = {
      status,
      message: err.message,
    };

    res.status(statusCode).json(response);
    return;
  }

  // Programming or unknown error: don't leak error details to client
  logger.error('NON-OPERATIONAL ERROR - CRITICAL', {
    error: err,
    stack: err.stack,
    url: req.originalUrl,
  });

  const response: ErrorResponse = {
    status: 'error',
    message: 'Something went wrong. Please try again later.',
  };

  res.status(500).json(response);
};

export { sendErrorDev, sendErrorProd };

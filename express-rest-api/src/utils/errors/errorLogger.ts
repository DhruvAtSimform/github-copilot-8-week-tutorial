import { Request } from 'express';
import logger from '../logger.js';
import { sanitizeRequestBody } from './sanitizer.js';
import AppError from './AppError.js';

/**
 * Extended error interface with AppError properties
 */
interface ErrorWithDetails extends Error {
  statusCode?: number;
  code?: string | number;
  isOperational?: boolean;
}

/**
 * Log comprehensive error information for debugging
 *
 * Includes error details, request context, and user information
 * while ensuring sensitive data is sanitized.
 *
 * @param err - The error to log
 * @param req - Express request object
 */
const logError = (err: Error | AppError, req: Request): void => {
  const errorDetails = err as ErrorWithDetails;

  const errorLog = {
    timestamp: new Date().toISOString(),
    errorInfo: {
      message: err.message,
      name: err.name,
      statusCode: errorDetails.statusCode || 500,
      code: errorDetails.code,
      isOperational: errorDetails.isOperational,
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
      userId:
        (req as Request & { user?: { id: string } }).user?.id || 'anonymous',
    },
  };

  // Log based on error severity
  if (
    (errorDetails.statusCode && errorDetails.statusCode >= 500) ||
    !errorDetails.isOperational
  ) {
    logger.error('Internal Server Error', errorLog);
  } else if (errorDetails.statusCode && errorDetails.statusCode >= 400) {
    logger.warn('Client Error', errorLog);
  } else {
    logger.info('Error', errorLog);
  }
};

export { logError };

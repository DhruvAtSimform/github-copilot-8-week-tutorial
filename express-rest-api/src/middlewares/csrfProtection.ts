import { Request, Response, NextFunction } from 'express';
import crypto from 'crypto';
import AppError from '../utils/errors/AppError.js';
import logger from '../utils/logger.js';

/**
 * Generate CSRF token using crypto
 */
const createCSRFToken = (): string => {
  return crypto.randomBytes(32).toString('hex');
};

/**
 * Middleware to generate CSRF token and attach to request
 * Uses Double Submit Cookie pattern for CSRF protection
 */
export const generateCSRFToken = (
  _req: Request,
  res: Response,
  next: NextFunction
): void => {
  // Generate token
  const token = createCSRFToken();

  // Set token in cookie
  res.cookie('XSRF-TOKEN', token, {
    httpOnly: false, // JavaScript needs to read it
    secure: process.env.NODE_ENV === 'production', // HTTPS only in production
    sameSite: 'strict', // Prevent CSRF
    maxAge: 24 * 60 * 60 * 1000, // 24 hours
  });

  // Attach token to response locals for EJS templates
  res.locals.csrfToken = token;

  next();
};

/**
 * Middleware to validate CSRF token on state-changing requests
 * Implements Double Submit Cookie pattern
 */
export const validateCSRFToken = (
  req: Request,
  _res: Response,
  next: NextFunction
): void => {
  // Skip validation for safe methods
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) {
    return next();
  }

  try {
    // Get token from cookie
    const cookieToken = req.cookies?.['XSRF-TOKEN'];

    // Get token from header (frontend should send this)
    const headerToken = req.headers['x-xsrf-token'] as string;

    // Validate both tokens exist and match
    if (!cookieToken || !headerToken) {
      logger.warn('CSRF token missing', {
        ip: req.ip,
        path: req.path,
        method: req.method,
        hasCookie: !!cookieToken,
        hasHeader: !!headerToken,
        severity: 'HIGH',
        category: 'CSRF_FAILURE',
      });
      throw new AppError('CSRF token missing', 403);
    }

    if (cookieToken !== headerToken) {
      logger.warn('CSRF token mismatch', {
        ip: req.ip,
        path: req.path,
        method: req.method,
        severity: 'HIGH',
        category: 'CSRF_FAILURE',
      });
      throw new AppError('Invalid CSRF token', 403);
    }

    // Token is valid, proceed
    next();
  } catch (error) {
    next(error);
  }
};

/**
 * Endpoint to provide CSRF token to frontend
 * GET /api/csrf-token
 */
export const getCSRFToken = (_req: Request, res: Response): void => {
  // Token is already in cookie, also return in response body for convenience
  const token = (res.locals.csrfToken as string) || createCSRFToken();

  res.status(200).json({
    status: 'success',
    data: {
      csrfToken: token,
    },
  });
};

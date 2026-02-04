import rateLimit, { type RateLimitRequestHandler } from 'express-rate-limit';
import { Request, Response } from 'express';
import logger from '../utils/logger.js';

/**
 * Custom handler for rate limit exceeded
 */
const rateLimitHandler = (req: Request, res: Response): void => {
  const ip = req.ip || req.socket.remoteAddress;
  const userAgent = req.get('user-agent');

  logger.warn('Rate limit exceeded', {
    ip,
    userAgent,
    path: req.path,
    method: req.method,
    severity: 'MEDIUM',
    category: 'RATE_LIMIT',
  });

  res.status(429).json({
    status: 'error',
    statusCode: 429,
    message: 'Too many requests from this IP, please try again later',
    retryAfter: res.getHeader('Retry-After'),
  });
};

/**
 * General API rate limiter for all routes
 * Allows 100 requests per 15 minutes per IP
 * Uses default key generator which properly handles IPv6
 */
export const apiLimiter: RateLimitRequestHandler = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
  message: {
    status: 'error',
    message: 'Too many requests from this IP, please try again later',
  },
  standardHeaders: true, // Return rate limit info in `RateLimit-*` headers
  legacyHeaders: false, // Disable `X-RateLimit-*` headers
  handler: rateLimitHandler,
  skip: (req: Request): boolean => {
    // Skip rate limiting for health check endpoint
    return req.path === '/health';
  },
});

/**
 * Strict limiter for authentication endpoints (when implemented)
 * Only 5 attempts per 15 minutes
 */
export const authLimiter: RateLimitRequestHandler = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // Only 5 attempts per 15 minutes
  skipSuccessfulRequests: true, // Don't count successful requests
  message: {
    status: 'error',
    message: 'Too many authentication attempts, please try again later',
  },
  handler: rateLimitHandler,
});

/**
 * Stricter limiter for write operations
 * 10 writes per minute to prevent abuse
 */
export const writeLimiter: RateLimitRequestHandler = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 10, // 10 writes per minute
  message: {
    status: 'error',
    message: 'Too many write operations, please slow down',
  },
  handler: rateLimitHandler,
});

/**
 * Strict limiter for sensitive data endpoints
 * More restrictive for endpoints that return large datasets
 */
export const dataLimiter: RateLimitRequestHandler = rateLimit({
  windowMs: 5 * 60 * 1000, // 5 minutes
  max: 20, // 20 requests per 5 minutes
  message: {
    status: 'error',
    message: 'Too many requests for this resource, please try again later',
  },
  handler: rateLimitHandler,
});

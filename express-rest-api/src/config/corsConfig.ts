import { CorsOptions } from 'cors';
import AppError from '../utils/errors/AppError.js';
import logger from '../utils/logger.js';

/**
 * Whitelist of allowed origins based on environment
 */
const getAllowedOrigins = (): readonly string[] => {
  const origins: string[] = [];

  // Development environment - allow localhost
  if (process.env.NODE_ENV === 'development') {
    origins.push('http://localhost:3000');
    origins.push('http://127.0.0.1:3000');
  }

  // Production environment - add production URLs from env
  if (process.env.FRONTEND_URL) {
    origins.push(process.env.FRONTEND_URL);
  }

  // Allow additional origins from env variable (comma-separated)
  if (process.env.ALLOWED_ORIGINS) {
    const additionalOrigins = process.env.ALLOWED_ORIGINS.split(',').map((o) =>
      o.trim()
    );
    origins.push(...additionalOrigins);
  }

  return origins;
};

/**
 * CORS configuration with strict origin validation
 */
export const corsOptions: CorsOptions = {
  origin: (origin, callback) => {
    const allowedOrigins = getAllowedOrigins();

    // Allow requests with no origin (mobile apps, Postman, curl, same-origin)
    if (!origin) {
      return callback(null, true);
    }

    // Check if origin is in whitelist
    if (allowedOrigins.includes(origin)) {
      return callback(null, true);
    } else {
      logger.warn('Blocked CORS request from unauthorized origin', {
        origin,
        allowedOrigins,
        severity: 'MEDIUM',
        category: 'CORS_VIOLATION',
      });
      callback(
        new AppError(`Origin ${origin} not allowed by CORS policy`, 403)
      );
    }
  },
  credentials: true, // Allow cookies
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowedHeaders: [
    'Content-Type',
    'Authorization',
    'X-Requested-With',
    'X-CSRF-Token',
    'X-XSRF-Token',
  ],
  exposedHeaders: [
    'X-Total-Count',
    'X-Page-Number',
    'RateLimit-Limit',
    'RateLimit-Remaining',
  ],
  maxAge: 600, // Cache preflight requests for 10 minutes
  optionsSuccessStatus: 204,
};

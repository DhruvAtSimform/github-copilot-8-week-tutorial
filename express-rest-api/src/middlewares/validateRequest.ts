import { z, ZodSchema } from 'zod';
import { Request, Response, NextFunction } from 'express';
import AppError from '../utils/errors/AppError.js';
import logger from '../utils/logger.js';

/**
 * Validate request data against Zod schema
 * Supports validation of query, body, and params
 */
export const validateRequest = (schema: {
  query?: ZodSchema;
  body?: ZodSchema;
  params?: ZodSchema;
}) => {
  return (req: Request, _res: Response, next: NextFunction): void => {
    try {
      // Validate query parameters (don't modify req.query - it's immutable in Express 5)
      if (schema.query) {
        schema.query.parse(req.query);
      }

      // Validate request body
      if (schema.body) {
        req.body = schema.body.parse(req.body) as typeof req.body;
      }

      // Validate route parameters (don't modify req.params - it's immutable)
      if (schema.params) {
        schema.params.parse(req.params);
      }

      next();
    } catch (error) {
      if (error instanceof z.ZodError) {
        const errorMessages = error.issues.map(
          (err) => `${err.path.join('.')}: ${err.message}`
        );

        logger.warn('Request validation failed', {
          errors: error.issues,
          path: req.path,
          method: req.method,
          ip: req.ip,
          severity: 'LOW',
          category: 'VALIDATION_FAILURE',
        });

        next(
          new AppError(`Validation error: ${errorMessages.join(', ')}`, 400)
        );
      } else {
        next(error);
      }
    }
  };
};

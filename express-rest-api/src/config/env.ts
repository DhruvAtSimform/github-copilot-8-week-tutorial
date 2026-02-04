import { z } from 'zod';
import logger from '../utils/logger.js';

/**
 * Environment variable validation schema
 */
const envSchema = z.object({
  // Application
  NODE_ENV: z
    .enum(['development', 'production', 'test'])
    .default('development'),
  PORT: z
    .string()
    .default('3000')
    .transform((val) => parseInt(val, 10))
    .pipe(z.number().min(1).max(65535)),
  LOG_LEVEL: z.enum(['error', 'warn', 'info', 'debug']).default('info'),

  // CORS
  FRONTEND_URL: z.string().url().optional(),
  ALLOWED_ORIGINS: z.string().optional(),

  // Database
  DATABASE_URL: z.string().optional(),

  // Redis (for rate limiting - optional for now)
  REDIS_URL: z.string().url().optional(),
});

/**
 * Validated environment variables type
 */
export type Env = z.infer<typeof envSchema>;

/**
 * Validate and export environment configuration
 */
function validateEnv(): Env {
  try {
    const validated = envSchema.parse(process.env);

    // Additional runtime checks for production
    if (validated.NODE_ENV === 'production') {
      // Warn if FRONTEND_URL is not HTTPS
      if (
        validated.FRONTEND_URL &&
        !validated.FRONTEND_URL.startsWith('https://')
      ) {
        logger.warn('FRONTEND_URL should use HTTPS in production', {
          url: validated.FRONTEND_URL,
        });
      }
    }

    logger.info('Environment variables validated successfully', {
      nodeEnv: validated.NODE_ENV,
      port: validated.PORT,
      logLevel: validated.LOG_LEVEL,
    });

    return validated;
  } catch (error) {
    if (error instanceof z.ZodError) {
      logger.error('Environment validation failed', {
        errors: error.issues,
      });
      console.error('❌ Invalid environment variables:');
      error.issues.forEach((err) => {
        console.error(`  - ${err.path.join('.')}: ${err.message}`);
      });
    } else if (error instanceof Error) {
      logger.error('Environment validation error', {
        message: error.message,
      });
      console.error(`❌ ${error.message}`);
    }

    process.exit(1);
  }
}

export const env = validateEnv();

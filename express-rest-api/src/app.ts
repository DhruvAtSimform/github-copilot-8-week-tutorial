import express, { Application, Request, Response, NextFunction } from 'express';
import cookieParser from 'cookie-parser';
import cors from 'cors';
import compression from 'compression';
import morgan from 'morgan';
import path from 'path';
import { fileURLToPath } from 'url';

// Security configurations
import { env } from './config/env.js';
import { corsOptions } from './config/corsConfig.js';
import { securityHeadersConfig } from './config/securityHeaders.js';
import { apiLimiter } from './middlewares/rateLimiter.js';
import { generateCSRFToken } from './middlewares/csrfProtection.js';

import { setRoutes } from './routes/index.js';
import { errorHandler } from './middlewares/errorHandler.js';
import AppError from './utils/errors/AppError.js';
import logger from './utils/logger.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app: Application = express();

// Security: Disable X-Powered-By header
app.disable('x-powered-by');

// Security: Trust proxy in production (for rate limiting and HTTPS detection)
if (env.NODE_ENV === 'production') {
  app.set('trust proxy', 1);
}

// View engine setup
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, '../views'));

// Static files
app.use(express.static(path.join(__dirname, '../public')));

// Security middlewares
app.use(securityHeadersConfig); // Comprehensive security headers (no unsafe-inline)
app.use(cors(corsOptions)); // Strict CORS with origin validation
app.use(compression());

// Cookie parser (required for CSRF)
app.use(cookieParser());

// Body parser middlewares
app.use(express.json({ limit: '100kb' }));
app.use(express.urlencoded({ extended: true, limit: '100kb' }));

// Rate limiting
app.use('/api/', apiLimiter);

// CSRF protection (generate token for all requests)
app.use(generateCSRFToken);

// HTTP request logger
if (env.NODE_ENV === 'development') {
  app.use(morgan('dev'));
} else {
  // Structured logs in production
  app.use(
    morgan('combined', {
      stream: {
        write: (message: string): void => {
          logger.info(message.trim());
        },
      },
    })
  );
}

// Health check endpoint
app.get('/health', (_req: Request, res: Response): void => {
  res.status(200).json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
  });
});

// API routes
setRoutes(app);

// Handle undefined routes - must be after all other routes
app.use((req: Request, _: Response, next: NextFunction): void => {
  next(new AppError(`Cannot find ${req.originalUrl} on this server`, 404));
});

// Global error handler - must be last middleware
app.use(errorHandler);

// Start server using validated env
app.listen(env.PORT, (): void => {
  logger.info(`Server is running on port ${env.PORT} in ${env.NODE_ENV} mode`);
});

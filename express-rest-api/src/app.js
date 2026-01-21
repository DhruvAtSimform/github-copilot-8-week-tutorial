import express from 'express';
import helmet from 'helmet';
import cors from 'cors';
import compression from 'compression';
import morgan from 'morgan';
import { setRoutes } from './routes/index.js';
import { errorHandler } from './middlewares/errorHandler.js';
import AppError from './utils/errors/AppError.js';
import logger from './utils/logger.js';

const app = express();

// Security middlewares
app.use(helmet());
app.use(cors());
app.use(compression());

// Body parser middlewares
app.use(express.json({ limit: '100kb' }));
app.use(express.urlencoded({ extended: true, limit: '100kb' }));

// HTTP request logger
if (process.env.NODE_ENV === 'development') {
  app.use(morgan('dev'));
} else {
  // Structured logs in production
  app.use(
    morgan('combined', {
      stream: {
        write: (message) => logger.info(message.trim()),
      },
    })
  );
}

// Health check endpoint
app.get('/health', (req, res) => {
  res.status(200).json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
  });
});

// API routes
setRoutes(app);

// Handle undefined routes - must be after all other routes
app.all('*', (req, _, next) => {
  next(new AppError(`Cannot find ${req.originalUrl} on this server`, 404));
});

// Global error handler - must be last middleware
app.use(errorHandler);

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  logger.info(
    `Server is running on port ${PORT} in ${process.env.NODE_ENV || 'development'
    } mode`
  );
});

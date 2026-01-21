import { Application, Request, Response, NextFunction } from 'express';
import IndexController from '../controllers/index.js';
import TimezoneController from '../controllers/timezoneController.js';
import AppError from '../utils/errors/AppError.js';

/**
 * Configure application routes
 *
 * @param app - Express application instance
 */
const setRoutes = (app: Application): void => {
  // Example routes with error handling
  app.get('/', (req, res) => IndexController.getIndex(req, res));

  // Timezone endpoints
  app.get('/api/timezones', (req, res, next) =>
    TimezoneController.getTimezonesByCountry(req, res, next)
  );

  // Example: Route with synchronous response
  app.get('/api/example', (_req: Request, res: Response): void => {
    // Simulating operation
    const data = { message: 'Success', timestamp: new Date().toISOString() };
    res.status(200).json({ status: 'success', data });
  });

  // Example: Route that throws operational error
  app.get(
    '/api/error',
    (_: Request, __: Response, next: NextFunction): void => {
      next(new AppError('This is a test operational error', 400));
    }
  );

  // Example: Route with unhandled error (for testing)
  app.get(
    '/api/crash',
    (_req: Request, _res: Response, _next: NextFunction): void => {
      throw new Error('Unhandled programming error for testing');
    }
  );
};

export { setRoutes };

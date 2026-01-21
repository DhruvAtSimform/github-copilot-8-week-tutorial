import IndexController from '../controllers/index.js';
import TimezoneController from '../controllers/timezoneController.js';
import { catchAsync } from '../middlewares/errorHandler.js';
import AppError from '../utils/errors/AppError.js';

const setRoutes = (app) => {
  // Example routes with error handling
  app.get('/', IndexController.getIndex);

  // Timezone endpoints
  app.get('/api/timezones', catchAsync(TimezoneController.getTimezonesByCountry));

  // Example: Route with async error handling
  app.get(
    '/api/example',
    catchAsync((_req, res) => {
      // Simulating async operation
      const data = { message: 'Success', timestamp: new Date().toISOString() };
      res.status(200).json({ status: 'success', data });
    })
  );

  // Example: Route that throws operational error
  app.get('/api/error', (_, __, next) => {
    next(new AppError('This is a test operational error', 400));
  });

  // Example: Route with unhandled error (for testing)
  app.get('/api/crash', (_req, _res, _next) => {
    throw new Error('Unhandled programming error for testing');
  });
};

export { setRoutes };

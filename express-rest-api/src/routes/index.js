const IndexController = require('../controllers/index');
const { catchAsync } = require('../middlewares/errorHandler');
const AppError = require('../utils/errors/AppError');

const setRoutes = (app) => {
  // Example routes with error handling
  app.get('/', IndexController.getIndex);

  // Example: Route with async error handling
  app.get(
    '/api/example',
    catchAsync(async (_req, res) => {
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

module.exports = { setRoutes };

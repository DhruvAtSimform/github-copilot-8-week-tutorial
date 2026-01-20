const AppError = require('./AppError');

/**
 * Transform MongoDB CastError into AppError
 * Occurs when invalid ObjectId or data type is provided
 */
const handleCastError = (err) => {
  const message = `Invalid ${err.path}: ${err.value}`;
  return new AppError(message, 400);
};

/**
 * Transform MongoDB duplicate key error into AppError
 * Occurs when trying to insert a duplicate value for a unique field
 */
const handleDuplicateFieldsError = (err) => {
  const field = Object.keys(err.keyValue || {})[0];
  const message = field
    ? `${field} already exists. Please use another value.`
    : 'Duplicate field value. Please use another value.';
  return new AppError(message, 400);
};

/**
 * Transform MongoDB validation error into AppError
 * Occurs when document doesn't meet schema validation requirements
 */
const handleValidationError = (err) => {
  const errors = Object.values(err.errors).map((el) => el.message);
  const message = `Invalid input data. ${errors.join('. ')}`;
  return new AppError(message, 400);
};

/**
 * Transform JWT authentication error into AppError
 * Occurs when token is malformed or invalid
 */
const handleJWTError = () =>
  new AppError('Invalid token. Please log in again.', 401);

/**
 * Transform JWT expired error into AppError
 * Occurs when token has exceeded its expiration time
 */
const handleJWTExpiredError = () =>
  new AppError('Your token has expired. Please log in again.', 401);

/**
 * Transform Multer file upload errors into AppError
 * Handles various file upload constraints violations
 */
const handleMulterError = (err) => {
  if (err.code === 'LIMIT_FILE_SIZE') {
    return new AppError('File size is too large.', 400);
  }
  if (err.code === 'LIMIT_FILE_COUNT') {
    return new AppError('Too many files uploaded.', 400);
  }
  if (err.code === 'LIMIT_UNEXPECTED_FILE') {
    return new AppError('Unexpected field in file upload.', 400);
  }
  return new AppError(err.message, 400);
};

/**
 * Transform common error types into operational AppErrors
 *
 * @param {Error} error - The error to transform
 * @returns {Error} - Transformed error or original error
 */
const transformError = (error) => {
  // MongoDB errors
  if (error.name === 'CastError') {
    return handleCastError(error);
  }
  if (error.code === 11000) {
    return handleDuplicateFieldsError(error);
  }
  if (error.name === 'ValidationError') {
    return handleValidationError(error);
  }

  // JWT errors
  if (error.name === 'JsonWebTokenError') {
    return handleJWTError();
  }
  if (error.name === 'TokenExpiredError') {
    return handleJWTExpiredError();
  }

  // Multer errors
  if (error.name === 'MulterError') {
    return handleMulterError(error);
  }

  // Return original error if no transformation needed
  return error;
};

module.exports = {
  handleCastError,
  handleDuplicateFieldsError,
  handleValidationError,
  handleJWTError,
  handleJWTExpiredError,
  handleMulterError,
  transformError,
};

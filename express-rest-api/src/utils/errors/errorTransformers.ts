import AppError from './AppError.js';

/**
 * MongoDB CastError interface
 */
interface MongoCastError extends Error {
  path: string;
  value: unknown;
  name: 'CastError';
}

/**
 * MongoDB Duplicate Key Error interface
 */
interface MongoDuplicateKeyError extends Error {
  code: 11000;
  keyValue?: Record<string, unknown>;
}

/**
 * MongoDB Validation Error interface
 */
interface MongoValidationError extends Error {
  name: 'ValidationError';
  errors: Record<string, { message: string }>;
}

/**
 * Multer Error interface
 */
interface MulterErrorType extends Error {
  name: 'MulterError';
  code: string;
}

/**
 * Transform MongoDB CastError into AppError
 * Occurs when invalid ObjectId or data type is provided
 */
const handleCastError = (err: MongoCastError): AppError => {
  const message = `Invalid ${err.path}: ${String(err.value)}`;
  return new AppError(message, 400);
};

/**
 * Transform MongoDB duplicate key error into AppError
 * Occurs when trying to insert a duplicate value for a unique field
 */
const handleDuplicateFieldsError = (err: MongoDuplicateKeyError): AppError => {
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
const handleValidationError = (err: MongoValidationError): AppError => {
  const errors = Object.values(err.errors).map((el) => el.message);
  const message = `Invalid input data. ${errors.join('. ')}`;
  return new AppError(message, 400);
};

/**
 * Transform JWT authentication error into AppError
 * Occurs when token is malformed or invalid
 */
const handleJWTError = (): AppError =>
  new AppError('Invalid token. Please log in again.', 401);

/**
 * Transform JWT expired error into AppError
 * Occurs when token has exceeded its expiration time
 */
const handleJWTExpiredError = (): AppError =>
  new AppError('Your token has expired. Please log in again.', 401);

/**
 * Transform Multer file upload errors into AppError
 * Handles various file upload constraints violations
 */
const handleMulterError = (err: MulterErrorType): AppError => {
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
 * Type guard to check if error is MongoCastError
 */
const isCastError = (error: Error): error is MongoCastError => {
  return error.name === 'CastError' && 'path' in error && 'value' in error;
};

/**
 * Type guard to check if error is MongoDuplicateKeyError
 */
const isDuplicateKeyError = (error: Error): error is MongoDuplicateKeyError => {
  return 'code' in error && (error as { code: number }).code === 11000;
};

/**
 * Type guard to check if error is MongoValidationError
 */
const isValidationError = (error: Error): error is MongoValidationError => {
  return error.name === 'ValidationError' && 'errors' in error;
};

/**
 * Type guard to check if error is MulterError
 */
const isMulterError = (error: Error): error is MulterErrorType => {
  return error.name === 'MulterError' && 'code' in error;
};

/**
 * Transform common error types into operational AppErrors
 *
 * @param error - The error to transform
 * @returns Transformed error or original error
 */
const transformError = (error: Error): Error => {
  // MongoDB errors
  if (isCastError(error)) {
    return handleCastError(error);
  }
  if (isDuplicateKeyError(error)) {
    return handleDuplicateFieldsError(error);
  }
  if (isValidationError(error)) {
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
  if (isMulterError(error)) {
    return handleMulterError(error);
  }

  // Return original error if no transformation needed
  return error;
};

export { transformError };

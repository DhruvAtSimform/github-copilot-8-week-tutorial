/**
 * List of sensitive field names that should be redacted from logs
 */
const SENSITIVE_FIELDS = [
  'password',
  'token',
  'apiKey',
  'api_key',
  'secret',
  'secretKey',
  'secret_key',
  'creditCard',
  'credit_card',
  'cvv',
  'ssn',
  'privateKey',
  'private_key',
  'accessToken',
  'access_token',
  'refreshToken',
  'refresh_token',
];

/**
 * Sanitize request body by removing or redacting sensitive information
 *
 * This prevents sensitive data like passwords and tokens from being logged,
 * which could lead to security vulnerabilities.
 *
 * @param {Object} body - Request body to sanitize
 * @returns {Object} - Sanitized body with sensitive fields redacted
 */
const sanitizeRequestBody = (body) => {
  if (!body || typeof body !== 'object') {
    return body;
  }

  const sanitized = { ...body };

  SENSITIVE_FIELDS.forEach((field) => {
    if (sanitized[field]) {
      sanitized[field] = '***REDACTED***';
    }
  });

  return sanitized;
};

/**
 * Sanitize headers by removing authorization and cookie information
 *
 * @param {Object} headers - Request headers to sanitize
 * @returns {Object} - Sanitized headers
 */
const sanitizeHeaders = (headers) => {
  if (!headers || typeof headers !== 'object') {
    return headers;
  }

  const sanitized = { ...headers };
  const sensitiveHeaders = [
    'authorization',
    'cookie',
    'x-api-key',
    'x-auth-token',
  ];

  sensitiveHeaders.forEach((header) => {
    if (sanitized[header]) {
      sanitized[header] = '***REDACTED***';
    }
  });

  return sanitized;
};

module.exports = {
  sanitizeRequestBody,
  sanitizeHeaders,
  SENSITIVE_FIELDS,
};

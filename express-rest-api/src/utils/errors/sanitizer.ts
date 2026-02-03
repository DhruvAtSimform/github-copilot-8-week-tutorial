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
] as const;

/**
 * Sanitize request body by removing or redacting sensitive information
 *
 * This prevents sensitive data like passwords and tokens from being logged,
 * which could lead to security vulnerabilities.
 *
 * @param body - Request body to sanitize
 * @returns Sanitized body with sensitive fields redacted
 */
const sanitizeRequestBody = (body: unknown): unknown => {
  if (!body || typeof body !== 'object') {
    return body;
  }

  const sanitized = { ...(body as Record<string, unknown>) };
  const sensitiveFieldsSet = new Set(SENSITIVE_FIELDS);

  Object.keys(sanitized).forEach((key) => {
    if (sensitiveFieldsSet.has(key)) {
      sanitized[key] = '***REDACTED***';
    }
  });

  return sanitized;
};

/**
 * Sanitize headers by removing authorization and cookie information
 *
 * @param headers - Request headers to sanitize
 * @returns Sanitized headers
 */
const sanitizeHeaders = (headers: unknown): unknown => {
  if (!headers || typeof headers !== 'object') {
    return headers;
  }

  const sanitized = { ...(headers as Record<string, unknown>) };
  const sensitiveHeadersSet = new Set([
    'authorization',
    'cookie',
    'x-api-key',
    'x-auth-token',
  ]);

  Object.keys(sanitized).forEach((key) => {
    if (sensitiveHeadersSet.has(key)) {
      sanitized[key] = '***REDACTED***';
    }
  });

  return sanitized;
};

export { sanitizeRequestBody, sanitizeHeaders, SENSITIVE_FIELDS };

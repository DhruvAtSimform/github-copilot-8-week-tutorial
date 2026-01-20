# Copilot Instructions - Express REST API

Concise guidelines for maintaining code quality, security, and consistency in this Node.js Express project.

> **Note**: Use separate `.github/copilot-instructions-*.md` files with `applyTo` glob patterns for feature-specific instructions (e.g., API routes, database models, auth).

---

## 1. Code Style & Conventions

### Naming
- **camelCase**: variables, functions, methods
- **PascalCase**: classes, constructors
- **UPPER_SNAKE_CASE**: constants, env variables
- **kebab-case**: files, folders
- **Underscore prefix**: private methods/variables

### Module Structure
```javascript
// 1. Third-party imports
// 2. Local imports  
// 3. Constants
// 4. Implementation
// 5. Exports
```

### Core Principles
- Use ES6+: `const/let`, arrow functions, template literals, destructuring, async/await
- Functions: single responsibility, <50 lines, descriptive names, early returns
- Always handle errors with try-catch and custom `AppError` class
- Use `logger` (Winston) instead of `console.log`
- JSDoc for public functions/classes

---

## 2. Architecture (MVC + Layered)

```
src/
├── routes/        # Endpoint definitions, no logic
├── controllers/   # Request/response handling, minimal logic
├── services/      # Business logic, reusable
├── models/        # Data schemas, DB operations
├── middlewares/   # Auth, validation, error handling
└── utils/         # Helpers, logger, errors
```

**Design Patterns**: Middleware chain, centralized error handling, dependency injection, singleton (logger/DB)

---

## 3. Development Scripts

```bash
pnpm dev          # Start with nodemon (auto-reload)
pnpm start        # Production server
pnpm lint         # Check ESLint errors
pnpm lint:fix     # Auto-fix lint issues
pnpm format       # Prettier formatting
pnpm audit        # Check vulnerabilities
```

**Pre-commit**: Run `lint:fix` and `format` before committing (enforced by Husky)

---

## 4. Security (OWASP Top 10)

### Current Implementation
- ✅ Helmet.js (secure headers)
- ✅ CORS configured
- ✅ Body parser limits (100kb)
- ✅ Winston logging (no sensitive data)
- ✅ Environment variables (.env)
- ✅ Custom AppError (no stack traces in production)

### Required Practices
- **Access Control**: Verify permissions in middleware
- **Crypto**: bcrypt with 12+ rounds, HTTPS in production
- **Injection**: Parameterized queries, validate/sanitize input
- **Rate Limiting**: Implement for auth endpoints (express-rate-limit)
- **Session Security**: httpOnly, secure, sameSite cookies
- **Dependencies**: Regular `pnpm audit`, lock file integrity
- **Logging**: Log security events, never log passwords/tokens
- **SSRF Prevention**: Validate URLs with allowlists

### Key Rules
- Never commit `.env` files
- Validate env variables on startup
- Use `sanitizer.js` for user input
- Implement input validation with express-validator
- Set CSP headers via Helmet
- Rate limit sensitive endpoints (5 attempts/15min)

---

## 5. Error Handling

```javascript
// Use custom errors
throw new AppError('Message', statusCode);

// Wrap async routes
const asyncHandler = fn => (req, res, next) => 
  Promise.resolve(fn(req, res, next)).catch(next);
```

**Response format**: `{ status, statusCode, message, [stack] }`

---

## 6. Logging

```javascript
const logger = require('./utils/logger');

logger.info('Action', { context });    // General info
logger.warn('Warning', { details });   // Warnings
logger.error('Error', { error });      // Errors
logger.debug('Debug', { data });       // Dev only
```

❌ Never use `console.log` in code

---

## 7. API Standards

**Success**: `{ status: "success", data: {...} }`  
**Error**: `{ status: "error", statusCode, message }`  
**Pagination**: Add `{ pagination: { page, limit, total } }`

---

## 8. Code Checklist

Generate code that:
1. Follows naming conventions
2. Includes error handling (try-catch, AppError)
3. Uses logger instead of console
4. Has JSDoc for public functions
5. Validates/sanitizes user input
6. Follows layered architecture (routes → controllers → services)
7. Uses async/await for async operations
8. Follows DRY principle
9. Implements security best practices
10. Uses environment variables for config

---

## 9. Feature-Specific Instructions

For domain-specific guidelines (e.g., authentication, database operations, API versioning), create separate instruction files:

```markdown
<!-- .github/copilot-instructions-auth.md -->
applyTo: ["src/routes/auth/**", "src/controllers/auth/**"]
```

This keeps the main instructions concise while allowing detailed guidance for specific features.

---

**Version**: 2.0.0 | **Updated**: Jan 19, 2026

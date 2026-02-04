# Copilot Instructions - Express REST API

## Project Overview

A production-grade REST API built with **Node.js**, **Express.js**, and **TypeScript** following enterprise-level best practices for security, scalability, and maintainability.

### Tech Stack

**Runtime & Framework**

- Node.js (ES2022+)
- Express.js 4.x
- TypeScript 5.9+ (strict mode)

**Development Tools**

- tsx (TypeScript execution and hot-reload)
- ESLint with TypeScript support
- Prettier (code formatting)
- Husky (Git hooks)
- pnpm (package manager)

**Logging & Monitoring**

- Winston (structured logging)
- Morgan (HTTP request logging)

**Security**

- Helmet.js (security headers)
- CORS (cross-origin resource sharing)
- Compression (response compression)

**Architecture**

- MVC + Layered architecture
- Centralized error handling
- Dependency injection patterns
- Singleton pattern for shared services

---

Concise guidelines for maintaining code quality, security, and consistency in this Node.js Express project.

> **Note**: Use separate `.github/copilot-instructions-*.md` files with `applyTo` glob patterns for feature-specific instructions (e.g., API routes, database models, auth).

---

## 1. Code Style & Conventions

### Naming

- **camelCase**: variables, functions, methods
- **PascalCase**: classes, constructors, interfaces, types
- **UPPER_SNAKE_CASE**: constants, env variables
- **kebab-case**: files, folders
- **Underscore prefix**: private methods/variables

### Module Structure

```typescript
// 1. Third-party imports
// 2. Local imports
// 3. Type definitions (interfaces, types)
// 4. Constants
// 5. Implementation
// 6. Exports
```

### Comment rules

````
 - Do not add `what is this` type of comments for variable and function when it's obvious
  - e.x // Validate the input, // Call the service method, //
 - Add JsDoc when needed for documentation
 - Add comment when there's complex logic or need clarity for our self
 - Use verbose and explicit naming conventions for variables, constants, functions and classes
 - Add comments if required for magic numbers. Better if we can follow explicit variable naming rule

### Core Principles

- Use ES6+: `const/let`, arrow functions, template literals, destructuring, async/await
- Functions: single responsibility, <50 lines, descriptive names, early returns
- Always handle errors with try-catch and custom `AppError` class
- Use `logger` (Winston) instead of `console.log`
- JSDoc for public functions/classes
- Explicit return types for all functions
- Use strict TypeScript mode

---

## 2. TypeScript Best Practices

### Type Safety

- **NO `any` type**: Use `unknown` when type is truly unknown, then narrow with type guards
- **Explicit function return types**: Always declare return types for functions
- **Interface over Type**: Prefer interfaces for object shapes, use types for unions/intersections
- **Readonly where applicable**: Use `readonly` for immutable properties
- **Const assertions**: Use `as const` for literal types

### Type Definitions

```typescript
// ✅ Good - Explicit types
interface UserResponse {
  readonly id: string;
  name: string;
  email: string;
}

function getUser(id: string): Promise<UserResponse> {
  // implementation
}

// ❌ Bad - Implicit any
function getData(id) {
  return fetch(`/api/${id}`);
}
````

### Type Guards

```typescript
// Use type guards for runtime type checking
function isAppError(error: Error): error is AppError {
  return "statusCode" in error && "isOperational" in error;
}
```

### Generics

```typescript
// Use generics for reusable type-safe functions
async function fetchData<T>(url: string): Promise<T> {
  const response = await fetch(url);
  return response.json() as T;
}
```

---

## 3. Architecture (MVC + Layered)

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

**File Extensions**: Use `.ts` for all TypeScript files

---

## 4. Development Scripts

```bash
pnpm dev          # Start with tsx watch (auto-reload)
pnpm build        # Compile TypeScript to JavaScript
pnpm build:watch  # Watch mode compilation
pnpm start        # Production server (from dist/)
pnpm lint         # Check ESLint errors
pnpm lint:fix     # Auto-fix lint issues
pnpm format       # Prettier formatting
pnpm audit        # Check vulnerabilities
```

**Pre-commit**: Run `lint:fix` and `format` before committing (enforced by Husky)

---

## 5. Security (OWASP Top 10)

### Current Implementation

- ✅ Helmet.js (secure headers)
- ✅ CORS configured
- ✅ Body parser limits (100kb)
- ✅ Winston logging (no sensitive data)
- ✅ Environment variables (.env)
- ✅ Custom AppError (no stack traces in production)
- ✅ TypeScript strict mode (type safety)

### Required Practices

- **Access Control**: Verify permissions in middleware
- **Crypto**: bcrypt with 12+ rounds, HTTPS in production
- **Injection**: Parameterized queries, validate/sanitize input
- **Rate Limiting**: Implement for auth endpoints (express-rate-limit)
- **Session Security**: httpOnly, secure, sameSite cookies
- **Dependencies**: Regular `pnpm audit`, lock file integrity
- **Logging**: Log security events, never log passwords/tokens
- **SSRF Prevention**: Validate URLs with allowlists
- **Type Safety**: Use TypeScript to prevent runtime errors

### Key Rules

- Never commit `.env` files
- Validate env variables on startup
- Use `zod` for user input validation
- Implement input validation with zod schemas
- Set CSP headers via Helmet
- Rate limit sensitive endpoints (5 attempts/15min)
- Always type external data (API responses, user input)

---

## 6. Error Handling

```typescript
// Use custom errors with proper typing
throw new AppError("Message", statusCode);

// Wrap async routes with proper types
const catchAsync = (
  fn: (req: Request, res: Response, next: NextFunction) => Promise<void>,
) => {
  return (req: Request, res: Response, next: NextFunction): void => {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
};
```

**Response format**: `{ status, statusCode, message, [stack] }`

---

## 7. Logging

```typescript
import logger from "./utils/logger";

logger.info("Action", { context }); // General info
logger.warn("Warning", { details }); // Warnings
logger.error("Error", { error }); // Errors
logger.debug("Debug", { data }); // Dev only
```

❌ Never use `console.log` in code

---

## 8. API Standards

**Success**: `{ status: "success", data: {...} }`  
**Error**: `{ status: "error", statusCode, message }`  
**Pagination**: Add `{ pagination: { page, limit, total } }`

---

## 9. Code Checklist

Generate code that:

1. Follows naming conventions
2. Uses TypeScript with explicit types (NO `any`)
3. Includes error handling (try-catch, AppError)
4. Uses logger instead of console
5. Has JSDoc for public functions
6. Validates/sanitizes user input
7. Follows layered architecture (routes → controllers → services)
8. Uses async/await for async operations
9. Follows DRY principle
10. Implements security best practices
11. Uses environment variables for config
12. Has proper type guards for unknown types
13. Exports types/interfaces alongside implementations

---

## 10. TypeScript-Specific Rules

### Import/Export

```typescript
// ✅ Use .js extension in imports (required for ES modules)
import { AppError } from "./errors/AppError.js";

// ✅ Export types separately
export type { UserResponse, ClientDetails };
export { UserService };
```

### Null Checks

```typescript
// ✅ Handle undefined/null with optional chaining
const ip = req.ip || req.connection?.remoteAddress;

// ✅ Use nullish coalescing
const port = process.env.PORT ?? 3000;
```

### Interfaces for Express

```typescript
// ✅ Extend Express types when needed
interface RequestWithUser extends Request {
  user?: {
    id: string;
    email: string;
  };
}
```

---

## 11. Feature-Specific Instructions

For domain-specific guidelines (e.g., authentication, database operations, API versioning), create separate instruction files:

```markdown
<!-- .github/copilot-instructions-auth.md -->

applyTo: ["src/routes/auth/**", "src/controllers/auth/**"]
```

This keeps the main instructions concise while allowing detailed guidance for specific features.

---

**Version**: 3.0.0 (TypeScript) | **Updated**: Jan 21, 2026

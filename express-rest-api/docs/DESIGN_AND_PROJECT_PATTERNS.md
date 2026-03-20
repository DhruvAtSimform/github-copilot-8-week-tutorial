# Express REST API Design and Project Patterns

Date: 2026-03-19  
Owner: API Engineering  
Status: Draft

Purpose: Document the implemented design patterns, coding architecture patterns, and project-level conventions used in this codebase.  
Audience: Maintainers, contributors, and reviewers aligning new changes to existing patterns.

## Index

- [1. Pattern Overview](#1-pattern-overview)
- [2. Layered Architecture Pattern](#2-layered-architecture-pattern)
- [3. Singleton Instance Pattern](#3-singleton-instance-pattern)
- [4. Repository Pattern](#4-repository-pattern)
- [5. Service Orchestration Pattern](#5-service-orchestration-pattern)
- [6. Controller Pattern](#6-controller-pattern)
- [7. Middleware Pipeline Pattern](#7-middleware-pipeline-pattern)
- [8. Validation Pattern](#8-validation-pattern)
- [9. Error Normalization Pattern](#9-error-normalization-pattern)
- [10. External Provider Integration Pattern](#10-external-provider-integration-pattern)
- [11. Security-by-Default Pattern](#11-security-by-default-pattern)
- [12. Observability Pattern](#12-observability-pattern)
- [13. Response Contract Pattern](#13-response-contract-pattern)
- [14. Project Conventions and Packaging](#14-project-conventions-and-packaging)
- [15. Pattern Application Checklist](#15-pattern-application-checklist)
- [16. References](#16-references)
- [17. Change Log](#17-change-log)

## 1. Pattern Overview

Related sections: [2. Layered Architecture Pattern](#2-layered-architecture-pattern), [11. Security-by-Default Pattern](#11-security-by-default-pattern)

Primary patterns currently implemented:

- Layered architecture for domain endpoints
- Singleton export strategy for stateful/shared modules
- Repository-service-controller decomposition
- Middleware chain for cross-cutting concerns
- Schema-first validation with zod
- Centralized AppError-based operational error handling
- Structured, sanitized logging for observability and auditability

## 2. Layered Architecture Pattern

Related sections: [4. Repository Pattern](#4-repository-pattern), [5. Service Orchestration Pattern](#5-service-orchestration-pattern), [6. Controller Pattern](#6-controller-pattern)

Implemented layering for API flows:

- Routes define endpoint mapping and route-specific middleware
- Controllers manage HTTP concerns (req/res/next)
- Services own business logic and transformations
- Repositories own data/provider access and low-level validation

Benefits observed in implementation:

- Swappable data/provider layer under stable controller/service contracts
- Reduced blast radius for feature changes
- Easier targeted testing by layer boundary

Scope note:

- Most domain endpoints follow full layered flow
- The countries list endpoint reads directly from repository in controller, which is a pragmatic but thinner layering exception

## 3. Singleton Instance Pattern

Related sections: [12. Observability Pattern](#12-observability-pattern), [4. Repository Pattern](#4-repository-pattern)

Common instantiation approach:

- Modules export pre-instantiated singleton objects via export default new ClassName()

Used in:

- Services
- Repositories
- Logger module

Implications:

- Simple import ergonomics
- Shared process-wide state for timezone repository map
- Requires care when adding mutating behavior in concurrent/test contexts

## 4. Repository Pattern

Related sections: [10. External Provider Integration Pattern](#10-external-provider-integration-pattern), [8. Validation Pattern](#8-validation-pattern)

Repository responsibilities in this codebase:

- Encapsulate all provider/data source access
- Validate and normalize payload shapes
- Convert external/raw payloads into domain entities
- Raise AppError for operationally meaningful failures

Repository flavors:

- In-memory domain repository:
- timezone repository stores and validates country/timezone data in Map
- HTTP integration repositories:
- joke repository and geopolitical repository wrap fetch logic, timeouts, and transformation

## 5. Service Orchestration Pattern

Related sections: [6. Controller Pattern](#6-controller-pattern), [13. Response Contract Pattern](#13-response-contract-pattern)

Service layer conventions:

- Delegate data access to repositories
- Convert domain entities into response-oriented models
- Apply business rules and fallback behavior
- Wrap unknown failures as AppError 5xx

Examples:

- Timezone service resolves country-code precedence and computes UTC offsets
- Joke and geopolitical services add generatedAt and expose stable response shape independent of provider schema

## 6. Controller Pattern

Related sections: [7. Middleware Pipeline Pattern](#7-middleware-pipeline-pattern), [9. Error Normalization Pattern](#9-error-normalization-pattern)

Controller conventions:

- Static controller methods grouped by endpoint domain
- Thin request parsing and response shaping
- Async methods forward errors using next(error)
- Success payloads follow status/data envelope style

Current style variants:

- Some endpoints are synchronous and throw directly
- Async endpoints use explicit try/catch forwarding

## 7. Middleware Pipeline Pattern

Related sections: [11. Security-by-Default Pattern](#11-security-by-default-pattern), [8. Validation Pattern](#8-validation-pattern)

Cross-cutting middleware ordering pattern:

1. security headers
2. CORS
3. compression
4. cookie parsing
5. body parsing with limits
6. rate limiting for /api
7. CSRF token generation
8. request logging
9. routes
10. fallback 404
11. global error handler

Why this pattern is used:

- Security and parsing context established before business handlers
- Logging has access to fully shaped request metadata
- Final error middleware guarantees single response emission path

## 8. Validation Pattern

Related sections: [9. Error Normalization Pattern](#9-error-normalization-pattern), [11. Security-by-Default Pattern](#11-security-by-default-pattern)

Validation strategy:

- zod schemas for request query/body/params via validateRequest middleware
- zod schemas inside repository methods for defensive domain validation
- zod schema for environment variables at startup

Pattern outcomes:

- Consistent fail-fast behavior
- Input sanitization and normalization near boundaries
- Human-readable validation errors wrapped as operational AppError

## 9. Error Normalization Pattern

Related sections: [12. Observability Pattern](#12-observability-pattern), [13. Response Contract Pattern](#13-response-contract-pattern)

Error normalization architecture:

- AppError defines statusCode/status/isOperational
- transformError maps known error families into operational errors
- global handler branches dev vs prod response level
- production hides non-operational internals from clients

Log safety pattern:

- Error logger sanitizes request body fields and selected headers to reduce sensitive data leakage risk

## 10. External Provider Integration Pattern

Related sections: [4. Repository Pattern](#4-repository-pattern), [12. Observability Pattern](#12-observability-pattern)

Provider adapter pattern characteristics:

- Endpoint URL is configuration-driven with defaults
- fetch wrapped with AbortController timeout
- provider non-2xx mapped to meaningful AppError statuses
- payload structure checked via type guards or zod schema
- result mapped to stable internal domain entity

Implemented adapters:

- JokeAPI adapter for joke-of-day
- GDELT DOC adapter for geopolitical-event-of-day

## 11. Security-by-Default Pattern

Related sections: [7. Middleware Pipeline Pattern](#7-middleware-pipeline-pattern), [8. Validation Pattern](#8-validation-pattern)

Security patterns embedded in baseline setup:

- Helmet policy with strict CSP directives
- Origin allowlist CORS callback with explicit denial logging
- Route family rate limiting under /api
- CSRF token issuance on all requests (double-submit approach utilities)
- Request-size limits to reduce abuse surface
- Sensitive value redaction in logs

Pattern gap to track:

- CSRF validation middleware is available but not mounted in current route chain

## 12. Observability Pattern

Related sections: [9. Error Normalization Pattern](#9-error-normalization-pattern), [14. Project Conventions and Packaging](#14-project-conventions-and-packaging)

Observability design:

- Winston as central logger abstraction
- JSON structured logs in file transports for machine processing
- Development console transport for local readability
- morgan integrated as HTTP edge logger, with production forwarding into Winston stream

Event taxonomy pattern:

- Logs include categories and severity tags for validation, CORS, CSRF, and rate-limit events

## 13. Response Contract Pattern

Related sections: [6. Controller Pattern](#6-controller-pattern), [9. Error Normalization Pattern](#9-error-normalization-pattern)

Current response contract conventions:

- Success shape commonly uses status and data
- Error shape includes status and message; some paths include statusCode and additional metadata (for example rate limit retryAfter)

Practical implication:

- Consumers should rely on HTTP status and status/message fields first
- Endpoint-specific metadata remains additive

## 14. Project Conventions and Packaging

Related sections: [2. Layered Architecture Pattern](#2-layered-architecture-pattern), [12. Observability Pattern](#12-observability-pattern)

Codebase-level conventions observed:

- TypeScript strict-mode oriented patterns and explicit interfaces in core modules
- ES module import style with .js specifiers in source imports
- File organization by architectural role: config, middlewares, controllers, services, repositories, utils, validators
- Scripted quality gates through lint and format commands in package scripts

Operational packaging pattern:

- Development via tsx watch on src/app.ts
- Production startup from compiled dist/app.js

## 15. Pattern Application Checklist

Related sections: [2. Layered Architecture Pattern](#2-layered-architecture-pattern), [8. Validation Pattern](#8-validation-pattern), [9. Error Normalization Pattern](#9-error-normalization-pattern)

Use this checklist for new endpoints/features:

1. Route registers path and route-specific validation middleware only.
2. Controller keeps HTTP-level concerns only and forwards errors via next.
3. Service applies business logic and maps to stable response model.
4. Repository encapsulates all provider/data access and shape normalization.
5. zod validation exists for external or user-controlled input boundaries.
6. Operational failures use AppError with meaningful status code.
7. Logger is used for significant state transitions and failure modes.
8. Response follows existing status/data or status/message conventions.
9. Security middleware expectations are preserved for new route paths.

## 16. References

Implementation sources:

- src/app.ts
- src/routes/index.ts
- src/controllers/index.ts
- src/controllers/timezoneController.ts
- src/controllers/jokeController.ts
- src/controllers/geopoliticalEventController.ts
- src/services/timezoneService.ts
- src/services/jokeService.ts
- src/services/geopoliticalEventService.ts
- src/repositories/timezoneRepository.ts
- src/repositories/jokeRepository.ts
- src/repositories/geopoliticalEventRepository.ts
- src/middlewares/validateRequest.ts
- src/middlewares/errorHandler.ts
- src/middlewares/rateLimiter.ts
- src/middlewares/csrfProtection.ts
- src/config/securityHeaders.ts
- src/config/corsConfig.ts
- src/config/env.ts
- src/utils/errors/AppError.ts
- src/utils/errors/errorTransformers.ts
- src/utils/errors/errorLogger.ts
- src/utils/errors/errorResponses.ts
- src/utils/errors/sanitizer.ts
- src/utils/errors/index.ts
- src/utils/logger.ts
- src/validators/timezoneValidators.ts

Related docs:

- docs/SYSTEM_ARCHITECTURE.md
- docs/SECURITY_IMPLEMENTATION_SUMMARY.md
- docs/TIMEZONE_UI.md

## 17. Change Log

- 2026-03-19: Initial version created from current implementation.

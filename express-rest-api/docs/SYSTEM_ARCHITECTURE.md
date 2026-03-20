# Express REST API System Architecture

Date: 2026-03-19  
Owner: API Engineering  
Status: Draft

Purpose: Document the implemented system architecture, runtime behavior, and operational constraints of the Express REST API.  
Audience: Backend engineers, security reviewers, maintainers, and onboarding developers.

## Index

- [1. System Overview](#1-system-overview)
- [2. Runtime Stack](#2-runtime-stack)
- [3. Component Boundaries](#3-component-boundaries)
- [4. Request Lifecycle](#4-request-lifecycle)
- [5. API Surface and Routing](#5-api-surface-and-routing)
- [6. Data and State Model](#6-data-and-state-model)
- [7. Security Architecture](#7-security-architecture)
- [8. Error Handling Architecture](#8-error-handling-architecture)
- [9. Observability and Logging](#9-observability-and-logging)
- [10. Configuration and Environment](#10-configuration-and-environment)
- [11. Frontend Integration Architecture](#11-frontend-integration-architecture)
- [12. Operational Constraints and Risks](#12-operational-constraints-and-risks)
- [13. References](#13-references)
- [14. Change Log](#14-change-log)

## 1. System Overview

Related sections: [3. Component Boundaries](#3-component-boundaries), [4. Request Lifecycle](#4-request-lifecycle), [7. Security Architecture](#7-security-architecture)

This service is a TypeScript Express 5 application that serves both:

- JSON API endpoints under /api
- A server-rendered entry page at /

High-level architecture characteristics:

- Layered backend: routes -> controllers -> services -> repositories
- Security middleware-first request pipeline
- Centralized environment-based error handling
- Structured logging through Winston with environment-specific request logging strategy
- Mixed data sources:
- In-memory timezone domain data
- External HTTP providers for jokes and geopolitical events

## 2. Runtime Stack

Related sections: [10. Configuration and Environment](#10-configuration-and-environment), [9. Observability and Logging](#9-observability-and-logging)

Runtime and framework stack:

- Node.js ES Modules
- Express 5.2
- TypeScript 5.9 (compiled to dist for production)

Key middleware and libraries:

- helmet for security headers and CSP
- cors with strict origin checks
- compression for response compression
- cookie-parser for CSRF cookie handling
- express-rate-limit for API protection
- zod for environment and request validation
- morgan for HTTP request logging
- winston for structured application logs

View and static delivery:

- ejs view engine for /
- Static assets served from public

## 3. Component Boundaries

Related sections: [4. Request Lifecycle](#4-request-lifecycle), [8. Error Handling Architecture](#8-error-handling-architecture), [6. Data and State Model](#6-data-and-state-model)

### 3.1 Application Bootstrap Layer

The app bootstrap configures process-level runtime behavior:

- Express app initialization
- trust proxy in production
- global middleware registration
- route mounting
- fallback 404 for unknown paths
- terminal global error middleware
- HTTP listener startup

### 3.2 Route Layer

The route registration module maps URL paths to controller handlers and per-route validation middleware:

- Timezone query validation is applied at route level using validateRequest and zod schema
- CSRF token endpoint is exposed for browser clients
- Testing/demo endpoints include success, operational error, and unhandled error paths

### 3.3 Controller Layer

Controllers are thin HTTP orchestration units:

- Parse request inputs and route/query context
- Delegate domain logic to services (or repository directly for list-countries endpoint)
- Shape HTTP responses in status/data format
- Forward async errors via next for centralized error handling

### 3.4 Service Layer

Services encapsulate business behavior:

- Timezone service resolves country code priority and computes UTC offsets dynamically
- Joke and geopolitical services normalize repository entities into API response models and add generatedAt timestamps
- Services translate unknown exceptions into AppError for predictable API behavior

### 3.5 Repository Layer

Repositories abstract data/provider access:

- Timezone repository manages in-memory country/timezone map with zod-based validation and fallback retrieval strategy
- Joke repository calls JokeAPI and enforces payload shape/type guards
- Geopolitical repository calls GDELT DOC API and validates payload schema using zod

## 4. Request Lifecycle

Related sections: [7. Security Architecture](#7-security-architecture), [8. Error Handling Architecture](#8-error-handling-architecture)

Implemented processing order:

1. Security baseline:

- security headers
- CORS validation
- compression

2. Cookie and body parsing:

- cookie-parser
- JSON/urlencoded body parsing with 100kb limits

3. Global API rate limiting under /api/
4. CSRF token generation middleware for all requests
5. HTTP request logging:

- morgan dev in development
- morgan combined piped to Winston in production

6. Route matching and controller execution
7. Undefined route handling with AppError 404
8. Global error middleware transforms and emits environment-appropriate responses

Error propagation model:

- Async controllers use try/catch and next(error)
- Sync handlers throw AppError or Error directly
- Global handler logs, transforms known error types, then emits dev/prod responses

## 5. API Surface and Routing

Related sections: [4. Request Lifecycle](#4-request-lifecycle), [11. Frontend Integration Architecture](#11-frontend-integration-architecture)

### 5.1 Entry and Utility Endpoints

- GET / renders EJS timezone explorer page
- GET /health returns service status, timestamp, and uptime
- GET /api/csrf-token returns CSRF token payload

### 5.2 Timezone Domain Endpoints

- GET /api/timezones
- Query: countryCode, clientCountry, fallback
- Returns normalized timezone objects with name and computed offset
- GET /api/timezones/countries
- Returns country map and timezone counts

### 5.3 Content Endpoints

- GET /api/joke-of-day
- Fetches normalized joke payload via external provider
- GET /api/geopolitical-event-of-day
- Fetches normalized geopolitical event payload via external provider

### 5.4 Demonstration/Error Endpoints

- GET /api/example returns fixed success payload
- GET /api/error triggers operational AppError 400
- GET /api/crash throws unhandled programming error for error pipeline testing

## 6. Data and State Model

Related sections: [3. Component Boundaries](#3-component-boundaries), [12. Operational Constraints and Risks](#12-operational-constraints-and-risks)

State ownership:

- Timezone domain data is initialized from constants and persisted in-memory Map within singleton repository instance
- Joke/geopolitical data is fetched per request and not persisted locally

Key model shapes:

- Timezone API response includes countryCode, timezones array, count
- Joke API response includes category/type/content and generatedAt
- Geopolitical response includes title/url/publishedAt/source metadata and generatedAt

Fallback and resilience behavior:

- Timezone fallback mode resolves to default country code IN when requested country is missing/invalid
- External provider requests enforce AbortController timeouts and map failures to operational AppError statuses

## 7. Security Architecture

Related sections: [4. Request Lifecycle](#4-request-lifecycle), [10. Configuration and Environment](#10-configuration-and-environment), [12. Operational Constraints and Risks](#12-operational-constraints-and-risks)

Security controls implemented:

- Helmet security headers with strict CSP
- Strict origin-based CORS allowlist logic
- API rate limiting with custom audit logging for violations
- Body size limits on JSON and urlencoded payloads
- CSRF protection via Double Submit Cookie pattern
- Sensitive-field sanitization in error logs

Security control placement:

- Cross-cutting middleware controls are mounted before routes
- Validation controls occur at route/repository boundaries using zod
- Error sanitizer and production response masking prevent sensitive leakage

Notable implementation detail:

- CSRF token generation middleware runs globally; token validation middleware exists but is not currently mounted in route chain

## 8. Error Handling Architecture

Related sections: [9. Observability and Logging](#9-observability-and-logging), [4. Request Lifecycle](#4-request-lifecycle)

Error architecture components:

- AppError as canonical operational error type
- Error transformer module for common error families (JWT, Multer, Mongo-style errors)
- Request-aware error logger with body/header sanitization
- Environment split responses:
- Development: includes stack and request context
- Production: operational message only, non-operational generic message

Response contract behavior:

- AppError 4xx maps to status fail
- AppError 5xx maps to status error
- Unknown programming errors are treated as non-operational in production response path

## 9. Observability and Logging

Related sections: [8. Error Handling Architecture](#8-error-handling-architecture), [10. Configuration and Environment](#10-configuration-and-environment)

Logging architecture:

- Winston logger with JSON format and timestamp
- File transports:
- logs/error.log for level error
- logs/combined.log for all levels
- Development console transport with colorized readable format

Request logging:

- Development uses morgan dev directly
- Production routes morgan combined output into Winston info logs

Structured security events:

- CORS violations, rate-limit hits, CSRF failures, and validation failures are logged with category/severity fields

## 10. Configuration and Environment

Related sections: [7. Security Architecture](#7-security-architecture), [2. Runtime Stack](#2-runtime-stack)

Environment management pattern:

- zod schema validates env values at startup
- Process exits on invalid configuration
- Production-specific warnings for insecure FRONTEND_URL protocol

Primary environment concerns:

- Runtime: NODE_ENV, PORT, LOG_LEVEL
- Security/network: FRONTEND_URL, ALLOWED_ORIGINS
- External providers: JOKE_API_URL, GDELT_DOC_API_URL
- Optional infra hooks: DATABASE_URL, REDIS_URL

## 11. Frontend Integration Architecture

Related sections: [5. API Surface and Routing](#5-api-surface-and-routing), [7. Security Architecture](#7-security-architecture)

The project includes a thin browser client used for timezone exploration:

- Server-rendered EJS shell served at /
- Static JS client fetches countries and timezone data from API
- Static CSS provides responsive UI presentation and animations

Frontend request behavior:

- Initial load calls /api/timezones/countries
- Form submit calls /api/timezones with selected country code
- UI handles loading, error display, and result rendering with safe DOM APIs

## 12. Operational Constraints and Risks

Related sections: [6. Data and State Model](#6-data-and-state-model), [7. Security Architecture](#7-security-architecture)

Current architectural constraints:

- Timezone data storage is in-memory only; state resets on restart and does not scale horizontally without external state
- External endpoints depend on third-party provider availability and latency
- Single process startup path with direct app.listen in bootstrap module

Residual risks to track:

- CSRF validation middleware is implemented but not mounted for non-safe methods
- Mixed route-level async error patterns (manual try/catch instead of consistent wrapper strategy)
- Production durability limits for timezone write operations due to non-persistent storage

## 13. References

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
- src/middlewares/errorHandler.ts
- src/middlewares/rateLimiter.ts
- src/middlewares/csrfProtection.ts
- src/middlewares/validateRequest.ts
- src/config/env.ts
- src/config/corsConfig.ts
- src/config/securityHeaders.ts
- src/utils/errors/index.ts
- src/utils/logger.ts
- src/validators/timezoneValidators.ts
- src/utils/constants/timezones.ts
- views/index.ejs
- public/js/app.js

Related documentation:

- docs/SECURITY_IMPLEMENTATION_SUMMARY.md
- docs/SECURITY_AUDIT_REPORT.md
- docs/TIMEZONE_UI.md

## 14. Change Log

- 2026-03-19: Initial version created from current implementation.

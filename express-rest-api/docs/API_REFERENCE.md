# Express REST API — Developer & Manager Reference

**Status:** Live · **Version:** 1.0.0 · **Last Updated:** 19 March 2026  
**Owner:** Engineering Team  
**Audience:** Backend developers, frontend integrators, and non-technical managers

This document is the single source of truth for every HTTP endpoint in the Express REST API, covering request/response shapes, validation rules, security controls, error codes, and operational notes. All content is derived directly from the source code.

---

## Index

1. [What This API Does](#1-what-this-api-does)
2. [Base URL & Environment](#2-base-url--environment)
3. [Endpoint Quick-Reference Table](#3-endpoint-quick-reference-table)
4. [Endpoints In Detail](#4-endpoints-in-detail)
   - [4.1 Home Page](#41-home-page----get-)
   - [4.2 Health Check](#42-health-check----get-health)
   - [4.3 CSRF Token](#43-csrf-token----get-apicsrf-token)
   - [4.4 Timezones by Country](#44-timezones-by-country----get-apitimezones)
   - [4.5 All Countries](#45-all-countries----get-apitimezonescountries)
   - [4.6 Joke of the Day](#46-joke-of-the-day----get-apijoke-of-day)
   - [4.7 Geopolitical Event of the Day](#47-geopolitical-event-of-the-day----get-apigeopolitical-event-of-day)
   - [4.8 Example Endpoint](#48-example-endpoint----get-apiexample)
5. [Standard Response Shapes](#5-standard-response-shapes)
6. [Error Codes & Messages](#6-error-codes--messages)
7. [Security Controls](#7-security-controls)
   - [7.1 Rate Limiting](#71-rate-limiting)
   - [7.2 CSRF Protection](#72-csrf-protection)
   - [7.3 CORS Policy](#73-cors-policy)
   - [7.4 Security Headers](#74-security-headers)
8. [Environment Configuration](#8-environment-configuration)
9. [Architecture Overview](#9-architecture-overview)
10. [Supported Countries & Timezones](#10-supported-countries--timezones)
11. [References](#11-references)

---

## 1. What This API Does

The Express REST API is a production-grade backend service that provides three main capabilities accessible by any HTTP client (browser, mobile app, or third-party system):

| Capability                        | Plain-Language Summary                                                                                                          |
| --------------------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| **Timezone lookup**               | Given a two-letter country code (e.g., `US`, `IN`), return every timezone that country observes, including current UTC offsets. |
| **Joke of the day**               | Fetch a safe, randomly selected joke from the JokeAPI provider.                                                                 |
| **Geopolitical event of the day** | Fetch the most recent geopolitical headline from the GDELT Document API (global news coverage, last 24 hours).                  |

The API also exposes a health-check endpoint for infrastructure monitoring and a CSRF-token endpoint required for browser-based form submissions.

---

## 2. Base URL & Environment

| Environment       | Base URL                                           |
| ----------------- | -------------------------------------------------- |
| Local development | `http://localhost:3000`                            |
| Production        | Configured via `FRONTEND_URL` environment variable |

All API data endpoints are prefixed with `/api/`. The root `/` serves an HTML page (Timezone Explorer UI). The `/health` endpoint is intentionally not rate-limited so monitoring tools can poll freely.

---

## 3. Endpoint Quick-Reference Table

| Method | Path                             | Auth | Rate Limited | Description                                  |
| ------ | -------------------------------- | ---- | ------------ | -------------------------------------------- |
| `GET`  | `/`                              | None | Yes          | Renders the Timezone Explorer web page       |
| `GET`  | `/health`                        | None | **No**       | Infrastructure health check                  |
| `GET`  | `/api/csrf-token`                | None | Yes          | Returns a fresh CSRF cookie                  |
| `GET`  | `/api/timezones`                 | None | Yes          | Timezones for a given country code           |
| `GET`  | `/api/timezones/countries`       | None | Yes          | All supported countries with timezone counts |
| `GET`  | `/api/joke-of-day`               | None | Yes          | Random safe joke from JokeAPI                |
| `GET`  | `/api/geopolitical-event-of-day` | None | Yes          | Latest geopolitical headline from GDELT      |
| `GET`  | `/api/example`                   | None | Yes          | Static example success response              |

> **Manager Note:** "Rate Limited" means the API allows up to **100 requests per 15 minutes per IP address**. This prevents automated abuse while being well above normal human usage.

---

## 4. Endpoints In Detail

---

### 4.1 Home Page — `GET /`

Renders the **Timezone Explorer** interactive web page (EJS template). Not a data endpoint — no JSON returned.

**Response:** HTML page (`text/html`)

---

### 4.2 Health Check — `GET /health`

Used by load balancers, uptime monitors (e.g., UptimeRobot, Pingdom), and container orchestrators to verify the server is alive.

**Request:** No parameters required.

**Success Response — `200 OK`**

```json
{
  "status": "ok",
  "timestamp": "2026-03-19T10:30:00.000Z",
  "uptime": 3600.123
}
```

| Field       | Type                | Description                                  |
| ----------- | ------------------- | -------------------------------------------- |
| `status`    | `string`            | Always `"ok"` when the server responds       |
| `timestamp` | `string` (ISO 8601) | Server time at the moment of the request     |
| `uptime`    | `number`            | Seconds the Node.js process has been running |

> **Note:** This endpoint is **excluded from rate limiting** to allow frequent polling by monitoring infrastructure.

---

### 4.3 CSRF Token — `GET /api/csrf-token`

Browser-based applications that submit state-changing requests (POST, PUT, DELETE) must first obtain a CSRF token. This endpoint sets the `XSRF-TOKEN` cookie and returns the token value in the body.

**Request:** No parameters required.

**How the CSRF flow works (for developers):**

1. On page load, call `GET /api/csrf-token`.
2. The server sets a `XSRF-TOKEN` cookie in the response.
3. For every subsequent state-changing request, read the cookie value and send it as the `X-XSRF-TOKEN` request header.
4. The server validates that the header value matches the cookie value (Double Submit Cookie pattern).

**Cookie set:**

| Cookie       | `httpOnly`            | `secure`             | `sameSite` | `maxAge` |
| ------------ | --------------------- | -------------------- | ---------- | -------- |
| `XSRF-TOKEN` | `false` (JS-readable) | `true` in production | `strict`   | 24 hours |

> **Manager Note:** CSRF (Cross-Site Request Forgery) is a type of attack where a malicious website tricks a user's browser into making unwanted requests to this API. The CSRF token flow prevents this by requiring knowledge of a secret that only the legitimate frontend application can read.

---

### 4.4 Timezones by Country — `GET /api/timezones`

Returns the list of IANA timezone identifiers and their current UTC offsets for a given country.

#### Query Parameters

| Parameter       | Type     | Required | Validation                               | Description                                                                                                                |
| --------------- | -------- | -------- | ---------------------------------------- | -------------------------------------------------------------------------------------------------------------------------- |
| `countryCode`   | `string` | No       | 2 uppercase letters (ISO 3166-1 alpha-2) | Country to look up. If omitted, the server uses the `clientCountry` hint or a global default.                              |
| `clientCountry` | `string` | No       | 2 uppercase letters                      | Hint from the frontend about the user's detected country (e.g., from browser geolocation).                                 |
| `fallback`      | `string` | No       | `"true"`, `"false"`, `"1"`, or `"0"`     | When `true` or `1`, an unrecognised country code silently falls back to the default country instead of returning an error. |

#### Behaviour Modes

| Mode                 | How to trigger                          | What happens if country not found              |
| -------------------- | --------------------------------------- | ---------------------------------------------- |
| **Strict** (default) | Omit `fallback` or set `fallback=false` | Returns `400 Bad Request`                      |
| **Fallback**         | Set `fallback=true` or `fallback=1`     | Returns timezones for the default country (US) |

#### Example Requests

```
# Strict lookup for India
GET /api/timezones?countryCode=IN

# United States with fallback enabled
GET /api/timezones?countryCode=US&fallback=true

# Send a browser-detected country hint
GET /api/timezones?countryCode=DE&clientCountry=DE
```

#### Success Response — `200 OK`

```json
{
  "status": "success",
  "data": {
    "countryCode": "US",
    "timezones": [
      { "name": "America/New_York", "offset": -5 },
      { "name": "America/Chicago", "offset": -6 },
      { "name": "America/Denver", "offset": -7 },
      { "name": "America/Los_Angeles", "offset": -8 },
      { "name": "America/Anchorage", "offset": -9 },
      { "name": "Pacific/Honolulu", "offset": -10 }
    ],
    "count": 6
  }
}
```

| Field                | Type     | Description                                                               |
| -------------------- | -------- | ------------------------------------------------------------------------- |
| `countryCode`        | `string` | Resolved ISO 3166-1 alpha-2 code (may differ from input in fallback mode) |
| `timezones`          | `array`  | List of timezone objects for the country                                  |
| `timezones[].name`   | `string` | IANA timezone identifier (e.g., `"America/New_York"`)                     |
| `timezones[].offset` | `number` | Current UTC offset in hours (e.g., `-5`, `+5.5`). Reflects DST.           |
| `count`              | `number` | Number of timezones in the list                                           |

#### Validation Errors — `400 Bad Request`

```json
{
  "status": "error",
  "statusCode": 400,
  "message": "Validation error: countryCode: Country code must be exactly 2 characters"
}
```

---

### 4.5 All Countries — `GET /api/timezones/countries`

Returns a map of all countries supported by the API, each with their name, timezone list, and a count.

**Request:** No parameters required.

**Success Response — `200 OK`**

```json
{
  "status": "success",
  "data": {
    "countries": {
      "IN": { "name": "India", "timezones": ["Asia/Kolkata"], "count": 1 },
      "US": {
        "name": "United States",
        "timezones": ["America/New_York", "..."],
        "count": 6
      },
      "GB": {
        "name": "United Kingdom",
        "timezones": ["Europe/London"],
        "count": 1
      }
    },
    "totalCountries": 19
  }
}
```

| Field                       | Type       | Description                                  |
| --------------------------- | ---------- | -------------------------------------------- |
| `countries`                 | `object`   | Map keyed by ISO 3166-1 alpha-2 country code |
| `countries[code].name`      | `string`   | Full country name                            |
| `countries[code].timezones` | `string[]` | IANA timezone names for that country         |
| `countries[code].count`     | `number`   | Number of timezones                          |
| `totalCountries`            | `number`   | Total number of countries in the dataset     |

See [Section 10](#10-supported-countries--timezones) for the full list of supported countries.

---

### 4.6 Joke of the Day — `GET /api/joke-of-day`

Fetches a random, safe-mode joke from the [JokeAPI](https://v2.jokeapi.dev) third-party provider. Jokes are filtered to exclude explicit, racist, religious, political, and dark-humour categories.

**Request:** No parameters required.

**Success Response — `200 OK`**

```json
{
  "status": "success",
  "data": {
    "category": "Programming",
    "type": "twopart",
    "content": "",
    "setup": "Why do programmers prefer dark mode?",
    "delivery": "Because light attracts bugs!",
    "source": "https://v2.jokeapi.dev/joke/Any?safe-mode",
    "generatedAt": "2026-03-19T10:30:00.000Z"
  }
}
```

```json
{
  "status": "success",
  "data": {
    "category": "Misc",
    "type": "single",
    "content": "I'm reading a book about anti-gravity. It's impossible to put down.",
    "setup": null,
    "delivery": null,
    "source": "https://v2.jokeapi.dev/joke/Any?safe-mode",
    "generatedAt": "2026-03-19T10:30:00.000Z"
  }
}
```

| Field         | Type                      | Description                                                                  |
| ------------- | ------------------------- | ---------------------------------------------------------------------------- |
| `category`    | `string`                  | Joke category (e.g., `"Programming"`, `"Misc"`)                              |
| `type`        | `"single"` \| `"twopart"` | Single-line joke or two-part setup/delivery                                  |
| `content`     | `string`                  | The full joke text (populated for `single` type; empty string for `twopart`) |
| `setup`       | `string \| null`          | The question part of a two-part joke; `null` for single jokes                |
| `delivery`    | `string \| null`          | The punchline of a two-part joke; `null` for single jokes                    |
| `source`      | `string`                  | URL of the upstream provider used                                            |
| `generatedAt` | `string` (ISO 8601)       | Timestamp when the response was generated                                    |

#### Provider Error Responses

| Scenario                          | HTTP Status               | Message                                     |
| --------------------------------- | ------------------------- | ------------------------------------------- |
| Provider returned an error status | `502 Bad Gateway`         | `"Failed to fetch joke from provider"`      |
| Provider did not respond in time  | `504 Gateway Timeout`     | `"Joke provider request timed out"`         |
| Provider is unreachable           | `503 Service Unavailable` | `"Joke service is temporarily unavailable"` |

> **Manager Note:** Because this endpoint calls an external service, it may occasionally be slower or unavailable if JokeAPI experiences downtime. The server enforces a **5-second timeout** to prevent slow responses from blocking the API.

---

### 4.7 Geopolitical Event of the Day — `GET /api/geopolitical-event-of-day`

Returns one representative geopolitical headline from the past 24 hours, sourced from the [GDELT Document API](https://api.gdeltproject.org). The query covers terrorism, foreign policy, public sector management, and crisis-related themes.

**Request:** No parameters required.

**Success Response — `200 OK`**

```json
{
  "status": "success",
  "data": {
    "title": "Leaders gather for emergency UN Security Council session",
    "summary": "Most recent geopolitical headline observed in the last 24 hours across global news coverage.",
    "url": "https://example-news-outlet.com/article/un-security-council",
    "publishedAt": "2026-03-19T08:15:00Z",
    "source": "example-news-outlet.com",
    "sourceCountry": "United States",
    "language": "English",
    "imageUrl": "https://example-news-outlet.com/images/article.jpg",
    "provider": "GDELT Document API v2",
    "generatedAt": "2026-03-19T10:30:00.000Z"
  }
}
```

| Field           | Type                | Description                                       |
| --------------- | ------------------- | ------------------------------------------------- |
| `title`         | `string`            | Headline of the news article                      |
| `summary`       | `string`            | Fixed contextual note about the data source       |
| `url`           | `string`            | Direct link to the original article               |
| `publishedAt`   | `string` (ISO 8601) | When the article was published                    |
| `source`        | `string`            | Domain of the news outlet                         |
| `sourceCountry` | `string`            | Country of the news source                        |
| `language`      | `string`            | Language of the article                           |
| `imageUrl`      | `string \| null`    | Social/preview image URL; `null` if not available |
| `provider`      | `string`            | The upstream data provider name                   |
| `generatedAt`   | `string` (ISO 8601) | Timestamp when the API response was generated     |

#### Provider Error Responses

| Scenario                          | HTTP Status               | Message                                                                   |
| --------------------------------- | ------------------------- | ------------------------------------------------------------------------- |
| Provider returned an error status | `502 Bad Gateway`         | `"Failed to fetch geopolitical event from provider"`                      |
| Provider rate-limited the request | `503 Service Unavailable` | `"Geopolitical provider rate-limited the request. Please retry shortly."` |
| Provider did not respond in time  | `504 Gateway Timeout`     | `"Geopolitical provider request timed out"`                               |

> **Manager Note:** The GDELT API is a free, public service. Occasional slow responses or temporary unavailability are possible. The server enforces a **10-second timeout**. No data is cached — each request fetches live data.

---

### 4.8 Example Endpoint — `GET /api/example`

A static reference endpoint demonstrating the standard success response format. Useful for integration testing and connectivity checks.

**Success Response — `200 OK`**

```json
{
  "status": "success",
  "data": {
    "message": "Success",
    "timestamp": "2026-03-19T10:30:00.000Z"
  }
}
```

---

## 5. Standard Response Shapes

Every endpoint returns JSON with a consistent envelope:

### Success

```json
{
  "status": "success",
  "data": {}
}
```

### Client Error (4xx)

```json
{
  "status": "error",
  "statusCode": 400,
  "message": "Human-readable description of the problem"
}
```

In **development mode only**, error responses additionally include a `stack` field with the full stack trace to aid debugging. Stack traces are never sent in production.

### Rate Limit Exceeded (429)

```json
{
  "status": "error",
  "statusCode": 429,
  "message": "Too many requests from this IP, please try again later",
  "retryAfter": "900"
}
```

The `RateLimit-*` response headers (standardised format) are included on every `/api/` response to let clients track their remaining quota.

---

## 6. Error Codes & Messages

| HTTP Status                 | When It Occurs                                                | Example Message                                                              |
| --------------------------- | ------------------------------------------------------------- | ---------------------------------------------------------------------------- |
| `400 Bad Request`           | Request validation failed (invalid parameter format or value) | `"Validation error: countryCode: Country code must be exactly 2 characters"` |
| `403 Forbidden`             | CSRF token missing or mismatched; CORS origin blocked         | `"CSRF token missing"`                                                       |
| `404 Not Found`             | Requested URL does not exist                                  | `"Cannot find /api/unknown on this server"`                                  |
| `429 Too Many Requests`     | IP exceeded 100 requests in 15 minutes                        | `"Too many requests from this IP, please try again later"`                   |
| `500 Internal Server Error` | Unhandled server-side programming error                       | `"Something went wrong"` (production)                                        |
| `502 Bad Gateway`           | External provider (JokeAPI / GDELT) returned a failure status | `"Failed to fetch joke from provider"`                                       |
| `503 Service Unavailable`   | External provider is temporarily unavailable or rate-limited  | `"Joke service is temporarily unavailable"`                                  |
| `504 Gateway Timeout`       | External provider did not respond within the timeout window   | `"Joke provider request timed out"`                                          |

> **Manager Note:** Errors in the 5xx range indicate a server-side or third-party issue — the client request was not at fault. Errors in the 4xx range mean the request itself needs to be corrected.

---

## 7. Security Controls

### 7.1 Rate Limiting

The API applies rate limits using `express-rate-limit` to protect against denial-of-service and brute-force attacks.

| Limiter                     | Applied To                  | Window     | Max Requests | Counts Successful?                   |
| --------------------------- | --------------------------- | ---------- | ------------ | ------------------------------------ |
| **API Limiter**             | All `/api/*` routes         | 15 minutes | 100 per IP   | Yes                                  |
| **Auth Limiter** (reserved) | Future `/api/auth/*` routes | 15 minutes | 5 per IP     | No (successful requests not counted) |

- Rate limit information is returned in standardised `RateLimit-*` response headers.
- The `/health` endpoint is explicitly **excluded** from rate limiting.
- When the limit is exceeded, a `429` response is returned and the event is logged with `severity: MEDIUM`.

### 7.2 CSRF Protection

State-changing requests (POST, PUT, DELETE, PATCH) that originate from a browser must include a valid CSRF token using the **Double Submit Cookie pattern**:

1. Fetch a token via `GET /api/csrf-token`.
2. The server sets `XSRF-TOKEN` cookie (readable by JavaScript).
3. For every state-changing request, add the header `X-XSRF-TOKEN: <cookie value>`.
4. The server verifies the header matches the cookie.

Safe HTTP methods (`GET`, `HEAD`, `OPTIONS`) bypass CSRF validation entirely.

CSRF failures are logged with `severity: HIGH, category: CSRF_FAILURE`.

### 7.3 CORS Policy

Cross-Origin Resource Sharing is configured with strict origin validation:

| Environment | Allowed Origins                                                     |
| ----------- | ------------------------------------------------------------------- |
| Development | `http://localhost:3000`, `http://127.0.0.1:3000`                    |
| Production  | Value of `FRONTEND_URL` env var + comma-separated `ALLOWED_ORIGINS` |

- Requests from origins not on the allowlist receive a `403 Forbidden` response.
- Requests with no `Origin` header (mobile apps, curl, Postman, same-origin requests) are always allowed.
- Credentials (cookies) are permitted (`credentials: true`).
- CORS violations are logged with `severity: MEDIUM, category: CORS_VIOLATION`.

### 7.4 Security Headers

All responses include the following security headers enforced via **Helmet.js**:

| Header                      | Value / Effect                                                           |
| --------------------------- | ------------------------------------------------------------------------ |
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains; preload` — forces HTTPS for 1 year |
| `Content-Security-Policy`   | Strict; no `unsafe-inline`; `objectSrc: none`; `frameSrc: none`          |
| `X-Frame-Options`           | `DENY` — prevents clickjacking                                           |
| `X-Content-Type-Options`    | `nosniff` — prevents MIME-type sniffing                                  |
| `Referrer-Policy`           | `strict-origin-when-cross-origin`                                        |
| `X-DNS-Prefetch-Control`    | `off`                                                                    |
| `X-Powered-By`              | Removed entirely                                                         |

---

## 8. Environment Configuration

The API validates all environment variables on startup using **Zod**. Missing or invalid values cause the server to exit with a clear error message.

| Variable            | Required | Default                                                         | Description                                                             |
| ------------------- | -------- | --------------------------------------------------------------- | ----------------------------------------------------------------------- |
| `NODE_ENV`          | No       | `development`                                                   | Runtime mode: `development`, `production`, or `test`                    |
| `PORT`              | No       | `3000`                                                          | TCP port the server listens on (1–65535)                                |
| `LOG_LEVEL`         | No       | `info`                                                          | Winston log verbosity: `error`, `warn`, `info`, or `debug`              |
| `FRONTEND_URL`      | No       | —                                                               | Full URL of the frontend application (must be `https://` in production) |
| `ALLOWED_ORIGINS`   | No       | —                                                               | Comma-separated list of additional allowed CORS origins                 |
| `DATABASE_URL`      | No       | —                                                               | Database connection string (Prisma)                                     |
| `REDIS_URL`         | No       | —                                                               | Redis connection URL for distributed rate limiting                      |
| `JOKE_API_URL`      | No       | `https://v2.jokeapi.dev/joke/Any?safe-mode&type=single,twopart` | Override for the joke provider URL                                      |
| `GDELT_DOC_API_URL` | No       | `https://api.gdeltproject.org/api/v2/doc/doc`                   | Override for the GDELT provider URL                                     |

Copy `.env.example` to `.env` and set values before starting the server. **Never commit `.env` to version control.**

### Quick Start (Development)

```bash
# Install dependencies
pnpm install

# Copy environment file
cp .env.example .env

# Start with hot-reload
pnpm dev
```

The server starts at `http://localhost:3000`.

### Production Build

```bash
pnpm build    # Compiles TypeScript → dist/
pnpm start    # Runs dist/app.js
```

---

## 9. Architecture Overview

The API follows a strict **MVC + Layered architecture**. Every request travels through the same pipeline, ensuring consistent validation, error handling, and logging at every layer.

```
HTTP Request
     │
     ▼
┌─────────────────────────────────────────────────────────┐
│  Middleware Pipeline (applied in order)                 │
│  ─ Security headers (Helmet)                            │
│  ─ CORS validation                                      │
│  ─ Response compression                                 │
│  ─ Cookie parser                                        │
│  ─ Body parser (JSON & URL-encoded, max 100 kb)         │
│  ─ Rate limiter (100 req / 15 min / IP)                 │
│  ─ CSRF token generation                                │
│  ─ HTTP request logger (Morgan)                         │
└────────────────────────┬────────────────────────────────┘
                         │
                         ▼
              ┌──────────────────────┐
              │   Route Definition   │  src/routes/index.ts
              │  (endpoint mapping + │
              │  validation middleware│
              └──────────┬───────────┘
                         │
                         ▼
              ┌──────────────────────┐
              │     Controller       │  src/controllers/
              │  (HTTP I/O only;     │
              │  parse req, send res)│
              └──────────┬───────────┘
                         │
                         ▼
              ┌──────────────────────┐
              │      Service         │  src/services/
              │  (business logic &   │
              │  orchestration)      │
              └──────────┬───────────┘
                         │
                         ▼
              ┌──────────────────────┐
              │     Repository       │  src/repositories/
              │  (data access: DB    │
              │  or external APIs)   │
              └──────────┬───────────┘
                         │
                         ▼
              ┌──────────────────────┐
              │  External Systems    │
              │  · Static timezone   │
              │    data (in-memory)  │
              │  · JokeAPI (HTTPS)   │
              │  · GDELT API (HTTPS) │
              └──────────────────────┘
                         │
                         ▼  (on error at any layer)
              ┌──────────────────────┐
              │  Global Error Handler│  src/middlewares/errorHandler.ts
              │  (logs + formats     │
              │  error response)     │
              └──────────────────────┘
```

### Key Design Decisions

| Decision                                   | Rationale                                                                                                                                                  |
| ------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Layer boundaries strictly enforced         | Business logic stays in services; HTTP concerns stay in controllers. Easier to test and maintain.                                                          |
| Express 5 used (no `asyncHandler` wrapper) | Express 5 natively propagates async errors, eliminating boilerplate `try/catch` in route handlers.                                                         |
| Zod for all input validation               | Schema-first validation with automatic TypeScript type inference. Errors are user-friendly and structured.                                                 |
| In-memory timezone data                    | Timezone data is static and small. No database round-trip needed. Data is managed via the repository abstraction.                                          |
| External API timeouts                      | All outbound HTTP calls use `AbortController` to enforce timeouts (5 s for jokes, 10 s for GDELT), preventing slow external services from hanging the API. |

---

## 10. Supported Countries & Timezones

The following 19 countries are available in the timezone dataset. Pass the **Code** value to the `countryCode` query parameter.

| Code | Country        | Timezones                                                   |
| ---- | -------------- | ----------------------------------------------------------- |
| `AU` | Australia      | Sydney, Melbourne, Brisbane, Perth, Adelaide                |
| `BR` | Brazil         | São Paulo, Manaus, Fortaleza                                |
| `CA` | Canada         | Toronto, Vancouver, Edmonton, Winnipeg                      |
| `CN` | China          | Shanghai                                                    |
| `DE` | Germany        | Berlin                                                      |
| `EG` | Egypt          | Cairo                                                       |
| `ES` | Spain          | Madrid                                                      |
| `FR` | France         | Paris                                                       |
| `GB` | United Kingdom | London                                                      |
| `IN` | India          | Kolkata                                                     |
| `IT` | Italy          | Rome                                                        |
| `JP` | Japan          | Tokyo                                                       |
| `MX` | Mexico         | Mexico City, Monterrey, Cancun                              |
| `NG` | Nigeria        | Lagos                                                       |
| `NZ` | New Zealand    | Auckland, Chatham                                           |
| `RU` | Russia         | Moscow, Vladivostok, Novosibirsk                            |
| `SG` | Singapore      | Singapore                                                   |
| `US` | United States  | New York, Chicago, Denver, Los Angeles, Anchorage, Honolulu |
| `ZA` | South Africa   | Johannesburg                                                |

UTC offsets returned by the API reflect **current** Daylight Saving Time adjustments (calculated at request time).

---

## 11. References

| Source                           | Path                                                                                                  |
| -------------------------------- | ----------------------------------------------------------------------------------------------------- |
| Route definitions                | [src/routes/index.ts](../src/routes/index.ts)                                                         |
| Application bootstrap            | [src/app.ts](../src/app.ts)                                                                           |
| Timezone controller              | [src/controllers/timezoneController.ts](../src/controllers/timezoneController.ts)                     |
| Joke controller                  | [src/controllers/jokeController.ts](../src/controllers/jokeController.ts)                             |
| Geopolitical event controller    | [src/controllers/geopoliticalEventController.ts](../src/controllers/geopoliticalEventController.ts)   |
| Timezone service                 | [src/services/timezoneService.ts](../src/services/timezoneService.ts)                                 |
| Joke service                     | [src/services/jokeService.ts](../src/services/jokeService.ts)                                         |
| Geopolitical event service       | [src/services/geopoliticalEventService.ts](../src/services/geopoliticalEventService.ts)               |
| Timezone repository              | [src/repositories/timezoneRepository.ts](../src/repositories/timezoneRepository.ts)                   |
| Joke repository                  | [src/repositories/jokeRepository.ts](../src/repositories/jokeRepository.ts)                           |
| Geopolitical event repository    | [src/repositories/geopoliticalEventRepository.ts](../src/repositories/geopoliticalEventRepository.ts) |
| Timezone query validation schema | [src/validators/timezoneValidators.ts](../src/validators/timezoneValidators.ts)                       |
| Request validation middleware    | [src/middlewares/validateRequest.ts](../src/middlewares/validateRequest.ts)                           |
| Rate limiter config              | [src/middlewares/rateLimiter.ts](../src/middlewares/rateLimiter.ts)                                   |
| CSRF protection                  | [src/middlewares/csrfProtection.ts](../src/middlewares/csrfProtection.ts)                             |
| CORS configuration               | [src/config/corsConfig.ts](../src/config/corsConfig.ts)                                               |
| Security headers (Helmet)        | [src/config/securityHeaders.ts](../src/config/securityHeaders.ts)                                     |
| Environment validation           | [src/config/env.ts](../src/config/env.ts)                                                             |
| AppError class                   | [src/utils/errors/AppError.ts](../src/utils/errors/AppError.ts)                                       |
| Global error handler             | [src/middlewares/errorHandler.ts](../src/middlewares/errorHandler.ts)                                 |
| Timezone seed data               | [src/utils/constants/timezones.ts](../src/utils/constants/timezones.ts)                               |
| Existing README                  | [README.md](../README.md)                                                                             |
| Security audit                   | [docs/SECURITY_AUDIT_REPORT.md](SECURITY_AUDIT_REPORT.md)                                             |
| Security implementation summary  | [docs/SECURITY_IMPLEMENTATION_SUMMARY.md](SECURITY_IMPLEMENTATION_SUMMARY.md)                         |

---

_Document generated from source code at commit HEAD · 19 March 2026_

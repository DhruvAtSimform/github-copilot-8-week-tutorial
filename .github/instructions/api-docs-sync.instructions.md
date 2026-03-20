---
applyTo: "**/{express-rest-api/src/app.ts,express-rest-api/src/routes/**/*.ts,express-rest-api/docs/API_REFERENCE.md}"
---

# API Docs Sync Rules

Apply these rules whenever route definitions or API behavior changes.

## Scope

- Route declarations in `express-rest-api/src/app.ts` and `express-rest-api/src/routes/`.
- Public API documentation in `express-rest-api/docs/API_REFERENCE.md`.

## Required Updates

- Keep the quick-reference table aligned with implemented endpoints.
- Keep detailed endpoint sections aligned with request/response behavior.
- Document validation constraints for query, params, and body inputs.
- Document operational errors and expected status codes.
- Mention security behavior when relevant (rate limiting, CSRF, CORS, headers).

## Response Contracts

- Success responses should follow: `{ "status": "success", "data": { ... } }`
- Error responses should follow: `{ "status": "error", "statusCode": number, "message": string }`

## Verification

- Run `.github/skills/api-doc-sync/scripts/check-endpoint-doc-coverage.mjs` from the workspace root with Node.
- Resolve missing or stale endpoint entries before finalizing changes.

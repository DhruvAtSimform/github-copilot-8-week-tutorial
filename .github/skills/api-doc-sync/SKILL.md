---
name: api-doc-sync
description: "Generate and maintain Express REST API documentation. Use when adding, changing, reviewing, or validating endpoints and response contracts in src/app.ts, src/routes/, and docs/API_REFERENCE.md."
argument-hint: "Describe the API change, files touched, and whether you want full docs update or doc gap check."
user-invocable: true
---

# API Documentation Sync

Create and maintain accurate API documentation for this Express REST API project.

## When to Use

- A route is added, removed, or renamed in `src/app.ts` or `src/routes/`.
- A controller response shape changes and docs must be updated.
- A code review asks for API reference updates.
- You need a fast check for route-to-documentation mismatches.

## Inputs To Gather

- Changed endpoint method and path.
- Request validation rules (query, params, body).
- Success and error response shapes.
- Security behavior (rate limit, CSRF, CORS, headers).

## Procedure

1. Inventory implemented endpoints from `src/app.ts` and route files in `src/routes/`.
2. Compare current implementation against `docs/API_REFERENCE.md`.
3. Update endpoint quick-reference table and detailed endpoint sections.
4. Ensure each endpoint entry includes:
   - Method and path
   - Purpose and behavior
   - Input parameters and validation
   - Success response example
   - Error scenarios and status codes
   - Security notes if applicable
5. Preserve the existing response format conventions:
   - Success: `{ "status": "success", "data": { ... } }`
   - Error: `{ "status": "error", "statusCode": number, "message": string }`
6. Run the endpoint coverage checker: [check-endpoint-doc-coverage.mjs](./scripts/check-endpoint-doc-coverage.mjs)
7. If the checker reports gaps, update docs and rerun until clean.

## Completion Criteria

- Every live endpoint is represented in `docs/API_REFERENCE.md`.
- Quick-reference table and detailed sections are consistent.
- Validation and error details match implementation.
- Coverage checker exits successfully.

## Notes

- Keep manager-facing language clear and non-ambiguous.
- Do not document internal test endpoints unless they are intentionally public.
- Prefer concise examples that match real response shapes.

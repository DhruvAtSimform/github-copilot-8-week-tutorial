---
applyTo: "**/src/{routes,controllers,services,repositories}/**/*.ts"
---

# API Development Guidelines - Express REST API

Use these rules for all API work in `src/routes/`, `src/controllers/`, `src/services/`, and `src/repositories/`.

## 1. Non-Negotiable Architecture

Data flow must always be:

```text
Request -> Route -> Controller -> Service -> Repository -> Database
Response <- Route <- Controller <- Service <- Repository <- Database
```

Layer boundaries:

- Routes: endpoint mapping + middleware only.
- Controllers: HTTP input/output handling only.
- Services: business logic and orchestration.
- Repositories: data access and DB-to-domain mapping.

Never violate boundaries:

- No business logic in routes/controllers.
- No HTTP handling in services/repositories.
- No raw DB queries outside repositories.
- Do not use asyncHandler for async route handlers. Express 5 handles it by default.

## 2. Required Coding Rules

- Validate and sanitize request input (for example `express-validator` or `zod`).
- Throw `AppError` for operational errors.
- Use `logger` instead of `console.log`.
- Return consistent response shape:

```json
{ "status": "success", "data": {} }
```

```json
{ "status": "error", "statusCode": 400, "message": "..." }
```

- Sanitize sensitive fields before returning data.
- Add concise JSDoc on public classes/functions.

## 3. Dependency and Reuse

- Depend on abstractions (inject repositories/services when possible).
- Keep each class focused on one responsibility.
- Extract shared validation and handler wrappers to avoid duplication.

Reusable async wrapper:

```javascript
const asyncHandler = (fn) => (req, res, next) =>
  Promise.resolve(fn(req, res, next)).catch(next);
```

## 4. Minimal End-to-End Example

### Route (`src/routes/user-routes.ts`)

```typescript
import { Router } from "express";
import { userController } from "../controllers/user-controller.js";
import { validateUserInput } from "../middlewares/validators.js";

const router = Router();

router.get("/:id", userController.getById);
router.post("/", validateUserInput, userController.create);

export default router;
```


### Controller (`src/controllers/user-controller.ts`)

```typescript
import type { Request, Response } from "express";
import { userService } from "../services/user-service.js";
import logger from "../utils/logger.js";

class UserController {
  async getById(req: Request, res: Response): Promise<void> {
    const user = await userService.getById(req.params.id);
    res.json({ status: "success", data: { user } });
  }

  async create(req: Request, res: Response): Promise<void> {
    const user = await userService.createUser(req.body);
    logger.info("User created", { userId: user.id });
    res.status(201).json({ status: "success", data: { user } });
  }
}

export const userController = new UserController();
```

module.exports = new UserController();
```

### Service (`src/services/user-service.js`)

```javascript
const { userRepository } = require("../repositories");
const AppError = require("../utils/errors/AppError");

class UserService {
  async getById(id) {
    const user = await userRepository.findById(id);
    if (!user) throw new AppError("User not found", 404);
    return this._sanitizeUser(user);
  }

  async createUser(input) {
    if (await userRepository.existsByEmail(input.email)) {
      throw new AppError("Email already exists", 409);
    }
    const created = await userRepository.create(input);
    return this._sanitizeUser(created);
  }

  _sanitizeUser(user) {
    const { password, ...safeUser } = user;
    return safeUser;
  }
}

module.exports = new UserService();
```

### Repository (`src/repositories/user-repository.js`)

```javascript
class UserRepository {
  constructor(db) {
    this.db = db;
  }

  async findById(id) {
    const row = await this.db.user.findUnique({ where: { id } });
    return row ? this._toEntity(row) : null;
  }

  async existsByEmail(email) {
    const count = await this.db.user.count({ where: { email } });
    return count > 0;
  }

  async create(input) {
    const row = await this.db.user.create({ data: this._toDbModel(input) });
    return this._toEntity(row);
  }

  _toEntity(row) {
    return {
      id: row.id,
      email: row.email,
      firstName: row.first_name,
      lastName: row.last_name,
      password: row.password,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
    };
  }

  _toDbModel(entity) {
    return {
      email: entity.email,
      first_name: entity.firstName,
      last_name: entity.lastName,
      password: entity.password,
    };
  }
}

module.exports = new UserRepository();
```

## 5. Quick Review Checklist

1. Route contains no business logic.
2. Controller performs no DB access.
3. Service enforces business rules and sanitizes output.
4. Repository is the only DB/ORM layer.
5. Errors use `AppError` and flow to centralized error middleware.
6. No `console.log`; use `logger`.

## 6. Common Mistakes

- Business logic in controllers.
- Raw ORM models leaking outside repositories.
- Missing input validation.
- Inconsistent API response format.
- Returning sensitive fields (for example passwords).

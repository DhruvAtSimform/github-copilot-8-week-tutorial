---
applyTo: "src/{routes,controllers,services,repositories}/**/*.js"
---

# API Development Guidelines - Express REST API

Instructions for implementing routes, controllers, services, and repositories following clean architecture principles.

---

## 1. Layered Architecture (Mandatory)

### Data Flow

```
Request → Route → Controller → Service → Repository → Database
Response ← Route ← Controller ← Service ← Repository ← Database

Each module or Resource should have separate file or folders as per requirements
```

### Layer Responsibilities

**Routes** (`src/routes/`)

- Define endpoints only
- Map HTTP methods to controllers
- Apply route-specific middleware
- NO business logic

```javascript
// ✅ Good
router.get("/users/:id", validateUserId, userController.getById);
router.post("/users", validateUserInput, userController.create);

// ❌ Bad - logic in route
router.get("/users/:id", async (req, res) => {
  const user = await db.query("SELECT * FROM users WHERE id = ?", [
    req.params.id,
  ]);
  res.json(user);
});
```

**Controllers** (`src/controllers/`)

- Handle HTTP request/response
- Validate input (use express-validator)
- Call service methods
- Format responses
- NO business logic, NO database access

```javascript
// ✅ Good
const getById = async (req, res, next) => {
  try {
    const user = await userService.getById(req.params.id);
    res.json({ status: "success", data: { user } });
  } catch (error) {
    next(error);
  }
};

// ❌ Bad - business logic in controller
const getById = async (req, res, next) => {
  const user = await userRepository.findById(req.params.id);
  if (user.isActive && user.subscriptionExpiry > Date.now()) {
    // Business logic belongs in service
  }
};
```

**Services** (`src/services/`)

- Business logic implementation
- Orchestrate repository calls
- Data transformation
- Validation rules
- Transaction management
- NO HTTP handling, NO database queries

```javascript
// ✅ Good
class UserService {
  async getById(userId) {
    const user = await userRepository.findById(userId);
    if (!user) {
      throw new AppError("User not found", 404);
    }
    return this._sanitizeUser(user);
  }

  async createUser(userData) {
    // Business validation
    if (await userRepository.existsByEmail(userData.email)) {
      throw new AppError("Email already exists", 409);
    }

    // Hash password
    userData.password = await bcrypt.hash(userData.password, 12);

    return await userRepository.create(userData);
  }

  _sanitizeUser(user) {
    const { password, ...sanitized } = user;
    return sanitized;
  }
}
```

**Repositories** (`src/repositories/`)

- Database operations only
- Abstract ORM/database implementation
- Return domain objects (not ORM models)
- Define own types (not ORM types)
- NO business logic

```javascript
// ✅ Good - ORM-agnostic
class UserRepository {
  async findById(id) {
    // ORM call here (Prisma, Sequelize, etc.)
    const dbUser = await db.user.findUnique({ where: { id } });
    return dbUser ? this._toEntity(dbUser) : null;
  }

  async create(userData) {
    const dbUser = await db.user.create({ data: userData });
    return this._toEntity(dbUser);
  }

  async existsByEmail(email) {
    const count = await db.user.count({ where: { email } });
    return count > 0;
  }

  // Convert ORM model to domain entity
  _toEntity(dbModel) {
    return {
      id: dbModel.id,
      email: dbModel.email,
      firstName: dbModel.first_name,
      lastName: dbModel.last_name,
      createdAt: dbModel.created_at,
      updatedAt: dbModel.updated_at,
    };
  }
}
```

---

## 2. SOLID Principles

### Single Responsibility Principle (SRP)

- Each class/module has ONE reason to change
- Separate concerns: auth service, email service, user service

```javascript
// ❌ Bad - Multiple responsibilities
class UserService {
  async createUser(data) {
    const user = await userRepository.create(data);
    await this.sendWelcomeEmail(user); // Email responsibility
    await this.logToAnalytics(user); // Analytics responsibility
  }
}

// ✅ Good - Single responsibility
class UserService {
  constructor(emailService, analyticsService) {
    this.emailService = emailService;
    this.analyticsService = analyticsService;
  }

  async createUser(data) {
    const user = await userRepository.create(data);
    await this.emailService.sendWelcome(user);
    await this.analyticsService.trackSignup(user);
    return user;
  }
}
```

### Open/Closed Principle (OCP)

- Open for extension, closed for modification
- Use dependency injection

```javascript
// ✅ Good - Easy to extend with new storage
class UserService {
  constructor(userRepository) {
    this.repository = userRepository;
  }

  async getById(id) {
    return await this.repository.findById(id);
  }
}

// Can inject different repositories
const service = new UserService(new PostgresUserRepository());
// or
const service = new UserService(new MongoUserRepository());
```

### Liskov Substitution Principle (LSP)

- Implementations should be interchangeable

```javascript
// ✅ All repositories follow same interface
class BaseRepository {
  async findById(id) {
    throw new Error("Not implemented");
  }
  async create(data) {
    throw new Error("Not implemented");
  }
  async update(id, data) {
    throw new Error("Not implemented");
  }
  async delete(id) {
    throw new Error("Not implemented");
  }
}

class UserRepository extends BaseRepository {
  async findById(id) {
    /* implementation */
  }
  async create(data) {
    /* implementation */
  }
}
```

### Interface Segregation Principle (ISP)

- Don't force clients to depend on unused methods
- Create focused interfaces

```javascript
// ✅ Good - Focused interfaces
class ReadOnlyRepository {
  async findById(id) {
    /* implementation */
  }
  async findAll() {
    /* implementation */
  }
}

class WritableRepository extends ReadOnlyRepository {
  async create(data) {
    /* implementation */
  }
  async update(id, data) {
    /* implementation */
  }
  async delete(id) {
    /* implementation */
  }
}
```

### Dependency Inversion Principle (DIP)

- Depend on abstractions, not concrete implementations

```javascript
// ✅ Good - Inject dependencies
class UserController {
  constructor(userService) {
    this.userService = userService;
  }

  getById = async (req, res, next) => {
    const user = await this.userService.getById(req.params.id);
    res.json({ status: "success", data: { user } });
  };
}

// Initialize with dependencies
const userService = new UserService(userRepository);
const userController = new UserController(userService);
```

---

## 3. DRY Principle (Don't Repeat Yourself)

### Extract Common Logic

```javascript
// ❌ Bad - Repeated validation
router.post("/users", async (req, res) => {
  if (!req.body.email) throw new AppError("Email required", 400);
  if (!req.body.password) throw new AppError("Password required", 400);
  // ...
});

router.put("/users/:id", async (req, res) => {
  if (!req.body.email) throw new AppError("Email required", 400);
  if (!req.body.password) throw new AppError("Password required", 400);
  // ...
});

// ✅ Good - Reusable middleware
const validateUserInput = [
  body("email").isEmail().normalizeEmail(),
  body("password").isLength({ min: 8 }),
  handleValidationErrors,
];

router.post("/users", validateUserInput, userController.create);
router.put("/users/:id", validateUserInput, userController.update);
```

### Extract Common Patterns

```javascript
// ✅ Good - Reusable async wrapper
const asyncHandler = (fn) => (req, res, next) =>
  Promise.resolve(fn(req, res, next)).catch(next);

// Use everywhere
router.get("/users", asyncHandler(userController.getAll));
router.get("/posts", asyncHandler(postController.getAll));
```

---

## 4. Repository Pattern (ORM Decoupling)

### Purpose

- Abstract database implementation details
- Easy to swap ORM (Prisma → Sequelize → TypeORM)
- Consistent interface across data sources
- Define own domain types

### Structure

```javascript
/**
 * Repository for User entity
 * Abstracts database operations from ORM specifics
 */
class UserRepository {
  /**
   * @param {Object} db - Database connection/ORM instance
   */
  constructor(db) {
    this.db = db;
  }

  /**
   * Find user by ID
   * @param {string} id - User ID
   * @returns {Promise<User|null>} User entity or null
   */
  async findById(id) {
    const dbUser = await this.db.user.findUnique({ where: { id } });
    return dbUser ? this._toEntity(dbUser) : null;
  }

  /**
   * Find all users with pagination
   * @param {Object} options - Query options
   * @param {number} options.page - Page number
   * @param {number} options.limit - Items per page
   * @returns {Promise<{users: User[], total: number}>}
   */
  async findAll({ page = 1, limit = 10 }) {
    const skip = (page - 1) * limit;

    const [users, total] = await Promise.all([
      this.db.user.findMany({ skip, take: limit }),
      this.db.user.count(),
    ]);

    return {
      users: users.map(this._toEntity),
      total,
    };
  }

  /**
   * Create new user
   * @param {Object} userData - User data
   * @returns {Promise<User>} Created user entity
   */
  async create(userData) {
    const dbUser = await this.db.user.create({
      data: this._toDbModel(userData),
    });
    return this._toEntity(dbUser);
  }

  /**
   * Update user
   * @param {string} id - User ID
   * @param {Object} userData - Updated data
   * @returns {Promise<User|null>} Updated user or null
   */
  async update(id, userData) {
    const dbUser = await this.db.user.update({
      where: { id },
      data: this._toDbModel(userData),
    });
    return this._toEntity(dbUser);
  }

  /**
   * Delete user
   * @param {string} id - User ID
   * @returns {Promise<boolean>} Success status
   */
  async delete(id) {
    await this.db.user.delete({ where: { id } });
    return true;
  }

  /**
   * Check if email exists
   * @param {string} email - Email to check
   * @returns {Promise<boolean>}
   */
  async existsByEmail(email) {
    const count = await this.db.user.count({ where: { email } });
    return count > 0;
  }

  /**
   * Convert DB model to domain entity
   * Maps database column names to domain properties
   * @private
   * @param {Object} dbModel - Database model object
   * @returns {User} Domain entity
   */
  _toEntity(dbModel) {
    if (!dbModel) return null;

    return {
      id: dbModel.id,
      email: dbModel.email,
      firstName: dbModel.first_name,
      lastName: dbModel.last_name,
      isActive: dbModel.is_active,
      role: dbModel.role,
      createdAt: dbModel.created_at,
      updatedAt: dbModel.updated_at,
    };
  }

  /**
   * Convert domain entity to DB model
   * Maps domain properties to database column names
   * @private
   * @param {Object} entity - Domain entity
   * @returns {Object} Database model
   */
  _toDbModel(entity) {
    return {
      email: entity.email,
      first_name: entity.firstName,
      last_name: entity.lastName,
      password: entity.password,
      is_active: entity.isActive,
      role: entity.role,
    };
  }
}

module.exports = UserRepository;
```

### Domain Types (not ORM types)

```javascript
/**
 * User entity type definition
 * @typedef {Object} User
 * @property {string} id - Unique identifier
 * @property {string} email - User email
 * @property {string} firstName - First name
 * @property {string} lastName - Last name
 * @property {boolean} isActive - Active status
 * @property {string} role - User role (admin, user, etc.)
 * @property {Date} createdAt - Creation timestamp
 * @property {Date} updatedAt - Last update timestamp
 */
```

---

## 5. API Implementation Checklist

When creating/editing API endpoints:

1. ✅ **Route** defines endpoint and middleware only
2. ✅ **Controller** handles HTTP, calls service
3. ✅ **Service** contains business logic
4. ✅ **Repository** handles database operations
5. ✅ Use `asyncHandler` for async routes
6. ✅ Validate input with express-validator
7. ✅ Throw `AppError` for errors
8. ✅ Use logger (not console.log)
9. ✅ Add JSDoc comments
10. ✅ Return consistent response format
11. ✅ Handle pagination for list endpoints
12. ✅ Sanitize output (remove sensitive fields)

---

## 6. Complete Example

### Route

```javascript
// src/routes/user-routes.js
const express = require("express");
const { userController } = require("../controllers");
const { validateUserInput } = require("../middlewares/validators");
const { asyncHandler } = require("../utils/async-handler");

const router = express.Router();

router.get("/", asyncHandler(userController.getAll));
router.get("/:id", asyncHandler(userController.getById));
router.post("/", validateUserInput, asyncHandler(userController.create));
router.put("/:id", validateUserInput, asyncHandler(userController.update));
router.delete("/:id", asyncHandler(userController.delete));

module.exports = router;
```

### Controller

```javascript
// src/controllers/user-controller.js
const { userService } = require("../services");
const logger = require("../utils/logger");

class UserController {
  /**
   * Get all users
   */
  async getAll(req, res) {
    const { page = 1, limit = 10 } = req.query;
    const result = await userService.getAll({ page, limit });

    res.json({
      status: "success",
      data: result.users,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total: result.total,
      },
    });
  }

  /**
   * Get user by ID
   */
  async getById(req, res) {
    const user = await userService.getById(req.params.id);
    res.json({ status: "success", data: { user } });
  }

  /**
   * Create new user
   */
  async create(req, res) {
    const user = await userService.createUser(req.body);
    logger.info("User created", { userId: user.id });
    res.status(201).json({ status: "success", data: { user } });
  }

  /**
   * Update user
   */
  async update(req, res) {
    const user = await userService.updateUser(req.params.id, req.body);
    logger.info("User updated", { userId: user.id });
    res.json({ status: "success", data: { user } });
  }

  /**
   * Delete user
   */
  async delete(req, res) {
    await userService.deleteUser(req.params.id);
    logger.info("User deleted", { userId: req.params.id });
    res.status(204).send();
  }
}

module.exports = new UserController();
```

### Service

```javascript
// src/services/user-service.js
const { userRepository } = require("../repositories");
const AppError = require("../utils/errors/AppError");
const bcrypt = require("bcrypt");

class UserService {
  /**
   * Get all users with pagination
   */
  async getAll({ page, limit }) {
    const result = await userRepository.findAll({ page, limit });

    // Sanitize sensitive fields
    result.users = result.users.map(this._sanitizeUser);

    return result;
  }

  /**
   * Get user by ID
   */
  async getById(id) {
    const user = await userRepository.findById(id);

    if (!user) {
      throw new AppError("User not found", 404);
    }

    return this._sanitizeUser(user);
  }

  /**
   * Create new user
   */
  async createUser(userData) {
    // Business validation
    if (await userRepository.existsByEmail(userData.email)) {
      throw new AppError("Email already exists", 409);
    }

    // Hash password
    userData.password = await bcrypt.hash(userData.password, 12);

    const user = await userRepository.create(userData);
    return this._sanitizeUser(user);
  }

  /**
   * Update user
   */
  async updateUser(id, userData) {
    const existingUser = await userRepository.findById(id);

    if (!existingUser) {
      throw new AppError("User not found", 404);
    }

    // Check email uniqueness if changed
    if (userData.email && userData.email !== existingUser.email) {
      if (await userRepository.existsByEmail(userData.email)) {
        throw new AppError("Email already exists", 409);
      }
    }

    // Hash password if provided
    if (userData.password) {
      userData.password = await bcrypt.hash(userData.password, 12);
    }

    const user = await userRepository.update(id, userData);
    return this._sanitizeUser(user);
  }

  /**
   * Delete user
   */
  async deleteUser(id) {
    const user = await userRepository.findById(id);

    if (!user) {
      throw new AppError("User not found", 404);
    }

    await userRepository.delete(id);
  }

  /**
   * Remove sensitive fields from user object
   * @private
   */
  _sanitizeUser(user) {
    const { password, ...sanitized } = user;
    return sanitized;
  }
}

module.exports = new UserService();
```

### Repository

```javascript
// src/repositories/user-repository.js
class UserRepository {
  constructor(db) {
    this.db = db; // Injected database connection
  }

  async findById(id) {
    const dbUser = await this.db.user.findUnique({ where: { id } });
    return dbUser ? this._toEntity(dbUser) : null;
  }

  async findAll({ page = 1, limit = 10 }) {
    const skip = (page - 1) * limit;

    const [users, total] = await Promise.all([
      this.db.user.findMany({ skip, take: limit }),
      this.db.user.count(),
    ]);

    return {
      users: users.map((u) => this._toEntity(u)),
      total,
    };
  }

  async create(userData) {
    const dbUser = await this.db.user.create({
      data: this._toDbModel(userData),
    });
    return this._toEntity(dbUser);
  }

  async update(id, userData) {
    const dbUser = await this.db.user.update({
      where: { id },
      data: this._toDbModel(userData),
    });
    return this._toEntity(dbUser);
  }

  async delete(id) {
    await this.db.user.delete({ where: { id } });
    return true;
  }

  async existsByEmail(email) {
    const count = await this.db.user.count({ where: { email } });
    return count > 0;
  }

  _toEntity(dbModel) {
    return {
      id: dbModel.id,
      email: dbModel.email,
      firstName: dbModel.first_name,
      lastName: dbModel.last_name,
      password: dbModel.password,
      isActive: dbModel.is_active,
      role: dbModel.role,
      createdAt: dbModel.created_at,
      updatedAt: dbModel.updated_at,
    };
  }

  _toDbModel(entity) {
    const dbModel = {};
    if (entity.email) dbModel.email = entity.email;
    if (entity.firstName) dbModel.first_name = entity.firstName;
    if (entity.lastName) dbModel.last_name = entity.lastName;
    if (entity.password) dbModel.password = entity.password;
    if (entity.isActive !== undefined) dbModel.is_active = entity.isActive;
    if (entity.role) dbModel.role = entity.role;
    return dbModel;
  }
}

module.exports = new UserRepository();
```

---

## 7. Common Mistakes to Avoid

❌ Business logic in controllers  
❌ Database queries in services  
❌ HTTP handling in services  
❌ Direct ORM types exposed outside repository  
❌ Missing error handling  
❌ No input validation  
❌ Exposing sensitive data  
❌ Hardcoded values (use env vars)  
❌ Using console.log (use logger)  
❌ Skipping JSDoc comments

---

**Apply these guidelines to all code in `src/routes/`, `src/controllers/`, `src/services/`, and `src/repositories/`**

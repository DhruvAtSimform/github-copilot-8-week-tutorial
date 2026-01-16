# Express REST API

A production-grade REST API built with Node.js and Express, featuring industry-standard error handling, structured logging, and security best practices.

## ✨ Features

- **Production-Grade Error Handling** - Comprehensive error handling with Winston logging
- **Security First** - Helmet, CORS, request size limits
- **Structured Logging** - Winston logger with file rotation and environment-aware configuration
- **Developer Experience** - ESLint, Prettier, Husky pre-commit hooks
- **Performance** - Response compression, efficient error handling
- **Best Practices** - Following Node.js and Express.js recommended patterns

## Table of Contents

- [Installation](#installation)
- [Usage](#usage)
- [Error Handling](#error-handling)
- [Linting and Formatting](#linting-and-formatting)
- [API Endpoints](#api-endpoints)
- [Environment Variables](#environment-variables)
- [Contributing](#contributing)

## Installation

1. Clone the repository:

   ```bash
   git clone <repository-url>
   cd express-rest-api
   ```

2. Install dependencies using PNPM:

   ```bash
   pnpm install
   ```

3. Copy the example environment file:

   ```bash
   cp .env.example .env
   ```

4. Configure your environment variables in `.env` file.

## Usage

### Development Mode

Start the server with auto-reload:

```bash
pnpm dev
```

### Production Mode

Start the server:

```bash
NODE_ENV=production pnpm start
```

The server will run at `http://localhost:3000` (or your configured PORT).

## Error Handling

This application implements production-grade error handling following industry best practices:

- **Winston Logger**: Structured, performant logging with file rotation
- **AppError Class**: Custom error class for operational errors
- **Global Error Handler**: Centralized error handling middleware
- **catchAsync Wrapper**: Eliminates try-catch boilerplate in async routes
- **Environment-Aware**: Detailed errors in dev, sanitized in production
- **Security**: Sensitive data redaction, safe error messages

For detailed documentation, see [ERROR_HANDLING.md](./ERROR_HANDLING.md)

### Quick Example

```javascript
const { catchAsync, AppError } = require('./middlewares/errorHandler');

// Use catchAsync to handle async errors automatically
app.get(
  '/users/:id',
  catchAsync(async (req, res) => {
    const user = await User.findById(req.params.id);
    if (!user) throw new AppError('User not found', 404);
    res.json({ data: user });
  })
);
```

## API Endpoints

### Health Check

```bash
GET /health
```

Returns server status and uptime.

### Example Routes

```bash
GET /api/example    # Successful response
GET /api/error      # Operational error (400)
GET /api/crash      # Programming error (500)
```

## Linting and Formatting

This project uses ESLint and Prettier for code quality. Husky runs linting checks before commits.

```bash
# Run linting
pnpm lint

# Fix linting issues automatically
pnpm lint:fix

# Format code
pnpm format
```

## Environment Variables

Create a `.env` file in the root directory:

```bash
NODE_ENV=development    # 'development' or 'production'
PORT=3000              # Server port
LOG_LEVEL=info         # 'error', 'warn', 'info', 'debug'
```

## Project Structure

```
express-rest-api/
├── src/
│   ├── app.js                      # Express app configuration
│   ├── routes/
│   │   └── index.js                # Route definitions
│   ├── controllers/
│   │   └── index.js                # Business logic
│   ├── middlewares/
│   │   └── errorHandler.js         # Error handling orchestration
│   └── utils/
│       ├── logger.js               # Winston logger configuration
│       └── errors/                 # Error handling modules (SOLID)
│           ├── index.js            # Barrel export
│           ├── AppError.js         # Custom error class
│           ├── errorTransformers.js # Error type transformations
│           ├── errorLogger.js      # Error logging logic
│           ├── errorResponses.js   # Response formatting
│           └── sanitizer.js        # Data sanitization
├── logs/                           # Log files (gitignored)
│   ├── error.log
│   └── combined.log
├── .env.example                    # Environment variable template
├── .eslintrc.json                 # ESLint configuration
├── .prettierrc                    # Prettier configuration
├── .lintstagedrc.json             # Lint-staged configuration
├── ERROR_HANDLING.md              # Error handling documentation
├── CLEAN_ARCHITECTURE.md          # Architecture documentation
├── package.json
└── README.md
```

## Architecture

This project follows **clean code principles** and **SOLID design patterns**:

- **Single Responsibility**: Each module has one clear purpose
- **Separation of Concerns**: Error handling split into focused modules
- **Dependency Inversion**: Abstractions over concrete implementations
- **Open/Closed**: Easy to extend without modifying existing code

See [CLEAN_ARCHITECTURE.md](./CLEAN_ARCHITECTURE.md) for detailed architecture documentation.

## Dependencies

### Production

- **express** - Fast, minimalist web framework
- **winston** - Professional logging library
- **helmet** - Security headers middleware
- **cors** - Cross-origin resource sharing
- **morgan** - HTTP request logger
- **compression** - Response compression

### Development

- **eslint** - JavaScript linting
- **prettier** - Code formatting
- **husky** - Git hooks
- **lint-staged** - Pre-commit linting
- **nodemon** - Auto-reload in development

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.

## License

This project is licensed under the MIT License.

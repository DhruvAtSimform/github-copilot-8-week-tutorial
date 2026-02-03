import js from '@eslint/js';
import tseslint from 'typescript-eslint';
import pluginN from 'eslint-plugin-n';
import pluginPromise from 'eslint-plugin-promise';
import pluginSecurity from 'eslint-plugin-security';
import globals from 'globals';

export default tseslint.config(
  // Base recommended configs
  js.configs.recommended,
  ...tseslint.configs.recommendedTypeChecked,
  pluginPromise.configs['flat/recommended'],
  pluginSecurity.configs.recommended,

  // Global ignores (replaces .eslintignore)
  {
    ignores: [
      'dist/',
      'node_modules/',
      'logs/',
      'prisma/generated/',
      '**/*.d.ts',
      'src/**/*.js',
      'eslint.config.js',
    ],
  },

  // Main configuration
  {
    files: ['**/*.ts', '**/*.tsx'],

    languageOptions: {
      ecmaVersion: 'latest',
      sourceType: 'module',
      parser: tseslint.parser,
      parserOptions: {
        project: true,
        tsconfigRootDir: import.meta.dirname,
      },
      globals: {
        ...globals.node,
        ...globals.es2022,
      },
    },

    plugins: {
      '@typescript-eslint': tseslint.plugin,
      n: pluginN,
      promise: pluginPromise,
      security: pluginSecurity,
    },

    rules: {
      // Formatting rules
      indent: ['error', 2],
      'linebreak-style': ['error', 'unix'],
      quotes: ['error', 'single'],
      semi: ['error', 'always'],

      // TypeScript rules
      'no-unused-vars': 'off',
      '@typescript-eslint/no-unused-vars': [
        'error',
        { argsIgnorePattern: '^_' },
      ],
      '@typescript-eslint/explicit-function-return-type': [
        'warn',
        {
          allowExpressions: true,
          allowTypedFunctionExpressions: true,
        },
      ],
      '@typescript-eslint/no-explicit-any': 'error',
      '@typescript-eslint/no-unsafe-assignment': 'off',
      '@typescript-eslint/no-unsafe-member-access': 'off',
      '@typescript-eslint/no-unsafe-call': 'off',
      '@typescript-eslint/no-unsafe-return': 'off',
      '@typescript-eslint/no-unsafe-argument': 'off',
      'require-await': 'off',
      '@typescript-eslint/require-await': 'error',
      'no-return-await': 'off',
      '@typescript-eslint/return-await': ['error', 'in-try-catch'],

      // General JavaScript rules
      'no-console': 'error',
      'prefer-const': 'error',
      eqeqeq: ['error', 'always'],
      curly: ['error', 'all'],
      'no-var': 'error',

      // Promise rules
      'promise/no-return-wrap': 'error',
      'promise/catch-or-return': ['error', { allowFinally: true }],

      // Security rules
      'security/detect-object-injection': 'off',

      // Node.js plugin rules
      'n/no-unsupported-features/es-syntax': 'off',
      'n/no-missing-import': 'off',
    },
  },
);

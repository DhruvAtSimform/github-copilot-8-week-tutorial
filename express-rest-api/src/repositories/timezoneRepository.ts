import { z } from 'zod';
import logger from '../utils/logger.js';
import AppError from '../utils/errors/AppError.js';
import {
  INITIAL_TIMEZONE_DATA,
  DEFAULT_COUNTRY_CODE,
  COUNTRY_NAMES,
} from '../utils/constants/timezones.js';

/**
 * Validation schema for country codes (ISO 3166-1 alpha-2)
 */
const CountryCodeSchema = z
  .string()
  .trim()
  .min(2, 'Country code must be 2 characters')
  .max(2, 'Country code must be 2 characters')
  .regex(/^[A-Z]{2}$/, 'Country code must be two uppercase letters')
  .transform((val: string): string => val.toUpperCase());
/**
 * Validation schema for timezone strings
 */
const TimezoneSchema = z
  .string()
  .trim()
  .min(3, 'Timezone must be at least 3 characters')
  .regex(
    /^[A-Za-z_/]+$/,
    'Timezone must contain only letters, underscores, and forward slashes'
  );

/**
 * Schema for adding a new timezone to a country
 */
const AddTimezoneSchema = z.object({
  countryCode: CountryCodeSchema,
  timezone: TimezoneSchema,
});

/**
 * Schema for validating timezone input
 */
const ValidateTimezoneInputSchema = z.object({
  countryCode: CountryCodeSchema.optional(),
});

/**
 * Domain entity for timezone data
 */
interface TimezoneEntity {
  countryCode: string;
  timezones: readonly string[];
}

/**
 * Repository for timezone data operations
 * Manages read/write access to timezone data with validation and type safety
 */
class TimezoneRepository {
  /**
   * In-memory store for timezone data
   * In production, this would be backed by a database
   */
  private timezoneStore: Map<string, readonly string[]>;

  constructor() {
    // Initialize with seed data
    this.timezoneStore = new Map(
      Object.entries(INITIAL_TIMEZONE_DATA) as [string, readonly string[]][]
    );
  }

  /**
   * Get timezone data for a specific country code
   * @param countryCode - ISO 3166-1 alpha-2 country code
   * @returns Timezone entity with country code and timezone array
   * @throws {AppError} If country code is invalid or not found
   */
  getByCountryCode(countryCode: string | null | undefined): TimezoneEntity {
    try {
      // Validate and sanitize input
      const validatedCode = CountryCodeSchema.parse(countryCode || '');

      // Check if country exists
      const timezones = this.timezoneStore.get(validatedCode);
      if (!timezones) {
        logger.warn('Timezone data not found for country code', {
          countryCode: validatedCode,
        });
        throw new AppError(
          `No timezones found for country code: ${validatedCode}. Please use ISO 3166-1 alpha-2 format (e.g., 'US', 'IN')`,
          404
        );
      }

      logger.debug('Timezone data retrieved', {
        countryCode: validatedCode,
        timezoneCount: timezones.length,
      });

      return {
        countryCode: validatedCode,
        timezones,
      };
    } catch (err: unknown) {
      const error = err instanceof Error ? err : new Error(String(err));
      if (error instanceof z.ZodError) {
        logger.warn('Invalid country code format', {
          input: countryCode,
          errors: error.issues,
        });
        throw new AppError(
          'Invalid country code format. Must be two uppercase letters (e.g., "US", "IN")',
          400
        );
      }

      if (error instanceof AppError) {
        throw error;
      }

      logger.error('Error retrieving timezone data', {
        error: error.message,
        countryCode,
      });
      throw new AppError('Failed to retrieve timezone data', 500);
    }
  }

  /**
   * Get timezone data with fallback to default country
   * @param countryCode - Optional country code; defaults to DEFAULT_COUNTRY_CODE if invalid
   * @returns Timezone entity
   */
  getByCountryCodeWithFallback(
    countryCode: string | null | undefined
  ): TimezoneEntity {
    try {
      // Try to get specific country
      if (countryCode) {
        const validatedCode = CountryCodeSchema.safeParse(countryCode);
        if (validatedCode.success) {
          const result = this.timezoneStore.get(validatedCode.data);
          if (result) {
            return {
              countryCode: validatedCode.data,
              timezones: result,
            };
          }
        }
      }

      // Fall back to default
      const defaultTimezones = this.timezoneStore.get(DEFAULT_COUNTRY_CODE);
      if (!defaultTimezones) {
        throw new AppError('Default country timezone data not found', 500);
      }

      logger.debug('Using default country code for timezone', {
        provided: countryCode,
        default: DEFAULT_COUNTRY_CODE,
      });

      return {
        countryCode: DEFAULT_COUNTRY_CODE,
        timezones: defaultTimezones,
      };
    } catch (error) {
      if (error instanceof AppError) {
        throw error;
      }

      logger.error('Error in getByCountryCodeWithFallback', {
        error: error instanceof Error ? error.message : 'Unknown error',
      });
      throw new AppError('Failed to retrieve timezone data', 500);
    }
  }

  /**
   * Add a new timezone to a country (for future write operations)
   * Validates both country code and timezone format
   * @param countryCode - ISO 3166-1 alpha-2 country code
   * @param timezone - Timezone string to add
   * @returns Updated timezone entity
   * @throws {AppError} If validation fails or country doesn't exist
   */
  addTimezone(countryCode: string, timezone: string): TimezoneEntity {
    try {
      // Validate inputs
      const validated = AddTimezoneSchema.parse({
        countryCode,
        timezone,
      });

      // Check if country exists
      const existingTimezones = this.timezoneStore.get(validated.countryCode);
      if (!existingTimezones) {
        throw new AppError(
          `Country code ${validated.countryCode} does not exist`,
          404
        );
      }

      // Check for duplicates
      const isDuplicate = (existingTimezones as string[]).includes(
        validated.timezone
      );
      if (isDuplicate) {
        throw new AppError(
          `Timezone ${validated.timezone} already exists for ${validated.countryCode}`,
          409
        );
      }

      // Add timezone (create new array to maintain immutability where possible)
      const updatedTimezones = [
        ...(existingTimezones as string[]),
        validated.timezone,
      ] as readonly string[];

      this.timezoneStore.set(validated.countryCode, updatedTimezones);

      logger.info('Timezone added successfully', {
        countryCode: validated.countryCode,
        timezone: validated.timezone,
      });

      return {
        countryCode: validated.countryCode,
        timezones: updatedTimezones,
      };
    } catch (err: unknown) {
      const error = err instanceof Error ? err : new Error(String(err));
      if (error instanceof z.ZodError) {
        logger.warn('Invalid timezone data format', {
          countryCode,
          timezone,
          errors: error.issues,
        });
        throw new AppError('Invalid timezone or country code format', 400);
      }

      if (error instanceof AppError) {
        throw error;
      }

      logger.error('Error adding timezone', {
        error: error.message,
        countryCode,
        timezone,
      });
      throw new AppError('Failed to add timezone', 500);
    }
  }

  /**
   * Remove a timezone from a country (for future write operations)
   * @param countryCode - ISO 3166-1 alpha-2 country code
   * @param timezone - Timezone string to remove
   * @returns Updated timezone entity
   * @throws {AppError} If country doesn't exist or timezone not found
   */
  removeTimezone(countryCode: string, timezone: string): TimezoneEntity {
    try {
      // Validate inputs
      const validated = AddTimezoneSchema.parse({
        countryCode,
        timezone,
      });

      // Check if country exists
      const existingTimezones = this.timezoneStore.get(validated.countryCode);
      if (!existingTimezones) {
        throw new AppError(
          `Country code ${validated.countryCode} does not exist`,
          404
        );
      }

      // Check if timezone exists
      if (!(existingTimezones as string[]).includes(validated.timezone)) {
        throw new AppError(
          `Timezone ${validated.timezone} not found for ${validated.countryCode}`,
          404
        );
      }

      // Prevent removal of all timezones
      if (existingTimezones.length === 1) {
        throw new AppError(
          'Cannot remove the only timezone for a country',
          400
        );
      }

      // Remove timezone
      const updatedTimezones = (existingTimezones as string[]).filter(
        (tz) => tz !== validated.timezone
      ) as readonly string[];

      this.timezoneStore.set(validated.countryCode, updatedTimezones);

      logger.info('Timezone removed successfully', {
        countryCode: validated.countryCode,
        timezone: validated.timezone,
      });

      return {
        countryCode: validated.countryCode,
        timezones: updatedTimezones,
      };
    } catch (err: unknown) {
      const error = err instanceof Error ? err : new Error(String(err));
      if (error instanceof z.ZodError) {
        throw new AppError('Invalid timezone or country code format', 400);
      }

      if (error instanceof AppError) {
        throw error;
      }

      logger.error('Error removing timezone', {
        error: error.message,
        countryCode,
        timezone,
      });
      throw new AppError('Failed to remove timezone', 500);
    }
  }

  /**
   * Get all available countries with their timezone counts
   * @returns Map of country codes to country information (name and timezone count)
   */
  getAllCountries(): Record<string, { name: string; timezoneCount: number }> {
    const countries: Record<string, { name: string; timezoneCount: number }> =
      {};

    this.timezoneStore.forEach((timezones, countryCode: string) => {
      countries[countryCode] = {
        name: COUNTRY_NAMES[countryCode] || countryCode,
        timezoneCount: timezones.length,
      };
    });

    return countries;
  }

  /**
   * Validate timezone input without throwing errors
   * Useful for pre-validation in controllers
   * @param countryCode - Country code to validate
   * @returns Validation result object
   */
  validateCountryCodeInput(countryCode: string | null | undefined): {
    isValid: boolean;
    error?: string;
  } {
    try {
      ValidateTimezoneInputSchema.parse({
        countryCode: countryCode || '',
      });
      return { isValid: true };
    } catch (err: unknown) {
      const error = err instanceof Error ? err : new Error(String(err));
      if (error instanceof z.ZodError) {
        return {
          isValid: false,
          error:
            (error.issues[0] as { message?: string })?.message ||
            'Invalid input',
        };
      }

      return { isValid: false, error: 'Unknown validation error' };
    }
  }
}

// Export singleton instance
export default new TimezoneRepository();

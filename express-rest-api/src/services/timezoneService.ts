import AppError from '../utils/errors/AppError.js';
import logger from '../utils/logger.js';
import timezoneRepository from '../repositories/timezoneRepository.js';

/**
 * Client details for timezone resolution
 */
interface ClientDetails {
  ip?: string;
  userAgent?: string;
  countryCode?: string | null;
}

/**
 * Timezone service response
 */
interface TimezoneResult {
  countryCode: string;
  timezones: readonly string[];
  count: number;
}

/**
 * Service for timezone-related business logic
 * Handles timezone queries and transformations
 */
class TimezoneService {
  /**
   * Get timezones for a country code with strict validation
   * @param countryCode - ISO 3166-1 alpha-2 country code (e.g., 'US', 'IN')
   * @param clientDetails - Client/browser details for geolocation fallback
   * @returns Object containing country code and array of timezones
   * @throws {AppError} If country code is invalid
   */
  getTimezonesByCountry(
    countryCode: string | null | undefined,
    clientDetails: ClientDetails | null = null
  ): TimezoneResult {
    try {
      // Prioritize provided country code, then client details, then fallback
      const targetCountryCode = this._resolveCountryCode(
        countryCode,
        clientDetails
      );

      // Fetch from repository with strict validation
      const timezoneEntity =
        timezoneRepository.getByCountryCode(targetCountryCode);

      logger.info('Timezones retrieved successfully', {
        countryCode: timezoneEntity.countryCode,
        timezoneCount: timezoneEntity.timezones.length,
        clientIp: clientDetails?.ip,
      });

      return {
        countryCode: timezoneEntity.countryCode,
        timezones: timezoneEntity.timezones,
        count: timezoneEntity.timezones.length,
      };
    } catch (error) {
      if (error instanceof AppError) {
        throw error;
      }

      logger.error('Error retrieving timezones', {
        error: error instanceof Error ? error.message : 'Unknown error',
        countryCode,
      });
      throw new AppError('Failed to retrieve timezones', 500);
    }
  }

  /**
   * Get timezones with fallback to default country
   * @param countryCode - Optional country code
   * @param clientDetails - Optional client details
   * @returns Timezone result with fallback applied
   */
  getTimezonesWithFallback(
    countryCode: string | null | undefined,
    clientDetails: ClientDetails | null = null
  ): TimezoneResult {
    try {
      // Use repository's fallback mechanism
      const timezoneEntity = timezoneRepository.getByCountryCodeWithFallback(
        this._resolveCountryCode(countryCode, clientDetails)
      );

      logger.info('Timezones retrieved with fallback', {
        requested: countryCode,
        resolved: timezoneEntity.countryCode,
        timezoneCount: timezoneEntity.timezones.length,
      });

      return {
        countryCode: timezoneEntity.countryCode,
        timezones: timezoneEntity.timezones,
        count: timezoneEntity.timezones.length,
      };
    } catch (error) {
      if (error instanceof AppError) {
        throw error;
      }

      logger.error('Error in getTimezonesWithFallback', {
        error: error instanceof Error ? error.message : 'Unknown error',
      });
      throw new AppError('Failed to retrieve timezones', 500);
    }
  }

  /**
   * Resolve country code from multiple sources with priority
   * @private
   * @param countryCode - Explicit country code
   * @param clientDetails - Client details for extraction
   * @returns The resolved country code
   */
  private _resolveCountryCode(
    countryCode: string | null | undefined,
    clientDetails: ClientDetails | null
  ): string | null | undefined {
    // Priority 1: Use provided country code if present
    if (countryCode && typeof countryCode === 'string') {
      const trimmed = countryCode.trim();
      if (trimmed.length > 0) {
        return trimmed;
      }
    }

    // Priority 2: Extract from client details
    if (
      clientDetails?.countryCode &&
      typeof clientDetails.countryCode === 'string'
    ) {
      const trimmed = clientDetails.countryCode.trim();
      if (trimmed.length > 0) {
        return trimmed;
      }
    }

    // Return undefined to trigger fallback or error handling
    return undefined;
  }
}

export default new TimezoneService();

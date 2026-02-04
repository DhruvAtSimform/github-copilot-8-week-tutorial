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
 * Timezone object with name and UTC offset
 */
interface TimezoneObject {
  name: string;
  offset: number;
}

/**
 * Timezone service response
 */
interface TimezoneResult {
  countryCode: string;
  timezones: TimezoneObject[];
  count: number;
}

/**
 * Service for timezone-related business logic
 * Handles timezone queries and transformations
 */
class TimezoneService {
  /**
   * Convert timezone string to object with offset
   * @private
   * @param timezoneName - Timezone string (e.g., 'America/New_York')
   * @returns Timezone object with name and offset
   */
  private _getTimezoneOffset(timezoneName: string): number {
    try {
      // Get current date to calculate offset
      const now = new Date();

      // Format date in the target timezone and get offset
      const formatter = new Intl.DateTimeFormat('en-US', {
        timeZone: timezoneName,
        timeZoneName: 'longOffset',
      });

      const parts = formatter.formatToParts(now);
      const offsetPart = parts.find((part) => part.type === 'timeZoneName');

      if (offsetPart && offsetPart.value) {
        // Parse offset string like "GMT+5:30" or "GMT-5"
        // eslint-disable-next-line security/detect-unsafe-regex
        const match = offsetPart.value.match(/GMT([+-])(\d{1,2})(?::(\d{2}))?/);
        if (match && match[1] && match[2]) {
          const sign = match[1] === '+' ? 1 : -1;
          const hours = parseInt(match[2], 10);
          const minutes = match[3] ? parseInt(match[3], 10) : 0;
          return sign * (hours + minutes / 60);
        }
      }

      // Fallback: calculate offset manually
      const utcDate = new Date(
        now.toLocaleString('en-US', { timeZone: 'UTC' })
      );
      const tzDate = new Date(
        now.toLocaleString('en-US', { timeZone: timezoneName })
      );
      const offset = (tzDate.getTime() - utcDate.getTime()) / (1000 * 60 * 60);

      return Math.round(offset * 2) / 2; // Round to nearest 0.5
    } catch (error) {
      logger.warn('Failed to calculate timezone offset', {
        timezone: timezoneName,
        error: error instanceof Error ? error.message : 'Unknown error',
      });
      return 0; // Default to UTC if calculation fails
    }
  }

  /**
   * Transform timezone strings to objects with offsets
   * @private
   * @param timezones - Array of timezone strings
   * @returns Array of timezone objects with name and offset
   */
  private _transformTimezones(timezones: readonly string[]): TimezoneObject[] {
    return timezones.map((tz) => ({
      name: tz,
      offset: this._getTimezoneOffset(tz),
    }));
  }

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

      // Transform timezone strings to objects with offsets
      const timezoneObjects = this._transformTimezones(
        timezoneEntity.timezones
      );

      logger.info('Timezones retrieved successfully', {
        countryCode: timezoneEntity.countryCode,
        timezoneCount: timezoneObjects.length,
        clientIp: clientDetails?.ip,
      });

      return {
        countryCode: timezoneEntity.countryCode,
        timezones: timezoneObjects,
        count: timezoneObjects.length,
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

      // Transform timezone strings to objects with offsets
      const timezoneObjects = this._transformTimezones(
        timezoneEntity.timezones
      );

      logger.info('Timezones retrieved with fallback', {
        requested: countryCode,
        resolved: timezoneEntity.countryCode,
        timezoneCount: timezoneObjects.length,
      });

      return {
        countryCode: timezoneEntity.countryCode,
        timezones: timezoneObjects,
        count: timezoneObjects.length,
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

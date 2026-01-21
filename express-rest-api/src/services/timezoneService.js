import AppError from '../utils/errors/AppError.js';
import logger from '../utils/logger.js';
import { TIMEZONE_BY_COUNTRY, DEFAULT_COUNTRY_CODE } from '../utils/constants/timezones.js';

/**
 * Service for timezone-related business logic
 */
class TimezoneService {
  /**
     * Get timezones for a country code
     * @param {string|null} countryCode - ISO 3166-1 alpha-2 country code (e.g., 'US', 'IN')
     * @param {object|null} clientDetails - Client/browser details for geolocation fallback
     * @returns {object} Object containing country code and array of timezones
     * @throws {AppError} If country code is invalid
     */
  getTimezonesByCountry(countryCode, clientDetails = null) {
    try {
      // Determine which country code to use
      const finalCountryCode = this._resolveCountryCode(countryCode, clientDetails);

      // Validate country code exists
      if (!TIMEZONE_BY_COUNTRY[finalCountryCode]) {
        logger.warn('Invalid country code requested', {
          countryCode: finalCountryCode,
          clientIp: clientDetails?.ip,
        });
        throw new AppError(
          `Invalid country code: ${finalCountryCode}. Please use ISO 3166-1 alpha-2 format (e.g., 'US', 'IN')`,
          400
        );
      }

      // Get timezones for the country
      const timezones = TIMEZONE_BY_COUNTRY[finalCountryCode];

      logger.info('Timezones retrieved successfully', {
        countryCode: finalCountryCode,
        timezoneCount: timezones.length,
      });

      return {
        countryCode: finalCountryCode,
        timezones,
        count: timezones.length,
      };
    } catch (error) {
      if (error instanceof AppError) { throw error; }

      logger.error('Error retrieving timezones', { error: error.message });
      throw new AppError('Failed to retrieve timezones', 500);
    }
  }

  /**
     * Resolve the country code from multiple sources
     * @private
     * @param {string|null} countryCode - Explicit country code
     * @param {object|null} clientDetails - Client details for fallback
     * @returns {string} The resolved country code
     */
  _resolveCountryCode(countryCode, clientDetails) {
    // Use provided country code if valid
    if (countryCode && typeof countryCode === 'string') {
      return countryCode.toUpperCase().trim();
    }

    // Try to extract from client details (e.g., geo-IP information)
    if (clientDetails && clientDetails.countryCode) {
      return clientDetails.countryCode.toUpperCase().trim();
    }

    // Default to India
    logger.debug('No country code provided, using default', {
      default: DEFAULT_COUNTRY_CODE,
    });
    return DEFAULT_COUNTRY_CODE;
  }
}

export default new TimezoneService();

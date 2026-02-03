import { Request, Response, NextFunction } from 'express';
import { catchAsync } from '../middlewares/errorHandler.js';
import timezoneService from '../services/timezoneService.js';
import timezoneRepository from '../repositories/timezoneRepository.js';
import logger from '../utils/logger.js';
import AppError from '../utils/errors/AppError.js';

/**
 * Client details for timezone resolution
 */
interface ClientDetails {
  ip?: string;
  userAgent?: string;
  countryCode?: string | null;
}

/**
 * Controller for timezone-related endpoints
 */
class TimezoneController {
  /**
   * Get timezones for a country code
   * GET /api/timezones?countryCode=IN
   *
   * Supports two modes:
   * 1. Strict: Requires valid country code, throws error if not found
   * 2. Fallback: Uses default country if provided code is invalid
   *
   * @param req - Express request object
   * @param res - Express response object
   * @param _next - Express next middleware function
   */

  static readonly getTimezonesByCountry = catchAsync(
    // eslint-disable-next-line @typescript-eslint/require-await
    async (req: Request, res: Response, _next: NextFunction): Promise<void> => {
      const { countryCode, clientCountry, fallback } = req.query;

      // Extract client details for timezone resolution
      const clientDetails: ClientDetails = {
        ip: req.ip,
        userAgent: req.get('user-agent'),
        countryCode: (clientCountry as string) || null,
      };

      // Determine whether to use fallback mode
      const useFallback = fallback === 'true' || fallback === '1';

      // Call appropriate service method
      const result = useFallback
        ? timezoneService.getTimezonesWithFallback(
            (countryCode as string) || null,
            clientDetails
          )
        : timezoneService.getTimezonesByCountry(
            (countryCode as string) || null,
            clientDetails
          );

      logger.info('Timezone request processed successfully', {
        countryCode: result.countryCode,
        mode: useFallback ? 'fallback' : 'strict',
        clientIp: clientDetails.ip,
        timezoneCount: result.count,
      });

      // Send success response
      res.status(200).json({
        status: 'success',
        data: {
          countryCode: result.countryCode,
          timezones: result.timezones,
          count: result.count,
        },
      });
    }
  );

  /**
   * Get all available countries with timezone counts
   * GET /api/timezones/countries
   *
   * @param _req - Express request object
   * @param res - Express response object
   * @param _next - Express next middleware function
   */

  static readonly getAllCountries = catchAsync(
    async (_req: Request, res: Response, _next: NextFunction) => {
      const countries = timezoneRepository.getAllCountries();

      logger.info('All countries retrieved', {
        countriesCount: Object.keys(countries).length,
      });

      res.status(200).json({
        status: 'success',
        data: {
          countries,
          totalCountries: Object.keys(countries).length,
        },
      });
    }
  );

  /**
   * Add a new timezone to a country (future write operation)
   * POST /api/timezones/:countryCode
   *
   * @param req - Express request object
   * @param res - Express response object
   * @param _next - Express next middleware function
   */

  static readonly addTimezone = catchAsync(
    // eslint-disable-next-line @typescript-eslint/require-await
    async (req: Request, res: Response, _next: NextFunction): Promise<void> => {
      const { countryCode } = req.params as { countryCode: string };
      const { timezone } = req.body as { timezone?: unknown };

      // Validate request body

      if (!timezone || typeof timezone !== 'string') {
        throw new AppError('Timezone is required and must be a string', 400);
      }

      // Add timezone via repository
      const result = timezoneRepository.addTimezone(countryCode, timezone);

      logger.info('Timezone added successfully', {
        countryCode: result.countryCode,
        timezone,
      });

      res.status(201).json({
        status: 'success',

        message: `Timezone ${timezone} added to ${countryCode}`,
        data: {
          countryCode: result.countryCode,
          timezones: result.timezones,
          count: result.timezones.length,
        },
      });
    }
  );

  /**
   * Remove a timezone from a country (future write operation)
   * DELETE /api/timezones/:countryCode/:timezone
   *
   * @param req - Express request object
   * @param res - Express response object
   * @param _next - Express next middleware function
   */

  static readonly removeTimezone = catchAsync(
    // eslint-disable-next-line @typescript-eslint/require-await
    async (req: Request, res: Response, _next: NextFunction): Promise<void> => {
      const params = req.params as { countryCode: string; timezone: string };
      const { countryCode, timezone } = params;

      // Remove timezone via repository
      const result = timezoneRepository.removeTimezone(countryCode, timezone);

      logger.info('Timezone removed successfully', {
        countryCode: result.countryCode,
        timezone,
      });

      res.status(200).json({
        status: 'success',
        message: `Timezone ${timezone} removed from ${countryCode}`,
        data: {
          countryCode: result.countryCode,
          timezones: result.timezones,
          count: result.timezones.length,
        },
      });
    }
  );
}

export default TimezoneController;

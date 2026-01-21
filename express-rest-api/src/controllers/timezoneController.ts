import { Request, Response, NextFunction } from 'express';
import timezoneService from '../services/timezoneService.js';
import logger from '../utils/logger.js';

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
   * @param req - Express request object
   * @param res - Express response object
   * @param next - Express next middleware function
   */
  static getTimezonesByCountry(
    req: Request,
    res: Response,
    next: NextFunction
  ): void {
    try {
      const { countryCode, clientCountry } = req.query;

      // Extract client details for fallback geolocation
      const clientDetails: ClientDetails = {
        ip: req.ip,
        userAgent: req.get('user-agent'),
        countryCode: (clientCountry as string) || null,
      };

      // Call service to get timezones
      const result = timezoneService.getTimezonesByCountry(
        countryCode as string | undefined,
        clientDetails
      );

      logger.info('Timezone request processed successfully', {
        countryCode: result.countryCode,
        clientIp: clientDetails.ip,
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
    } catch (error) {
      next(error);
    }
  }
}

export default TimezoneController;

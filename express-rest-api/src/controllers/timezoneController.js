import timezoneService from '../services/timezoneService.js';
import logger from '../utils/logger.js';

/**
 * Controller for timezone-related endpoints
 */
class TimezoneController {
  /**
     * Get timezones for a country code
     * GET /api/timezones?countryCode=IN
     *
     * @param {object} req - Express request object
     * @param {object} res - Express response object
     * @param {function} next - Express next middleware function
     */
  static async getTimezonesByCountry(req, res, next) {
    try {
      const { countryCode } = req.query;

      // Extract client details for fallback geolocation
      const clientDetails = {
        ip: req.ip || req.connection.remoteAddress,
        userAgent: req.get('user-agent'),
        countryCode: req.query.clientCountry || null,
      };

      // Call service to get timezones
      const result = await timezoneService.getTimezonesByCountry(countryCode, clientDetails);

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

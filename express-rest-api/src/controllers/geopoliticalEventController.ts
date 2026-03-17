import { Request, Response, NextFunction } from 'express';
import geopoliticalEventService from '../services/geopoliticalEventService.js';
import logger from '../utils/logger.js';

/**
 * Controller for geopolitical event endpoints
 */
class GeopoliticalEventController {
  /**
   * Get geopolitical event of the day
   * GET /api/geopolitical-event-of-day
   */
  static readonly getGeopoliticalEventOfDay = async (
    _req: Request,
    res: Response,
    next: NextFunction
  ): Promise<void> => {
    try {
      const event = await geopoliticalEventService.getGeopoliticalEventOfDay();

      logger.info('Geopolitical-event-of-day request served successfully', {
        source: event.source,
        sourceCountry: event.sourceCountry,
      });

      res.status(200).json({
        status: 'success',
        data: event,
      });
    } catch (error: unknown) {
      next(error);
    }
  };
}

export default GeopoliticalEventController;

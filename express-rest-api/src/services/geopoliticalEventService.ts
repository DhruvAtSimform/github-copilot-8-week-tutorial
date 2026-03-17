import AppError from '../utils/errors/AppError.js';
import logger from '../utils/logger.js';
import geopoliticalEventRepository from '../repositories/geopoliticalEventRepository.js';
import type { GeopoliticalEventEntity } from '../repositories/geopoliticalEventRepository.js';

/**
 * Response model for geopolitical event of day endpoint
 */
export interface GeopoliticalEventResponse {
  readonly title: string;
  readonly summary: string;
  readonly url: string;
  readonly publishedAt: string;
  readonly source: string;
  readonly sourceCountry: string;
  readonly language: string;
  readonly imageUrl: string | null;
  readonly provider: string;
  readonly generatedAt: string;
}

/**
 * Service for geopolitical event business logic
 */
class GeopoliticalEventService {
  /**
   * Get one representative geopolitical event for the day
   */
  async getGeopoliticalEventOfDay(): Promise<GeopoliticalEventResponse> {
    try {
      const event =
        await geopoliticalEventRepository.fetchGeopoliticalEventOfDay();
      return this._toResponse(event);
    } catch (error: unknown) {
      if (error instanceof AppError) {
        throw error;
      }

      logger.error('Unexpected error in geopolitical event service', {
        error: error instanceof Error ? error.message : 'Unknown error',
      });
      throw new AppError(
        'Unable to retrieve geopolitical event of the day',
        500
      );
    }
  }

  private _toResponse(
    event: GeopoliticalEventEntity
  ): GeopoliticalEventResponse {
    return {
      title: event.title,
      summary:
        'Most recent geopolitical headline observed in the last 24 hours across global news coverage.',
      url: event.url,
      publishedAt: event.publishedAt,
      source: event.source,
      sourceCountry: event.sourceCountry,
      language: event.language,
      imageUrl: event.imageUrl,
      provider: event.provider,
      generatedAt: new Date().toISOString(),
    };
  }
}

export default new GeopoliticalEventService();

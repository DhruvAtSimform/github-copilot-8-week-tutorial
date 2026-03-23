import geopoliticalEventService from './geopoliticalEventService.js';
import geopoliticalEventRepository from '../repositories/geopoliticalEventRepository.js';
import AppError from '../utils/errors/AppError.js';
import logger from '../utils/logger.js';

jest.mock('../repositories/geopoliticalEventRepository.js');
jest.mock('../utils/logger.js');

describe('GeopoliticalEventService', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('getGeopoliticalEventOfDay', () => {
    it('should return a properly formatted geopolitical event response', async () => {
      const mockEventEntity = {
        title: 'Major diplomatic summit held',
        url: 'https://news.example.com/summit',
        publishedAt: '2024-03-20T10:00:00Z',
        source: 'Reuters',
        sourceCountry: 'GB',
        language: 'en',
        imageUrl: 'https://images.example.com/summit.jpg',
        provider: 'GDELT',
      };

      (geopoliticalEventRepository.fetchGeopoliticalEventOfDay as jest.Mock).mockResolvedValue(
        mockEventEntity
      );

      const result = await geopoliticalEventService.getGeopoliticalEventOfDay();

      expect(result).toHaveProperty('title');
      expect(result).toHaveProperty('summary');
      expect(result).toHaveProperty('url');
      expect(result).toHaveProperty('publishedAt');
      expect(result).toHaveProperty('source');
      expect(result).toHaveProperty('sourceCountry');
      expect(result).toHaveProperty('language');
      expect(result).toHaveProperty('imageUrl');
      expect(result).toHaveProperty('provider');
      expect(result).toHaveProperty('generatedAt');
    });

    it('should map event entity properties to response correctly', async () => {
      const mockEventEntity = {
        title: 'Trade negotiations ongoing',
        url: 'https://news.example.com/trade',
        publishedAt: '2024-03-20T08:30:00Z',
        source: 'AP News',
        sourceCountry: 'US',
        language: 'en',
        imageUrl: 'https://images.example.com/trade.jpg',
        provider: 'GDELT',
      };

      (geopoliticalEventRepository.fetchGeopoliticalEventOfDay as jest.Mock).mockResolvedValue(
        mockEventEntity
      );

      const result = await geopoliticalEventService.getGeopoliticalEventOfDay();

      expect(result.title).toBe('Trade negotiations ongoing');
      expect(result.url).toBe('https://news.example.com/trade');
      expect(result.publishedAt).toBe('2024-03-20T08:30:00Z');
      expect(result.source).toBe('AP News');
      expect(result.sourceCountry).toBe('US');
      expect(result.language).toBe('en');
      expect(result.imageUrl).toBe('https://images.example.com/trade.jpg');
      expect(result.provider).toBe('GDELT');
    });

    it('should set a standard summary for all events', async () => {
      const mockEventEntity = {
        title: 'Security incident reported',
        url: 'https://news.example.com/security',
        publishedAt: '2024-03-20T12:00:00Z',
        source: 'BBC',
        sourceCountry: 'GB',
        language: 'en',
        imageUrl: null,
        provider: 'GDELT',
      };

      (geopoliticalEventRepository.fetchGeopoliticalEventOfDay as jest.Mock).mockResolvedValue(
        mockEventEntity
      );

      const result = await geopoliticalEventService.getGeopoliticalEventOfDay();

      expect(result.summary).toBe(
        'Most recent geopolitical headline observed in the last 24 hours across global news coverage.'
      );
    });

    it('should set generatedAt timestamp in ISO format', async () => {
      const mockEventEntity = {
        title: 'Regional conflict update',
        url: 'https://news.example.com/conflict',
        publishedAt: '2024-03-20T15:45:00Z',
        source: 'AFP',
        sourceCountry: 'FR',
        language: 'en',
        imageUrl: 'https://images.example.com/conflict.jpg',
        provider: 'GDELT',
      };

      (geopoliticalEventRepository.fetchGeopoliticalEventOfDay as jest.Mock).mockResolvedValue(
        mockEventEntity
      );

      const result = await geopoliticalEventService.getGeopoliticalEventOfDay();

      expect(result.generatedAt).toBeDefined();
      expect(typeof result.generatedAt).toBe('string');
      expect(new Date(result.generatedAt)).toBeInstanceOf(Date);
    });

    it('should handle null imageUrl', async () => {
      const mockEventEntity = {
        title: 'Policy announcement',
        url: 'https://news.example.com/policy',
        publishedAt: '2024-03-20T09:00:00Z',
        source: 'Official Source',
        sourceCountry: 'DE',
        language: 'de',
        imageUrl: null,
        provider: 'GDELT',
      };

      (geopoliticalEventRepository.fetchGeopoliticalEventOfDay as jest.Mock).mockResolvedValue(
        mockEventEntity
      );

      const result = await geopoliticalEventService.getGeopoliticalEventOfDay();

      expect(result.imageUrl).toBeNull();
    });

    it('should throw error when repository throws AppError', async () => {
      const appError = new AppError('GDELT API unavailable', 503);
      (geopoliticalEventRepository.fetchGeopoliticalEventOfDay as jest.Mock).mockRejectedValue(
        appError
      );

      await expect(
        geopoliticalEventService.getGeopoliticalEventOfDay()
      ).rejects.toThrow(appError);
    });

    it('should wrap unexpected errors in AppError with 500 status', async () => {
      const unexpectedError = new Error('Database connection failed');
      (geopoliticalEventRepository.fetchGeopoliticalEventOfDay as jest.Mock).mockRejectedValue(
        unexpectedError
      );

      const error: any = await geopoliticalEventService
        .getGeopoliticalEventOfDay()
        .catch((err) => err);

      expect(error).toBeInstanceOf(AppError);
      expect(error.statusCode).toBe(500);
      expect(error.message).toContain(
        'Unable to retrieve geopolitical event'
      );
    });

    it('should log error when repository throws unexpected error', async () => {
      const unexpectedError = new Error('Network timeout');
      (geopoliticalEventRepository.fetchGeopoliticalEventOfDay as jest.Mock).mockRejectedValue(
        unexpectedError
      );

      await expect(
        geopoliticalEventService.getGeopoliticalEventOfDay()
      ).rejects.toThrow();

      expect(logger.error).toHaveBeenCalledWith(
        'Unexpected error in geopolitical event service',
        expect.objectContaining({
          error: 'Network timeout',
        })
      );
    });

    it('should handle error with non-Error type', async () => {
      (geopoliticalEventRepository.fetchGeopoliticalEventOfDay as jest.Mock).mockRejectedValue(
        'Unknown error string'
      );

      await expect(
        geopoliticalEventService.getGeopoliticalEventOfDay()
      ).rejects.toThrow(AppError);

      expect(logger.error).toHaveBeenCalledWith(
        'Unexpected error in geopolitical event service',
        expect.objectContaining({
          error: 'Unknown error',
        })
      );
    });

    it('should call repository fetchGeopoliticalEventOfDay method', async () => {
      const mockEventEntity = {
        title: 'International agreement signed',
        url: 'https://news.example.com/agreement',
        publishedAt: '2024-03-20T11:00:00Z',
        source: 'UN News',
        sourceCountry: 'US',
        language: 'en',
        imageUrl: 'https://images.example.com/agreement.jpg',
        provider: 'GDELT',
      };

      (geopoliticalEventRepository.fetchGeopoliticalEventOfDay as jest.Mock).mockResolvedValue(
        mockEventEntity
      );

      await geopoliticalEventService.getGeopoliticalEventOfDay();

      expect(
        geopoliticalEventRepository.fetchGeopoliticalEventOfDay
      ).toHaveBeenCalledTimes(1);
    });

    it('should preserve all required response properties', async () => {
      const mockEventEntity = {
        title: 'Breaking news',
        url: 'https://news.example.com/breaking',
        publishedAt: '2024-03-20T20:00:00Z',
        source: 'Breaking News Network',
        sourceCountry: 'US',
        language: 'en',
        imageUrl: 'https://images.example.com/breaking.jpg',
        provider: 'GDELT',
      };

      (geopoliticalEventRepository.fetchGeopoliticalEventOfDay as jest.Mock).mockResolvedValue(
        mockEventEntity
      );

      const result = await geopoliticalEventService.getGeopoliticalEventOfDay();

      expect(result).toHaveProperty('title');
      expect(result).toHaveProperty('summary');
      expect(result).toHaveProperty('url');
      expect(result).toHaveProperty('publishedAt');
      expect(result).toHaveProperty('source');
      expect(result).toHaveProperty('sourceCountry');
      expect(result).toHaveProperty('language');
      expect(result).toHaveProperty('imageUrl');
      expect(result).toHaveProperty('provider');
      expect(result).toHaveProperty('generatedAt');
    });

    it('should handle various source countries', async () => {
      const countries = ['US', 'GB', 'FR', 'DE', 'JP', 'IN', 'BR'];

      for (const country of countries) {
        const mockEventEntity = {
          title: `Event from ${country}`,
          url: `https://news.example.com/${country.toLowerCase()}`,
          publishedAt: '2024-03-20T14:00:00Z',
          source: `News from ${country}`,
          sourceCountry: country,
          language: 'en',
          imageUrl: null,
          provider: 'GDELT',
        };

        (geopoliticalEventRepository.fetchGeopoliticalEventOfDay as jest.Mock).mockResolvedValue(
          mockEventEntity
        );

        const result = await geopoliticalEventService.getGeopoliticalEventOfDay();

        expect(result.sourceCountry).toBe(country);
      }
    });

    it('should handle various languages', async () => {
      const languages = ['en', 'fr', 'de', 'es', 'zh', 'ar', 'ru'];

      for (const lang of languages) {
        const mockEventEntity = {
          title: 'International news',
          url: 'https://news.example.com/intl',
          publishedAt: '2024-03-20T16:00:00Z',
          source: 'Global News',
          sourceCountry: 'US',
          language: lang,
          imageUrl: null,
          provider: 'GDELT',
        };

        (geopoliticalEventRepository.fetchGeopoliticalEventOfDay as jest.Mock).mockResolvedValue(
          mockEventEntity
        );

        const result = await geopoliticalEventService.getGeopoliticalEventOfDay();

        expect(result.language).toBe(lang);
      }
    });

    it('should not log on successful retrieval', async () => {
      const mockEventEntity = {
        title: 'Breaking news',
        url: 'https://news.example.com/breaking',
        publishedAt: '2024-03-20T20:00:00Z',
        source: 'Breaking News Network',
        sourceCountry: 'US',
        language: 'en',
        imageUrl: 'https://images.example.com/breaking.jpg',
        provider: 'GDELT',
      };

      (geopoliticalEventRepository.fetchGeopoliticalEventOfDay as jest.Mock).mockResolvedValue(
        mockEventEntity
      );

      (logger.error as jest.Mock).mockClear();

      await geopoliticalEventService.getGeopoliticalEventOfDay();

      expect(logger.error).not.toHaveBeenCalled();
    });

    it('should handle very long event titles', async () => {
      const longTitle =
        'A'.repeat(500) + ' - Very long geopolitical event title';
      const mockEventEntity = {
        title: longTitle,
        url: 'https://news.example.com/long',
        publishedAt: '2024-03-20T17:00:00Z',
        source: 'News Source',
        sourceCountry: 'US',
        language: 'en',
        imageUrl: null,
        provider: 'GDELT',
      };

      (geopoliticalEventRepository.fetchGeopoliticalEventOfDay as jest.Mock).mockResolvedValue(
        mockEventEntity
      );

      const result = await geopoliticalEventService.getGeopoliticalEventOfDay();

      expect(result.title).toBe(longTitle);
    });

    it('should handle special characters in fields', async () => {
      const mockEventEntity = {
        title:
          'Crisis in "Region A" & region B - Update: 50% increase in tensions',
        url: 'https://news.example.com/special?id=123&lang=en',
        publishedAt: '2024-03-20T13:00:00Z',
        source: "Reuters & AP's Joint Report",
        sourceCountry: 'US',
        language: 'en',
        imageUrl: null,
        provider: 'GDELT',
      };

      (geopoliticalEventRepository.fetchGeopoliticalEventOfDay as jest.Mock).mockResolvedValue(
        mockEventEntity
      );

      const result = await geopoliticalEventService.getGeopoliticalEventOfDay();

      expect(result.title).toContain('"Region A"');
      expect(result.source).toContain('&');
    });
  });
});

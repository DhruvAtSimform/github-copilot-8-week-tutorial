import timezoneService from './timezoneService.js';
import timezoneRepository from '../repositories/timezoneRepository.js';
import AppError from '../utils/errors/AppError.js';
import logger from '../utils/logger.js';

jest.mock('../repositories/timezoneRepository.js');
jest.mock('../utils/logger.js');

describe('TimezoneService', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('getTimezonesByCountry', () => {
    it('should return timezones for a valid country code', () => {
      const mockRepositoryResponse = {
        countryCode: 'US',
        timezones: ['America/New_York', 'America/Chicago'],
      };

      (timezoneRepository.getByCountryCode as jest.Mock).mockReturnValue(
        mockRepositoryResponse
      );

      const result = timezoneService.getTimezonesByCountry('US');

      expect(result.countryCode).toBe('US');
      expect(result.count).toBe(2);
      expect(result.timezones).toHaveLength(2);
      expect(result.timezones[0]).toHaveProperty('name');
      expect(result.timezones[0]).toHaveProperty('offset');
      expect(timezoneRepository.getByCountryCode).toHaveBeenCalledWith('US');
      expect(logger.info).toHaveBeenCalledWith(
        'Timezones retrieved successfully',
        expect.objectContaining({
          countryCode: 'US',
          timezoneCount: 2,
        })
      );
    });

    it('should throw AppError when repository throws AppError', () => {
      const appError = new AppError('Invalid country code', 400);
      (timezoneRepository.getByCountryCode as jest.Mock).mockImplementation(
        () => {
          throw appError;
        }
      );

      expect(() => {
        timezoneService.getTimezonesByCountry('ZZ');
      }).toThrow(appError);
      expect(timezoneRepository.getByCountryCode).toHaveBeenCalledWith('ZZ');
    });

    it('should wrap unexpected errors in AppError with 500 status', () => {
      const unexpectedError = new Error('Database connection failed');
      (timezoneRepository.getByCountryCode as jest.Mock).mockImplementation(
        () => {
          throw unexpectedError;
        }
      );

      expect(() => {
        timezoneService.getTimezonesByCountry('US');
      }).toThrow(AppError);

      expect(logger.error).toHaveBeenCalledWith(
        'Error retrieving timezones',
        expect.objectContaining({
          error: 'Database connection failed',
        })
      );
    });

    it('should prioritize explicit country code over client details', () => {
      const mockRepositoryResponse = {
        countryCode: 'IN',
        timezones: ['Asia/Kolkata'],
      };

      (timezoneRepository.getByCountryCode as jest.Mock).mockReturnValue(
        mockRepositoryResponse
      );

      const clientDetails = {
        countryCode: 'US',
        ip: '192.168.1.1',
      };

      const result = timezoneService.getTimezonesByCountry('IN', clientDetails);

      expect(result.countryCode).toBe('IN');
      expect(timezoneRepository.getByCountryCode).toHaveBeenCalledWith('IN');
    });

    it('should use client country code when explicit code is not provided', () => {
      const mockRepositoryResponse = {
        countryCode: 'FR',
        timezones: ['Europe/Paris'],
      };

      (timezoneRepository.getByCountryCode as jest.Mock).mockReturnValue(
        mockRepositoryResponse
      );

      const clientDetails = {
        countryCode: 'FR',
        ip: '192.168.1.1',
      };

      const result = timezoneService.getTimezonesByCountry(null, clientDetails);

      expect(result.countryCode).toBe('FR');
      expect(timezoneRepository.getByCountryCode).toHaveBeenCalledWith('FR');
    });

    it('should handle country code with whitespace by trimming', () => {
      const mockRepositoryResponse = {
        countryCode: 'AU',
        timezones: ['Australia/Sydney'],
      };

      (timezoneRepository.getByCountryCode as jest.Mock).mockReturnValue(
        mockRepositoryResponse
      );

      const result = timezoneService.getTimezonesByCountry('  AU  ');

      expect(timezoneRepository.getByCountryCode).toHaveBeenCalledWith('AU');
      expect(result.countryCode).toBe('AU');
    });

    it('should calculate correct timezone offsets', () => {
      const mockRepositoryResponse = {
        countryCode: 'GB',
        timezones: ['Europe/London'],
      };

      (timezoneRepository.getByCountryCode as jest.Mock).mockReturnValue(
        mockRepositoryResponse
      );

      const result = timezoneService.getTimezonesByCountry('GB');

      expect(result.timezones.length).toBeGreaterThan(0);
      expect(result.timezones[0]!.name).toBe('Europe/London');
      expect(typeof result.timezones[0]!.offset).toBe('number');
    });

    it('should return count matching timezones array length', () => {
      const mockRepositoryResponse = {
        countryCode: 'JP',
        timezones: ['Asia/Tokyo'],
      };

      (timezoneRepository.getByCountryCode as jest.Mock).mockReturnValue(
        mockRepositoryResponse
      );

      const result = timezoneService.getTimezonesByCountry('JP');

      expect(result.count).toBe(result.timezones.length);
    });

    it('should log client IP when provided', () => {
      const mockRepositoryResponse = {
        countryCode: 'CA',
        timezones: ['America/Vancouver'],
      };

      (timezoneRepository.getByCountryCode as jest.Mock).mockReturnValue(
        mockRepositoryResponse
      );

      const clientDetails = {
        ip: '203.0.113.1',
        countryCode: 'CA',
      };

      timezoneService.getTimezonesByCountry('CA', clientDetails);

      expect(logger.info).toHaveBeenCalledWith(
        'Timezones retrieved successfully',
        expect.objectContaining({
          clientIp: '203.0.113.1',
        })
      );
    });

    it('should handle empty timezone array', () => {
      const mockRepositoryResponse = {
        countryCode: 'XX',
        timezones: [],
      };

      (timezoneRepository.getByCountryCode as jest.Mock).mockReturnValue(
        mockRepositoryResponse
      );

      const result = timezoneService.getTimezonesByCountry('XX');

      expect(result.count).toBe(0);
      expect(result.timezones).toEqual([]);
    });
  });

  describe('getTimezonesWithFallback', () => {
    it('should return timezones with fallback mechanism', () => {
      const mockRepositoryResponse = {
        countryCode: 'US',
        timezones: ['America/New_York', 'America/Los_Angeles'],
      };

      (timezoneRepository.getByCountryCodeWithFallback as jest.Mock).mockReturnValue(
        mockRepositoryResponse
      );

      const result = timezoneService.getTimezonesWithFallback('US');

      expect(result.countryCode).toBe('US');
      expect(result.count).toBe(2);
      expect(result.timezones).toHaveLength(2);
      expect(
        timezoneRepository.getByCountryCodeWithFallback
      ).toHaveBeenCalled();
    });

    it('should fall back to default country when invalid code provided', () => {
      const mockRepositoryResponse = {
        countryCode: 'US',
        timezones: ['America/New_York'],
      };

      (timezoneRepository.getByCountryCodeWithFallback as jest.Mock).mockReturnValue(
        mockRepositoryResponse
      );

      const result = timezoneService.getTimezonesWithFallback('INVALID');

      expect(result.countryCode).toBe('US');
      expect(logger.info).toHaveBeenCalledWith(
        'Timezones retrieved with fallback',
        expect.objectContaining({
          requested: 'INVALID',
          resolved: 'US',
        })
      );
    });

    it('should handle null country code with fallback', () => {
      const mockRepositoryResponse = {
        countryCode: 'US',
        timezones: ['America/Chicago'],
      };

      (timezoneRepository.getByCountryCodeWithFallback as jest.Mock).mockReturnValue(
        mockRepositoryResponse
      );

      const result = timezoneService.getTimezonesWithFallback(null);

      expect(result.countryCode).toBe('US');
      expect(
        timezoneRepository.getByCountryCodeWithFallback
      ).toHaveBeenCalledWith(undefined);
    });

    it('should throw AppError when repository throws', () => {
      const appError = new AppError('Repository error', 500);
      (timezoneRepository.getByCountryCodeWithFallback as jest.Mock).mockImplementation(
        () => {
          throw appError;
        }
      );

      expect(() => {
        timezoneService.getTimezonesWithFallback('US');
      }).toThrow(appError);
    });

    it('should wrap unexpected errors in AppError', () => {
      const unexpectedError = new Error('Network error');
      (timezoneRepository.getByCountryCodeWithFallback as jest.Mock).mockImplementation(
        () => {
          throw unexpectedError;
        }
      );

      expect(() => {
        timezoneService.getTimezonesWithFallback('US');
      }).toThrow(AppError);

      expect(logger.error).toHaveBeenCalledWith(
        'Error in getTimezonesWithFallback',
        expect.objectContaining({
          error: 'Network error',
        })
      );
    });

    it('should prioritize explicit code over client details with fallback', () => {
      const mockRepositoryResponse = {
        countryCode: 'IN',
        timezones: ['Asia/Kolkata'],
      };

      (timezoneRepository.getByCountryCodeWithFallback as jest.Mock).mockReturnValue(
        mockRepositoryResponse
      );

      const clientDetails = {
        countryCode: 'US',
      };

      timezoneService.getTimezonesWithFallback('IN', clientDetails);

      expect(
        timezoneRepository.getByCountryCodeWithFallback
      ).toHaveBeenCalledWith('IN');
    });

    it('should log requested and resolved country codes', () => {
      const mockRepositoryResponse = {
        countryCode: 'GB',
        timezones: ['Europe/London'],
      };

      (timezoneRepository.getByCountryCodeWithFallback as jest.Mock).mockReturnValue(
        mockRepositoryResponse
      );

      timezoneService.getTimezonesWithFallback('XX');

      expect(logger.info).toHaveBeenCalledWith(
        'Timezones retrieved with fallback',
        expect.objectContaining({
          requested: 'XX',
          resolved: 'GB',
        })
      );
    });
  });
});

import jokeService from './jokeService.js';
import jokeRepository from '../repositories/jokeRepository.js';
import AppError from '../utils/errors/AppError.js';
import logger from '../utils/logger.js';

jest.mock('../repositories/jokeRepository.js');
jest.mock('../utils/logger.js');

describe('JokeService', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('getJokeOfDay', () => {
    it('should return a properly formatted joke response', async () => {
      const mockJokeEntity = {
        category: 'General',
        type: 'single' as const,
        joke: 'Why did the scarecrow win an award? He was outstanding in his field!',
        setup: null,
        delivery: null,
        source: 'https://jokeapi.dev',
      };

      (jokeRepository.fetchRandomJoke as jest.Mock).mockResolvedValue(
        mockJokeEntity
      );

      const result = await jokeService.getJokeOfDay();

      expect(result).toHaveProperty('category');
      expect(result).toHaveProperty('type');
      expect(result).toHaveProperty('content');
      expect(result).toHaveProperty('setup');
      expect(result).toHaveProperty('delivery');
      expect(result).toHaveProperty('source');
      expect(result).toHaveProperty('generatedAt');
    });

    it('should map joke entity properties to response correctly', async () => {
      const mockJokeEntity = {
        category: 'Programming',
        type: 'single' as const,
        joke: 'How many programmers does it take to change a light bulb? None, that is a hardware problem',
        setup: null,
        delivery: null,
        source: 'https://jokeapi.dev',
      };

      (jokeRepository.fetchRandomJoke as jest.Mock).mockResolvedValue(
        mockJokeEntity
      );

      const result = await jokeService.getJokeOfDay();

      expect(result.category).toBe('Programming');
      expect(result.type).toBe('single');
      expect(result.content).toBe(mockJokeEntity.joke);
      expect(result.source).toBe('https://jokeapi.dev');
    });

    it('should handle two-part jokes with setup and delivery', async () => {
      const mockJokeEntity = {
        category: 'Knock-knock',
        type: 'twopart' as const,
        joke: '',
        setup: 'Knock knock',
        delivery: "Who's there?",
        source: 'https://jokeapi.dev',
      };

      (jokeRepository.fetchRandomJoke as jest.Mock).mockResolvedValue(
        mockJokeEntity
      );

      const result = await jokeService.getJokeOfDay();

      expect(result.type).toBe('twopart');
      expect(result.setup).toBe('Knock knock');
      expect(result.delivery).toBe("Who's there?");
    });

    it('should set generatedAt timestamp in ISO format', async () => {
      const mockJokeEntity = {
        category: 'General',
        type: 'single' as const,
        joke: 'Test joke',
        setup: null,
        delivery: null,
        source: 'https://jokeapi.dev',
      };

      (jokeRepository.fetchRandomJoke as jest.Mock).mockResolvedValue(
        mockJokeEntity
      );

      const result = await jokeService.getJokeOfDay();

      expect(result.generatedAt).toBeDefined();
      expect(typeof result.generatedAt).toBe('string');
      expect(new Date(result.generatedAt)).toBeInstanceOf(Date);
    });

    it('should throw error when repository throws AppError', async () => {
      const appError = new AppError('Joke API unavailable', 503);
      (jokeRepository.fetchRandomJoke as jest.Mock).mockRejectedValue(
        appError
      );

      await expect(jokeService.getJokeOfDay()).rejects.toThrow(appError);
      await expect(jokeService.getJokeOfDay()).rejects.toThrow(AppError);
    });

    it('should wrap unexpected errors in AppError with 500 status', async () => {
      const unexpectedError = new Error('Network timeout');
      (jokeRepository.fetchRandomJoke as jest.Mock).mockRejectedValue(
        unexpectedError
      );

      await expect(jokeService.getJokeOfDay()).rejects.toThrow(AppError);

      const error: any = await jokeService
        .getJokeOfDay()
        .catch((err) => err);
      expect(error.statusCode).toBe(500);
      expect(error.message).toContain('Unable to retrieve joke');

      expect(logger.error).toHaveBeenCalledWith(
        'Unexpected error in joke service',
        expect.objectContaining({
          error: 'Network timeout',
        })
      );
    });

    it('should handle error with non-Error type', async () => {
      (jokeRepository.fetchRandomJoke as jest.Mock).mockRejectedValue(
        'Unknown error string'
      );

      await expect(jokeService.getJokeOfDay()).rejects.toThrow(AppError);

      expect(logger.error).toHaveBeenCalledWith(
        'Unexpected error in joke service',
        expect.objectContaining({
          error: 'Unknown error',
        })
      );
    });

    it('should call repository fetchRandomJoke method', async () => {
      const mockJokeEntity = {
        category: 'General',
        type: 'single' as const,
        joke: 'Test joke',
        setup: null,
        delivery: null,
        source: 'https://jokeapi.dev',
      };

      (jokeRepository.fetchRandomJoke as jest.Mock).mockResolvedValue(
        mockJokeEntity
      );

      await jokeService.getJokeOfDay();

      expect(jokeRepository.fetchRandomJoke).toHaveBeenCalledTimes(1);
    });

    it('should handle null values for setup and delivery in single-type jokes', async () => {
      const mockJokeEntity = {
        category: 'Dark',
        type: 'single' as const,
        joke: 'Dark joke content',
        setup: null,
        delivery: null,
        source: 'https://jokeapi.dev',
      };

      (jokeRepository.fetchRandomJoke as jest.Mock).mockResolvedValue(
        mockJokeEntity
      );

      const result = await jokeService.getJokeOfDay();

      expect(result.setup).toBeNull();
      expect(result.delivery).toBeNull();
    });

    it('should handle various joke categories', async () => {
      const categories = ['General', 'Programming', 'Knock-knock', 'Sport'];

      for (const category of categories) {
        const mockJokeEntity = {
          category,
          type: 'single' as const,
          joke: `A ${category} joke`,
          setup: null,
          delivery: null,
          source: 'https://jokeapi.dev',
        };

        (jokeRepository.fetchRandomJoke as jest.Mock).mockResolvedValue(
          mockJokeEntity
        );

        const result = await jokeService.getJokeOfDay();

        expect(result.category).toBe(category);
      }
    });

    it('should not log on successful retrieval', async () => {
      const mockJokeEntity = {
        category: 'General',
        type: 'single' as const,
        joke: 'Test joke',
        setup: null,
        delivery: null,
        source: 'https://jokeapi.dev',
      };

      (jokeRepository.fetchRandomJoke as jest.Mock).mockResolvedValue(
        mockJokeEntity
      );

      (logger.error as jest.Mock).mockClear();

      await jokeService.getJokeOfDay();

      expect(logger.error).not.toHaveBeenCalled();
    });

    it('should preserve all required response properties', async () => {
      const mockJokeEntity = {
        category: 'General',
        type: 'single' as const,
        joke: 'Test joke',
        setup: null,
        delivery: null,
        source: 'https://jokeapi.dev',
      };

      (jokeRepository.fetchRandomJoke as jest.Mock).mockResolvedValue(
        mockJokeEntity
      );

      const result = await jokeService.getJokeOfDay();

      expect(result).toHaveProperty('category');
      expect(result).toHaveProperty('type');
      expect(result).toHaveProperty('content');
      expect(result).toHaveProperty('setup');
      expect(result).toHaveProperty('delivery');
      expect(result).toHaveProperty('source');
      expect(result).toHaveProperty('generatedAt');
    });
  });
});

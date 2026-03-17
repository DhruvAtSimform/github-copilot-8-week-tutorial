import AppError from '../utils/errors/AppError.js';
import logger from '../utils/logger.js';
import jokeRepository from '../repositories/jokeRepository.js';
import type { JokeEntity } from '../repositories/jokeRepository.js';

/**
 * Response model for joke-of-day endpoint
 */
export interface JokeResponse {
  readonly category: string;
  readonly type: 'single' | 'twopart';
  readonly content: string;
  readonly setup: string | null;
  readonly delivery: string | null;
  readonly source: string;
  readonly generatedAt: string;
}

/**
 * Service for joke-related business logic
 */
class JokeService {
  /**
   * Get random joke data for API response
   */
  async getJokeOfDay(): Promise<JokeResponse> {
    try {
      const joke = await jokeRepository.fetchRandomJoke();
      return this._toResponse(joke);
    } catch (error: unknown) {
      if (error instanceof AppError) {
        throw error;
      }

      logger.error('Unexpected error in joke service', {
        error: error instanceof Error ? error.message : 'Unknown error',
      });
      throw new AppError('Unable to retrieve joke of the day', 500);
    }
  }

  /**
   * Convert domain entity to API response model
   */
  private _toResponse(joke: JokeEntity): JokeResponse {
    return {
      category: joke.category,
      type: joke.type,
      content: joke.joke,
      setup: joke.setup,
      delivery: joke.delivery,
      source: joke.source,
      generatedAt: new Date().toISOString(),
    };
  }
}

export default new JokeService();

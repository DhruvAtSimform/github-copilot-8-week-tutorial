import AppError from '../utils/errors/AppError.js';
import logger from '../utils/logger.js';
import { env } from '../config/env.js';

/**
 * Raw joke response from JokeAPI
 */
interface JokeApiResponse {
  readonly error: boolean;
  readonly category?: string;
  readonly type?: 'single' | 'twopart';
  readonly joke?: string;
  readonly setup?: string;
  readonly delivery?: string;
  readonly message?: string;
}

/**
 * Domain entity for joke data
 */
export interface JokeEntity {
  readonly category: string;
  readonly type: 'single' | 'twopart';
  readonly setup: string | null;
  readonly delivery: string | null;
  readonly joke: string;
  readonly source: string;
}

/**
 * Repository for external joke API operations
 */
class JokeRepository {
  private readonly jokeApiUrl: string;

  constructor() {
    this.jokeApiUrl =
      env.JOKE_API_URL ??
      'https://v2.jokeapi.dev/joke/Any?safe-mode&type=single,twopart';
  }

  /**
   * Fetch a random joke from a third-party provider
   */
  async fetchRandomJoke(): Promise<JokeEntity> {
    try {
      const response = await fetch(this.jokeApiUrl, {
        method: 'GET',
        headers: {
          Accept: 'application/json',
        },
      });

      if (!response.ok) {
        logger.error('Joke provider returned non-success status', {
          status: response.status,
          statusText: response.statusText,
        });
        throw new AppError('Failed to fetch joke from provider', 502);
      }

      const data: unknown = await response.json();
      return this._toEntity(data);
    } catch (error: unknown) {
      if (error instanceof AppError) {
        throw error;
      }

      logger.error('Error while fetching joke from provider', {
        error: error instanceof Error ? error.message : 'Unknown error',
      });
      throw new AppError('Joke service is temporarily unavailable', 503);
    }
  }

  /**
   * Transform provider response into a stable domain entity
   */
  private _toEntity(payload: unknown): JokeEntity {
    if (!this.isValidJokeApiResponse(payload)) {
      logger.error('Joke provider returned payload with unexpected structure', {
        payload,
      });
      throw new AppError('Invalid joke response from provider', 502);
    }

    const apiResponse = payload;

    if (apiResponse.error) {
      logger.error('Joke provider returned an application error', {
        message: apiResponse.message ?? 'Unknown provider error',
      });
      throw new AppError('Joke provider returned an invalid response', 502);
    }

    const category = apiResponse.category ?? 'General';

    if (apiResponse.type === 'single' && apiResponse.joke) {
      return {
        category,
        type: 'single',
        setup: null,
        delivery: null,
        joke: apiResponse.joke,
        source: 'JokeAPI',
      };
    }

    if (
      apiResponse.type === 'twopart' &&
      apiResponse.setup &&
      apiResponse.delivery
    ) {
      return {
        category,
        type: 'twopart',
        setup: apiResponse.setup,
        delivery: apiResponse.delivery,
        joke: `${apiResponse.setup} ${apiResponse.delivery}`,
        source: 'JokeAPI',
      };
    }

    logger.error('Unexpected joke provider payload structure', {
      payload: apiResponse,
    });
    throw new AppError('Invalid joke response from provider', 502);
  }

  private isValidJokeApiResponse(payload: unknown): payload is JokeApiResponse {
    if (typeof payload !== 'object' || payload === null) {
      return false;
    }

    const candidate = payload as {
      error?: unknown;
      category?: unknown;
      type?: unknown;
      joke?: unknown;
      setup?: unknown;
      delivery?: unknown;
      message?: unknown;
    };

    if (typeof candidate.error !== 'boolean') {
      return false;
    }

    if (
      candidate.type !== undefined &&
      candidate.type !== 'single' &&
      candidate.type !== 'twopart'
    ) {
      return false;
    }

    if (candidate.category !== undefined && typeof candidate.category !== 'string') {
      return false;
    }

    if (candidate.joke !== undefined && typeof candidate.joke !== 'string') {
      return false;
    }

    if (candidate.setup !== undefined && typeof candidate.setup !== 'string') {
      return false;
    }

    if (candidate.delivery !== undefined && typeof candidate.delivery !== 'string') {
      return false;
    }

    if (candidate.message !== undefined && typeof candidate.message !== 'string') {
      return false;
    }

    return true;
  }
}

export default new JokeRepository();

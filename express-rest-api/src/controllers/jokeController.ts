import { Request, Response, NextFunction } from 'express';
import jokeService from '../services/jokeService.js';
import logger from '../utils/logger.js';

/**
 * Controller for joke endpoints
 */
class JokeController {
  /**
   * Get a random joke of the day
   * GET /api/joke-of-day
   */
  static readonly getJokeOfDay = async (
    _req: Request,
    res: Response,
    next: NextFunction
  ): Promise<void> => {
    try {
      const joke = await jokeService.getJokeOfDay();

      logger.info('Joke-of-day request served successfully', {
        category: joke.category,
        type: joke.type,
      });

      res.status(200).json({
        status: 'success',
        data: joke,
      });
    } catch (error: unknown) {
      next(error);
    }
  };
}

export default JokeController;

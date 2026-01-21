import { Request, Response } from 'express';

/**
 * Controller for basic application endpoints
 */
class IndexController {
  /**
   * Handle root endpoint
   * GET /
   *
   * @param _req - Express request object (unused)
   * @param res - Express response object
   */
  static getIndex(_req: Request, res: Response): void {
    res.send('Hello, World!');
  }
}

export default IndexController;

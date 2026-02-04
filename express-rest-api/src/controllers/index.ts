import { Request, Response } from 'express';

/**
 * Controller for basic application endpoints
 */
class IndexController {
  /**
   * Handle root endpoint - render timezone search page
   * GET /
   *
   * @param _req - Express request object (unused)
   * @param res - Express response object
   */
  static getIndex(_req: Request, res: Response): void {
    res.render('index', {
      title: 'Timezone Explorer',
    });
  }
}

export default IndexController;

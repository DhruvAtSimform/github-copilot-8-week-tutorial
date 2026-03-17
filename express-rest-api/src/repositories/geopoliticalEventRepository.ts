import { z } from 'zod';
import AppError from '../utils/errors/AppError.js';
import logger from '../utils/logger.js';
import { env } from '../config/env.js';

/**
 * Normalized geopolitical event entity from external provider
 */
export interface GeopoliticalEventEntity {
  readonly title: string;
  readonly url: string;
  readonly publishedAt: string;
  readonly source: string;
  readonly sourceCountry: string;
  readonly language: string;
  readonly imageUrl: string | null;
  readonly provider: string;
}

const GdeltArticleSchema = z.object({
  url: z.string().min(1).optional(),
  title: z.string().min(1).optional(),
  seendate: z.string().min(1).optional(),
  socialimage: z.string().nullable().optional(),
  domain: z.string().nullable().optional(),
  language: z.string().nullable().optional(),
  sourcecountry: z.string().nullable().optional(),
});

const GdeltResponseSchema = z.object({
  articles: z.array(GdeltArticleSchema).optional(),
});

/**
 * Repository for fetching geopolitical coverage from GDELT DOC API
 */
class GeopoliticalEventRepository {
  private readonly gdeltDocApiUrl: string;

  private readonly requestTimeoutMs = 10000;

  private readonly query =
    '(theme:TERROR OR theme:US_FOREIGN_POLICY OR theme:WB_696_PUBLIC_SECTOR_MANAGEMENT OR theme:CRISISLEX_C07_SAFETY)';

  constructor() {
    this.gdeltDocApiUrl =
      env.GDELT_DOC_API_URL ?? 'https://api.gdeltproject.org/api/v2/doc/doc';
  }

  /**
   * Fetch the most recent geopolitical event candidate from the last 24 hours
   */
  async fetchGeopoliticalEventOfDay(): Promise<GeopoliticalEventEntity> {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => {
      controller.abort();
    }, this.requestTimeoutMs);

    try {
      const requestUrl = this._buildRequestUrl();

      const response = await fetch(requestUrl, {
        method: 'GET',
        headers: {
          Accept: 'application/json',
          'User-Agent': 'express-rest-api/1.0 (+geopolitical-event-endpoint)',
        },
        signal: controller.signal,
      });

      if (!response.ok) {
        logger.error('GDELT provider returned non-success status', {
          status: response.status,
          statusText: response.statusText,
        });

        if (response.status === 429) {
          throw new AppError(
            'Geopolitical provider rate-limited the request. Please retry shortly.',
            503
          );
        }

        throw new AppError(
          'Failed to fetch geopolitical event from provider',
          502
        );
      }

      const payload: unknown = await response.json();
      return this._toEntity(payload);
    } catch (error: unknown) {
      if (error instanceof Error && error.name === 'AbortError') {
        logger.error('GDELT provider request timed out', {
          timeoutMs: this.requestTimeoutMs,
        });
        throw new AppError(
          'Geopolitical provider request timed out',
          504
        );
      }

      if (error instanceof AppError) {
        throw error;
      }

      logger.error('Error while fetching geopolitical event from provider', {
        error: error instanceof Error ? error.message : 'Unknown error',
      });
      throw new AppError(
        'Geopolitical event service is temporarily unavailable',
        503
      );
    } finally {
      clearTimeout(timeoutId);
    }
  }

  private _buildRequestUrl(): string {
    const params = new URLSearchParams({
      query: this.query,
      mode: 'artlist',
      maxrecords: '25',
      timespan: '1day',
      sort: 'datedesc',
      format: 'json',
    });

    return `${this.gdeltDocApiUrl}?${params.toString()}`;
  }

  private _toEntity(payload: unknown): GeopoliticalEventEntity {
    const parsed = GdeltResponseSchema.safeParse(payload);

    if (!parsed.success) {
      logger.error('Unexpected GDELT payload structure', {
        issues: parsed.error.issues,
      });
      throw new AppError(
        'Invalid geopolitical event response from provider',
        502
      );
    }

    const articles = parsed.data.articles ?? [];

    const article = articles.find((item) => {
      if (!item.url || !item.title || !item.seendate) {
        return false;
      }

      return this._isValidUrl(item.url);
    });

    if (!article?.url || !article.title || !article.seendate) {
      throw new AppError(
        'No geopolitical event found for the requested period',
        404
      );
    }

    return {
      title: article.title,
      url: article.url,
      publishedAt: this._parseSeenDate(article.seendate),
      source: article.domain?.trim() ? article.domain : 'Unknown source',
      sourceCountry: article.sourcecountry?.trim()
        ? article.sourcecountry
        : 'Unknown',
      language: article.language?.trim() ? article.language : 'Unknown',
      imageUrl: this._normalizeOptionalUrl(article.socialimage),
      provider: 'GDELT DOC 2.0',
    };
  }

  private _isValidUrl(url: string): boolean {
    try {
      const parsed = new URL(url);
      return parsed.protocol === 'http:' || parsed.protocol === 'https:';
    } catch {
      return false;
    }
  }

  private _normalizeOptionalUrl(
    value: string | null | undefined
  ): string | null {
    if (!value || !value.trim()) {
      return null;
    }

    return this._isValidUrl(value) ? value : null;
  }

  private _parseSeenDate(seenDate: string): string {
    const match = seenDate.match(
      /^(\d{4})(\d{2})(\d{2})T(\d{2})(\d{2})(\d{2})Z$/
    );

    if (!match) {
      return new Date().toISOString();
    }

    const year = match[1];
    const month = match[2];
    const day = match[3];
    const hour = match[4];
    const minute = match[5];
    const second = match[6];

    return `${year}-${month}-${day}T${hour}:${minute}:${second}Z`;
  }
}

export default new GeopoliticalEventRepository();

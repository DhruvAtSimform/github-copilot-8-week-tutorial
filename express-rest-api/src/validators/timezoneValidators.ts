import { z } from 'zod';

/**
 * Validation schema for timezone query parameters
 */
export const getTimezonesQuerySchema = z.object({
  countryCode: z
    .string()
    .trim()
    .length(2, 'Country code must be exactly 2 characters')
    .regex(/^[A-Z]{2}$/i, 'Country code must be two letters')
    .transform((val) => val.toUpperCase())
    .optional(),
  clientCountry: z
    .string()
    .trim()
    .length(2)
    .regex(/^[A-Z]{2}$/i)
    .transform((val) => val.toUpperCase())
    .optional(),
  fallback: z
    .enum(['true', 'false', '1', '0'])
    .transform((val) => val === 'true' || val === '1')
    .optional(),
});

export type GetTimezonesQuery = z.infer<typeof getTimezonesQuerySchema>;

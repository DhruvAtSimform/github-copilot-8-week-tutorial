/**
 * Timezone mappings by ISO 3166-1 alpha-2 country codes
 * Contains the primary timezone(s) for each country
 */
export const TIMEZONE_BY_COUNTRY: Record<string, string[]> = {
  IN: ['Asia/Kolkata'],
  US: [
    'America/New_York',
    'America/Chicago',
    'America/Denver',
    'America/Los_Angeles',
    'America/Anchorage',
    'Pacific/Honolulu',
  ],
  GB: ['Europe/London'],
  CA: [
    'America/Toronto',
    'America/Vancouver',
    'America/Edmonton',
    'America/Winnipeg',
  ],
  AU: [
    'Australia/Sydney',
    'Australia/Melbourne',
    'Australia/Brisbane',
    'Australia/Perth',
    'Australia/Adelaide',
  ],
  JP: ['Asia/Tokyo'],
  DE: ['Europe/Berlin'],
  FR: ['Europe/Paris'],
  IT: ['Europe/Rome'],
  ES: ['Europe/Madrid'],
  BR: ['America/Sao_Paulo', 'America/Manaus', 'America/Fortaleza'],
  MX: ['America/Mexico_City', 'America/Monterrey', 'America/Cancun'],
  ZA: ['Africa/Johannesburg'],
  NG: ['Africa/Lagos'],
  EG: ['Africa/Cairo'],
  SG: ['Asia/Singapore'],
  CN: ['Asia/Shanghai'],
  NZ: ['Pacific/Auckland', 'Pacific/Chatham'],
  RU: ['Europe/Moscow', 'Asia/Vladivostok', 'Asia/Novosibirsk'],
} as const;

/**
 * Default country code when none is provided
 */
export const DEFAULT_COUNTRY_CODE = 'IN';

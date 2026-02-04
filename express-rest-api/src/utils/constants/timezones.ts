/**
 * Initial timezone seed data by ISO 3166-1 alpha-2 country codes
 * This is the base data; additional timezones can be managed via repository
 */
export const INITIAL_TIMEZONE_DATA = {
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
 * Country names mapping (ISO 3166-1 alpha-2 to country name)
 */
export const COUNTRY_NAMES: Record<string, string> = {
  IN: 'India',
  US: 'United States',
  GB: 'United Kingdom',
  CA: 'Canada',
  AU: 'Australia',
  JP: 'Japan',
  DE: 'Germany',
  FR: 'France',
  IT: 'Italy',
  ES: 'Spain',
  BR: 'Brazil',
  MX: 'Mexico',
  ZA: 'South Africa',
  NG: 'Nigeria',
  EG: 'Egypt',
  SG: 'Singapore',
  CN: 'China',
  NZ: 'New Zealand',
  RU: 'Russia',
};

/**
 * Default country code when none is provided
 */
export const DEFAULT_COUNTRY_CODE = 'IN' as const;

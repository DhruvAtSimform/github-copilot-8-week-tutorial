import helmet from 'helmet';

/**
 * Comprehensive security headers configuration using Helmet
 * Configured for REST API with JSON responses
 */
export const securityHeadersConfig = helmet({
  // Strict Transport Security (HSTS)
  hsts: {
    maxAge: 31536000, // 1 year in seconds
    includeSubDomains: true,
    preload: true,
  },

  // Content Security Policy - STRICT (No unsafe-inline)
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"], // ✅ No unsafe-inline
      styleSrc: ["'self'"], // ✅ No unsafe-inline
      imgSrc: ["'self'", 'data:', 'https:'],
      connectSrc: ["'self'"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      mediaSrc: ["'self'"],
      frameSrc: ["'none'"],
      baseUri: ["'self'"],
      formAction: ["'self'"],
      upgradeInsecureRequests: [],
    },
  },

  // Referrer Policy
  referrerPolicy: {
    policy: 'strict-origin-when-cross-origin',
  },

  // X-Frame-Options (Clickjacking protection)
  frameguard: {
    action: 'deny',
  },

  // X-Content-Type-Options
  noSniff: true,

  // X-DNS-Prefetch-Control
  dnsPrefetchControl: {
    allow: false,
  },

  // X-Download-Options for IE8+
  ieNoOpen: true,

  // Cross-Origin policies - relaxed for REST API
  crossOriginEmbedderPolicy: false, // Changed from true
  crossOriginOpenerPolicy: { policy: 'same-origin-allow-popups' }, // Relaxed
  crossOriginResourcePolicy: { policy: 'cross-origin' }, // Changed from same-origin
});

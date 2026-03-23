/**
 * Mock timezone repository for testing
 */
export default {
  getByCountryCode: jest.fn(),
  getByCountryCodeWithFallback: jest.fn(),
};

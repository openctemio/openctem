/**
 * Sensor API keys for tests. Obviously fake so secret scanners (betterleaks,
 * gitleaks, GitHub secret scanning) skip them: never write a realistic
 * `octs_…` or `rda_<hex>` literal in a test.
 */
export const TEST_SENSOR_KEY = 'octs_test_placeholder'

/** The key prefix a sensor row shows (`api_key_prefix`). */
export const TEST_SENSOR_KEY_PREFIX = 'octs_test'

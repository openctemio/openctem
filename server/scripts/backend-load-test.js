import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate } from 'k6/metrics';

// Custom metrics
const errorRate = new Rate('errors');

// Test configuration
export const options = {
    stages: [
        { duration: '30s', target: 20 }, // Ramp up to 20 users
        { duration: '1m', target: 20 },  // Stay at 20 users
        { duration: '30s', target: 0 },  // Ramp down to 0
    ],
    thresholds: {
        http_req_duration: ['p(95)<500'], // 95% of requests must complete below 500ms
        errors: ['rate<0.01'],            // Error rate must be less than 1%
    },
};

const BASE_URL = __ENV.API_URL || 'http://localhost:8080/api/v1';
const TEST_USER = {
    email: __ENV.TEST_EMAIL || 'admin@openctem.io',
    password: __ENV.TEST_PASSWORD || 'password123',
};

export function setup() {
    // Login to get token
    const loginRes = http.post(`${BASE_URL}/auth/login`, JSON.stringify(TEST_USER), {
        headers: { 'Content-Type': 'application/json' },
    });

    check(loginRes, {
        'login successful': (r) => r.status === 200,
    }) || errorRate.add(1);

    if (loginRes.status !== 200) {
        console.error('Login failed:', loginRes.body);
        return {};
    }

    const data = loginRes.json();
    const token = data.refresh_token; // Initially we get refresh token
    const tenantId = data.tenants[0]?.id; // Pick first tenant

    // Exchange for access token
    const tokenRes = http.post(`${BASE_URL}/auth/token`, JSON.stringify({
        tenant_id: tenantId,
        refresh_token: token
    }), {
        headers: { 'Content-Type': 'application/json' },
    });

    const tokenData = tokenRes.json();
    return { token: tokenData.access_token };
}

export default function (data) {
    if (!data.token) return;

    const params = {
        headers: {
            Authorization: `Bearer ${data.token}`,
            'Content-Type': 'application/json',
        },
    };

    // Test 1: List Assets
    const assetsRes = http.get(`${BASE_URL}/assets`, params);
    check(assetsRes, {
        'assets status 200': (r) => r.status === 200,
        'assets listing fast': (r) => r.timings.duration < 200,
    }) || errorRate.add(1);

    // Test 2: Get Findings (Another heavy endpoint)
    const findingsRes = http.get(`${BASE_URL}/findings`, params);
    check(findingsRes, {
        'findings status 200': (r) => r.status === 200,
    }) || errorRate.add(1);

    sleep(1);
}

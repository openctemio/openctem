#!/usr/bin/env python3
"""
OpenCTEM OSS API Integration Tests
Tests all major API flows to ensure migrations and code are working correctly.
"""

import requests
import json
import time
import sys
import uuid
from datetime import datetime
from typing import Optional, Dict, Any, List

# Configuration
BASE_URL = "http://localhost:8080"
API_V1 = f"{BASE_URL}/api/v1"

# Test data
TEST_EMAIL = f"test_{uuid.uuid4().hex[:8]}@example.com"
TEST_PASSWORD = "TestPassword123!"
TEST_TEAM_NAME = f"Test Team {uuid.uuid4().hex[:8]}"
TEST_TEAM_SLUG = f"test-team-{uuid.uuid4().hex[:8]}"

# Global state
access_token: Optional[str] = None
refresh_token: Optional[str] = None
user_id: Optional[str] = None
tenant_id: Optional[str] = None
tenant_slug: Optional[str] = None
agent_id: Optional[str] = None
agent_api_key: Optional[str] = None
asset_id: Optional[str] = None
finding_id: Optional[str] = None
scan_id: Optional[str] = None


class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    RESET = '\033[0m'
    BOLD = '\033[1m'


def log_info(msg: str):
    print(f"{Colors.CYAN}[INFO]{Colors.RESET} {msg}")


def log_success(msg: str):
    print(f"{Colors.GREEN}[PASS]{Colors.RESET} {msg}")


def log_error(msg: str):
    print(f"{Colors.RED}[FAIL]{Colors.RESET} {msg}")


def log_warning(msg: str):
    print(f"{Colors.YELLOW}[WARN]{Colors.RESET} {msg}")


def log_section(msg: str):
    print(f"\n{Colors.BOLD}{Colors.BLUE}{'='*60}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.BLUE}{msg}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.BLUE}{'='*60}{Colors.RESET}")


def get_headers(with_auth: bool = True) -> Dict[str, str]:
    """Get request headers with optional authentication."""
    headers = {"Content-Type": "application/json"}
    if with_auth and access_token:
        headers["Authorization"] = f"Bearer {access_token}"
    if tenant_slug:
        headers["X-Tenant"] = tenant_slug
    return headers


def get_agent_headers() -> Dict[str, str]:
    """Get headers for agent API calls."""
    return {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {agent_api_key}"
    }


def api_request(method: str, endpoint: str, data: Optional[Dict] = None,
                with_auth: bool = True, expected_status: int = 200,
                use_agent_auth: bool = False) -> Optional[Dict]:
    """Make an API request and handle response."""
    url = f"{API_V1}{endpoint}"
    headers = get_agent_headers() if use_agent_auth else get_headers(with_auth)

    try:
        if method == "GET":
            resp = requests.get(url, headers=headers, timeout=30)
        elif method == "POST":
            resp = requests.post(url, json=data, headers=headers, timeout=30)
        elif method == "PUT":
            resp = requests.put(url, json=data, headers=headers, timeout=30)
        elif method == "PATCH":
            resp = requests.patch(url, json=data, headers=headers, timeout=30)
        elif method == "DELETE":
            resp = requests.delete(url, headers=headers, timeout=30)
        else:
            log_error(f"Unknown method: {method}")
            return None

        if resp.status_code == expected_status:
            if resp.text:
                return resp.json()
            return {}
        else:
            log_error(f"{method} {endpoint} - Expected {expected_status}, got {resp.status_code}")
            if resp.text:
                try:
                    error_detail = resp.json()
                    log_error(f"  Error: {json.dumps(error_detail, indent=2)}")
                except:
                    log_error(f"  Response: {resp.text[:500]}")
            return None
    except Exception as e:
        log_error(f"{method} {endpoint} - Exception: {str(e)}")
        return None


# ============================================================================
# HEALTH CHECK TESTS
# ============================================================================

def test_health():
    """Test health endpoints."""
    log_section("HEALTH CHECK TESTS")

    # Health endpoint
    resp = requests.get(f"{BASE_URL}/health", timeout=10)
    if resp.status_code == 200 and resp.json().get("status") == "healthy":
        log_success("GET /health - API is healthy")
    else:
        log_error("GET /health - API is not healthy")
        return False

    # Ready endpoint
    resp = requests.get(f"{BASE_URL}/ready", timeout=10)
    if resp.status_code == 200:
        log_success("GET /ready - API is ready")
    else:
        log_warning("GET /ready - API not ready (may be expected)")

    return True


# ============================================================================
# AUTH TESTS
# ============================================================================

def test_auth_register():
    """Test user registration."""
    global user_id

    log_section("AUTH TESTS - Registration")

    data = {
        "email": TEST_EMAIL,
        "password": TEST_PASSWORD,
        "name": "Test User"
    }

    result = api_request("POST", "/auth/register", data, with_auth=False, expected_status=201)
    if result:
        user_id = result.get("user", {}).get("id")
        log_success(f"POST /auth/register - User created: {user_id}")
        return True
    return False


def test_auth_login():
    """Test user login - returns refresh_token and list of tenants."""
    global refresh_token

    log_section("AUTH TESTS - Login")

    data = {
        "email": TEST_EMAIL,
        "password": TEST_PASSWORD
    }

    result = api_request("POST", "/auth/login", data, with_auth=False)
    if result:
        refresh_token = result.get("refresh_token")
        tenants = result.get("tenants", [])
        if refresh_token:
            log_success(f"POST /auth/login - Got refresh token")
            log_info(f"  User has {len(tenants)} tenants")
            return True
        else:
            log_error("No refresh_token in response")
    return False


def test_auth_create_first_team():
    """Test creating first team during signup."""
    global tenant_id, tenant_slug, access_token, refresh_token

    log_section("AUTH TESTS - Create First Team")

    # API expects team_name and team_slug (snake_case)
    # refresh_token is sent via cookie
    data = {
        "team_name": TEST_TEAM_NAME,
        "team_slug": TEST_TEAM_SLUG
    }

    url = f"{API_V1}/auth/create-first-team"
    headers = {"Content-Type": "application/json"}
    cookies = {"refresh_token": refresh_token}

    try:
        resp = requests.post(url, json=data, headers=headers, cookies=cookies, timeout=30)
        if resp.status_code == 201:
            result = resp.json()
            tenant_id = result.get("tenant_id")
            tenant_slug = result.get("tenant_slug")
            access_token = result.get("access_token")
            # IMPORTANT: Update refresh_token since the old one is revoked after use
            new_refresh = result.get("refresh_token")
            if new_refresh:
                refresh_token = new_refresh
            log_success(f"POST /auth/create-first-team - Team created: {tenant_slug}")
            if access_token:
                log_success("  Got access token for new team")
            return True
        else:
            log_error(f"POST /auth/create-first-team - Expected 201, got {resp.status_code}")
            try:
                log_error(f"  Error: {json.dumps(resp.json(), indent=2)}")
            except:
                log_error(f"  Response: {resp.text[:500]}")
            return False
    except Exception as e:
        log_error(f"POST /auth/create-first-team - Exception: {str(e)}")
        return False


def test_auth_exchange_token():
    """Test exchanging refresh token for access token (when tenant exists)."""
    global access_token

    log_section("AUTH TESTS - Exchange Token")

    if not tenant_id:
        log_warning("No tenant_id available, skipping token exchange")
        return True

    data = {
        "refresh_token": refresh_token,
        "tenant_id": tenant_id
    }

    result = api_request("POST", "/auth/token", data, with_auth=False)
    if result and result.get("access_token"):
        access_token = result.get("access_token")
        log_success(f"POST /auth/token - Got access token for tenant {result.get('tenant_slug')}")
        return True
    return False


def test_auth_refresh():
    """Test token refresh with rotation."""
    global access_token, refresh_token

    if not tenant_id:
        log_warning("No tenant_id available, skipping refresh test")
        return True

    data = {
        "refresh_token": refresh_token,
        "tenant_id": tenant_id
    }
    result = api_request("POST", "/auth/refresh", data, with_auth=False)
    if result and result.get("access_token"):
        access_token = result.get("access_token")
        new_refresh = result.get("refresh_token")
        if new_refresh:
            refresh_token = new_refresh
        log_success("POST /auth/refresh - Token refreshed")
        return True
    return False


def test_user_profile():
    """Test user profile endpoints."""
    log_section("USER PROFILE TESTS")

    # Get profile
    result = api_request("GET", "/users/me")
    if result and isinstance(result, dict) and result.get("id"):
        log_success(f"GET /users/me - Got user profile: {result.get('email')}")
    else:
        return False

    # Get user's tenants - may return array directly
    result = api_request("GET", "/users/me/tenants")
    if result is not None:
        if isinstance(result, dict):
            tenants = result.get('tenants', [])
        else:
            tenants = result  # array directly
        log_success(f"GET /users/me/tenants - Got {len(tenants)} tenants")
    else:
        return False

    return True


# ============================================================================
# TENANT/TEAM TESTS
# ============================================================================

def test_tenant_operations():
    """Test tenant/team operations."""
    log_section("TENANT TESTS")

    # List tenants
    result = api_request("GET", "/tenants")
    if result:
        log_success(f"GET /tenants - Listed {len(result.get('tenants', []))} tenants")
    else:
        return False

    # Get tenant details
    result = api_request("GET", f"/tenants/{tenant_slug}")
    if result and result.get("id"):
        log_success(f"GET /tenants/{tenant_slug} - Got tenant details")
    else:
        return False

    # List members
    result = api_request("GET", f"/tenants/{tenant_slug}/members")
    if result:
        log_success(f"GET /tenants/{tenant_slug}/members - Listed {len(result.get('members', []))} members")
    else:
        return False

    # Get settings
    result = api_request("GET", f"/tenants/{tenant_slug}/settings")
    if result:
        log_success(f"GET /tenants/{tenant_slug}/settings - Got settings")
    else:
        return False

    return True


# ============================================================================
# ROLES & PERMISSIONS TESTS
# ============================================================================

def test_roles_permissions():
    """Test roles and permissions endpoints."""
    log_section("ROLES & PERMISSIONS TESTS")

    # List roles
    result = api_request("GET", "/roles")
    if result:
        # Handle both wrapped {roles: [...]} and array response formats
        roles = result.get("roles", []) if isinstance(result, dict) else result
        log_success(f"GET /roles - Listed {len(roles)} roles")
        for role in roles[:3]:
            log_info(f"  - {role.get('name')} ({role.get('slug')})")
    else:
        return False

    # List permissions - returns array directly
    result = api_request("GET", "/permissions")
    if result is not None:
        # Handle both wrapped {permissions: [...]} and array response formats
        perms = result.get("permissions", []) if isinstance(result, dict) else result
        log_success(f"GET /permissions - Listed {len(perms)} permissions")
    else:
        return False

    # Get current user's permissions - returns array directly
    result = api_request("GET", "/me/permissions")
    if result is not None:
        # Handle both wrapped and array response formats
        perms = result.get("permissions", []) if isinstance(result, dict) else result
        log_success(f"GET /me/permissions - User has {len(perms)} permissions")
    else:
        return False

    return True


# ============================================================================
# AGENT TESTS
# ============================================================================

def test_agent_crud():
    """Test agent CRUD operations."""
    global agent_id, agent_api_key

    log_section("AGENT TESTS")

    # Create agent
    data = {
        "name": f"Test Agent {uuid.uuid4().hex[:8]}",
        "type": "runner",
        "executionMode": "daemon",
        "tools": ["semgrep", "trivy", "gitleaks"],
        "capabilities": ["sast", "sca", "secrets"]
    }

    result = api_request("POST", "/agents", data, expected_status=201)
    if result:
        agent_id = result.get("agent", {}).get("id")
        agent_api_key = result.get("api_key")  # snake_case from API
        log_success(f"POST /agents - Agent created: {agent_id}")
        if agent_api_key:
            log_info(f"  API Key: {agent_api_key[:20]}...")
    else:
        return False

    # List agents
    result = api_request("GET", "/agents")
    if result:
        log_success(f"GET /agents - Listed {len(result.get('agents', []))} agents")
    else:
        return False

    # Get agent details
    result = api_request("GET", f"/agents/{agent_id}")
    if result and result.get("id"):
        log_success(f"GET /agents/{agent_id} - Got agent details")
        log_info(f"  Status: {result.get('status')}, Health: {result.get('health')}")
    else:
        return False

    # Update agent
    data = {"description": "Updated test agent"}
    result = api_request("PUT", f"/agents/{agent_id}", data)
    if result:
        log_success(f"PUT /agents/{agent_id} - Agent updated")
    else:
        return False

    return True


def test_agent_heartbeat():
    """Test agent heartbeat with API key auth."""
    log_section("AGENT HEARTBEAT TEST")

    if not agent_api_key:
        log_warning("No agent API key available, skipping heartbeat test")
        return True

    data = {
        "status": "online",
        "tools": ["semgrep", "trivy", "gitleaks"],
        "capabilities": ["sast", "sca", "secrets"],
        "agentVersion": "1.0.0",
        "osInfo": "Linux 5.4.0",
        "metrics": {
            "cpuPercent": 25.5,
            "memoryPercent": 45.2,
            "diskReadMbps": 10.5,
            "diskWriteMbps": 5.2
        }
    }

    result = api_request("POST", "/agent/heartbeat", data, use_agent_auth=True)
    if result:
        log_success("POST /agent/heartbeat - Heartbeat successful")
        return True
    return False


# ============================================================================
# ASSET TESTS
# ============================================================================

def test_asset_crud():
    """Test asset CRUD operations."""
    global asset_id

    log_section("ASSET TESTS")

    # Create asset
    data = {
        "name": f"test-repo-{uuid.uuid4().hex[:8]}",
        "type": "repository",
        "status": "active",
        "classification": "internal",
        "criticality": "medium",
        "repository": {
            "url": "https://github.com/example/test-repo",
            "provider": "github",
            "defaultBranch": "main"
        }
    }

    result = api_request("POST", "/assets", data, expected_status=201)
    if result:
        asset_id = result.get("id")
        log_success(f"POST /assets - Asset created: {asset_id}")
    else:
        return False

    # List assets
    result = api_request("GET", "/assets")
    if result:
        log_success(f"GET /assets - Listed {result.get('total', 0)} assets")
    else:
        return False

    # Get asset details
    result = api_request("GET", f"/assets/{asset_id}")
    if result and result.get("id"):
        log_success(f"GET /assets/{asset_id} - Got asset details")
    else:
        return False

    # Get asset stats
    result = api_request("GET", "/assets/stats")
    if result:
        log_success(f"GET /assets/stats - Got asset statistics")
    else:
        return False

    # Update asset
    data = {"description": "Updated test asset"}
    result = api_request("PUT", f"/assets/{asset_id}", data)
    if result:
        log_success(f"PUT /assets/{asset_id} - Asset updated")
    else:
        return False

    return True


# ============================================================================
# FINDING TESTS
# ============================================================================

def test_finding_crud():
    """Test finding CRUD operations."""
    global finding_id

    log_section("FINDING TESTS")

    if not asset_id:
        log_warning("No asset available, skipping finding tests")
        return True

    # Create finding - API uses snake_case
    data = {
        "asset_id": asset_id,
        "source": "sast",
        "tool_name": "semgrep",
        "title": "SQL Injection vulnerability",
        "message": "Potential SQL injection in user input handling",
        "severity": "high",
        "status": "open",
        "file_path": "src/db/query.py",
        "start_line": 42,
        "end_line": 45,
        "fingerprint": f"fp_{uuid.uuid4().hex}",
        "cwe_ids": ["CWE-89"],
        "owasp_ids": ["A03:2021"]
    }

    result = api_request("POST", "/findings", data, expected_status=201)
    if result:
        finding_id = result.get("id")
        log_success(f"POST /findings - Finding created: {finding_id}")
    else:
        return False

    # List findings
    result = api_request("GET", "/findings")
    if result:
        log_success(f"GET /findings - Listed {result.get('total', 0)} findings")
    else:
        return False

    # Get finding details
    result = api_request("GET", f"/findings/{finding_id}")
    if result and result.get("id"):
        log_success(f"GET /findings/{finding_id} - Got finding details")
    else:
        return False

    # Get finding stats
    result = api_request("GET", "/findings/stats")
    if result:
        log_success(f"GET /findings/stats - Got finding statistics")
        log_info(f"  Total: {result.get('total', 0)}, Open: {result.get('open', 0)}")
    else:
        return False

    # Update finding status
    data = {"status": "in_progress"}
    result = api_request("PATCH", f"/findings/{finding_id}/status", data)
    if result:
        log_success(f"PATCH /findings/{finding_id}/status - Status updated")
    else:
        return False

    # Triage finding
    data = {"triageStatus": "confirmed", "triageReason": "Verified by security team"}
    result = api_request("PATCH", f"/findings/{finding_id}/triage", data)
    if result:
        log_success(f"PATCH /findings/{finding_id}/triage - Finding triaged")
    else:
        return False

    # Add comment
    data = {"content": "This needs immediate attention"}
    result = api_request("POST", f"/findings/{finding_id}/comments", data, expected_status=201)
    if result:
        log_success(f"POST /findings/{finding_id}/comments - Comment added")
    else:
        return False

    return True


# ============================================================================
# SCAN TESTS
# ============================================================================

def test_scan_crud():
    """Test scan CRUD operations."""
    global scan_id

    log_section("SCAN TESTS")

    # Create scan
    data = {
        "name": f"Test Scan {uuid.uuid4().hex[:8]}",
        "scan_type": "single",
        "scanner_name": "semgrep",
        "schedule_type": "manual",
        "targets": ["https://github.com/example/test-repo"],
        "agent_preference": "auto"
    }

    result = api_request("POST", "/scans", data, expected_status=201)
    if result:
        scan_id = result.get("id")
        log_success(f"POST /scans - Scan created: {scan_id}")
    else:
        return False

    # List scans
    result = api_request("GET", "/scans")
    if result:
        log_success(f"GET /scans - Listed {result.get('total', 0)} scans")
    else:
        return False

    # Get scan details
    result = api_request("GET", f"/scans/{scan_id}")
    if result and result.get("id"):
        log_success(f"GET /scans/{scan_id} - Got scan details")
    else:
        return False

    # Get scan stats
    result = api_request("GET", "/scans/stats")
    if result:
        log_success(f"GET /scans/stats - Got scan statistics")
    else:
        return False

    # Update scan
    data = {"description": "Updated test scan"}
    result = api_request("PUT", f"/scans/{scan_id}", data)
    if result:
        log_success(f"PUT /scans/{scan_id} - Scan updated")
    else:
        return False

    return True


# ============================================================================
# TOOL TESTS
# ============================================================================

def test_tools():
    """Test tool endpoints."""
    log_section("TOOL TESTS")

    # List platform tools
    result = api_request("GET", "/tools/platform")
    if result:
        tools = result.get("tools", [])
        log_success(f"GET /tools/platform - Listed {len(tools)} platform tools")
        for tool in tools[:5]:
            log_info(f"  - {tool.get('name')} ({tool.get('category')})")
    else:
        return False

    # List tools
    result = api_request("GET", "/tools")
    if result:
        log_success(f"GET /tools - Listed {result.get('total', 0)} tools")
    else:
        return False

    # List capabilities
    result = api_request("GET", "/capabilities/all")
    if result:
        caps = result.get("capabilities", [])
        log_success(f"GET /capabilities/all - Listed {len(caps)} capabilities")
    else:
        return False

    return True


# ============================================================================
# INTEGRATION TESTS
# ============================================================================

def test_integrations():
    """Test integration endpoints."""
    log_section("INTEGRATION TESTS")

    # List integrations
    result = api_request("GET", "/integrations")
    if result:
        log_success(f"GET /integrations - Listed {len(result.get('integrations', []))} integrations")
    else:
        return False

    # List SCM integrations
    result = api_request("GET", "/integrations/scm")
    if result:
        log_success(f"GET /integrations/scm - Listed {len(result.get('integrations', []))} SCM integrations")
    else:
        return False

    return True


# ============================================================================
# VULNERABILITY TESTS
# ============================================================================

def test_vulnerabilities():
    """Test vulnerability endpoints."""
    log_section("VULNERABILITY TESTS")

    # List vulnerabilities
    result = api_request("GET", "/vulnerabilities?limit=10")
    if result:
        log_success(f"GET /vulnerabilities - Listed {result.get('total', 0)} vulnerabilities")
    else:
        return False

    return True


# ============================================================================
# DASHBOARD TESTS
# ============================================================================

def test_dashboard():
    """Test dashboard endpoints."""
    log_section("DASHBOARD TESTS")

    # Get dashboard stats
    result = api_request("GET", "/dashboard/stats")
    if result:
        log_success(f"GET /dashboard/stats - Got dashboard statistics")
        log_info(f"  Assets: {result.get('assets', {}).get('total', 0)}")
        log_info(f"  Findings: {result.get('findings', {}).get('total', 0)}")
    else:
        return False

    return True


# ============================================================================
# AUDIT LOG TESTS
# ============================================================================

def test_audit_logs():
    """Test audit log endpoints."""
    log_section("AUDIT LOG TESTS")

    # List audit logs
    result = api_request("GET", "/audit-logs?limit=10")
    if result:
        log_success(f"GET /audit-logs - Listed {result.get('total', 0)} audit logs")
    else:
        return False

    return True


# ============================================================================
# CLEANUP
# ============================================================================

def cleanup():
    """Clean up test data."""
    log_section("CLEANUP")

    # Delete finding
    if finding_id:
        result = api_request("DELETE", f"/findings/{finding_id}", expected_status=204)
        if result is not None:
            log_success(f"Deleted finding: {finding_id}")

    # Delete scan
    if scan_id:
        result = api_request("DELETE", f"/scans/{scan_id}", expected_status=204)
        if result is not None:
            log_success(f"Deleted scan: {scan_id}")

    # Delete asset
    if asset_id:
        result = api_request("DELETE", f"/assets/{asset_id}", expected_status=204)
        if result is not None:
            log_success(f"Deleted asset: {asset_id}")

    # Delete agent
    if agent_id:
        result = api_request("DELETE", f"/agents/{agent_id}", expected_status=204)
        if result is not None:
            log_success(f"Deleted agent: {agent_id}")

    log_success("Cleanup completed")


# ============================================================================
# MAIN
# ============================================================================

def main():
    """Run all tests."""
    print(f"\n{Colors.BOLD}OpenCTEM OSS API Integration Tests{Colors.RESET}")
    print(f"Base URL: {BASE_URL}")
    print(f"Test Email: {TEST_EMAIL}")
    print(f"Test Team: {TEST_TEAM_NAME}")

    tests = [
        ("Health Check", test_health),
        ("User Registration", test_auth_register),
        ("User Login", test_auth_login),
        ("Create First Team", test_auth_create_first_team),
        ("Exchange Token", test_auth_exchange_token),
        ("Token Refresh", test_auth_refresh),
        ("User Profile", test_user_profile),
        ("Tenant Operations", test_tenant_operations),
        ("Roles & Permissions", test_roles_permissions),
        ("Agent CRUD", test_agent_crud),
        ("Agent Heartbeat", test_agent_heartbeat),
        ("Asset CRUD", test_asset_crud),
        ("Finding CRUD", test_finding_crud),
        ("Scan CRUD", test_scan_crud),
        ("Tools", test_tools),
        ("Integrations", test_integrations),
        ("Vulnerabilities", test_vulnerabilities),
        ("Dashboard", test_dashboard),
        ("Audit Logs", test_audit_logs),
    ]

    passed = 0
    failed = 0

    for name, test_func in tests:
        try:
            if test_func():
                passed += 1
            else:
                failed += 1
                log_error(f"Test '{name}' failed")
        except Exception as e:
            failed += 1
            log_error(f"Test '{name}' raised exception: {str(e)}")

    # Cleanup
    try:
        cleanup()
    except Exception as e:
        log_warning(f"Cleanup failed: {str(e)}")

    # Summary
    log_section("TEST SUMMARY")
    print(f"\n{Colors.BOLD}Results:{Colors.RESET}")
    print(f"  {Colors.GREEN}Passed: {passed}{Colors.RESET}")
    print(f"  {Colors.RED}Failed: {failed}{Colors.RESET}")
    print(f"  Total: {passed + failed}")

    if failed > 0:
        print(f"\n{Colors.RED}Some tests failed!{Colors.RESET}")
        sys.exit(1)
    else:
        print(f"\n{Colors.GREEN}All tests passed!{Colors.RESET}")
        sys.exit(0)


if __name__ == "__main__":
    main()

# The three images the e2e stack (compose.yml) runs, built in parallel by
# .github/workflows/web-e2e.yml with the GitHub Actions layer cache. Paths are
# relative to the repository root (the bake-action's `source: .`).

variable "API_IMAGE" { default = "local/openctem-api:e2e" }
variable "WEB_IMAGE" { default = "local/openctem-web:e2e" }
variable "ADMIN_IMAGE" { default = "local/admin-cli:e2e" }

group "default" {
  targets = ["api", "admin", "web"]
}

target "api" {
  context    = "api"
  target     = "production"
  tags       = [API_IMAGE]
  cache-from = ["type=gha,scope=e2e-api"]
  cache-to   = ["type=gha,scope=e2e-api,mode=max"]
  output     = ["type=docker"]
}

target "admin" {
  context    = "api"
  dockerfile = "Dockerfile.admin-cli"
  tags       = [ADMIN_IMAGE]
  cache-from = ["type=gha,scope=e2e-admin"]
  cache-to   = ["type=gha,scope=e2e-admin,mode=max"]
  output     = ["type=docker"]
}

target "web" {
  context    = "web"
  tags       = [WEB_IMAGE]
  cache-from = ["type=gha,scope=e2e-web"]
  cache-to   = ["type=gha,scope=e2e-web,mode=max"]
  output     = ["type=docker"]
}

# Test-only API image for the end-to-end stack: the production API image
# (API_IMAGE) with its server binary rebuilt with the build tag authtestseam,
# so AUTHTESTSEAM_PROVIDER_URL can point the social sign-in providers at a
# stand-in (internal/app/auth/provider_endpoints.go). Never published.
#
#   docker build -f server/tests/testseam/Dockerfile \
#     --build-arg API_IMAGE=<the e2e API image> -t local/openctem-server:testseam server
ARG API_IMAGE
FROM golang:1.27.4-alpine@sha256:0a5f7fe796599ff487605987432e7619ae45beeb2fba4c2ce0b907879932aebf AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -tags authtestseam -o /out/server ./cmd/server

FROM ${API_IMAGE}
COPY --from=build /out/server /app/server
# Runs as the production API image's non-root user (server/Dockerfile).
USER 1000:1000

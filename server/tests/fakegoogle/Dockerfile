# Test-only image of the Google sign-in stand-in for the end-to-end stack
# (web/e2e/ci/fake-google.compose.yml). Never published.
FROM golang:1.27.4-alpine@sha256:0a5f7fe796599ff487605987432e7619ae45beeb2fba4c2ce0b907879932aebf AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download github.com/golang-jwt/jwt/v5
COPY tests/fakegoogle ./tests/fakegoogle
RUN CGO_ENABLED=0 go build -trimpath -o /fakegoogle ./tests/fakegoogle && mkdir /ca

FROM gcr.io/distroless/static-debian13:nonroot@sha256:aafe993665bf6200db38a02c11a9351e782a84b6a45e7f33b6695638c88e3931
COPY --from=build /fakegoogle /app/fakegoogle
# Where it writes its certificate authority (a named volume takes this owner).
COPY --from=build --chown=65532:65532 /ca /ca
# Runs as the image's non-root user; the overlay lets it bind port 443 (the
# provider's URLs are fixed in the API) with a network-namespace sysctl.
USER 65532:65532
ENTRYPOINT ["/app/fakegoogle"]

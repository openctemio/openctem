# Kubernetes Deployment Guide

Deploying the OpenCTEM platform (API, UI, PostgreSQL, Redis) on Kubernetes.

**Prerequisites**: Kubernetes 1.27+, `kubectl` configured, container images pushed to a registry.

```bash
kubectl create namespace openctem
kubectl config set-context --current --namespace=openctem
```

## Secrets

```yaml
# k8s/secrets.yaml
apiVersion: v1
kind: Secret
metadata: { name: openctem-secrets, namespace: openctem }
type: Opaque
stringData:
  db-user: "openctem"
  db-password: "CHANGE_ME_IN_PRODUCTION"
  db-name: "openctem"
  jwt-secret: "GENERATE_A_64_CHAR_RANDOM_STRING"        # min 64 chars
  encryption-key: "GENERATE_WITH_OPENSSL_RAND_HEX_32"   # openssl rand -hex 32
  redis-password: ""
```

## ConfigMap

See `docker-compose.yml` for all supported environment variables.

```yaml
# k8s/configmap.yaml
apiVersion: v1
kind: ConfigMap
metadata: { name: openctem-config, namespace: openctem }
data:
  APP_NAME: "openctem"
  APP_ENV: "production"
  SERVER_HOST: "0.0.0.0"
  SERVER_PORT: "8080"
  GRPC_PORT: "9090"
  DB_HOST: "openctem-postgres"
  DB_PORT: "5432"
  DB_SSLMODE: "require"
  REDIS_HOST: "openctem-redis"
  REDIS_PORT: "6379"
  LOG_LEVEL: "info"
  LOG_FORMAT: "json"
  AUTH_PROVIDER: "local"
  AUTH_ACCESS_TOKEN_DURATION: "15m"
  CORS_ALLOWED_ORIGINS: "https://openctem.example.com"
  RATE_LIMIT_ENABLED: "true"
  RATE_LIMIT_RPS: "100"
  RATE_LIMIT_BURST: "200"
```

## PostgreSQL

For production, prefer a managed service (AWS RDS, GCP Cloud SQL). For in-cluster PostgreSQL:

```yaml
# k8s/postgres.yaml
apiVersion: v1
kind: PersistentVolumeClaim
metadata: { name: openctem-postgres-data, namespace: openctem }
spec:
  accessModes: [ReadWriteOnce]
  storageClassName: standard
  resources: { requests: { storage: 50Gi } }
---
apiVersion: apps/v1
kind: StatefulSet
metadata: { name: openctem-postgres, namespace: openctem }
spec:
  serviceName: openctem-postgres
  replicas: 1
  selector: { matchLabels: { app: openctem-postgres } }
  template:
    metadata: { labels: { app: openctem-postgres } }
    spec:
      containers:
        - name: postgres
          image: postgres:17-alpine
          ports: [{ containerPort: 5432 }]
          env:
            - name: POSTGRES_USER
              valueFrom: { secretKeyRef: { name: openctem-secrets, key: db-user } }
            - name: POSTGRES_PASSWORD
              valueFrom: { secretKeyRef: { name: openctem-secrets, key: db-password } }
            - name: POSTGRES_DB
              valueFrom: { secretKeyRef: { name: openctem-secrets, key: db-name } }
            - { name: PGDATA, value: /var/lib/postgresql/data/pgdata }
          volumeMounts: [{ name: data, mountPath: /var/lib/postgresql/data }]
          resources:
            requests: { cpu: 500m, memory: 1Gi }
            limits: { cpu: "2", memory: 4Gi }
          readinessProbe:
            exec: { command: [pg_isready, -U, openctem, -d, openctem] }
            initialDelaySeconds: 10
            periodSeconds: 10
      volumes:
        - name: data
          persistentVolumeClaim: { claimName: openctem-postgres-data }
---
apiVersion: v1
kind: Service
metadata: { name: openctem-postgres, namespace: openctem }
spec:
  clusterIP: None
  selector: { app: openctem-postgres }
  ports: [{ port: 5432, targetPort: 5432 }]
```

## Redis

```yaml
# k8s/redis.yaml
apiVersion: apps/v1
kind: Deployment
metadata: { name: openctem-redis, namespace: openctem }
spec:
  replicas: 1
  selector: { matchLabels: { app: openctem-redis } }
  template:
    metadata: { labels: { app: openctem-redis } }
    spec:
      containers:
        - name: redis
          image: redis:7-alpine
          command: [redis-server, --appendonly, "yes", --maxmemory, 512mb, --maxmemory-policy, allkeys-lru]
          ports: [{ containerPort: 6379 }]
          resources:
            requests: { cpu: 100m, memory: 256Mi }
            limits: { cpu: 500m, memory: 1Gi }
          readinessProbe:
            exec: { command: [redis-cli, ping] }
            initialDelaySeconds: 5
            periodSeconds: 10
---
apiVersion: v1
kind: Service
metadata: { name: openctem-redis, namespace: openctem }
spec:
  selector: { app: openctem-redis }
  ports: [{ port: 6379, targetPort: 6379 }]
```

## API Deployment

Stateless, horizontally scalable. Migrations run automatically on startup.

```yaml
# k8s/api.yaml
apiVersion: apps/v1
kind: Deployment
metadata: { name: openctem-api, namespace: openctem }
spec:
  replicas: 2
  selector: { matchLabels: { app: openctem-api } }
  template:
    metadata: { labels: { app: openctem-api } }
    spec:
      containers:
        - name: api
          image: your-registry/openctem-api:latest
          ports:
            - { name: http, containerPort: 8080 }
            - { name: grpc, containerPort: 9090 }
          envFrom:
            - configMapRef: { name: openctem-config }
          env:
            - name: DB_USER
              valueFrom: { secretKeyRef: { name: openctem-secrets, key: db-user } }
            - name: DB_PASSWORD
              valueFrom: { secretKeyRef: { name: openctem-secrets, key: db-password } }
            - name: DB_NAME
              valueFrom: { secretKeyRef: { name: openctem-secrets, key: db-name } }
            - name: AUTH_JWT_SECRET
              valueFrom: { secretKeyRef: { name: openctem-secrets, key: jwt-secret } }
            - name: APP_ENCRYPTION_KEY
              valueFrom: { secretKeyRef: { name: openctem-secrets, key: encryption-key } }
            - name: REDIS_PASSWORD
              valueFrom: { secretKeyRef: { name: openctem-secrets, key: redis-password } }
          resources:
            requests: { cpu: 250m, memory: 256Mi }
            limits: { cpu: "1", memory: 512Mi }
          readinessProbe:
            httpGet: { path: /health, port: 8080 }
            initialDelaySeconds: 5
            periodSeconds: 10
          livenessProbe:
            httpGet: { path: /health, port: 8080 }
            initialDelaySeconds: 15
            periodSeconds: 30
          startupProbe:
            httpGet: { path: /health, port: 8080 }
            failureThreshold: 30
            periodSeconds: 2
---
apiVersion: v1
kind: Service
metadata: { name: openctem-api, namespace: openctem }
spec:
  selector: { app: openctem-api }
  ports:
    - { name: http, port: 8080, targetPort: 8080 }
    - { name: grpc, port: 9090, targetPort: 9090 }
```

## UI Deployment

```yaml
# k8s/ui.yaml
apiVersion: apps/v1
kind: Deployment
metadata: { name: openctem-ui, namespace: openctem }
spec:
  replicas: 2
  selector: { matchLabels: { app: openctem-ui } }
  template:
    metadata: { labels: { app: openctem-ui } }
    spec:
      containers:
        - name: ui
          image: your-registry/openctem-ui:latest
          ports: [{ containerPort: 3000 }]
          env:
            - { name: NODE_ENV, value: "production" }
            - { name: NEXT_TELEMETRY_DISABLED, value: "1" }
            - { name: BACKEND_API_URL, value: "http://openctem-api:8080" }
            - { name: NEXT_PUBLIC_API_URL, value: "http://openctem-api:8080" }
            - { name: NEXT_PUBLIC_APP_NAME, value: "OpenCTEM" }
          resources:
            requests: { cpu: 100m, memory: 256Mi }
            limits: { cpu: 500m, memory: 512Mi }
          readinessProbe:
            httpGet: { path: /, port: 3000 }
            initialDelaySeconds: 10
            periodSeconds: 10
---
apiVersion: v1
kind: Service
metadata: { name: openctem-ui, namespace: openctem }
spec:
  selector: { app: openctem-ui }
  ports: [{ port: 3000, targetPort: 3000 }]
```

## Ingress

```yaml
# k8s/ingress.yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: openctem-ingress
  namespace: openctem
  annotations:  # Adjust for your Ingress controller
    nginx.ingress.kubernetes.io/proxy-body-size: "50m"
    nginx.ingress.kubernetes.io/proxy-read-timeout: "60"
    nginx.ingress.kubernetes.io/websocket-services: "openctem-api"
    cert-manager.io/cluster-issuer: letsencrypt-prod
spec:
  ingressClassName: nginx
  tls:
    - hosts: [openctem.example.com]
      secretName: openctem-tls
  rules:
    - host: openctem.example.com
      http:
        paths:
          - path: /api/
            pathType: Prefix
            backend:
              service: { name: openctem-api, port: { number: 8080 } }
          - path: /health
            pathType: Exact
            backend:
              service: { name: openctem-api, port: { number: 8080 } }
          - path: /ws
            pathType: Prefix
            backend:
              service: { name: openctem-api, port: { number: 8080 } }
          - path: /
            pathType: Prefix
            backend:
              service: { name: openctem-ui, port: { number: 3000 } }
```

## Horizontal Pod Autoscaler (see [Scaling Guide](../../../docs/operations/SCALING.md))

```yaml
# k8s/hpa.yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: openctem-api
  namespace: openctem
spec:
  scaleTargetRef: { apiVersion: apps/v1, kind: Deployment, name: openctem-api }
  minReplicas: 2
  maxReplicas: 10
  metrics:
    - type: Resource
      resource: { name: cpu, target: { type: Utilization, averageUtilization: 70 } }
---
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: openctem-ui
  namespace: openctem
spec:
  scaleTargetRef: { apiVersion: apps/v1, kind: Deployment, name: openctem-ui }
  minReplicas: 2
  maxReplicas: 5
  metrics:
    - type: Resource
      resource: { name: cpu, target: { type: Utilization, averageUtilization: 80 } }
```

## Deploy and Verify

```bash
kubectl apply -f k8s/secrets.yaml -f k8s/configmap.yaml
kubectl apply -f k8s/postgres.yaml && kubectl apply -f k8s/redis.yaml
kubectl apply -f k8s/api.yaml -f k8s/ui.yaml
kubectl apply -f k8s/ingress.yaml -f k8s/hpa.yaml
kubectl get pods -n openctem
kubectl exec -n openctem deploy/openctem-api -- wget -qO- http://localhost:8080/health
```

**Health**: The API exposes `GET /health` (no auth) returning `200 OK`. Used by readiness, liveness, and startup probes.

**Rolling update**: `kubectl set image -n openctem deployment/openctem-api api=your-registry/openctem-api:v1.2.0`

## Production Considerations

- **Database**: Use a managed PostgreSQL service for backups and failover. Enable SSL (`DB_SSLMODE: require`). Add PgBouncer above 100 connections.
- **Redis**: Use Redis Sentinel or a managed service for HA.
- **Secrets**: Use a secrets manager (Vault, External Secrets Operator) instead of plain K8s Secrets.
- **Networking**: Enable NetworkPolicies. Set `CORS_ALLOWED_ORIGINS` to your domain.
- **Monitoring**: Export metrics to Prometheus/Grafana. Alert on pod restarts, error rates, and latency.

## Related Documentation

- [Scaling Guide](../../../docs/operations/SCALING.md) -- Capacity planning and database scaling
- [API Documentation](../api/README.md) -- REST API endpoint reference

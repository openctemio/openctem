# Kubernetes Deployment

## Prerequisites

- kubectl configured
- Kubernetes cluster

## Manifests

### Deployment

```yaml
# k8s/deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: openctem
spec:
  replicas: 3
  selector:
    matchLabels:
      app: openctem
  template:
    metadata:
      labels:
        app: openctem
    spec:
      containers:
        - name: openctem
          image: openctem:latest
          ports:
            - containerPort: 8080
          env:
            - name: DATABASE_URL
              valueFrom:
                secretKeyRef:
                  name: app-secrets
                  key: database-url
```

### Service

```yaml
# k8s/service.yaml
apiVersion: v1
kind: Service
metadata:
  name: openctem
spec:
  selector:
    app: openctem
  ports:
    - port: 80
      targetPort: 8080
  type: LoadBalancer
```

## Deploy

```bash
# Apply manifests
kubectl apply -f k8s/

# Check status
kubectl get pods -l app=openctem

# View logs
kubectl logs -f deployment/openctem
```

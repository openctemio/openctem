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
  name:.exploop
spec:
  replicas: 3
  selector:
    matchLabels:
      app:.exploop
  template:
    metadata:
      labels:
        app:.exploop
    spec:
      containers:
        - name:.exploop
          image:.exploop:latest
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
  name:.exploop
spec:
  selector:
    app:.exploop
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
kubectl get pods -l app.exploop

# View logs
kubectl logs -f deployment.exploop
```

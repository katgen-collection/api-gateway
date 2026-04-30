# API Gateway Deployment Guide

## 1. Environment Preparation
Create the environment configuration file on the VPS:
`/etc/api-gateway/service.env`
```env
PORT=3002
AUTH_SERVICE_URL=http://localhost:3000
CHAT_SERVICE_URL=http://localhost:3001
RSA_PUBLIC_KEY_PATH=/etc/katgen-secrets/public.pem
AUTH_COOKIE_DOMAIN=.mikhailjbs.my.id
```

## 2. Secrets Management
The API Gateway requires the **RSA Public Key** to validate JWTs. 
Copy your `public.pem` to the VPS at `/etc/katgen-secrets/public.pem` and ensure the `svc` user has read access.

## 3. GitHub Actions
Deployment is automated via GitHub Actions `.github/workflows/deploy.yml`. 
Ensure the following repository secrets are set:
- `VPS_HOST`
- `VPS_USER`
- `VPS_PORT`
- `VPS_SSH_KEY`
- `VPS_SERVICE_USER` (defaults to `svc`)
- `VPS_SERVICE_GROUP` (defaults to `svc`)

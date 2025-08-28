# Docker Deployment Guide for SSO Kawasan Digital Backend

## Prerequisites

- Docker (v20.10+)
- Docker Compose (v2.0+)
- Git

## Configuration

1. Copy `.env.example` to `.env`

   ```bash
   cp .env.example .env
   ```

2. Edit `.env` with your specific configuration
   - Update database credentials
   - Set Supabase configuration
   - Customize environment variables

## Building and Running

### Development Mode

```bash
# Build and start services
docker-compose up --build

# Run in detached mode
docker-compose up -d --build

# View logs
docker-compose logs -f app
```

### Production Mode

```bash
# Set environment to production
export APP_ENV=production

# Build and start services
docker-compose -f docker-compose.yml up --build -d
```

## Services

- **Main Application**: Runs on port 8080
- **PostgreSQL**: Database service on port 5432
- **Redis**: Caching and rate limiting on port 6379
- **Prometheus**: Monitoring on port 9090
- **Grafana**: Visualization on port 3000

## Monitoring

Access Grafana dashboard:

- URL: `http://localhost:3000`
- Default Credentials: admin/admin

## Troubleshooting

1. Check service status

   ```bash
   docker-compose ps
   ```

2. Restart a specific service

   ```bash
   docker-compose restart app
   ```

3. View logs for debugging
   ```bash
   docker-compose logs -f app
   ```

## Database Migrations

Migrations are automatically applied on container startup via `./db/migrations`

## Security Recommendations

- Never commit `.env` to version control
- Use strong, unique passwords
- Regularly update Docker images
- Configure firewall rules
- Use secrets management in production

## Performance Tuning

Adjust resource limits in `docker-compose.yml`:

```yaml
app:
  deploy:
    resources:
      limits:
        cpus: "1"
        memory: 512M
      reservations:
        cpus: "0.5"
        memory: 256M
```

## Cleanup

```bash
# Stop and remove containers
docker-compose down

# Remove volumes (careful!)
docker-compose down -v
```

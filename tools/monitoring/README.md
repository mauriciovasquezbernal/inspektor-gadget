# monitoring

This directory contains docker compose files for spinning up grafana and prometheus for local testing.
Prometheus is configured to scrape metrics from the `ig` instance running on the host machine. The containers can be
started with:

```bash
docker compose up -d
```

<!-- markdown-link-check-disable-next-line -->
Grafana will be available at http://localhost:3000 and prometheus at http://localhost:9090.

To stop the containers:

```bash
docker compose down
```


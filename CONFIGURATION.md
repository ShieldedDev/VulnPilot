# Configuration Guide

VulnPilot uses a small but explicit configuration model in `modules/config.py`.

## Runtime Configuration

The `ScannerConfig` dataclass defines safe defaults for scanner execution:

- timeout: 10 seconds
- retries: 2
- concurrency: 5
- rate_limit: 1.0 requests/sec
- user_agent: default VulnPilot user-agent
- verify_tls: true
- max_crawl_depth: 2
- max_crawl_links: 50
- max_requests: 200
- scope controls: default empty lists for allowed/excluded targets and paths

## Environment Variables

You can override local admin settings by creating a `.env` file from `.env.example`.

Example:

```bash
cp .env.example .env
```

Then edit values such as:

```bash
VULNPILOT_ADMIN_USER=admin
VULNPILOT_ADMIN_PASSWORD=StrongPassword!
```

## Scope Controls

The scanner supports:

- allowed_targets
- excluded_targets
- allowed_ports
- excluded_ports
- allowed_paths
- excluded_paths

These are currently conservative defaults and should be expanded as the project evolves.

## Security Recommendation

Avoid logging or storing secrets. Use local environment configuration for credentials and keep production values out of source control.

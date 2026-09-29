from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class ScannerConfig:
    """Shared runtime settings for safe and configurable scanning."""

    timeout: int = 10
    retries: int = 2
    concurrency: int = 5
    rate_limit: float = 1.0
    user_agent: str = 'VulnPilot/1.1 (authorized security testing only)'
    proxy: str | None = None
    verify_tls: bool = True
    max_crawl_depth: int = 2
    max_crawl_links: int = 50
    max_requests: int = 200
    allowed_targets: list[str] = field(default_factory=list)
    excluded_targets: list[str] = field(default_factory=list)
    allowed_ports: list[int] = field(default_factory=list)
    excluded_ports: list[int] = field(default_factory=list)
    allowed_paths: list[str] = field(default_factory=list)
    excluded_paths: list[str] = field(default_factory=list)
    scope_enabled: bool = True
    scan_type: str = 'full'

    def to_dict(self) -> dict[str, Any]:
        return {
            'timeout': self.timeout,
            'retries': self.retries,
            'concurrency': self.concurrency,
            'rate_limit': self.rate_limit,
            'user_agent': self.user_agent,
            'proxy': self.proxy,
            'verify_tls': self.verify_tls,
            'max_crawl_depth': self.max_crawl_depth,
            'max_crawl_links': self.max_crawl_links,
            'max_requests': self.max_requests,
            'scope_enabled': self.scope_enabled,
            'allowed_targets': list(self.allowed_targets),
            'excluded_targets': list(self.excluded_targets),
            'allowed_ports': list(self.allowed_ports),
            'excluded_ports': list(self.excluded_ports),
            'allowed_paths': list(self.allowed_paths),
            'excluded_paths': list(self.excluded_paths),
        }

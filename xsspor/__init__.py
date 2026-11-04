"""xomlsx XSS scanner package — authorized XSS testing only."""

__version__ = "1.0.0"

from xsspor.engine import DetectionEngine, ScanConfig, Finding
from xsspor.proxy import ProxyPool
from xsspor.browser import verify_xss, USER_AGENTS
from xsspor.context import detect_context, severity_for, context_to_categories
from xsspor.payloads import all_payloads, build_payloads
from xsspor.crawler import crawl
from xsspor.chain import (
    ChainAdvanced,
    hash_password,
    packet_to_d,
    d_to_packet,
)

__all__ = [
    "DetectionEngine",
    "ScanConfig",
    "Finding",
    "ProxyPool",
    "verify_xss",
    "USER_AGENTS",
    "detect_context",
    "severity_for",
    "context_to_categories",
    "all_payloads",
    "build_payloads",
    "crawl",
    "ChainAdvanced",
    "hash_password",
    "packet_to_d",
    "d_to_packet",
]

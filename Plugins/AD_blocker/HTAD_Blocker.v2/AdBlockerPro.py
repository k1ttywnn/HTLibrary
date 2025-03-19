#!/usr/bin/env python3
"""
adblocker_pro.py – Enhanced ad blocker for mitmproxy.
Blocks ads, sanitizes DOM, intercepts tracking, and prunes HLS/DASH streams.
Usage: mitmproxy -s adblocker_pro.py
"""
import re
import json
import logging
from typing import List, Pattern, Dict, Set, Optional, Tuple
from functools import lru_cache
from urllib.parse import urlparse
from mitmproxy import http, ctx
from bs4 import BeautifulSoup, Tag


class AdBlockerPro:
    def __init__(self):
        # Compile regex patterns only once for performance
        self.block_url_patterns: List[Pattern] = [
            re.compile(
                r".*(?:doubleclick|googlesyndication|google-analytics|googleadservices)\.(?:com|net).*",
                re.I,
            ),
            re.compile(r".*(?:adservice|adserver|adtech|adsystem|advert).*", re.I),
            re.compile(r".*/(?:ads|banners|analytics|tracking)/.*", re.I),
            re.compile(r".*(?:pagead|videoad|sponsor|affiliate).*", re.I),
            re.compile(r".*(?:tracker|pixel|beacon|impression).*", re.I),
        ]

        # HTML/CSS selectors for ad elements (direct matching for performance)
        self.ad_selectors: List[str] = [
            '[id*="ad-"],[id*="-ad"],[id*="ads-"],[id*="-ads"]',
            '[class*="ad-"],[class*="-ad"],[class*="ads-"],[class*="-ads"]',
            '[id*="banner"],[class*="banner"]',
            '[id*="sponsor"],[class*="sponsor"]',
            '[id*="promo"],[class*="promo"]',
        ]

        # Media stream patterns
        self.hls_ad_marker = re.compile(
            r"#EXT-X-(?:DATERANGE|CUE|DISCONTINUITY).*(?:DURATION|SCTE|AD).*", re.I
        )
        self.dash_ad_marker = re.compile(r"<Period[^>]*(?:ad|Ad|AD)[^>]*>", re.I)

        # Cache for domain decisions to avoid repeated processing
        self.domain_cache: Dict[str, bool] = {}

        # Track blocked request counts
        self.stats: Dict[str, int] = {"urls": 0, "elements": 0, "segments": 0}

        # Load external blocklists if available
        self.block_domains: Set[str] = self._load_blocklists()

    def _load_blocklists(self) -> Set[str]:
        """Load external blocklists for enhanced blocking."""
        try:
            with open("blocklists.txt", "r") as f:
                return {
                    line.strip()
                    for line in f
                    if line.strip() and not line.startswith("#")
                }
        except FileNotFoundError:
            return set()

    @lru_cache(maxsize=1024)
    def _should_block_domain(self, domain: str) -> bool:
        """Determine if domain should be blocked using cached results."""
        if domain in self.domain_cache:
            return self.domain_cache[domain]

        # Check against compiled patterns and blocklists
        should_block = domain in self.block_domains or any(
            pattern.search(domain) for pattern in self.block_url_patterns
        )

        self.domain_cache[domain] = should_block
        return should_block

    def request(self, flow: http.HTTPFlow) -> None:
        """Process HTTP requests and block ads at request level."""
        # Extract domain for efficient checking
        domain = urlparse(flow.request.url).netloc

        # Block by domain or URL pattern
        if self._should_block_domain(domain) or any(
            p.search(flow.request.url) for p in self.block_url_patterns
        ):
            self.stats["urls"] += 1
            ctx.log.info(f"[AdBlockerPro] Blocked: {flow.request.url}")
            flow.response = http.HTTPResponse.make(
                204, b"", {"Content-Type": "text/plain"}
            )
            return

    def response(self, flow: http.HTTPFlow) -> None:
        """Process HTTP responses to remove ad content."""
        if not flow.response or not flow.response.content:
            return

        ct = flow.response.headers.get("Content-Type", "")

        # Handle HTML content
        if "text/html" in ct:
            self._process_html(flow)

        # Handle HLS playlists
        elif "application/vnd.apple.mpegurl" in ct or flow.request.url.endswith(
            ".m3u8"
        ):
            self._process_hls(flow)

        # Handle DASH manifests
        elif "application/dash+xml" in ct or flow.request.url.endswith(".mpd"):
            self._process_dash(flow)

        # Handle JSON responses (often contain ad configs)
        elif "application/json" in ct:
            self._process_json(flow)

    def _process_html(self, flow: http.HTTPFlow) -> None:
        """Remove ad elements from HTML using efficient DOM parsing."""
        try:
            # Parse only once for efficiency
            html = flow.response.text
            soup = BeautifulSoup(html, "html.parser")

            # Remove script tags containing ad keywords
            ad_scripts = soup.find_all(
                "script",
                src=lambda s: s and any(p.search(s) for p in self.block_url_patterns),
            )
            for script in ad_scripts:
                script.decompose()
                self.stats["elements"] += 1

            # Remove iframes with ad sources
            ad_iframes = soup.find_all(
                "iframe",
                src=lambda s: s and any(p.search(s) for p in self.block_url_patterns),
            )
            for iframe in ad_iframes:
                iframe.decompose()
                self.stats["elements"] += 1

            # Use CSS selectors for faster matching
            for selector in self.ad_selectors:
                for element in soup.select(selector):
                    element.decompose()
                    self.stats["elements"] += 1

            # Update response with cleaned HTML
            flow.response.text = str(soup)

        except Exception as e:
            ctx.log.error(f"[AdBlockerPro] HTML processing error: {e}")

    def _process_hls(self, flow: http.HTTPFlow) -> None:
        """Filter advertisements from HLS playlists."""
        try:
            lines = flow.response.text.splitlines()
            filtered_lines = []
            skip_segment = False
            removed = 0

            for line in lines:
                # Detect ad markers using regex pattern matching
                if self.hls_ad_marker.search(line):
                    skip_segment = True
                    removed += 1
                    continue

                # Skip the segment URI if it follows an ad marker
                if skip_segment and not line.startswith("#"):
                    skip_segment = False
                    continue

                filtered_lines.append(line)

            if removed > 0:
                self.stats["segments"] += removed
                ctx.log.info(f"[AdBlockerPro] Removed {removed} HLS ad segments")

            flow.response.text = "\n".join(filtered_lines)

        except Exception as e:
            ctx.log.error(f"[AdBlockerPro] HLS processing error: {e}")

    def _process_dash(self, flow: http.HTTPFlow) -> None:
        """Filter advertisements from DASH manifests."""
        try:
            content = flow.response.text
            # Remove <Period> tags containing ad markers
            filtered_content = self.dash_ad_marker.sub("", content)

            if filtered_content != content:
                self.stats["segments"] += 1
                ctx.log.info(f"[AdBlockerPro] Removed DASH ad periods")
                flow.response.text = filtered_content

        except Exception as e:
            ctx.log.error(f"[AdBlockerPro] DASH processing error: {e}")

    def _process_json(self, flow: http.HTTPFlow) -> None:
        """Sanitize JSON responses that may contain ad configurations."""
        try:
            data = json.loads(flow.response.text)

            # Common JSON ad configuration keys
            ad_keys = ["ads", "advertising", "adConfig", "adUnit", "sponsors"]
            modified = False

            # Recursively scan and clean nested dicts
            def clean_dict(obj: dict) -> Tuple[dict, bool]:
                local_modified = False
                for key in list(obj.keys()):
                    if any(
                        ad_term in key.lower()
                        for ad_term in ["ad", "ads", "advert", "sponsor"]
                    ):
                        obj.pop(key)
                        local_modified = True
                    elif isinstance(obj[key], dict):
                        obj[key], child_modified = clean_dict(obj[key])
                        local_modified = local_modified or child_modified
                return obj, local_modified

            # Process dict objects
            if isinstance(data, dict):
                data, modified = clean_dict(data)

            if modified:
                self.stats["elements"] += 1
                ctx.log.info(f"[AdBlockerPro] Sanitized JSON ad config")
                flow.response.text = json.dumps(data)

        except (json.JSONDecodeError, TypeError, ValueError):
            # Not valid JSON or not a dict, skip processing
            pass
        except Exception as e:
            ctx.log.error(f"[AdBlockerPro] JSON processing error: {e}")

    def load(self, loader):
        """Initialize logging and configuration on load."""
        logging.basicConfig(level=logging.INFO)
        ctx.log.info("[AdBlockerPro] Initialized with enhanced capabilities")

    def done(self):
        """Report statistics when mitmproxy exits."""
        ctx.log.info(
            f"[AdBlockerPro] Blocking summary - URLs: {self.stats['urls']}, Elements: {self.stats['elements']}, Segments: {self.stats['segments']}"
        )


# Register the addon with mitmproxy
addons = [AdBlockerPro()]

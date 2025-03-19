#!/usr/bin/env python3
"""
adblocker_advanced.py – Comprehensive mitmproxy add-on that decapitates ad requests,
removes ad elements from HTML, and filters out ad segments from HLS manifests.
Integrate with your plugin manager for uninterrupted video binges.
Load with: mitmproxy -s adblocker_advanced.py
"""
import re
from mitmproxy import http, ctx
from bs4 import BeautifulSoup

class AdBlockerAdvanced:
    # URL blocking patterns for typical ad domains & assets.
    url_patterns = [
        re.compile(r".*doubleclick\.net.*", re.I),
        re.compile(r".*googlesyndication\.com.*", re.I),
        re.compile(r".*adservice.*", re.I),
        re.compile(r".*/ads/.*", re.I),
        re.compile(r".*banner.*", re.I),
        re.compile(r".*videoad.*", re.I),
        re.compile(r".*/adserver/.*", re.I),
        re.compile(r".*\.ad\.", re.I)
    ]
    # HTML elements with ad-like id/class patterns.
    html_patterns = [re.compile(r".*ad.*", re.I)]

    def request(self, flow: http.HTTPFlow) -> None:
        url = flow.request.url
        if any(p.search(url) for p in self.url_patterns):
            ctx.log.info(f"Blocked ad URL: {url}")
            flow.response = http.HTTPResponse.make(404, b"Blocked by AdBlockerAdvanced", {"Content-Type": "text/plain"})

    def response(self, flow: http.HTTPFlow) -> None:
        ct = flow.response.headers.get("Content-Type", "")
        if "text/html" in ct:
            soup = BeautifulSoup(flow.response.text, "html.parser")
            # Remove elements with ad-like id's or class's.
            for tag in soup.find_all(True, id=lambda i: i and any(p.search(i) for p in self.html_patterns)):
                tag.decompose()
            for tag in soup.find_all(True, class_=lambda c: c and any(p.search(c) for p in self.html_patterns)):
                tag.decompose()
            flow.response.text = str(soup)
        # HLS manifest filtering: drop segments flagged as ads.
        elif "application/vnd.apple.mpegurl" in ct or flow.request.url.endswith(".m3u8"):
            lines = flow.response.text.splitlines()
            filtered, skip_next = [], False
            for line in lines:
                # Skip daterange markers indicating ads.
                if line.startswith("#EXT-X-DATERANGE") and "ad" in line.lower():
                    skip_next = True
                    continue
                # Skip the following URI if marked.
                if skip_next and line and not line.startswith("#"):
                    skip_next = False
                    continue
                filtered.append(line)
            flow.response.text = "\n".join(filtered)

addons = [AdBlockerAdvanced()]

#!/usr/bin/env python3
"""Fetch operator-maintained Googlebot and Bingbot networks; replace cache atomically.

Run daily, then restart Rustgate to load the updated file. No third-party feeds.
"""
import argparse
import ipaddress
import json
import os
from pathlib import Path
import tempfile
import time
import urllib.request

SOURCES = [
    ("Googlebot", "Googlebot", "https://developers.google.com/crawling/ipranges/common-crawlers.json"),
    ("Bingbot", "bingbot", "https://www.bing.com/toolbox/bingbot.json"),
]

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", default="config/crawlers.json")
    args = parser.parse_args()
    bots = []
    for name, agent, url in SOURCES:
        with urllib.request.urlopen(url, timeout=20) as response:
            if response.geturl() != url:
                raise ValueError("Unexpected feed redirect; verify the operator's current URL")
            raw = response.read(2 * 1024 * 1024 + 1)
            if len(raw) > 2 * 1024 * 1024:
                raise ValueError("Feed too large")
        data = json.loads(raw)
        networks = []
        for item in data["prefixes"]:
            net = ipaddress.ip_network(item.get("ipv4Prefix") or item["ipv6Prefix"])
            if net.prefixlen == 0 or not net.is_global:
                raise ValueError("Invalid public crawler network")
            networks.append(str(net))
        if not networks:
            raise ValueError(f"Empty {name} feed")
        bots.append(dict(name=name, user_agent=agent, networks=networks))
    destination = Path(args.output)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", dir=destination.parent, delete=False) as output:
        json.dump(dict(expires_at=int(time.time()) + 3 * 86400, bots=bots), output)
        temporary = output.name
    os.replace(temporary, destination)
    print(f"Updated {len(bots)} crawler definitions in {destination}; restart Rustgate to reload")

if __name__ == "__main__":
    main()

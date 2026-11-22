#!/usr/bin/env python3
"""Local smoke benchmark, including its Python client/origin bottlenecks; not a capacity claim."""
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler
import http.client
import json
import platform
from pathlib import Path
import statistics
import subprocess
import tempfile
import threading
import time
from integration import Proxy, TestOriginServer

class FastOrigin(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def log_message(self, *_): pass
    def do_GET(self):
        self.wfile.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")

def process_stats(pid):
    raw = subprocess.check_output(["ps", "-o", "rss=,time=", "-p", str(pid)], text=True).split()
    parts = raw[1].split(":")
    cpu = sum(float(value) * (60 ** i) for i, value in enumerate(reversed(parts)))
    return int(raw[0]) / 1024, cpu

def workload(port, path, expected, workers=8, per_worker=300):
    def worker(_):
        latencies = []
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
        try:
            for _ in range(per_worker):
                started = time.perf_counter()
                conn.request("GET", path, headers={"Host":"a.test"})
                response = conn.getresponse()
                response.read()
                assert response.status == expected, response.status
                latencies.append((time.perf_counter() - started)*1000)
        finally:
            conn.close()
        return latencies
    started = time.perf_counter()
    with ThreadPoolExecutor(max_workers=workers) as pool:
        latencies = sorted(value for result in pool.map(worker, range(workers)) for value in result)
    seconds = time.perf_counter()-started
    return dict(requests=len(latencies),workers=workers,seconds=round(seconds,3),requests_per_second=round(len(latencies)/seconds),p50_ms=round(statistics.median(latencies),3),p99_ms=round(latencies[int(len(latencies)*.99)],3))

def main():
    origin = TestOriginServer(("127.0.0.1",0),FastOrigin)
    threading.Thread(target=origin.serve_forever,daemon=True).start()
    with tempfile.TemporaryDirectory() as directory:
        p = Proxy(directory,[origin.server_port,origin.server_port],extra="connections_per_second = 100000\nconnection_burst = 100000",route_extra="requests_per_second = 100000\nburst = 100000\nglobal_requests_per_second = 100000\nglobal_burst = 100000")
        try:
            idle, before = process_stats(p.process.pid)
            report=dict(platform=platform.platform(),binary="release",origin="Python HTTP/1.1 on loopback",notes="Smoke measurement only. Includes client, origin, OS scheduling, and connection costs; not isolated proxy latency or a production capacity guarantee.",idle_rss_mib=round(idle,2))
            report["direct_origin"]=workload(origin.server_port,"/",200)
            report["proxy_allowed"]=workload(p.port,"/",200)
            report["proxy_blocked"]=workload(p.port,"/.env",403)
            rss, after=process_stats(p.process.pid)
            report["rss_after_load_mib"]=round(rss,2)
            report["proxy_cpu_seconds"]=round(after-before,3)
            out=Path("VALIDATION.json")
            out.write_text(json.dumps(report,indent=2)+"\n")
            print(json.dumps(report,indent=2))
        finally:
            p.close()
    origin.shutdown()
    origin.server_close()

if __name__=="__main__": main()

#!/usr/bin/env python3
"""Offline end-to-end checks against real HTTP origins and the compiled proxy."""
import base64
import hashlib
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
BINARY = Path(os.environ.get("ZNTIL_BINARY", os.environ.get("RUSTGATE_BINARY", ROOT / "target/release/zntil")))

class TestOriginServer(ThreadingHTTPServer):
    def handle_error(self, request, client_address):
        # Rejected uploads intentionally close the partially-read origin connection.
        pass

def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]

class Origin(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def log_message(self, *_):
        pass
    def do_GET(self):
        if self.headers.get("Upgrade", "").lower() == "websocket":
            key = self.headers["Sec-WebSocket-Key"]
            accept = base64.b64encode(hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()).decode()
            self.send_response(101)
            self.send_header("Upgrade", "websocket")
            self.send_header("Connection", "Upgrade")
            self.send_header("Sec-WebSocket-Accept", accept)
            self.end_headers()
            self.connection.settimeout(5)
            # Test transport transparency; the proxy must not interpret tunnel bytes as uploads.
            try:
                while data := self.connection.recv(4096):
                    self.connection.sendall(data)
            except (TimeoutError, OSError):
                pass
            self.close_connection = True
            return
        if self.path == "/slow":
            time.sleep(1)
        self.reply(b"")
    def do_POST(self):
        if self.headers.get("Transfer-Encoding", "").lower() == "chunked":
            body = b""
            while True:
                line = self.rfile.readline().strip()
                if not line:  # Oversized uploads are deliberately interrupted by the proxy.
                    self.close_connection = True
                    return
                n = int(line, 16)
                if not n:
                    self.rfile.readline()
                    break
                body += self.rfile.read(n)
                self.rfile.read(2)
        else:
            body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        self.reply(body)
    def reply(self, body):
        raw = json.dumps(dict(origin=self.server.server_port, path=self.path, body=body.decode(), headers=dict(self.headers))).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        try:
            self.wfile.write(raw)
        except (BrokenPipeError, ConnectionResetError):
            pass

class Proxy:
    def __init__(self, directory, origins, mode="enforce", extra="", route_extra="", tls=False):
        self.port = free_port()
        self.tls_port = free_port()
        config = f'''listen = "127.0.0.1:{self.port}"
mode = "{mode}"
max_body_bytes = 128
{extra}
'''
        if tls:
            cert, key = Path(directory) / "cert.pem", Path(directory) / "key.pem"
            subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key), "-out", str(cert), "-days", "1", "-subj", "/CN=a.test"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            config += f'tls_cert = "{cert}"\ntls_key = "{key}"\ntls_listen = "127.0.0.1:{self.tls_port}"\n'
        for host, origin in zip(["a.test", "b.test"], origins):
            config += f'''\n[[routes]]
hosts = ["{host}"]
upstream = "127.0.0.1"
upstream_port = {origin}
{route_extra}
'''
        path = Path(directory) / f"{self.port}.toml"
        path.write_text(config)
        self.log = open(Path(directory) / f"{self.port}.log", "w+")
        self.process = subprocess.Popen([str(BINARY)], cwd=ROOT, env={**os.environ, "RUSTGATE_CONFIG": str(path)}, stdout=self.log, stderr=self.log)
        for _ in range(100):
            if self.process.poll() is not None:
                self.log.seek(0)
                raise RuntimeError(self.log.read())
            try:
                with socket.create_connection(("127.0.0.1", self.port), timeout=.1):
                    break
            except OSError:
                time.sleep(.05)
        else:
            self.close()
            raise RuntimeError("proxy startup timed out")
    def request(self, path="/", host="a.test", method="GET", headers=None, body=None, tls=False):
        conn = http.client.HTTPSConnection("127.0.0.1", self.tls_port, timeout=5, context=ssl._create_unverified_context()) if tls else http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        conn.request(method, path, body=body, headers={"Host": host, **(headers or {})})
        response = conn.getresponse()
        data = response.read()
        conn.close()
        return response.status, data
    def close(self):
        self.process.terminate()
        try:
            self.process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait()
        self.log.close()

class Integration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.origins = [TestOriginServer(("127.0.0.1", 0), Origin) for _ in range(2)]
        for origin in cls.origins:
            threading.Thread(target=origin.serve_forever, daemon=True).start()
    @classmethod
    def tearDownClass(cls):
        for origin in cls.origins:
            origin.shutdown()
            origin.server_close()
        cls.temp.cleanup()
    def proxy(self, **kwargs):
        proxy = Proxy(self.temp.name, [o.server_port for o in self.origins], **kwargs)
        self.addCleanup(proxy.close)
        return proxy
    def test_host_routing_and_query_preservation(self):
        p = self.proxy()
        for host, origin in zip(["a.test", "b.test"], self.origins):
            code, body = p.request("/hello?x=1", host=host)
            self.assertEqual(code, 200)
            data = json.loads(body)
            self.assertEqual(data["origin"], origin.server_port)
            self.assertEqual(data["path"], "/hello?x=1")
        self.assertEqual(p.request(host="evil.test")[0], 421)
        self.assertEqual(p.request("http://evil.test/")[0], 400)
    def test_spoofed_identity_and_hop_headers_are_removed(self):
        p = self.proxy()
        code, body = p.request(headers={"X-Real-IP": "192.0.2.99", "X-Forwarded-For": "192.0.2.99", "Forwarded": "for=192.0.2.99", "X-Rustgate-Origin-Token": "forged", "Connection": "x-remove", "X-Remove": "remove-me"})
        self.assertEqual(code, 200)
        headers = {k.lower(): v for k,v in json.loads(body)["headers"].items()}
        self.assertEqual(headers["x-real-ip"], "127.0.0.1")
        self.assertEqual(headers["x-forwarded-for"], "127.0.0.1")
        self.assertNotIn("forwarded", headers)
        self.assertNotIn("x-rustgate-origin-token", headers)
        self.assertNotIn("x-remove", headers)
    def test_probe_enforcement_ban_and_site_isolation(self):
        p = self.proxy()
        for path in ["/.git/config", "/%252eenv", "/wp-login.php", "/xmlrpc.php"]:
            self.assertEqual(p.request(path)[0], 403)
        self.assertEqual(p.request("/legitimate")[0], 403)
        self.assertEqual(p.request("/legitimate", host="b.test")[0], 200)
    def test_observe_mode_forwards_probes(self):
        p = self.proxy(mode="observe")
        self.assertEqual(p.request("/.git/config")[0], 200)
    def test_query_and_body_injection(self):
        p = self.proxy()
        self.assertEqual(p.request("/?q=%27%20OR%20%271%27%3D%271%27%20--")[0],403)
        self.assertEqual(p.request(method="POST",body='{"q":"<script>alert(1)</script>"}',headers={"Content-Type":"application/json"})[0],403)
        code, raw = p.request(method="POST",body='{"q":"Hello Nico"}',headers={"Content-Type":"application/json"})
        self.assertEqual(code,200)
        self.assertEqual(json.loads(raw)["body"],'{"q":"Hello Nico"}')
        self.assertEqual(p.request(method="POST",body="q=%3Cscript%3Ealert(1)%3C/script%3E",headers={"Content-Type":"application/x-www-form-urlencoded"})[0],403)
    def test_chunk_split_injection_and_observation(self):
        for mode, expected in [("enforce",403),("observe",200)]:
            p = self.proxy(mode=mode)
            conn = http.client.HTTPConnection("127.0.0.1", p.port, timeout=5)
            conn.request("POST", "/", body=iter([b'{"q":"<scr', b'ipt>alert(1)</script>"}']),headers={"Host":"a.test","Content-Type":"application/json"},encode_chunked=True)
            response=conn.getresponse()
            self.assertEqual(response.status,expected)
            raw=response.read()
            if expected==200:
                self.assertEqual(json.loads(raw)["body"],'{"q":"<script>alert(1)</script>"}')
            conn.close()
    def test_content_and_webhook_bytes_are_preserved(self):
        p = self.proxy(route_extra='body_inspection_exempt_prefixes = ["/api/items", "/api/billing/webhook"]')
        payload=b'{ "html": "<script>alert(1)</script>", "n": 1 }\n'
        for path in ["/api/items","/api/billing/webhook"]:
            code,raw=p.request(path,method="POST",body=payload,headers={"Content-Type":"application/json"})
            self.assertEqual(code,200)
            self.assertEqual(json.loads(raw)["body"].encode(),payload)
        self.assertEqual(p.request("/api/login",method="POST",body=payload,headers={"Content-Type":"application/json"})[0],403)
    def test_shared_inspection_budget_recovers_after_disconnect(self):
        p = self.proxy(extra="max_inspected_body_bytes = 128\nmax_buffered_body_bytes = 128")
        sockets=[]
        try:
            for _ in range(2):
                sock=socket.create_connection(("127.0.0.1",p.port),timeout=3)
                sockets.append(sock)
                sock.sendall(b"POST / HTTP/1.1\r\nHost: a.test\r\nContent-Type: text/plain\r\nContent-Length: 128\r\n\r\n"+b"x"*64)
            time.sleep(.2)
            self.assertEqual(p.request(method="POST",body=b"hello",headers={"Content-Type":"text/plain"})[0],503)
        finally:
            for sock in sockets: sock.close()
        time.sleep(.2)
        self.assertEqual(p.request(method="POST",body=b"hello",headers={"Content-Type":"text/plain"})[0],200)
    def test_rate_limit_and_sensitive_limit(self):
        p = self.proxy(route_extra="requests_per_second = 0.001\nburst = 2\nsensitive_burst = 1")
        self.assertEqual(p.request("/login")[0], 200)
        self.assertEqual(p.request("/login")[0], 429)
        self.assertEqual(p.request("/")[0], 429)
    def test_fixed_and_chunked_upload_limits(self):
        p = self.proxy()
        self.assertEqual(p.request(method="POST", body=b"hello")[0], 200)
        self.assertEqual(p.request(method="POST", body=b"x" * 129)[0], 413)
        conn = http.client.HTTPConnection("127.0.0.1", p.port, timeout=5)
        conn.request("POST", "/", body=iter([b"x" * 64, b"x" * 65]), headers={"Host": "a.test"}, encode_chunked=True)
        try:
            response = conn.getresponse()
            self.assertEqual(response.status, 413)
            response.read()
        finally:
            conn.close()
    def test_tls_termination_and_scheme(self):
        p = self.proxy(tls=True)
        code, body = p.request(tls=True)
        self.assertEqual(code,200)
        headers = {k.lower(): v for k,v in json.loads(body)["headers"].items()}
        self.assertEqual(headers["x-forwarded-proto"], "https")
    def test_websocket_tunnel_not_subject_to_http_body_cap(self):
        p = self.proxy()
        with socket.create_connection(("127.0.0.1",p.port),timeout=5) as sock:
            sock.sendall(b"GET /socket.io/?transport=websocket HTTP/1.1\r\nHost: a.test\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n")
            header = b""
            while b"\r\n\r\n" not in header:
                part = sock.recv(1)
                self.assertTrue(part, "proxy closed before WebSocket handshake")
                header += part
            self.assertTrue(header.startswith(b"HTTP/1.1 101"),header)
            payload = b"x" * 2048
            sock.sendall(payload)
            result = b""
            while len(result) < len(payload):
                part = sock.recv(4096)
                self.assertTrue(part, "proxy closed WebSocket tunnel")
                result += part
            self.assertEqual(result,payload)
    def test_global_concurrency_cap(self):
        p = self.proxy(extra="max_inflight = 1")
        result = []
        t = threading.Thread(target=lambda: result.append(p.request("/slow")[0]))
        t.start()
        time.sleep(.2)
        self.assertEqual(p.request()[0],503)
        t.join()
        self.assertEqual(result,[200])
        self.assertEqual(p.request()[0],200)
    def test_unfinished_headers_are_bounded_and_expire(self):
        p = self.proxy(extra="max_connections = 2\nheader_timeout_seconds = 1")
        time.sleep(.1)
        sockets = [socket.create_connection(("127.0.0.1",p.port),timeout=3) for _ in range(2)]
        try:
            for sock in sockets:
                sock.sendall(b"GET / HTTP/1.1\r\n")
            time.sleep(.1)
            with self.assertRaises((http.client.RemoteDisconnected, ConnectionResetError)):
                p.request()
            # Pingora's timer wheel rounds short deadlines; allow scheduling tolerance.
            time.sleep(2.5)
            self.assertEqual(p.request()[0],200)
        finally:
            for sock in sockets:
                sock.close()
    def test_ingress_and_origin_tokens(self):
        os.environ["RUSTGATE_TEST_TOKEN"] = "x" * 32
        p = self.proxy(extra='ingress_token_env = "RUSTGATE_TEST_TOKEN"', route_extra='origin_token_env = "RUSTGATE_TEST_TOKEN"')
        self.assertEqual(p.request()[0],403)
        code, body = p.request(headers={"X-Rustgate-Ingress-Token":"x"*32})
        self.assertEqual(code,200)
        headers = {k.lower():v for k,v in json.loads(body)["headers"].items()}
        self.assertEqual(headers["x-rustgate-origin-token"],"x"*32)
        self.assertNotIn("x-rustgate-ingress-token",headers)
    def test_trusted_proxy_requires_single_valid_client_ip(self):
        p = self.proxy(extra='trusted_proxies = ["127.0.0.1/32"]')
        self.assertEqual(p.request()[0],400)
        code, body = p.request(headers={"X-Real-IP":"192.0.2.1"})
        self.assertEqual(code,200)
        headers = {k.lower():v for k,v in json.loads(body)["headers"].items()}
        self.assertEqual(headers["x-real-ip"],"192.0.2.1")

if __name__ == "__main__":
    unittest.main(verbosity=2)

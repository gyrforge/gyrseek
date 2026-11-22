#!/usr/bin/env python3
"""A stand-in for a corporate mirror: forwards every GET to an upstream registry and logs the paths.

usage: mirror_proxy.py UPSTREAM LOGFILE PORTFILE

Listens on 127.0.0.1 on a free port (written to PORTFILE once it is ready). The end-to-end
redirect checks point a package manager at it to show that gyrseek refuses the redirect until the
host is in `trusted_index_hosts`, and that a trusted install really goes through the mirror.
"""
import http.server
import sys
import urllib.error
import urllib.request

upstream = sys.argv[1].rstrip("/")
log_path = sys.argv[2]
port_path = sys.argv[3]


class Mirror(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        headers = {k: v for k, v in self.headers.items() if k.lower() in ("accept", "user-agent")}
        try:
            response = urllib.request.urlopen(
                urllib.request.Request(upstream + self.path, headers=headers), timeout=60
            )
        except urllib.error.HTTPError as error:
            response = error
        body = response.read()
        with open(log_path, "a") as log:
            log.write(self.path + "\n")
        try:
            self.send_response(response.status)
            content_type = response.headers.get("Content-Type")
            if content_type:
                self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass  # the client gave up (a package manager drops connections it no longer needs)

    def log_message(self, *_):
        pass


server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Mirror)
with open(port_path, "w") as port_file:
    port_file.write(str(server.server_address[1]))
server.serve_forever()

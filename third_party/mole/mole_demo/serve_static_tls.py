#!/usr/bin/env python3
# Copyright 2026 The Chromium Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
#
# A tiny HTTPS static-file server for the demo sites (shoes.com / socks.com),
# so every origin in the demo speaks TLS. Usage:
#   serve_static_tls.py PORT DIRECTORY CERT_PEM KEY_PEM
import functools
import http.server
import ssl
import sys

port = int(sys.argv[1])
directory = sys.argv[2]
cert = sys.argv[3]
key = sys.argv[4]

handler = functools.partial(http.server.SimpleHTTPRequestHandler,
                            directory=directory)
httpd = http.server.HTTPServer(("127.0.0.1", port), handler)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(certfile=cert, keyfile=key)
httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
httpd.serve_forever()

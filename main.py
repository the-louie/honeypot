#!/usr/bin/env python
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

import datetime
import os
import select
import socket
import socketserver
import struct
import subprocess
import sys
import threading
import time
import traceback
from termcolor import colored

try:
    from config import SERVICE, BIND_IP, PORT
except ImportError:
    print("Cannot start honeypot: No config.py found, see README.md")
    sys.exit(1)

from utils import log_append

from tcp_ssh import handle_tcp_ssh
from tcp_telnet import handle_tcp_telnet
from tcp_smtp import handle_tcp_smtp
from tcp_http_https import handle_tcp_http, handle_tcp_https
# from tcp_httpproxy import make_tcp_httpproxy_handler

port_to_service = {
    22: 'ssh',
    23: 'telnet',
    25: 'smtp',
    80: 'http',
    443: 'https',
    # 8080: 'http_proxy'
}
service_handlers = {
    'ssh': {
        'handler': handle_tcp_ssh,
        'port': 22
    },
    'telnet': {
        'handler': handle_tcp_telnet,
        'port': 23
    },
    'smtp': {
        'handler': handle_tcp_smtp,
        'port': 25
    },
    'http': {
        'handler': handle_tcp_http,
        'port': 80
    },
    'https': {
        'handler': handle_tcp_https,
        'port': 443
    },
    # 'http_proxy': {
    # 	'handler': tcp_httpproxy,
    # 	'port': 8081
    # }
}


class SingleTCPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            (srcaddr, srcport) = self.request.getpeername()
            (dsthost, dstport) = self.server.server_address
        except Exception:
            # This may happen if the connection gets closed by the
            # peer while we are still spawning the thread to handle it
            return

        timestr = datetime.datetime.now().strftime("%a %Y/%m/%d %H:%M:%S%z")
        print(colored("[{}]: Intruder {}:{} connected to {}:{}".format(
            timestr,
            srcaddr,
            srcport,
            dsthost,
            dstport), 'magenta'))

        service_name = port_to_service[dstport]
        service_handlers.get(service_name)['handler'](self.request, dstport)


class SimpleServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, server_address, RequestHandlerClass):
        print('Setting up service {} at {}:{}'.format(
            port_to_service[server_address[1]],
            server_address[0],
            server_address[1]))

        socketserver.TCPServer.__init__(
            self,
            server_address,
            RequestHandlerClass)


# SETUP SERVERS
servers = []
try:
    for service_name in service_handlers:
        service = service_handlers.get(service_name)
        port = service.get('port')
        servers.append({
            'server': SimpleServer((BIND_IP, port), SingleTCPHandler)
        })
except Exception:
    server = None
    print(traceback.format_exc())


if len(servers) > 0:
    try:
        print("Started successfully, waiting for intruders...")
        while True:
            for server in servers:
                server.get('server').handle_request()
    except KeyboardInterrupt:
        sys.exit(0)

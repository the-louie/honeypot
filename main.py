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
    from config import SERVERS, PERSONAS
except ImportError:
    print("Cannot start honeypot: No config.py found, see README.md")
    sys.exit(1)

from utils import log_append

from tcp_ssh import handle_tcp_ssh
from tcp_telnet import handle_tcp_telnet
from tcp_smtp import handle_tcp_smtp
from tcp_http_https import handle_tcp_http, handle_tcp_https

service_handlers = [
    {
        'name': 'ssh',
        'handler': handle_tcp_ssh,
        'port': 22
    }, {
        'name': 'telnet',
        'handler': handle_tcp_telnet,
        'port': 23
    }, {
        'name': 'smtp',
        'handler': handle_tcp_smtp,
        'port': 25
    }, {
        'name': 'http',
        'handler': handle_tcp_http,
        'port': 80
    }, {
        'name': 'https',
        'handler': handle_tcp_https,
        'port': 443
    },
    # 'http_proxy': {
    # 	'handler': tcp_httpproxy,
    # 	'port': 8081
    # }
]


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
        print(colored("[{}]: {}:{} connected to {}:{}".format(
            timestr,
            srcaddr,
            srcport,
            dsthost,
            dstport), 'magenta'))

        service_handler = port2service[dstport]['handler']
        if service_handler:
            persona = PERSONAS.get(ip2persona[dsthost])
            service_persona = persona.get('services').get(port2service[dstport]['name'])
            service_handler(self.request, dsthost, dstport, service_persona)


class SimpleServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, bind_ip, bind_port, service_name, RequestHandlerClass):


        socketserver.TCPServer.__init__(
            self,
            (bind_ip, bind_port),
            RequestHandlerClass)

def thread_service(bind_ip, service_name, service):
    try:
        server = SimpleServer(bind_ip, service['port'], service_name, SingleTCPHandler)
        print('Setting up {} {} at {}:{}'.format(
            ip2persona[bind_ip],
            service_name,
            bind_ip,
            service['port']))

        server.serve_forever()
    except OSError:
        print('Exception setting up {} {} at {}:{}'.format(
            ip2persona[bind_ip],
            service_name,
            bind_ip,
            service['port']))

# Spin up servers
try:
    # generate lookup tables
    ip2persona = {}
    port2service = {}
    for service in service_handlers:
        port2service[service['port']] = service

    threads = []
    for template_name in SERVERS:
        servers = SERVERS.get(template_name)
        persona = PERSONAS.get(template_name)
        for service_name in persona.get('services', []):
            service = persona.get('services').get(service_name)
            for bind_ip in servers:
                ip2persona[bind_ip] = template_name # cache which persona belongs to an ip
                s = threading.Thread(target=thread_service, args=(bind_ip, service_name, service,))
                s.start()
                threads.append(s)

except KeyboardInterrupt:
    for t in threads:
        t.kill()
        t.join()

except Exception:
    print(traceback.format_exc())

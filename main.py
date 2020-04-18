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

import datetime, os, select, socket, socketserver, struct, subprocess, sys, threading, time, traceback
from termcolor import colored

#import GeoIP
#geoip = GeoIP.new(GeoIP.GEOIP_MEMORY_CACHE | GeoIP.GEOIP_CHECK_CACHE)

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
from tcp_httpproxy import make_tcp_httpproxy_handler
from tcp_hexdump import handle_tcp_hexdump, handle_tcp_hexdump_ssl

service_handler = {
	'ssh': handle_tcp_ssh,
	'telnet': handle_tcp_telnet,
	'smtp': handle_tcp_smtp,
	'http': handle_tcp_http,
	'https': handle_tcp_https,
	#8080: handle_tcp_http,
	#8118: handle_tcp_httpproxy
}


class SingleTCPHandler(socketserver.BaseRequestHandler):
	def handle(self):
		try:
			srcaddr, srcport = self.request.getpeername()
		except:
			# This may happen if the connection gets closed by the
			# peer while we are still spawning the thread to handle it
			return

		timestr = datetime.datetime.now().strftime("%a %Y/%m/%d %H:%M:%S%z")
		print(colored("[{}]: Intruder {}:{} connected to fake port {}/tcp".format(timestr, srcaddr, srcport, PORT), 'magenta', attrs=['bold']))
		service_handler.get(SERVICE)(self.request, PORT)


class SimpleServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
	daemon_threads = True
	allow_reuse_address = True

	def __init__(self, server_address, RequestHandlerClass):
		print('Setting up service {} at :{}'.format(SERVICE, PORT))
		socketserver.TCPServer.__init__(self, server_address, RequestHandlerClass)



# SETUP SERVER
try:
	server = SimpleServer((BIND_IP, PORT), SingleTCPHandler)
except:
	server = None
	print(traceback.format_exc())


if server:
	try:
			print("Started successfully, waiting for intruders...")
			server.serve_forever()
	except KeyboardInterrupt:
		sys.exit(0)

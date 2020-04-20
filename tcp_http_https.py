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

import re, socket, ssl, testrun, time, traceback, uuid, os.path
from utils import TextChannel, log_append, readline, switchtossl

# default headers
HEADERS = {
	'Server': 'microhttpd (MontaVista/2.4, i386-uClibc)',
	'Content-Type': 'text/html',

}
# Adapted from 2.7/Lib/Cookie.py
def __getexpdate(future=0):
	weekdayname = [ 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun' ]
	monthname = [ None, 'Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec' ]
	year, month, day, hh, mm, ss, wd, _, _ = time.gmtime(time.time() + future)
	return "%s, %02d %3s %4d %02d:%02d:%02d GMT" % (weekdayname[wd], day, monthname[month], year, hh, mm, ss)

def handle_tcp_http(socket, dsthost, dstport, persona):
	# load body
	index_file = persona.get('index')
	if (os.path.exists(index_file) and os.path.isfile(index_file)):
		with open(index_file) as body_file:
			body = body_file.read()
	else:
		body = "<h1>It's Alive!</h1>"

	socket = TextChannel(socket)
	try:
		keep_alive = True
		while keep_alive:
			firstline = readline(socket).strip()
			if firstline == "":
				continue
			rematch = re.match("([A-Z]+) ([^ ]+) ?.*", firstline)
			if not rematch:
				raise Exception('Unexpected request: "{}"'.format(firstline))

			verb = rematch.group(1)
			url = rematch.group(2)

			# Skip headers
			keep_alive = False
			user_agent = ''
			while True:
				header = readline(socket).strip()
				if header == '':
					break
				elif header.upper() == 'CONNECTION: KEEP-ALIVE':
					keep_alive = True
				elif header.upper().startswith('USER-AGENT: '):
					user_agent = header[len('USER-AGENT: '):]

			session_token = uuid.uuid4().hex
			log_append('tcp_http_requests', socket.getpeername()[0], dstport, verb, url, user_agent, session_token)


			#HEADERS['Server'] = persona.get('headers').get('Server')
			HEADERS.update(persona.get('headers'))
			HEADERS['Set-Cookie'] = 'sessionToken={}; Expires={}'.format(session_token, __getexpdate(5 * 365 * 24 * 60 * 60))
			HEADERS['Connection'] = "keep-alive" if keep_alive else "close"
			HEADERS['Content-Length'] = str(len(body))

			header = 'HTTP/1.1 200 OK\n'
			for header_title in HEADERS:
				header += header_title + ': ' + HEADERS[header_title] + '\n'

			socket.send(header + '\n' + body)

	except ssl.SSLError as err:
		print("SSL error: {}".format(err.reason))
		pass
	except ConnectionResetError:
		print("Connection reset by peer")
		pass
	except Exception:
		print(traceback.format_exc())
		pass

	try:
		socket.close
	except:
		pass

def handle_tcp_https(socket, dsthost, dstport, persona):
	plaintext_socket = switchtossl(socket)
	if plaintext_socket:
		handle_tcp_http(plaintext_socket, dsthost, dstport, persona)
	else:
		socket.close()

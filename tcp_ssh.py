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

import paramiko, testrun, threading, traceback, sys, os.path
#from unixshell import interactive_shell, process_commandline
from utils import TextChannel, log_append, noexceptwrap

#paramiko.util.log_to_file('logs/tcp_ssh_server_paramiko.log')
default_key_rsa = paramiko.RSAKey(filename='secrets/tcp_ssh_rsa')
default_key_dss = paramiko.DSSKey(filename='secrets/tcp_ssh_dss')

class Server(paramiko.ServerInterface):
	def __init__(self, socket_peername):
		self.socket_peername = socket_peername
		self.username = None

	def check_channel_request(self, kind, chanid):
		print("Channel requested: kind={}".format(kind))
		if kind == 'session':
			return paramiko.OPEN_SUCCEEDED
		return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

	def check_auth_password(self, username, password):
		print("Password-based authentication: user={} pass={}".format(username, password))
		log_append('tcp_ssh_passwords', username, password, *self.socket_peername)
		#self.username =  username
		#return paramiko.AUTH_SUCCESSFUL
		return paramiko.AUTH_FAILED

	def check_auth_publickey(self, username, key):
		#print('Pubkey-based authentication: user={} key={}'.format(username, key.get_fingerprint().encode('hex')))
		#self.username =  username
		#return paramiko.AUTH_SUCCESSFUL
		return paramiko.AUTH_FAILED

	def get_allowed_auths(self, username):
		return 'password,publickey'

	def check_channel_shell_request(self, channel):
		# print("Shell requested")

		# if 'root' in self.username:
		# 	ps1 = '[root@localhost ~]# '
		# else:
		# 	ps1 = '[{}@localhost ~]$ '.format(self.username)

		# threading.Thread(target=noexceptwrap(interactive_shell), args=[TextChannel(channel, fix_incoming_endl=True), ps1]).start()
		return True

	def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
		print("PTY requested")
		return True

	def check_channel_exec_request(self, channel, command):
		# print("EXEC requested: {}".format(command))
		# threading.Thread(target=noexceptwrap(process_commandline), args=[TextChannel(channel, fix_incoming_endl=True), command]).start()
		return True

def handle_tcp_ssh(socket, dsthost, dstport, persona):
	try:
		#(dsthost, dstport) = socket.server_address

		t = paramiko.Transport(socket)
		t.local_version = persona.get('banner')
		t.load_server_moduli() # It can be safely commented out if it does not work on your system

		rsafile = './resources/ssh/{}_rsa'.format(dsthost)
		if (os.path.exists(rsafile)):
			print('SSH loading', rsafile)
			t.add_server_key(paramiko.RSAKey(filename=rsafile))
		else:
			print('SSH loading default rsa, missing:', rsafile)
			t.add_server_key(default_key_rsa)

		dssfile='resources/ssh/{}_dss'.format(dsthost)
		if (os.path.exists(dssfile)):
			print('SSH loading', dssfile)
			t.add_server_key(paramiko.DSSKey(filename=dssfile))
		else:
			print('SSH loading default dss, missing:', dssfile)
			t.add_server_key(default_key_dss)

		server = Server(socket.getpeername())
		try:
			t.start_server(server=server)
		except socket.timeout:
			print('Timeout')
		except paramiko.ssh_exception.SSHException as err:
			print('SSHException: ', err)
		except EOFError:
			print("Disconnected by peer.")

		t.join()

	except Exception:
		print(traceback.format_exc())
		pass

	try:
		t.close()
	except:
		print('When closing socket', traceback.format_exc())
		pass

	socket.close()

if __name__ == "__main__":
	testrun.run_tcp(2200, 22, handle_tcp_ssh)

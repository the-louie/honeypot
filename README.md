# honeypot
Yet another Python honeypot ;)

## About this project
This honeypot is designed to listen on **all** TCP and UDP ports. It emulates the following services:
 * SSH (`22/tcp`)
 * telnet (`23/tcp`)
 * SMTP (`25/tcp`)
 * HTTPS (`443/tcp` only)
 * HTTP GET and CONNECT (on every other `tcp` port)
 * SIP (`5060/udp`, with special support to detect [sipvicious](https://github.com/sandrogauci/sipvicious) scans)
 * Netis [factory backdoor](http://blog.trendmicro.com/trendlabs-security-intelligence/netis-routers-leave-wide-open-backdoor/)

HTTP is autodetected by monitoring whether the first bytes sent by the client are either `GET` or `CONNECT`. In case of HTTP CONNECT requests, the emulated proxy always loops back to the honeypot itself.

Similarly, SSL/TLS is also autodetected by checking if the first bytes sent by the client look like the first bytes of the `SSL Client Hello` handshake message.

Any other unrecognized TCP connection or UDP packet is logged as-is in hexdump-like form.

# Installation and setup

## Prerequisites
A Linux system with Python 2 and `iptables`, plus a few extra Python libraries:
 * Fedora packages: `python-termcolor`, `python-GeoIP`, `python-paramiko`, `pyip` and `pylibpcap`;
 * Ubuntu packages: `python-termcolor`, `python-geoip`, `python-paramiko`, `python-pyip` and `python-libpcap`.

## Configuration
 1. Copy `config.py.example` as `config.py`.
 2. Open and edit `config.py`:
     * `LOCAL_IP` must be set to the IP the honeypot will listen on (if you are behind NAT, this must be the private IP). The example texts in next section assume `LOCAL_IP` is 192.168.1.123 but, according to your network setup, you will probably use a different IP address. Change this value accordingly.
     * `TCP_MAGIC_PORT` is the TCP port where all TCP traffic is redirected to. There is no particular reason to change it but, if you do, just make sure to write the same value in the `iptables DNAT` rule (see next section).
     * The are other configuration parameters, documented directly inside `config.py.example`.
 3. Store the emulated SSH server's private keys (`tcp_ssh_rsa` and `tcp_ssh_dss`) you wish to use inside the `secrets/` subdirectory. Similarly, store SSL private key (`tcp_ssl.key`) and certificate (`tcp_ssl_cert.pem`) too. If you do not have existing keys and/or SSL certificates to use, run the following commands to generate new ones:
    <pre>cd secrets/
ssh-keygen -t rsa -f tcp_ssh_rsa -N ""
ssh-keygen -t dsa -f tcp_ssh_dss -N ""
openssl req -new -newkey rsa:1024 -x509 -subj "/C=IT/L=Catania/O=EasyIT/OU=Internal Network/CN=localhost" -days 3650 -nodes -keyout tcp_ssl.key -out tcp_ssl_cert.pem
</pre>
    **Note about SSL**: the previous command will generate a self-signed certificate, which some clients will reject. Also, it is probably a good idea to customize the `Subject Identifier` values.

## Running the honeypot

# Protocol support

## SSH and telnet
The honeypot pretends that all SSH and telnet login attempts succeed. Commands are executed by a fake shell that only implements a very basic set of UNIX commands. The fake shell will never access your real system.

## SMTP
The emulated server does not require authentication and it will always accept and log all messages that clients try to send, pretending they were sent or received successfully. SSL-protected SMTP (i.e. the `STARTTLS` command) is supported too.

## HTTP
Two HTTP methods are currently recognized: `GET` and `CONNECT`.
 * `GET` requests are always answered with a standard response and a randomly-generated cookie that is logged and can be used to track responses.
 * `CONNECT` (i.e. proxy) requests will always appear to succeed. Proxied connections are always answered by the honeypot itself and are never forwarded to external servers.


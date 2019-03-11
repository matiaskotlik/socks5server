import argparse
import logging
import socket
import struct
from collections import namedtuple
from logging.config import fileConfig
from socketserver import ThreadingTCPServer, StreamRequestHandler
from typing import Sequence
from select import select

fileConfig('logging_config.ini')
logger = logging.getLogger()


class Server(ThreadingTCPServer):
    pass


class Connection(namedtuple('Socks5Remote', ('address_family', 'address', 'port'))):
    def get_fmt(self) -> str:
        assert self.address_family in (socket.AF_INET, socket.AF_INET6), 'invalid socket family'
        if self.address_family == socket.AF_INET:
            return 'B' * 4
        elif self.address_family == socket.AF_INET6:
            return 'B' * 16

    def get_as_bytes(self) -> bytes:
        return socket.inet_pton(self.address_family, self.address)

    def is_valid(self):
        if 1 <= self.port <= 65535:
            try:
                self.get_as_bytes()
                return True
            except OSError:
                return False


class Socks5ConnectionHandler(StreamRequestHandler):
    VERSION = 5
    AUTH_METHODS = {
        0x00: 'NO AUTHENTICATION',
        0x01: 'GSSAPI',
        0x02: 'USERNAME/PASSWORD'
    }
    AVAIL_METHODS = (0x00,)
    CMD_CODES = {
        0x01: 'ESTABLISH TCP/IP STREAM',
        0x02: 'ESTABLISH TCP/IP PORT BINDING',
        0x03: 'ASSOCIATE UDP PORT'
    }
    AVAIL_CODES = (0x01,)
    ADDR_FAMILIES = {
        0x01: 'IPV4 ADDRESS',
        0x03: 'Domain Name',
        0x04: 'IPV6 ADDRESS'
    }
    SOCKET_CONVERSION = {
        socket.AF_INET: 0x01,
        socket.AF_INET6: 0x04
    }
    SF = '!'  # struct flags, '!' means to use network (big-endian) numbers
    RECV_BUFFER = 4096

    def get_log_format(self):
        return f'CLIENT AT {(self.address_formatted() + ":"):24}'

    def debug(self, msg):
        logger.debug(self.get_log_format() + msg)

    def info(self, msg):
        logger.info(self.get_log_format() + msg)

    def error(self, msg):
        logger.error(self.get_log_format() + msg)

    def handle(self):
        self.info(f'connection initiated')

        methods = self.recv_methods()
        self.debug(f'client supported methods: {", ".join(self.AUTH_METHODS[m] for m in methods)}')

        method = None
        for m in self.AVAIL_METHODS:
            if m in methods:
                method = m
                break

        if method is None:
            self.debug('valid method not found, sending 0xff')
            self.pack_and_send('BB', self.VERSION, 0xff)

            self.info(f'closing connection with {self.address_formatted()}, no methods found')
            self.close()
            return

        self.debug(f'using method {self.AUTH_METHODS[method]}')
        self.pack_and_send('BB', self.VERSION, method)

        remote = self.recv_connection_req()
        self.info(f'requested connection:\n{remote}')

        if not remote.is_valid():
            self.info(f'closing connection with {self.address_formatted()}, remote address invalid')
            self.pack_and_send('BBx', self.VERSION, 0x01)  # send general failure
            self.close()
            return

        remote_socket = socket.socket(remote.address_family, socket.SOCK_STREAM)
        try:
            remote_socket.connect((remote.address, remote.port))
        except socket.timeout:
            logger.debug(f'connection to remote {remote} timed out')
            self.close()
            return

        local = Connection(remote_socket.family, *remote_socket.getsockname()[:2])

        self.debug(f'local socket for connection:\n{local}')

        # socks version, status, padding, addr type, address, port
        self.pack_and_send('BBxB' + local.get_fmt() + 'H', self.VERSION, 0x00,
                           self.SOCKET_CONVERSION[local.address_family],
                           *local.get_as_bytes(), local.port)

        self.info(f'exchanging information to {remote}')
        self.exchange_information(remote_socket)

        self.close()

    def exchange_information(self, remote):
        while True:
            read, _, _ = select([self.request, remote], [], [])
            if self.request in read:
                try:
                    data = self.request.recv(self.RECV_BUFFER)
                    if len(data) == 0:
                        break
                    if remote.send(data) == 0:
                        break
                    self.debug(f'sent to remote:\n{hard_translate(data)}')
                except socket.error:
                    break
            if remote in read:
                try:
                    data = remote.recv(self.RECV_BUFFER)
                    if len(data) == 0:
                        break
                    if self.request.send(data) == 0:
                        break
                    self.debug(f'received from remote:\n{hard_translate(data)}')
                except socket.error:
                    break

    def recv_connection_req(self) -> Connection:
        version, cmd_code, addr_type = self.recv_and_unpack('BBxB', 4)
        self.check_version(version)

        code_alias = self.CMD_CODES.get(cmd_code, None)
        assert cmd_code in self.AVAIL_CODES, f'invalid command code {cmd_code}' \
                                             + (f': {code_alias}' if code_alias else '')

        address = None
        address_family = None
        if addr_type == 0x01:  # IPV4 ADDRESS
            address = socket.inet_ntoa(self.recv(4))  # convert 32-bit packed ip address to string
            address_family = socket.AF_INET
        elif addr_type == 0x03:  # Domain Name
            domain_length = self.recv_and_unpack('B', 1)[0]
            domain = self.recv_and_unpack(f'{domain_length}s', domain_length)[0].decode('utf-8')
            address = resolve_domain(domain)
            address_family = socket.AF_INET
        elif addr_type == 0x04:  # IPV6 ADDRESS
            address = socket.inet_ntop(socket.AF_INET6, self.recv(16))
            address_family = socket.AF_INET6

        port = self.recv_and_unpack('H', 2)[0]

        return Connection(address_family, address, port)

    def recv_methods(self) -> Sequence[int]:
        version, num_methods = self.recv_and_unpack('BB', 2)
        self.check_version(version)
        return self.recv_and_unpack('B' * num_methods, num_methods)

    def close(self) -> None:
        self.server.close_request(self.request)

    def address_formatted(self) -> str:
        return ':'.join(str(x) for x in self.client_address)

    def recv(self, size: int) -> bytes:
        data = self.request.recv(size)
        return data

    def check_version(self, version: int) -> None:
        assert version == self.VERSION, f'incorrect SOCKS version (got {version}, should be {self.VERSION})'

    def pack_and_send(self, fmt, *args) -> None:
        self.request.sendall(struct.pack(self.SF + fmt, *args))

    def recv_and_unpack(self, fmt: str, size: int):
        data = self.recv(size)
        assert len(data) != 0, 'no data recieved, was the connection closed unexpectedly?'
        try:
            return struct.unpack(self.SF + fmt, data)
        except struct.error:
            logger.error(f"error while unpacking: '{hard_translate(data)}'")


def get_hex(byts: bytes) -> str:
    return ' | '.join(hex(b) for b in byts)


def hard_translate(byts: bytes) -> str:
    return ''.join(chr(c) for c in byts)

def resolve_domain(domain: str) -> str:
    return socket.gethostbyname(domain)

def main():
    # set up logger
    logger.debug('starting program')

    # set up argument parser
    parser = argparse.ArgumentParser(description='A SOCKS5 server for python3')
    parser.add_argument('--host', default='localhost', help='The host to run the server on')
    parser.add_argument('-p', '--port', type=int, default=9001, help='The port to run the server on')

    # parse arguments
    logger.debug('parsing arguments')
    args = parser.parse_args()

    ip = args.host
    port = args.port

    # start server
    logger.info(f'starting server, binding to {ip}:{port}')
    with Server((ip, port), Socks5ConnectionHandler) as server:
        logger.debug('server bound, serving forever')
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            logger.debug('KeyboardInterrupt detected, stopping server')

    logger.info('server has been shut down')


if __name__ == '__main__':
    main()

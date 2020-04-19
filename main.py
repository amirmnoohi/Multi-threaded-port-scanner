from threading import Thread
from extra import *
import time
import datetime
import sys
import queue
from services import services
import argparse


def local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(('8.8.8.8', 1))
    return s.getsockname()[0]


def dedicate_local_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(('', 0))
    return s.getsockname()[1]


def checksum(msg):
    s = 0
    # loop taking 2 characters at a time
    for counter in range(0, len(msg), 2):
        w = (msg[counter] << 8) + (msg[counter + 1])
        s = s + w

    s = (s >> 16) + (s & 0xffff)
    # s = s + (s >> 16);
    # complement and mask to 4 byte short
    s = ~s & 0xffff
    return s


def unique(input_list):
    unique_list = []
    for x in input_list:
        if x not in unique_list:
            unique_list.append(x)
    return unique_list


class Extract:
    def __init__(self, __packet__):
        self.ip_header = unpack('!BBHHHBBH4s4sHHLLBBHHH', __packet__[:40])
        # -----------------------------IP Header Unpacking------------------------
        self.version_ihl = self.ip_header[0]
        self.version = self.version_ihl >> 4
        self.header_length = (self.version_ihl & 0xF) * 4
        self.type_of_service = self.ip_header[1]
        self.total_length = self.ip_header[2]
        self.identification = self.ip_header[3]
        self.flags = self.ip_header[4] >> 13
        self.fragment_offset = self.ip_header[4] & 0x1FFF
        self.ttl = self.ip_header[5]
        self.protocol = self.ip_header[6]
        self.header_checksum = self.ip_header[7]
        self.source_address = socket.inet_ntoa(self.ip_header[8])
        self.destination_address = socket.inet_ntoa(self.ip_header[9])
        # ----------------------------TCP Header Unpacking------------------------
        self.source_port = self.ip_header[10]
        self.destination_port = self.ip_header[11]
        self.sequence_number = self.ip_header[12]
        self.acknowledgment_number = self.ip_header[13]
        self.offset = self.ip_header[14] >> 4
        self.reserved = (self.ip_header[14] >> 1) & 0x7
        self.cwr = (self.ip_header[15] >> 7) & 0x1
        self.ece = (self.ip_header[15] >> 6) & 0x1
        self.urg = (self.ip_header[15] >> 5) & 0x1
        self.ack = (self.ip_header[15] >> 4) & 0x1
        self.psh = (self.ip_header[15] >> 3) & 0x1
        self.rst = (self.ip_header[15] >> 2) & 0x1
        self.syn = (self.ip_header[15] >> 1) & 0x1
        self.fin = self.ip_header[15] & 0x1
        self.windows = self.ip_header[16]
        self.checksum = self.ip_header[17]
        self.urgent_pointer = self.ip_header[18]
        self.ALL = [
            self.version_ihl, self.version, self.header_length, self.type_of_service, self.total_length,
            self.identification, self.flags, self.ttl, self.protocol, self.header_checksum, self.source_address,
            self.destination_address, self.source_port, self.destination_port, self.sequence_number,
            self.acknowledgment_number, self.offset, self.reserved, self.cwr, self.ece, self.urg, self.ack,
            self.psh, self.rst, self.syn, self.fin, self.windows, self.checksum, self.urgent_pointer
        ]


class TCPPACKET:
    def __init__(self, source_address, destination_address, source_port, destination_port, method):
        # ---------------------------------Assemble IP Header-------------------------------------
        self.version = 4
        self.header_length = 5
        self.version_ihl = (self.version << 4) + self.header_length
        self.type_of_service = 0
        self.total_length = 20 + 20
        self.identification = 54321
        self.frag_flag = 0
        self.ttl = 255
        self.protocol = socket.IPPROTO_TCP
        self.header_checksum = 10
        self.source_address = socket.inet_aton(source_address)
        self.destination_address = socket.inet_aton(destination_address)
        self.ip_header = pack('!BBHHHBBH4s4s', self.version_ihl, self.type_of_service, self.total_length,
                              self.identification, self.frag_flag, self.ttl, self.protocol,
                              self.header_checksum, self.source_address, self.destination_address)
        # ----------------------------------Assemble TCP Header-----------------------------------
        self.source_port = source_port
        self.destination_port = destination_port
        self.sequence_number = 0
        self.acknowledgment_number = 0
        self.offset_reserved = (5 << 4) + 0
        self.cwr = 0
        self.ece = 0
        self.urg = 0
        self.psh = 0
        self.rst = 0
        if method == 0:
            self.ack = 0
            self.syn = 1
            self.fin = 0
        if method == 1:
            self.ack = 1
            self.syn = 0
            self.fin = 0
        if method == 2:
            self.ack = 0
            self.syn = 0
            self.fin = 1
        self.tcp_flags = (self.cwr << 7) + (self.ece << 6) + (self.urg << 5) + (self.ack << 4) + \
                         (self.psh << 3) + (self.rst << 2) + (self.syn << 1) + self.fin
        self.windows_size = 1024  # socket.htons(5840)  # maximum allowed size
        self.checksum = 0
        self.urgent_pointer = 0
        self.tcp_header = pack('!HHLLBBHHH', self.source_port, self.destination_port, self.sequence_number,
                               self.acknowledgment_number, self.offset_reserved, self.tcp_flags,
                               self.windows_size, self.checksum, self.urgent_pointer)
        # --------------------------------Calculation TCP Checksum-----------------------------------
        self.placeholder = 0
        self.tcp_length = len(self.tcp_header)
        self.tmp = pack('!4s4sBBH', self.source_address, self.destination_address, self.placeholder, self.protocol,
                        self.tcp_length)
        self.tmp = self.tmp + self.tcp_header
        self.checksum = checksum(self.tmp)
        # --------------------------------Reassemble TCP Header-----------------------------------
        self.tcp_header = pack('!HHLLBBHHH', self.source_port, self.destination_port, self.sequence_number,
                               self.acknowledgment_number, self.offset_reserved, self.tcp_flags,
                               self.windows_size, self.checksum, self.urgent_pointer)
        self.packet = self.ip_header + self.tcp_header


def connect_scan(destination_port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        sock.connect((host, destination_port))
    except socket.error:
        return False
    return True


def connect_scan_worker():
    while True:
        destination_port = port_queue.get()
        if connect_scan(destination_port):
            opened_ports.append(destination_port)
        port_queue.task_done()


def syn_scan():
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    for destination_port in range(start_port, stop_port):
        packet = TCPPACKET(local_ip(), host, dedicate_local_port(), destination_port, 0)
        s.sendto(packet.packet, (host, 0))
        time.sleep(0.1)


def wait_syn_scan():
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    while (time.time() - start_time) <= e_time + delay:
        raw_data, addr = conn.recvfrom(65535)
        ip_header = ip(raw_data[14:])
        if (ip_header[11] == local_ip()) & (ip_header[10] == host):
            # print(tcp(ip_header[-1]))
            if ip_header[8] == 6:
                if (tcp(ip_header[-1])[10] == 1) & (tcp(ip_header[-1])[13] == 1):
                    # print(tcp(ip_header[-1]))
                    opened_ports.append(tcp(ip_header[-1])[0])


def ack_scan():
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    for destination_port in opened_ports[:]:
        # print("sent to : "+str(destination_port))
        packet = TCPPACKET(local_ip(), host, dedicate_local_port(), destination_port, 1)
        s.sendto(packet.packet, (host, 0))
        time.sleep(0.1)


def wait_ack_scan():
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    while (time.time() - start_time) <= e_time + delay:
        raw_data, addr = conn.recvfrom(65535)
        ip_header = ip(raw_data[14:])
        if (ip_header[11] == local_ip()) & (ip_header[10] == host):
            # print(tcp(ip_header[-1]))
            if ip_header[8] == 6:
                if tcp(ip_header[-1])[12] == 1:
                    # print((time.time() - start_time),e_time + delay)
                    # print("received ack : "+str(tcp(ip_header[-1])[0]))
                    try:
                        second_ports.append(tcp(ip_header[-1])[0])
                    except ValueError:
                        continue


def fin_scan():
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    for destination_port in opened_ports[:]:
        # print("sent to : "+str(destination_port))
        packet = TCPPACKET(local_ip(), host, dedicate_local_port(), destination_port, 2)
        s.sendto(packet.packet, (host, 0))
        time.sleep(0.1)


def wait_fin_scan():
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    while (time.time() - start_time) <= e_time + delay:
        raw_data, addr = conn.recvfrom(65535)
        ip_header = ip(raw_data[14:])
        if (ip_header[11] == local_ip()) & (ip_header[10] == host):
            # print(tcp(ip_header[-1]))
            if ip_header[8] == 6:
                if tcp(ip_header[-1])[12] == 1:
                    # print((time.time() - start_time),e_time + delay)
                    # print("received ack : "+str(tcp(ip_header[-1])[0]))
                    try:
                        second_ports.append(tcp(ip_header[-1])[0])
                    except ValueError:
                        continue


def windows_scan():
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    for destination_port in opened_ports[:]:
        # print("sent to : "+str(destination_port))
        packet = TCPPACKET(local_ip(), host, dedicate_local_port(), destination_port, 1)
        s.sendto(packet.packet, (host, 0))
        time.sleep(0.1)


rst_p = []
rst_z = []


def wait_window_scan():
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    while (time.time() - start_time) <= e_time + delay:
        raw_data, addr = conn.recvfrom(65535)
        ip_header = ip(raw_data[14:])
        if (ip_header[11] == local_ip()) & (ip_header[10] == host):
            # print(tcp(ip_header[-1]))
            if ip_header[8] == 6:
                if tcp(ip_header[-1])[12] == 1:
                    # print((time.time() - start_time),e_time + delay)
                    # print("received ack : "+str(tcp(ip_header[-1])[0]))
                    # print(tcp(ip_header[-1]))
                    if tcp(ip_header[-1])[-3] == 0:
                        rst_z.append(tcp(ip_header[-1])[0])
                    else:
                        rst_p.append(tcp(ip_header[-1])[0])


def show_connect_scan(result):
    if len(result) == 0:
        return
    else:
        result.sort()
        print("PORT\tSTATE\tSERVICE")
        for x in result:
            if str(x) in services:
                print(str(x) + "\topen\t" + services[str(x)])
            else:
                print(str(x) + "\topen\tunknown")
    print("Scan done: elapsed time : {0:.2f} Seconds".format(time.time() - start_time))


def show_syn_scan(result):
    if len(result) == 0:
        return
    else:
        result.sort()
        print("PORT\tSTATE\tSERVICE")
        for x in result:
            if str(x) in services:
                print(str(x) + "\topen\t" + services[str(x)])
            else:
                print(str(x) + "\topen\tunknown")
    print("Scan done: elapsed time : {0:.2f} Seconds".format(time.time() - start_time))


def show_ack_scan(result, method):
    if len(result) == 0:
        return
    else:
        print("PORT\tSTATE\t\tSERVICE")
        if method == 0:
            for x in result:
                if str(x) in services:
                    print(str(x) + "\tfiltered\t" + services[str(x)])
                else:
                    print(str(x) + "\tfiltered\tunknown")
        else:
            for x in result:
                if str(x) in services:
                    print(str(x) + "\tunfiltered\t" + services[str(x)])
                else:
                    print(str(x) + "\tunfiltered\tunknown")
    print("Scan done: elapsed time : {0:.2f} Seconds".format(time.time() - start_time))


def show_fin_scan(result):
    if len(result) == 0:
        return
    elif len(result) == len(opened_ports):
        print("All " + str(len(result)) + " scanned ports on " + args.target + "(" + str(host) + ") are open|filtered")
    else:
        result.sort()
        print("PORT\tSTATE\tSERVICE")
        for x in result:
            if str(x) in services:
                print(str(x) + "\topen\t" + services[str(x)])
            else:
                print(str(x) + "\topen\tunknown")
    print("Scan done: elapsed time : {0:.2f} Seconds".format(time.time() - start_time))


def show_windows_scan(no_rst, p_rst, z_rst):
    if (len(no_rst)) == 0 & (len(p_rst) == 0) & (len(z_rst) == 0):
        return
    print("PORT\tSTATE\tSERVICE")
    if len(no_rst) > 0:
        no_rst.sort()
        for x in no_rst:
            if str(x) in services:
                print(str(x) + "\tclosed\t" + services[str(x)])
            else:
                print(str(x) + "\tclosed\tunknown")
    if len(p_rst) > 0:
        p_rst.sort()
        for x in p_rst:
            if str(x) in services:
                print(str(x) + "\topen\t" + services[str(x)])
            else:
                print(str(x) + "\topen\tunknown")
    if len(z_rst) > 0:
        if len(z_rst) > len(opened_ports)/4:
            print("All " + str(len(z_rst)) + " other scanned ports on " + args.target + "(" + str(
                host) + ") are filtered")
        else:
            z_rst.sort()
            for x in z_rst:
                if str(x) in services:
                    print(str(x) + "\tfiltered\t" + services[str(x)])
                else:
                    print(str(x) + "\tfiltered\tunknown")
    print("Scan done: elapsed time : {0:.2f} Seconds".format(time.time() - start_time))


start_port = int()
stop_port = int()
e_time = start_time = time.time()
opened_ports = []
second_ports = []
port_queue = queue.Queue()
parser = argparse.ArgumentParser()
parser.add_argument('-t', '--target', help='Address of Target ip or hostname : google.com', required=True)
parser.add_argument('-p', '--port', help='Range of port for scanning : 0-200', required=True)
parser.add_argument('-s', '--scan',
                    help='Scan Type : CS(Connect Scan) - AS(Ack Scan) - SS(SYN Scan) - FS(FIN Scan) - WS(Windows Scan)',
                    required=True)
parser.add_argument('-d', '--delay', help='Delay for checking accurately all received packets Default : 2 Second')
args = parser.parse_args()
if args.delay is not None:
    delay = args.delay
else:
    delay = 2
try:
    host = socket.gethostbyname(args.target)
    print("Target IP : " + host)
except:
    print("Target is Unreachable")
    sys.exit()
fnd = args.port.find('-')
if fnd == -1:
    if int(args.port) > 65535 or int(args.port) < 0:
        print("Port is out of range")
        sys.exit()
else:
    start_port = min(int(args.port[0:fnd]), int(args.port[fnd + 1:]))
    stop_port = max(int(args.port[0:fnd]), int(args.port[fnd + 1:]))
print("Port Range : " + str(start_port) + " - " + str(stop_port))
if args.scan == 'CS':
    print("Starting Connect Scan at " + str(datetime.datetime.now()))
    try:
        for _ in range(20):
            t = Thread(target=connect_scan_worker)
            t.daemon = True
            t.start()
        for port in range(start_port, stop_port):
            port_queue.put(port)
        port_queue.join()
    except KeyboardInterrupt:
        print("\nYou Pressed Ctrl+C")
    show_connect_scan(opened_ports)

elif args.scan == 'SS':
    print("Starting SYN Scan at " + str(datetime.datetime.now()))
    z = Thread(target=wait_syn_scan)
    z.start()
    y = Thread(target=syn_scan)
    y.start()
    y.join()
    e_time = time.time() - start_time
    z.join()
    show_syn_scan(opened_ports)
elif args.scan == 'AS':
    opened_ports = list(range(start_port, stop_port))
    try:
        print("Starting ACK Scan at " + str(datetime.datetime.now()))
        z = Thread(target=wait_ack_scan)
        z.start()
        y = Thread(target=ack_scan)
        y.start()
        y.join()
        e_time = time.time() - start_time
        z.join()
    except KeyboardInterrupt:
        print("\nYou Pressed Ctrl+C")
        sys.exit()
    if len(second_ports) < (len(opened_ports) / 2):  # unfiltered ports are second_ports
        show_ack_scan(second_ports, 1)
    else:  # open_ports - second_ports = filtered ports
        show_ack_scan(list(set(opened_ports) - set(second_ports)), 0)
    sys.exit()

elif args.scan == 'FS':
    opened_ports = list(range(start_port, stop_port))
    try:
        print("Starting FIN Scan at " + str(datetime.datetime.now()))
        z = Thread(target=wait_fin_scan)
        z.start()
        y = Thread(target=fin_scan)
        y.start()
        y.join()
        e_time = time.time() - start_time
        z.join()
    except KeyboardInterrupt:
        print("\nYou Pressed Ctrl+C")
        sys.exit()
    show_fin_scan(list(set(opened_ports) - set(second_ports)))
elif args.scan == 'WS':
    opened_ports = list(range(start_port, stop_port))
    try:
        print("Starting WINDOW Scan at " + str(datetime.datetime.now()))
        z = Thread(target=wait_window_scan)
        z.start()
        y = Thread(target=windows_scan)
        y.start()
        y.join()
        e_time = time.time() - start_time
        z.join()
    except KeyboardInterrupt:
        print("\nYou Pressed Ctrl+C")
        sys.exit()
    show_windows_scan(list(set(opened_ports) - (set(rst_p).union(set(rst_z)))), rst_p, rst_z)
    sys.exit()

else:
    print("Scan Type Not Recognized")
    sys.exit(0)

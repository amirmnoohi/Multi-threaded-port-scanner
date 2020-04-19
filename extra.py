import socket
from struct import *

def ether(data):
    dest_mac, src_mac, proto = unpack('! 6s 6s H', data[:14])
    return [get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]]


def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    return ':'.join(bytes_str).upper()


def ip(data):
    maindata = data
    data = unpack('!BBHHHBBH4s4s', data[:20])
    return [(data[0] >> 4), (data[0] & 0xF) * 4, data[1], data[2],
            data[3], data[4] >> 13, data[4] & 0x1FFF, data[5],
            data[6], hex(data[7]), socket.inet_ntoa(data[8]),
            socket.inet_ntoa(data[9]), maindata[((data[0] & 0xF) * 4):]]


def icmp(data):
    return [unpack('!BBH', data[:4])]


def tcp(data):
    data = unpack('!HHLLHHHH', data[:20])
    return [data[0], data[1], data[2], data[3], (data[4] >> 4) * 4, (data[4] >> 9) & 7,
            (data[4] >> 8) & 1, (data[4] & 128) >> 7,
            (data[4] & 64) >> 6, (data[4] & 32) >> 5, (data[4] & 16) >> 4,
            (data[4] & 8) >> 3, (data[4] & 4) >> 2, (data[4] & 2) >> 1, data[4] & 1,
            data[5], hex(data[6]), data[7]]


def udp(data):
    data = unpack('!HHHH', data[:8])
    return [data[0], data[1], data[2], hex(data[3])]

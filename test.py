import socket
import struct
import textwrap
import gzip
import random
import shelve
import threading
import sys
import string
from collections import deque
from sortedcontainers import SortedDict

reassembly_strucutre = dict()
queue = deque([])
httpPackets = []

count = 0

class threadClass(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
 
    def run(self):
        global queue
        global count

        while len(queue) > 0:
            try:
                if len(queue) > 0:
                    element = queue.popleft()
                else:
                    continue
                    
                dest_mac, src_mac, protocol, data = ethernet_frame(element[0])
            
                if protocol != 8:
                    continue

                protocol_type, ip_src, ip_destination, data = getIpInfo(data)
                if protocol_type != 17 and protocol_type != 6:
                    continue

                port_src, port_destiantion, seq_number, ack_number, data = tcpUnpack(data)
    
                if port_src == 80 or port_destiantion == 80:
                    assembly_http(formatinIpAddress(ip_src), formatinIpAddress(ip_destination), port_src, port_destiantion, seq_number, element[1], data)
            except Exception as e:
                print(str(e))


def main(httpVerbs):
    global queue
    global event

    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    conn.setsockopt( socket.SOL_SOCKET, socket.SO_RCVBUF, 100000000) 
        
    while True:
            #65536
        raw_data, addr = conn.recvfrom(65536)

        queue.append((raw_data, httpVerbs))
        
        if len(queue) == 1:
            t1 = threadClass()
            t1.start()

def ethernet_frame(data):
    dest_mac, src_mac, protocol = struct.unpack("! 6s 6s H", data[:14])

    return get_addr_mac(dest_mac), get_addr_mac(src_mac), socket.htons(protocol), data[14:]

def get_addr_mac(bytes_addr):
    str = []
    for a in bytes_addr:
        h = hex(a)
        h = h[2:]
        if len(h) == 1:
            h = '0' + h
        str.append(h)
    return ':'.join(str).upper()

def getIpInfo(data):
    dataframe_length = bin(data[0])[-4:]
    dataframe_length = int(dataframe_length, 2)

    leght1, type_of_service, totalLenghth, frame_identificator, fragment_offset, ttl, protocol_type, control_sum, ip_src, ip_destination = struct.unpack("! 1s 1s H H H 1s B H 4s 4s", data[:20])

    return protocol_type, ip_src, ip_destination, data[dataframe_length * 4:]

def formatinIpAddress(ip_address):
    str_array = []
    for a in ip_address:
        str_array.append(str(a))
    return '.'.join(str_array)

def tcpUnpack(data):
    isHttpPackage = False
    port_src, port_destiantion, seq_number, ack_number, lenght_and_flags = struct.unpack("! H H L L H", data[:14])
    
    lenght_and_flags = bin(lenght_and_flags)

    lenght_and_flags = lenght_and_flags[2:]
    lenght = lenght_and_flags[:4]
    lenght = int(lenght, 2)

    ack_psh = lenght_and_flags[11:13]

    if ack_psh == "11":
        isHttpPackage = True

    return port_src, port_destiantion, seq_number, ack_number, data[lenght * 4:]


def getHeaderValue(headers, headerValue):
    headers = headers.decode("utf-8")
    splitHeaders = headers.split("\r\n")

    val = ""
    for header in splitHeaders:
        if headerValue in header:
            val = header[len(headerValue) + 1:]
    return val.strip()

def chunkedHttp(data):
    splitChunked = data.split(b"\r\n")
    if len(splitChunked[-1]) == 0:
        splitChunked = splitChunked[:-1] 
    payload = bytes()
    payloadLength = 0

    finishCheck = splitChunked[-2].decode('utf-8')
    if int(finishCheck, base= 16) != 0:
        return payload

    for idx, a in enumerate(splitChunked):
        if idx % 2 == 0 and idx != len(splitChunked) - 1:
            a = a.decode('utf-8')
            payloadLength = int(a, base = 16)
        else:
            if payloadLength == len(a) and payloadLength != 0:
                payload += a
    return payload

def verifyExistance(headers, content):
    global httpPackets

    for a in httpPackets:
        if a[0] == headers:
            return False
    return True
    
def parseHttp(httpPacket):
    global httpPackets
    try:
        splitRequest = httpPacket.split(b"\r\n\r\n", 1)

        if b'HTTP/1.1' not in splitRequest[0]:
            return

        length = getHeaderValue(splitRequest[0], 'Content-Length')

        if len(length) > 0:
            length = int(length)
        else:
            chunkedBool = getHeaderValue(splitRequest[0], 'Transfer-Encoding')
            if chunkedBool == 'chunked':
                splitRequest[1] = chunkedHttp(splitRequest[1])
                if len(splitRequest[1]) == 0:
                    length = 10
                else:
                    length = len(splitRequest[1])
            else:
                length = 0

        if length != len(splitRequest[1]) and length != 0:
            return

        if len(splitRequest[1]) == 0:
            headers = splitRequest[0].decode("utf-8")
            if verifyExistance(headers, "") == True:
                httpPackets.append((headers, ""))
            return

        str1 = ''.join(random.choices(string.ascii_lowercase, k=15))
        str1 = 'files/' + str1


        contentEncoding = getHeaderValue(splitRequest[0], "Content-Encoding")
        headers = splitRequest[0].decode("utf-8")

        if contentEncoding == 'gzip':
            splitEncoded = splitRequest[1].split(b"\r\n")
            maxLenString = max(splitEncoded, key = lambda i: len(i))

            content = gzip.decompress(maxLenString)

            if verifyExistance(headers, str1):
                httpPackets.append((headers, str1))
                f = open(str1, "wb")
                f.write(content)
                f.close()
        else:
            if verifyExistance(headers, str1):
                f = open(str1, "wb")
                httpPackets.append((headers, str1))
                f.write(splitRequest[1])
                f.close()
    except Exception as e:
        print(str(e))

def constructPacket(data):
    try:
        if len(data) > 0:
            payload = bytes()

        for idx, a in enumerate(data):
            if idx == 0:
                seq_nr = a
                segemntLength = len(data[a])
                payload = payload + data[a]
            else:
                if seq_nr + segemntLength != a:
                    return
                
                payload = payload + data[a]
                seq_nr = a 
                segemntLength = len(data[a])


        #sortedSegments = sorted(data, key = lambda i: i[0])

        #for a in range(1, len(sortedSegments), 1):
        #    if sortedSegments[a][0] != sortedSegments[a-1][0] + len(sortedSegments[a-1][1]):
        #        return
            
        #for a in sortedSegments:
        #    payload = payload + a[1]
        parseHttp(payload)
    except Exception as e:
        print(str(e))


count1 = 0
vec = bytes()

def assembly_http(ip_src, ip_dest, port_src, port_dest, seq_number, httpVerbs, data):
    global count1
    global vec
    
    if port_src == 80:
        comunicationIdentifier = ip_dest + ":" + ip_src + ":" + str(port_dest)
    else:
        comunicationIdentifier = ip_src + ":" + ip_dest + ":" + str(port_src)
    try:
        if len(data) != 0:
        
            if comunicationIdentifier not in reassembly_strucutre:
                firstSplit = data.split(b" ", 1)

                if firstSplit[0] in httpVerbs:
                    return

                new_set = set()
                new_set.add(seq_number)

                new_sorted_dic = SortedDict()
                new_sorted_dic.setdefault(seq_number, data)
                reassembly_strucutre[comunicationIdentifier] = [new_sorted_dic, port_src, new_set]
            else:

                if port_src != reassembly_strucutre[comunicationIdentifier][1]:
                    firstSplit = data.split(b" ", 1)

                    if firstSplit[0] in httpVerbs:
                        reassembly_strucutre.pop(comunicationIdentifier)
                        return
                        
                    new_set = set()
                    new_set.add(seq_number)
                    new_sorted_dic = SortedDict()
                    new_sorted_dic.setdefault(seq_number, data)
                    reassembly_strucutre[comunicationIdentifier] = [new_sorted_dic, port_src, new_set]
                else:
                    new_set = reassembly_strucutre[comunicationIdentifier][2]
                    sorted_dic = reassembly_strucutre[comunicationIdentifier][0]
                    isResend = False
                    
                    if seq_number in new_set:
                        isResend = True

                    if isResend == False:
                        new_set.add(seq_number)
                        sorted_dic.setdefault(seq_number, data)
                        reassembly_strucutre[comunicationIdentifier] = [sorted_dic, port_src, new_set]
                        
            constructPacket(reassembly_strucutre[comunicationIdentifier][0])
    except Exception as e:
        print(str(e))

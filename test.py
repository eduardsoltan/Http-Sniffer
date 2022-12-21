import socket
import struct
import gzip
import random
import threading
import string
import re
from collections import deque
from sortedcontainers import SortedDict

reassembly_strucutre = dict()
queue = deque([])
httpPackets = []
event = threading.Event()

count = 0

class threadClass(threading.Thread):
    """
        Worker thread is going to be started by main thread when packages deque has only one element and will run until the deque will be empty
    """
    
    def __init__(self):
        threading.Thread.__init__(self)
 
    def run(self):
        """
            The main responsabilities of the thread is to pop a internet package from the deque unpack all the layers: ethernet, ip and tcp.
            Extract the content and reconstruct the original http trafic. 
        """
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


def main(filterValues):
    """
        Takes as input user filters such as hostname from which to sniff trafic or/and specific Http methods.

        Function creates a raw socket that will capture internet trafic and will insert packeges in the deque where 
        further processing will be done by worker thread.
    """
    global queue
    global event

    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    conn.setsockopt( socket.SOL_SOCKET, socket.SO_RCVBUF, 100000000) 
        
    while True:
        #65536
        raw_data, addr = conn.recvfrom(65536)

        queue.append((raw_data, filterValues))
        
        if len(queue) == 1:
            t1 = threadClass()
            t1.start()

def ethernet_frame(data):
    """
        Unpack the ethernet layer    

        Input: a internet package captured by socket in form of bytes() 

        Return: source mac address, destination mac address, protocol, content of ethernet frame
    """

    dest_mac, src_mac, protocol = struct.unpack("! 6s 6s H", data[:14])

    return get_addr_mac(dest_mac), get_addr_mac(src_mac), socket.htons(protocol), data[14:]

def get_addr_mac(bytes_addr):
    """
        Convert mac address from bytes to human readable format

        Input: mac address in bytes() format

        Output: mac address in human readalbe format
    """
    str = []
    for a in bytes_addr:
        h = hex(a)
        h = h[2:]
        if len(h) == 1:
            h = '0' + h
        str.append(h)
    return ':'.join(str).upper()

def getIpInfo(data):
    """
        Unpacking ip layer

        Input: a internet package with ethernet layer unpacked

        Return: Superior level protocol, source ip address, destination ip address, content of the datagram  
    """

    dataframe_length = bin(data[0])[-4:]
    dataframe_length = int(dataframe_length, 2)

    leght1, type_of_service, totalLenghth, frame_identificator, fragment_offset, ttl, protocol_type, control_sum, ip_src, ip_destination = struct.unpack("! 1s 1s H H H 1s B H 4s 4s", data[:20])

    return protocol_type, ip_src, ip_destination, data[dataframe_length * 4:]

def formatinIpAddress(ip_address):
    """
        Converts ip address from computer readable format to human readable format

        Input: ip address in computer readable format

        Return: ip address in human readable format
    """
    
    str_array = []
    for a in ip_address:
        str_array.append(str(a))
    return '.'.join(str_array)

def tcpUnpack(data):
    """
        Unpack the tcp layer of a dataframe

        Input: A internet package with ethernet and ip layers unpacked

        Return: source port, destination port, sequence number, acknowledgement number, and http content
    """

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
    """
        Input: 
            http headers of a request, 
            name of header for which the value is wanted

        Return: 
            Value of the requested header
    """

    headers = headers.decode("utf-8")
    splitHeaders = headers.split("\r\n")

    val = ""
    for header in splitHeaders:
        if headerValue in header:
            val = header[len(headerValue) + 1:]
    return val.strip()

def chunkedHttp(data):
    """
        Verifies if all content was captured in case the Transfer-Encoding is set to chunked and decode the contetn in standart format

        Input: 
            http content encoded in chunked format

        Output:
            http content decoded in standard format 
    """

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
    """
        Verifies existance of a http package in global memory of http packages

        Input:
            Headers of a http request
        
        Return:
            True if http request is already present in gloabl memory and False otherwise
    """
    
    global httpPackets

    for a in httpPackets:
        if a[0] == headers and a[1] == content:
            return False
    return True
    
def parseHttp(httpPacket, comunicationIdentifier, filterValues):
    """
        The main function that proces the http package, verifies if all tcp segments have been captured, that these segments have been soreted in right order.
        If during the transfer data was encoded in some format it is ensured that data is decoded. And that a packegs passes user specified filters.

        Input:
            httpPackage
            comunicationIdentifier (source ip, destination ip, source port)
            user given filters
    """
    
    global httpPackets
    global reassembly_strucutre

    try:
        if reassembly_strucutre[comunicationIdentifier][3] == False:
            return

        splitRequest = httpPacket.split(b"\r\n\r\n", 1)

        if b'HTTP/1.1' not in splitRequest[0]:
            return

        length = getHeaderValue(splitRequest[0], 'Content-Length')

        host = getHeaderValue(splitRequest[0], 'Host')

        if len(host) > 0:
            if filterValues[0] not in host:
                reassembly_strucutre[comunicationIdentifier][3] = False
                return
    
        headers = splitRequest[0].decode("utf-8")
        firstSplit = headers.split(" ", 1)

        if firstSplit[0] in filterValues[1]:
            reassembly_strucutre[comunicationIdentifier][3] = False
            return

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
            if verifyExistance(headers, "") == True:
                httpPackets.append((headers, ""))
                event.set()
            return

        str1 = ''.join(random.choices(string.ascii_lowercase, k=15))
        str1 = 'files/' + str1


        contentEncoding =   getHeaderValue(splitRequest[0], "Content-Encoding")

        if contentEncoding == 'gzip':
            splitEncoded = splitRequest[1].split(b"\r\n")
            maxLenString = max(splitEncoded, key = lambda i: len(i))

            content = gzip.decompress(maxLenString)

            httpPackets.append((headers, str1))
            f = open(str1, "wb")
            f.write(content)
            event.set()
            f.close()
            #del reassembly_strucutre[comunicationIdentifier]
        else:
            f = open(str1, "wb")
            httpPackets.append((headers, str1))
            f.write(splitRequest[1])
            if event.is_set() == False:
                event.set()
            f.close()
            #del reassembly_strucutre[comunicationIdentifier]
    except Exception as e:
        print(str(e))

def constructPacket(data, comunicationIdentifier, filterValues):
    """
        Create http package by reassembly all catched tcp segments and verifies there are any segements losses

        Input:
            httpPackage
            comunicationIdentifier (source ip, destination ip, source port)
            user given filters
    """
    
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

        parseHttp(payload, comunicationIdentifier, filterValues)
    except Exception as e:
        print(str(e))

def assembly_http(ip_src, ip_dest, port_src, port_dest, seq_number, filterValues, data):
    """
        Manages a global structure in a form of python dictionary with a keys as comunication identifiers, that stores the the tcp segments
        Comunication identifier is a string that contained both ip addresses and ports.

        Input:
            Source Ip Address
            Destionation Ip Address
            Source Port
            Destination Port
            Sequence Number
            User Filters 
            Data from Tcp Segments
    """

    if port_src == 80:
        comunicationIdentifier = ip_dest + ":" + ip_src + ":" + str(port_dest)
    else:
        comunicationIdentifier = ip_src + ":" + ip_dest + ":" + str(port_src)
    try:
        if len(data) != 0:
            if comunicationIdentifier not in reassembly_strucutre:
                new_set = set()
                new_set.add(seq_number)

                new_sorted_dic = SortedDict()
                new_sorted_dic.setdefault(seq_number, data)
                reassembly_strucutre[comunicationIdentifier] = [new_sorted_dic, port_src, new_set, True]
            else:
                if port_src != reassembly_strucutre[comunicationIdentifier][1]:
                    if port_src == 80 and reassembly_strucutre[comunicationIdentifier][3] == False:
                        return

                    new_set = set()
                    new_set.add(seq_number)
                    new_sorted_dic = SortedDict()
                    new_sorted_dic.setdefault(seq_number, data)
                    reassembly_strucutre[comunicationIdentifier] = [new_sorted_dic, port_src, new_set, True]
                else:
                    new_set = reassembly_strucutre[comunicationIdentifier][2]
                    sorted_dic = reassembly_strucutre[comunicationIdentifier][0]
                    
                    isResend = False
                    
                    if seq_number in new_set:
                        isResend = True

                    if isResend == False:
                        new_set.add(seq_number)
                        sorted_dic.setdefault(seq_number, data)
                        reassembly_strucutre[comunicationIdentifier] = [sorted_dic, port_src, new_set, True]
                        
            constructPacket(reassembly_strucutre[comunicationIdentifier][0], comunicationIdentifier, filterValues)
    except Exception as e:
        print(str(e))

#!/usr/bin/python

import json
import os
import re
import select
import socket
import struct
import sys
import time
import urllib2

# Load config
try:
    with open(sys.argv[1], 'r') as config_file:
        config = json.loads(config_file.read())
except:
    try:
        with open('latency_check.json', 'r') as config_file:
            config = json.loads(config_file.read())
    except Exception as e:
        print('load_config | ERROR | ' + str(e))
        sys.exit(1)

"""Start plagiarisation from https://github.com/samuel/python-ping"""

if sys.platform == "win32":
    # On Windows, the best timer is time.clock()
    default_timer = time.clock
else:
    # On most other platforms the best timer is time.time()
    default_timer = time.time

# From /usr/include/linux/icmp.h; your milage may vary.
ICMP_ECHO_REQUEST = 8 # Seems to be the same on Solaris.


def checksum(source_string):
    """
    I'm not too confident that this is right but testing seems
    to suggest that it gives the same answers as in_cksum in ping.c
    """
    sum = 0
    countTo = (len(source_string)/2)*2
    count = 0
    while count<countTo:
        thisVal = ord(source_string[count + 1])*256 + ord(source_string[count])
        sum = sum + thisVal
        sum = sum & 0xffffffff # Necessary?
        count = count + 2

    if countTo<len(source_string):
        sum = sum + ord(source_string[len(source_string) - 1])
        sum = sum & 0xffffffff # Necessary?

    sum = (sum >> 16)  +  (sum & 0xffff)
    sum = sum + (sum >> 16)
    answer = ~sum
    answer = answer & 0xffff

    # Swap bytes. Bugger me if I know why.
    answer = answer >> 8 | (answer << 8 & 0xff00)

    return answer


def receive_one_ping(my_socket, ID, timeout):
    """
    receive the ping from the socket.
    """
    timeLeft = timeout
    while True:
        startedSelect = default_timer()
        whatReady = select.select([my_socket], [], [], timeLeft)
        howLongInSelect = (default_timer() - startedSelect)
        if whatReady[0] == []: # Timeout
            return

        timeReceived = default_timer()
        recPacket, addr = my_socket.recvfrom(1024)
        icmpHeader = recPacket[20:28]
        type, code, checksum, packetID, sequence = struct.unpack(
            "bbHHh", icmpHeader
        )
        # Filters out the echo request itself. 
        # This can be tested by pinging 127.0.0.1 
        # You'll see your own request
        if type != 8 and packetID == ID:
            bytesInDouble = struct.calcsize("d")
            timeSent = struct.unpack("d", recPacket[28:28 + bytesInDouble])[0]
            return timeReceived - timeSent

        timeLeft = timeLeft - howLongInSelect
        if timeLeft <= 0:
            return


def send_one_ping(my_socket, dest_addr, ID):
    """
    Send one ping to the given >dest_addr<.
    """
    dest_addr  =  socket.gethostbyname(dest_addr)

    # Header is type (8), code (8), checksum (16), id (16), sequence (16)
    my_checksum = 0

    # Make a dummy heder with a 0 checksum.
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, my_checksum, ID, 1)
    bytesInDouble = struct.calcsize("d")
    data = (192 - bytesInDouble) * "Q"
    data = struct.pack("d", default_timer()) + data

    # Calculate the checksum on the data and the dummy header.
    my_checksum = checksum(header + data)

    # Now that we have the right checksum, we put that in. It's just easier
    # to make up a new header than to stuff it into the dummy.
    header = struct.pack(
        "bbHHh", ICMP_ECHO_REQUEST, 0, socket.htons(my_checksum), ID, 1
    )
    packet = header + data
    my_socket.sendto(packet, (dest_addr, 1)) # Don't know about the 1


def do_one(dest_addr, timeout):
    """
    Returns either the delay (in seconds) or none on timeout.
    """
    icmp = socket.getprotobyname("icmp")
    try:
        my_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)
    except socket.error, (errno, msg):
        if errno == 1:
            # Operation not permitted
            msg = msg + (
                " - Note that ICMP messages can only be sent from processes"
                " running as root."
            )
            raise socket.error(msg)
        raise # raise the original error

    my_ID = os.getpid() & 0xFFFF

    send_one_ping(my_socket, dest_addr, my_ID)
    delay = receive_one_ping(my_socket, my_ID, timeout)

    my_socket.close()
    return delay


"""End plagiarisation from https://github.com/samuel/python-ping"""


def http_latency(host, timeout=config["timeout"]):
    """
    Connect HTTP client to host and return latency.

    :param host: hostname string
    :param timeout: timeout in seconds as float
    :return: latency in seconds as float
    """
    # print('http_latency | DEBUG | Opening connection to: ' + host)
    try:
        start = time.time()
        conn = urllib2.urlopen(url=host, timeout=timeout)
        conn.read(0)
        conn.close()
        end = time.time()
        return end - start
    except Exception as e:
        print('http_latency | ERROR | url=' + host + ' | ' + str(e))


def average_latency(proto, host, checks=config["check_count"], timeout=config["timeout"]):
    """
    Return average latency of checks to host for given protocol.
    Errors will break the loop and an average will be calculated of whatever data we have.
    If that doesn't work, it will return '-1'.

    :param proto: protocol string
    :param host: hostname string
    :param checks: number of checks to average as int
    :param timeout: connection timeout in seconds as float
    :return: average latency in seconds as float
    """
    latencies = []
    for check in range(0, checks):
        if proto == "icmp":
            try:
                result = do_one(host, timeout)
            except Exception as e:
                print('icmp_latency | ERROR | host=' + host + ' | ' + str(e))
                return float('-1')
            # print(' | '.join(['icmp_latency', 'DEBUG', host, str(timeout), str(result)]))
            if result:
                latencies.append(result)
            else:
                break
        elif proto == "http":
            result = http_latency(host, timeout)
            # print(' | '.join(['http_latency', 'DEBUG', host, str(timeout), str(result)]))
            if result:
                latencies.append(result)
            else:
                break
        else:
            print('average_latency | ERROR | Unknown protocol: ' + proto)
            return
    try:
        avg_latency = sum(latencies) / float(len(latencies))
    except:
        avg_latency = float('-1')
    # print(' | '.join(['average_latency', 'DEBUG', host, str(latencies), str(avg_latency)]))
    return avg_latency


def send_graphite(
            host,
            proto,
            latency,
            graphite_host=config["graphite_host"],
            graphite_port=config["graphite_port"],
            graphite_prefix=config["graphite_prefix"]
        ):
    """
    Send a latency value to Graphite.

    :param host: hostname as string
    :param proto: protocol as string
    :param latency: latency in seconds as float
    :param graphite_host: graphite hostname as string
    :param graphite_port: graphite port as int
    :param graphite_prefix: graphite prefix as string
    :return:
    """
    try:
        # Line format:
        # prefix.local_host.remote_host.protocol latency_in_milliseconds timestamp
        # The regex here extracts the hostname from URLs and translates non-alphanumeric characters to underscores
        if 'http' in host:
            rhost = re.findall(r'(?<=//)[\w.:\-]+', host)[0]
        else:
            rhost = host
        clean_rhost = re.sub(r'[^\w]', '_', rhost)
        clean_lhost = re.sub(r'[^\w]', '_', socket.getfqdn())
        if latency == float('-1'):
            # Keep '-1' error values
            clean_latency = str(latency)
        else:
            # Convert float of seconds to int of milliseconds
            clean_latency = str(int(latency * 1000))
        graphite_line = ' '.join([
            '.'.join([
                graphite_prefix,
                clean_lhost,
                clean_rhost,
                proto
            ]),
            clean_latency,
            str(int(time.time()))
        ])
        print('send_graphite | DEBUG | line: ' + graphite_line)
        graphite_connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        graphite_connection.connect((graphite_host, graphite_port))
        graphite_connection.sendall(graphite_line)
    except Exception as e:
        print('send_graphite | ERROR | ' + str(e))


# Do the things
for i in config['to_check']:
    for proto, host in i.iteritems():
        if proto == 'http':
            send_graphite(host, 'http', average_latency('http', host))
            send_graphite(host, 'icmp', average_latency('icmp', re.findall(r'(?<=//)[\w.\-]+', host)[0]))
        else:
            send_graphite(host, proto, average_latency(proto, host))

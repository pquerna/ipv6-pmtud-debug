#!/usr/bin/env python

# Copyright 2013 Paul Querna
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#


import os
import sys
import socket
import time

p = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'third_party', 'dpkt')
if p not in sys.path:
    sys.path.insert(0, p)

import dpkt

def resolve_with_dns(target):
    addrinfo = socket.getaddrinfo(target, None, socket.AF_INET6)

    if not addrinfo:
        raise RuntimeError('Unable to resolve: '+ target)

    return addrinfo[0][4][0]

def resolve_target(target):
    try:
        socket.inet_pton(socket.AF_INET6, target)
    except socket.error:
        target = resolve_with_dns(target)
    return target

def send_packet(target, pkt):
    s = socket.socket(socket.AF_INET6, socket.SOCK_RAW, dpkt.ip.IP_PROTO_ICMP6)
    s.connect((target, 1))
    s.send(str(pkt))

def send_packets(target):
    while True:
        pkt = dpkt.icmp6.ICMP6.TooBig()
        send_packet(target, pkt)
        time.sleep(1)

def main(argv):
    if len(argv) != 2:
        print "Tool to send IPv6 ICMP Packet too large"
        print ""
        print "Usage: send.py <address>"
        print ""
        sys.exit(1)

    target = argv[1]

    target = resolve_target(target)
    send_packets(target)

if __name__ == "__main__":
    main(sys.argv)

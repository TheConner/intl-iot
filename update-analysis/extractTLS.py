#!/usr/bin/env python3

#
# Extractor that is used for dumping PCAP file contents fotr the intl-iot dataset
# this tool dumps HTTP data only using tshark
# @author Conner Bradley
#

import os
import argparse
import pathlib
import uuid
import pickle
import subprocess
from joblib import Parallel, delayed
import socket
import pyshark

FILE = "../IOT-dataset/all-iot-data/iot-data/us/fridge/power/2019-04-25_18:57:02.171s.pcap"

def extract_tls_traffic(packet_file):
    def extract_packets_by_filter(packet_file, filter):
        collected_packets = []
        packets = pyshark.FileCapture(packet_file, display_filter=filter, use_json=True, custom_parameters=["-Y", "ssl.handshake.ciphersuites"])
        for pkt in packets:
            try:
                ip = pkt.ip.__dict__['_all_fields']
                ssl = pkt['SSL'].__dict__['_all_fields']
                ssl_handshake = ssl['ssl.record']['ssl.handshake']
                
                collected_packets.append({
                    "SSL": {
                        'ssl.handshake.version': ssl_handshake['ssl.handshake.version'],
                        'ssl.handshake.type': ssl_handshake['ssl.handshake.type'],
                        'ssl.handshake.ciphersuites': ssl_handshake['ssl.handshake.ciphersuites']['ssl.handshake.ciphersuite']
                    },
                    "IP": {
                        'ip.src': ip['ip.src']
                    }
                })
            except KeyError as e:
                #print("No SSL layer")
                print(e)
        
        packets.close()
        return collected_packets

    #server_hello_packets = extract_packets_by_filter(FILE, "ssl.handshake.type == 2")
    client_hello_packets = extract_packets_by_filter(FILE, "ssl.handshake.type == 1")

    return {
        #"server_hello_packets": server_hello_packets,
        "client_hello_packets": client_hello_packets
    }

print(extract_tls_traffic(FILE))
#!/usr/bin/env python3

import struct
import math
import dpkt
import socket
from collections import Counter
from frequency import *
import numpy

def substitute(attack_payload, substitution_table):
    # Using the substitution table you generated to encrypt attack payload
    # Note that you also need to generate a xor_table which will be used to decrypt
    # the attack_payload
    # i.e. (encrypted attack payload) XOR (xor_table) = (original attack payload)
    b_attack_payload = bytearray(attack_payload, "utf8")
    result = []
    xor_table = []
    # Based on your implementattion of substitution table, please prepare result
    # and xor_table as output
    
    for b in b_attack_payload:
        canbe = substitution_table[chr(b)]
        # if substitution is one-to-one
        if len(canbe)==1:
            print(canbe)
            result.append(canbe[0][0])
            xor_table.append(chr(ord(canbe[0][0])^b))
        # if subtitution is one-to-many
        else:
            canbe_list = [a[0] for a in canbe]
            prob = [a[1] for a in canbe]
            prob_sum = sum(prob)
            # randomly choose the cipher according to probabilities
            cipher = numpy.random.choice(canbe_list, 1, p=[pr/prob_sum for pr in prob])[0]
            result.append(cipher)
            xor_table.append(chr(ord(cipher)^b))
    print("xor_table:" +str(xor_table))
    print("result :" +str(result))
    return (xor_table, result)

def getSubstitutionTable(artificial_payload, attack_payload):
    # You will need to generate a substitution table which can be used to encrypt the attack
    # body by replacing the most frequent byte in attack body by the most frequent byte in
    # artificial profile one by one

    # Note that the frequency for each byte is provided below in dictionay format.
    # Please check frequency.py for more details
    artificial_frequency = frequency(artificial_payload)
    attack_frequency = frequency(attack_payload)

    sorted_artificial_frequency = sorting(artificial_frequency)
    sorted_attack_frequency = sorting(attack_frequency)

    # Your code here ...

    substitution_table = dict()
    
    # For the first m characters, map them one-to-one.
    for i in range(len(sorted_attack_frequency)):
        substitution_table[sorted_attack_frequency[i][0]] = [sorted_artificial_frequency[i]]
    
    # For the (m+1)th character and so on...
    rest = sorted_artificial_frequency[len(sorted_attack_frequency):]
    
    for i, item in enumerate(rest):
        relative_frequency = dict()
        for _item in sorted_attack_frequency:
            targets = substitution_table[_item[0]]
            freq_sum = 0
            # To calculate tf(yj)
            for x in targets :
                freq_sum +=x[1]
            print(freq_sum)

            # To calculate each delta value
            relative_frequency[_item[0]] = _item[1] / freq_sum

        # To get the character whose frequency is the maximum
        target = max(relative_frequency, key=relative_frequency.get)
        substitution_table[target].append(item)

    # Make sure your substitution table can be used in
    # substitute(attack_payload, subsitution_table)
    print(substitution_table)
    with open('substitution_table.txt', 'w') as f:
        f.write(str(substitution_table))
    return substitution_table


def getAttackBodyPayload(path):
    f = open(path, 'rb')
    pcap = dpkt.pcap.Reader(f)
    for ts, buf in pcap:
        eth = dpkt.ethernet.Ethernet(buf)
        ip = eth.data
        if socket.inet_ntoa(ip.dst) == "192.150.11.111": 
            tcp = ip.data
            if tcp.data == "":
                continue
            return tcp.data.rstrip()

def getArtificialPayload(path):
    f = open(path, 'rb')
    pcap = dpkt.pcap.Reader(f)
    for ts, buf in pcap:
        eth = dpkt.ethernet.Ethernet(buf)
        ip = eth.data
        tcp = ip.data
        if tcp.sport == 80 and len(tcp.data) > 0:
            return tcp.data

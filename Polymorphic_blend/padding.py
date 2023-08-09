#!/usr/bin/env python3

import struct
import math
import random
from frequency import *
from collections import Counter

def padding(artificial_payload, raw_payload):
    padding = ""
    
    # Get frequency of raw_payload and artificial profile payload
    artificial_frequency = frequency(artificial_payload)
    raw_payload_frequency = frequency(raw_payload)

    # To simplify padding, you only need to find the maximum frequency difference for each
    # byte in raw_payload and artificial_payload, and pad that byte at the end of the
    # raw_payload. 
    # Note: only consider the differences when artificial profile has higher frequency.


    # Depending upon the difference, call raw_payload.append
    max = 0

    for k, v in raw_payload_frequency.items():
        # If there is the same character in artificial payload
        if k in artificial_frequency.keys():
            art_v = artificial_frequency[k]
            diff = art_v - v
            # To get a character which has the maximum different frequency 
            if diff > max:
                max = diff
                max_cipher = k
    raw_payload.append(k)
    # Your code here....

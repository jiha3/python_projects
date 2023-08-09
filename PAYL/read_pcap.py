import dpkt, dpkt.dns
import sys
import ast

def hexify(x):
    #In case the strings from DNS resolver contain non-ASCII characters"
    toHex = lambda x:"".join([hex(ord(c))[2:].zfill(2) for c in x])
    return toHex(x)

def concatBytesToStr(bytes_str):
    return "".join(map(chr, bytes_str))

def decode_dns_response ( rr, response_type) :
    #source: https://github.com/jeffsilverm/dpkt_doc/blob/master/decode_dns.py 
    r_type = rr.type
    r_data = rr.rdata
    
    #print(repr(r_data))
    type_table = {1:"A",        # IP v4 address, RFC 1035
                  2:"NS",       # Authoritative name server, RFC 1035
                  5:"CNAME",    # Canonical name for an alias, RFC 1035
                  6:"SOA",      # Marks the start of a zone of authority, RFC 1035
                  12:"PTR",     # Domain name pointer, RFC 1035
                  13:"HINFO",   # Host information, RFC 1035
                  15:"MX",      # Mail exchange, RFC 1035
                  28:"AAAA",    # IP v6 address, RFC 3596
                  16:"TXT",     # 
                  33:"SRV",     # RFC 2782
                  255:"ANY",    # all cached reco
    }

    rr_string = ""
    if sys.version_info[0] >= 3:
        try:
            r_data.decode('utf-8')
        except UnicodeDecodeError:
            # print('This string contains more than just the ASCII characters.')
            return "\\" + type_table[r_type] + "\\" + concatBytesToStr(r_data)
    else:
        try:
            r_data.encode('utf-8')
        except UnicodeDecodeError: # Decoding error for checking ASCII
            # print('This string contains more than just the ASCII characters.')
            return "\\" + type_table[r_type] + "\\" + r_data
        
    if r_type == dpkt.dns.DNS_CNAME :
        #print("Response is a CNAME ", rr.cname)
        rr_string = rr.cname
        
    elif r_type == dpkt.dns.DNS_A :
        #print("response is an IPv4 address", socket.inet_ntoa( r_data ))
        rr_string = socket.inet_ntoa( r_data )
        #print("DNS_A", rr_string)
        
    elif r_type == dpkt.dns.DNS_NS :
        #print("Response is a NS name", rr.nsname)
        rr_string = rr.nsname
        
    elif r_type == dpkt.dns.DNS_AAAA :
        #print("response is an IPv6 address", socket.inet_ntop( socket.AF_INET6, r_data ))
        rr_string = socket.inet_ntop( socket.AF_INET6, r_data )
        #print("DNS_AAA:", rr_string)
        
    elif r_type == dpkt.dns.DNS_PTR :
        #print("response is a hostname from an IP address", rr.ptrname)
        rr_string = rr.ptrname

    elif r_type == dpkt.dns.DNS_SOA :
        #print('DNS_SOA:',rr.mname,rr.rname,rr.serial,rr.refresh,rr.retry,rr.expire, rr.minimum)
        rr_string = rr.mname + "," + rr.rname + "," + rr.serial + "," + rr.refresh + "," + rr.retry + "," + rr.expire + "," + rr.minimum
        
    elif r_type == dpkt.dns.DNS_MX :
        #print('DNS_MX:',rr.mxname,rr.preference)
        rr_string = rr.mxname + "," + rr.preference
        
    elif r_type == dpkt.dns.DNS_HINFO :
        #print('DNS_HINFO:',rr.text)
        rr_string = rr.rtext
        
    elif r_type == dpkt.dns.DNS_TXT :
        #print("TEXT:",rr.text)
        rr_string = rr.rtext
        
    elif r_type == dpkt.dns.DNS_SRV :
        #print('DNS_SRV:',rr.srvname,rr.port,rr.priority,rr.weight)
        rr_string = rr.srvname + "," + rr.port + "," + rr.priority + "," + rr.weight
        
    else :
        #print("Unknown")
        rr_string = "Unknown"

    #return "r_type" + ":" + type_table[r_type] + ":" + rr_string
    return "\\" + type_table[r_type] + "\\" + rr_string

        
def readPcap(fileName, mode):
    type_table = {1:"A",        # IP v4 address, RFC 1035
                  2:"NS",       # Authoritative name server, RFC 1035
                  5:"CNAME",    # Canonical name for an alias, RFC 1035
                  6:"SOA",      # Marks the start of a zone of authority, RFC 1035
                 12:"PTR",      # Domain name pointer, RFC 1035
                 13:"HINFO",    # Host information, RFC 1035
                 15:"MX",       # Mail exchange, RFC 1035
                 28:"AAAA",     # IP v6 address, RFC 3596
                 16:"TXT",      # 
                  33:"SRV",     # RFC 2782
                 255:"ANY",     # all cached reco
                 }

    payload_list = []
    f = open(fileName,"rb")
    pcap = dpkt.pcap.Reader(f)
    total = 0
    
    for ts, buf in pcap:
        try:
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data
            proto_data = ip.data
                
            if proto_data.sport == 53:
                dns_payload = dpkt.dns.DNS(proto_data.data)
                dns_payload_string = ""
                
                for rr in dns_payload.an:
                    rr_string = decode_dns_response ( rr, "AN" )
                    if rr_string == "Unknown":
                        print("DNS data unknown")
                        continue 
                    if dns_payload_string == "":
                        dns_payload_string = rr_string
                    else:
                        dns_payload_string = dns_payload_string + "," + str(rr_string)

                for rr in dns_payload.ns:
                    rr_string = decode_dns_response ( rr, "NS" )
                    if rr_string == "Unknown":
                        continue 
                    if dns_payload_string == "":
                        dns_payload_string = rr_string
                    else:
                        dns_payload_string = dns_payload_string + "," + str(rr_string)

                for rr in dns_payload.ar:
                    rr_string = decode_dns_response ( rr, "AR" )
                    if rr_string == "Unknown":
                        continue 
                    if dns_payload_string == "":
                        dns_payload_string = rr_string
                    else:
                        dns_payload_string = dns_payload_string + "," + str(rr_string)

                # #print("Payload string response:")
                # #print(dns_payload_string)
                
                if dns_payload_string != "":
                    dns_payload_string = str(dns_payload.id) + "\\" + str(dns_payload.qr) + "\\" + str(dns_payload.opcode) + "\\" + str(dns_payload.rcode) + "\\" +  str(len(dns_payload.an)) + "\\" + str(len(dns_payload.ns)) + "\\" + str(len(dns_payload.ar)) + "\\" + dns_payload_string

                    payload_list.append(str(dns_payload_string))
                    total = total + 1
       
                    #if mode == "testing":
                    #    print("\n\n\n= = = = = = = = = = = = = = = = =")
                    #    print("My testing payload has length: " + str(len(dns_payload_string)))
                    #    print(dns_payload_string)
                    #    print("\n")
                
            elif (proto_data.dport == 53):
                dns_payload = dpkt.dns.DNS(proto_data.data)
                #print(dns_payload)
                dns_payload_string = ""
                dns_payload_string = str(dns_payload.id) + "\\" + str(dns_payload.qr) + "\\" + str(dns_payload.opcode) + "\\" + str(dns_payload.rcode)  +  "\\" + str(len(dns_payload.an)) + "\\" + str(len(dns_payload.ns)) + "\\" + str(len(dns_payload.ar)) + "\\" + dns_payload.qd[0].name + "\\" + str(dns_payload.qd[0].type) + "\\" + type_table[dns_payload.qd[0].type]
                    
                if dns_payload_string != "":
                    payload_list.append(str(dns_payload_string))
                    #print(dns_payload_string)
                    total = total + 1
                    
                #if mode == "testing":
                #    print("\n\n\n= = = = = = = = = = = = = = = = =")
                #    print("My testing payload has length: " + str(len(dns_payload_string)) + ":")
                #    print(dns_payload_string)
                #    print("\n")

            elif (proto_data.sport == 1924 and proto_data.dport == 1957):
                dns_payload_string = proto_data.data
                if sys.version_info[0] >= 3:
                    dns_payload_string = concatBytesToStr(dns_payload_string)
                payload_list.append(str(dns_payload_string))
                total = total + 1 
    
            elif (proto_data.sport == 80 or proto_data.dport == 80):
                payload = proto_data.data
                if sys.version_info[0] >= 3:
                    payload = concatBytesToStr(payload)
                payload_list.append(str(payload))
                total = total + 1

                #if mode == "testing":
                #    print("\n\n\n= = = = = = = = = = = = = = = = =")
                #    print("My testing payload has length: " + str(len(payload)) + ":")
                #    print(payload)
                #    print("\n")

            elif (mode == "testing"):
                payload = payload_str
                if sys.version_info[0] >= 3:
                    payload = concatBytesToStr(payload)
                payload_list.append(str(payload))
                total = total + 1
                # print("\n\n\n= = = = = = = = = = = = = = = = =")
                # print("My testing payload has length: " + str(len(payload)) + ":")
                # print(payload)
                # print("\n")

        except :
            continue
    # print("Total payloads read:" + str(fileName) + ":" + str(total) + "\n")
    return payload_list

def getPayloadStrings(training_protocol):
    payload_list = []
    #DNS
    if training_protocol == "DNS":
        list1_dns = readPcap('data/dns.pcap', "training")
        payload_list.extend(list1_dns)

    #HTTP
    elif training_protocol == "HTTP":
        list1 = readPcap('data/HTTPtext_V1.pcap', "training")
        list2 = readPcap('data/HTTPtext_V2.pcap', "training")    
        list3 = readPcap('data/modified_new3_simple_http.pcap', "training")
        list4 = readPcap('data/modified_new4_simple_http.pcap', "training")
        list5 = readPcap('data/modified_new5_simple_http.pcap', "training")
        list6 = readPcap('data/modified_new6_simple_http.pcap', "training")
        list7 = readPcap('data/modified_new_simple_http.pcap', "training")

        payload_list.extend(list1)
        payload_list.extend(list2)
        payload_list.extend(list3)
        payload_list.extend(list4)
        payload_list.extend(list5)
        payload_list.extend(list6)
        payload_list.extend(list7)
    return payload_list


def read_attack_data(filename):
#This function reads the output of the polymorphic blend code (the file does not end in pcap)
    listl = open(filename, 'rb')
    listl1 = listl.read().decode("utf8")
    #print(listl1)
    return [listl1]

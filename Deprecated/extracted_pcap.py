# coding:utf-8
import os
import sys
import struct
from scapy.all import *
import binascii
import pdb

import flow_class


def get_pcap_content(pcap_path):

    fpcap = open(pcap_path, 'rb')
    string_data = fpcap.read()
    fpcap.close()
    pcap_header = {'magic_number': string_data[0:4],
                   'version_major': string_data[4:6],
                   'version_minor': string_data[6:8],
                   'thiszone': string_data[8:12],
                   'sigfigs': string_data[12:16],
                   'snaplen': string_data[16:20],
                   'linktype': string_data[20:24]}

    packet_num = 0
    packet_data = []
    pcap_packet_header = {}
    inf = {}
    count = 1
    i = 24
    while (i < len(string_data)):
        packet_num += 1
        package_information = {}
        pcap_packet_header['GMTtime'] = string_data[i:i + 4]
        pcap_packet_header['MicroTime'] = string_data[i + 4:i + 8]
        pcap_packet_header['caplen'] = string_data[i + 8:i + 12]
        pcap_packet_header['len'] = string_data[i + 12:i + 16]
        if len(string_data[i + 12:i + 16]) != 4:
            break
        packet_len = struct.unpack('I', pcap_packet_header['len'])[0]

        package_information['time'] = struct.unpack("l", pcap_packet_header['GMTtime'])[0]
        # print(package_information['time'])

        packet_data.append(string_data[i:i + 16 + packet_len])
        '''
        判断IP地址类型
        '''
        if hex(ord(string_data[i + 28:i + 29])) == '0x8':  ###IPv4协议类型
            pass
        else:
            i = i + packet_len + 16
            continue
        '''
        获取IP包头长度
        '''
        package_information['ipHeader_len'] = int(hex(ord(string_data[i + 30:i + 31]))[-1], 16) * 4
        if hex(ord(string_data[i + 39:i + 40])) == '0x6':
            package_information['proto'] = 'tcp'
            package_information['ip_src'] = str(int(hex(ord(string_data[i + 42:i + 43])), 16))
            for index in range(1, 4):
                package_information['ip_src'] += '.'
                package_information['ip_src'] += str(int(hex(ord(string_data[i + 42 + index:i + 43 + index])), 16))
            package_information['ip_dst'] = str(int(hex(ord(string_data[i + 46:i + 47])), 16))
            for index in range(1, 4):
                package_information['ip_dst'] += '.'
                package_information['ip_dst'] += str(int(hex(ord(string_data[i + 46 + index:i + 47 + index])), 16))
            package_information['tcpHeader_len'] = int(hex(ord(string_data[i + 30 + package_information[
                'ipHeader_len'] + 12:i + 30 + package_information['ipHeader_len'] + 13]))[0], 16) * 4
            flags_value = binascii.b2a_hex(string_data[
                                           i + 30 + package_information['ipHeader_len'] + 13:i + 30 +package_information['ipHeader_len'] + 14])
            flag = ""
            if flags_value[0] == '8':
                flag = 'C'
            elif flags_value[0] == '4':
                flag = 'E'
            elif flags_value[0] == '2':
                flag = 'U'
            elif flags_value[0] == '1':
                flag = 'A'
            elif flags_value[0] == '0':
                pass
            if flags_value[1] == '8':
                flag += 'P'
            elif flags_value[1] == '4':
                flag += 'R'
            elif flags_value[1] == '2':
                flag += 'S'
            elif flags_value[1] == '1':
                flag += 'F'
            # print flag
            package_information['tcp_flags'] = flag
            ack_data = string_data[
                       i + 30 + package_information['ipHeader_len'] + 8:i + 30 + package_information[
                           'ipHeader_len'] + 12]
            seq_data = string_data[
                       i + 30 + package_information['ipHeader_len'] + 4:i + 30 + package_information[
                           'ipHeader_len'] + 8]
            sport_data = string_data[
                         i + 30 + package_information['ipHeader_len'] + 0:i + 30 + package_information[
                             'ipHeader_len'] + 2]
            dport_data = string_data[
                         i + 30 + package_information['ipHeader_len'] + 2:i + 30 + package_information[
                             'ipHeader_len'] + 4]
            package_information['tcp_ack'] = str(struct.unpack("!L", ack_data)[0])
            # print package_information['tcp_ack']
            package_information['tcp_seq'] = str(struct.unpack("!L", seq_data)[0])
            # print package_information['tcp_ack']
            package_information['tcp_sport'] = str(struct.unpack("!H", sport_data)[0])
            package_information['tcp_dport'] = str(struct.unpack("!H", dport_data)[0])
            # print package_information['tcp_seq']
            # print package_information['tcp_ack']
            package_information['ip_len'] = len(
                string_data[i + 30 + package_information['ipHeader_len'] + package_information[
                    'tcpHeader_len']:i + packet_len + 16])
            i = i + packet_len + 16
            hash_ipsrc = hash(package_information['ip_src'])
            hash_ipdst = hash(package_information['ip_dst'])
            hash_sport = hash(package_information['tcp_sport'])
            hash_dport = hash(package_information['tcp_dport'])
            hash_pkg = hash_ipsrc + hash_ipdst + hash_dport + hash_sport
            # print "hash",hash_pkg
            # dict{hash:list[list[pkg]]}
            if inf.has_key(hash_pkg) == False:
                if package_information['tcp_flags'] == 'S' and long(package_information['tcp_ack']) == 0:
                    # print "one flow begin"
                    new_flows = []
                    new_flows.append([])
                    new_flows[0].append(package_information)
                    inf[hash_pkg] = new_flows
            else:
                flows = inf[hash_pkg]
                flow = flows[-1]
                if len(flow) == 1:
                    last_pkg = flow[-1]
                    if package_information['tcp_flags'] == 'AS' and long(package_information['tcp_ack']) == long(
                            last_pkg['tcp_seq']) + 1:
                        flow.append(package_information)
                elif len(flow) == 2:
                    last_pkg = flow[-1]
                    if package_information['tcp_flags'] == 'A' and long(package_information['tcp_seq']) == long(
                            last_pkg['tcp_ack']):
                        flow.append(package_information)
                elif len(flow) >= 3:
                    last_pkg = flow[-1]
                    last_pkg_time = last_pkg['time']
                    new_pkg_time = package_information['time']
                    if new_pkg_time - last_pkg_time < 1:
                        flow.append(package_information)
                    else:
                        if package_information['tcp_flags'] == 'S' and long(package_information['tcp_ack']) == 0:
                            new_flow = []
                            new_flow.append(package_information)
                            flows.append(new_flow)
        else:
            i = i + packet_len + 16
            continue
    newinf = inf.copy()
    for fs in inf:
        for f in inf[fs]:
            if len(f) <= 3:
                newinf[fs].remove(f)
        if len(inf[fs]) == 0:
            del newinf[fs]

    print "-" * 30
    print len(newinf)
    print "-" * 30
    count = 0
    lenlist = []
    for fs in newinf:
        count += len(newinf[fs])
        for f in newinf[fs]:
            lenlist.append(len(f))
    print lenlist
    print "num of flow", count
    from pandas import DataFrame
    # for fs in inf:
    #     print "num of flow",len(inf[fs])
    #     for f in inf[fs]:
    #         print "length of flow",len(f)
    # for fs in inf:
    #     for f in inf[fs]:
    #         print DataFrame(f)
    # fpcap.close()
    print count
    return inf


if __name__ == '__main__':
    pcap_path = 'D:/test/prediction/telegram_test.pcap'
    get_pcap_content(pcap_path)

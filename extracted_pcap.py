# coding:utf-8
import struct

import binascii

import os


def get_pcap_content(pcap_path):
    if os.path.exists(pcap_path):
        print pcap_path+" exists"
        pass
    else:
        print "no file exists"
        return
    with open(pcap_path, 'rb') as pcapfile:
        pcap_header_length = 24
        pcap_header = pcapfile.read(pcap_header_length)
        while True:
            time_data= pcapfile.read(4)
            # print len(time_string)
            if (len(time_data)) == 4:
                pass
            else:
                break
            package_information = {}
            time = struct.unpack('I', time_data)[0]
            # print time
            package_information['time'] = time
            unuseful_data = pcapfile.read(8)
            len_data=pcapfile.read(4)
            if (len(len_data)) == 4:
                pass
            else:
                break
            packet_len = struct.unpack('I', len_data)[0]
            # print packet_len
            packet_data = pcapfile.read(packet_len)

            if hex(ord(packet_data[28-16:  29-16])) == '0x8':  ###IPv4协议类型
                # print "ipv4"
                pass
            else:
                # print "not ipv4"
                continue
            '''
            获取IP包头长度
            '''
            ipHeader_len = int(hex(ord(packet_data[30-16:  31-16]))[-1], 16) * 4
            if hex(ord(packet_data[39-16:  40-16])) == '0x6':
                package_information['proto'] = 'tcp'
                package_information['ip_src'] = packet_data[42-16:  46-16]
                package_information['ip_dst'] = packet_data[46-16:  50-16]
                tcpHeader_len = int(hex(ord(packet_data[30 + ipHeader_len + 12-16:  30 + ipHeader_len + 13-16]))[0], 16) * 4
                flags_value = binascii.b2a_hex(packet_data[30 + ipHeader_len + 13-16:  30 + ipHeader_len + 14-16])
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
                ack_data = packet_data[
                           30-16 + ipHeader_len + 8:  30 -16+ ipHeader_len + 12]
                seq_data = packet_data[
                           30 -16+ ipHeader_len + 4:  30 -16+ ipHeader_len + 8]
                sport_data = packet_data[
                             30 -16+ ipHeader_len + 0:  30-16 + ipHeader_len + 2]
                dport_data = packet_data[
                             30 -16+ ipHeader_len + 2:  30 -16+ ipHeader_len + 4]
                package_information['tcp_ack'] = struct.unpack("!L", ack_data)[0]
                package_information['tcp_seq'] = struct.unpack("!L", seq_data)[0]
                package_information['tcp_sport'] = sport_data
                package_information['tcp_dport'] = dport_data
                package_information['ip_len'] = (packet_len + 16) - (30 + ipHeader_len + tcpHeader_len)
                # print package_information
                yield (package_information)


if __name__ =="__main__":
    path="D:/telegram/prediction/telegram_test.pcap"
    for pkg in get_pcap_content(path):
        print pkg
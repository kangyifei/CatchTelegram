# coding=utf-8
import copy
from pandas import DataFrame, Series
import pandas as pd


# 用Pandas计算流包长的时间序列的统计值
def calculateStatistics(series):
    return Series(
        [series.max(), series.min(), series.mean(), series.quantile(0.1), series.quantile(0.2), series.quantile(0.3),
         series.quantile(0.4),
         series.quantile(0.5), series.quantile(0.6), series.quantile(0.7), series.quantile(0.8),
         series.quantile(0.9),
         series.mad(), series.var(), series.std(), series.skew(), series.kurt(), len(list(series))])


# 调用calculateStatistics计算流簇中的每个流
def dictToSeriesStatistics(burstCluster):
    seriesStatisticsCluster = []
    for burst in burstCluster:
        df = DataFrame(burst).T
        # print df
        df.len = df.len.astype('int')
        series = df.len
        statistics = calculateStatistics(series)
        # 计算不出值的，比方说一个流中只有一个包，填0/与填平均值效果哪个好？
        statistics.fillna(0, inplace=True)
        seriesStatisticsCluster.append(statistics)
    return seriesStatisticsCluster


# 如果两个包之间间隔超过1S则分开
def burstSepatation(pcapContent):
    time = 0
    burst = []
    pcapTemp = {1: pcapContent[1]}
    for pcap in range(0, len(pcapContent)):
        if time == 0:
            time = pcapContent[pcap]['time']
        else:
            timeTemp = time
            time = pcapContent[pcap]['time']
            if abs(time - timeTemp) <= 1:
                pcapTemp[pcap] = pcapContent[pcap]
            else:
                burst.append(pcapTemp)
                pcapTemp = {pcap: pcapContent[pcap]}
    if pcapTemp:
        burst.append(pcapTemp)
    return burst


# 将流按1s一段分割
def newburstSepatation(pcapContent):
    time = 0
    burst = []
    pcapTemp = {1: pcapContent[1]}
    for pcap in range(0, len(pcapContent)):
        if time == 0:
            time = pcapContent[pcap]['time']
            timeTemp = time
        else:
            time = pcapContent[pcap]['time']
            if abs(time - timeTemp) <= 1:
                pcapTemp[pcap] = pcapContent[pcap]
            else:
                burst.append(pcapTemp)
                pcapTemp = {pcap: pcapContent[pcap]}
                timeTemp = time
    if pcapTemp:
        burst.append(pcapTemp)
    return burst


# 获得TCP会话流簇，writen by caoyu
def get_tcpFellow(dict_tcp):
    count = 0
    list_follow = []
    index_list = dict_tcp.keys()
    try:
        for i in index_list:
            flag = dict_tcp[i]['tcp_flags']
            ack = dict_tcp[i]['tcp_ack']
            if flag == 'S' and ack == '0':
                # print i
                flag = False
                for j in index_list[index_list.index(i) + 1:len(index_list)]:
                    dst = dict_tcp[i]['ip_dst']
                    src = dict_tcp[j]['ip_src']
                    if src == dst:
                        if dict_tcp[j]['ip_dst'] == dict_tcp[i]['ip_src']:
                            pass
                        else:
                            continue
                        if dict_tcp[j]['tcp_flags'] == 'AS' and dict_tcp[j]['tcp_ack'] == str(
                                long(dict_tcp[i]['tcp_seq']) + 1):
                            for k in index_list[index_list.index(j) + 1:len(index_list)]:
                                if dict_tcp[k]['ip_src'] == dict_tcp[i]['ip_src'] and dict_tcp[k]['ip_dst'] == \
                                        dict_tcp[i]['ip_dst']:
                                    if dict_tcp[k]['tcp_flags'] == 'A' and dict_tcp[k]['tcp_seq'] == dict_tcp[j][
                                        'tcp_ack']:
                                        flag = True
                                        address_A = dict_tcp[i]['ip_src']
                                        address_B = dict_tcp[i]['ip_dst']
                                        port_A = dict_tcp[i]['tcp_sport']
                                        port_B = dict_tcp[i]['tcp_dport']
                                        list = []
                                        list.append(i)
                                        list.append(j)
                                        list.append(k)
                                        break
                                    else:
                                        continue
                                else:
                                    continue
                        if flag:
                            break
                if flag:
                    if list != []:
                        # for h in range(list[2]+1,len(dict_tcp)):
                        for h in index_list[index_list.index(k) + 1:len(index_list)]:
                            if dict_tcp[h]['ip_src'] == address_A and dict_tcp[h]['ip_dst'] == address_B:
                                if dict_tcp[h]['tcp_sport'] == port_A and dict_tcp[h]['tcp_dport'] == port_B:
                                    list.append(h)
                            elif dict_tcp[h]['ip_src'] == address_B and dict_tcp[h]['ip_dst'] == address_A:
                                if dict_tcp[h]['tcp_sport'] == port_B and dict_tcp[h]['tcp_dport'] == port_A:
                                    list.append(h)
                        # print list
                        # print len(list)
                        list_follow.append(list)
                        count += 1
                    else:
                        continue
        print("num of tcp stream:" + str(len(list_follow)))
        return list_follow
    except Exception as e:
        print(e)
        return None


def dataFormat(pcapContent):
    # print pcapContent
    tcpFellowList = get_tcpFellow(pcapContent)
    # print tcpFellowList
    # print tcpFellowList
    tcpFellowOfPcapContent = []
    count = 0
    for fellow in tcpFellowList:
        tcpFellowOfPcapContent.append([])
        for j in fellow:
            tcpFellowOfPcapContent[count].append(pcapContent[j])
        count += 1
    # list[dict]
    burstCluster = []
    for fellow in tcpFellowOfPcapContent:
        burst = burstSepatation(fellow)
        burstCluster.extend(burst)
    print ("num of burst:" + str(len(burstCluster)))
    origin_data = copy.deepcopy(burstCluster)
    burstLen=[]
    for burst in burstCluster:
        burstLen.append(len(burst))
        print DataFrame(burst).T
        for b in burst:
            newpack = {
                'len': burst[b]['ip_len'],
            }
            burst[b] = newpack
    print burstLen
    # list[Series]
    seriesStatisticsCluster = dictToSeriesStatistics(burstCluster)
    print "num of sta", len(seriesStatisticsCluster)
    return seriesStatisticsCluster, origin_data

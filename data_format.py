# coding=utf-8
from pandas import Series, DataFrame

from extracted_pcap import get_pcap_content
import flow_class


def dictToSeriesStatistics(burst):
    df = DataFrame(burst).T
    # print df
    df.len = df.len.astype('int')
    series = df.len
    statistics = Series(
        [series.max(), series.min(), series.mean(), series.quantile(0.1), series.quantile(0.2), series.quantile(0.3),
         series.quantile(0.4),
         series.quantile(0.5), series.quantile(0.6), series.quantile(0.7), series.quantile(0.8),
         series.quantile(0.9),
         series.mad(), series.var(), series.std(), series.skew(), series.kurt(), len(list(series))])
    # 计算不出值的，比方说一个流中只有一个包，填0/与填平均值效果哪个好？
    statistics.fillna(0, inplace=True)
    return statistics


def data_format(path, inf):
    print "begin to put pkg into flow"
    for pkg in get_pcap_content(path):
        pkg2flow(pkg, inf)
    print "num of wuyuanzu", len(inf)


def pkg2flow(package_information, inf):
    if package_information is None:
        return
    hash_ipsrc = hash(package_information['ip_src'])
    hash_ipdst = hash(package_information['ip_dst'])
    hash_sport = hash(package_information['tcp_sport'])
    hash_dport = hash(package_information['tcp_dport'])
    hash_pkg = hash_ipsrc + hash_ipdst + hash_dport + hash_sport
    # 结构:
    # dict{hash:list[flow]]}
    if inf.has_key(hash_pkg) == False:
        if package_information['tcp_flags'] == 'S' and long(package_information['tcp_ack']) == 0:
            # print "one flow begin"
            new_flows = []
            new_flow = flow_class.flow()
            new_pkg = {'len': package_information['ip_len']}
            new_flow.addpkg(new_pkg, flow_class.flow.START_1, package_information['tcp_ack']
                            , package_information['tcp_seq'], package_information['time'])
            new_flows.append(new_flow)
            inf[hash_pkg] = new_flows
    else:
        flows = inf[hash_pkg]
        flow = flows[-1]
        if package_information['tcp_flags'] == 'S' and package_information['tcp_ack'] == 0:
            new_flow = flow_class.flow()
            new_pkg = {'len': package_information['ip_len']}
            new_flow.addpkg(new_pkg, flow_class.flow.START_1, package_information['tcp_ack']
                            , package_information['tcp_seq'], package_information['time'])
            flows.append(new_flow)
            inf[hash_pkg]=flows
        if flow.getstate() == flow_class.flow.START_1:
            if package_information['tcp_flags'] == 'AS' and package_information['tcp_ack'] == flow.getseq() + 1:
                new_pkg = {'len': package_information['ip_len']}
                flow.addpkg(new_pkg, flow_class.flow.START_2, package_information['tcp_ack']
                            , package_information['tcp_seq'], package_information['time'])
                inf[hash_pkg] = flows
        elif flow.getstate() == flow_class.flow.START_2:
            if package_information['tcp_flags'] == 'A' and package_information['tcp_seq'] == flow.getack():
                new_pkg = {'len': package_information['ip_len']}
                flow.addpkg(new_pkg, flow_class.flow.NORMAL, package_information['tcp_ack']
                            , package_information['tcp_seq'], package_information['time'])
                inf[hash_pkg] = flows
        elif flow.getstate() == flow_class.flow.NORMAL:
            last_pkg_time = flow.gettime()
            new_pkg_time = package_information['time']
            if new_pkg_time - last_pkg_time < 1:
                new_pkg = {'len': package_information['ip_len']}
                flow.addpkg(new_pkg, flow_class.flow.NORMAL, package_information['tcp_ack']
                            , package_information['tcp_seq'], package_information['time'])
                inf[hash_pkg] = flows
            else:
                flow.state=flow_class.flow.END_4
                if package_information['tcp_flags'] == 'S' and package_information['tcp_ack'] == 0:
                    new_flow = flow_class.flow()
                    new_pkg = {'len': package_information['ip_len']}
                    new_flow.addpkg(new_pkg, flow_class.flow.START_1, package_information['tcp_ack']
                                    , package_information['tcp_seq'], package_information['time'])
                    flows.append(new_flow)
                    inf[hash_pkg] = flows
                else:
                    new_flow = flow_class.flow()
                    new_pkg = {'len': package_information['ip_len']}
                    new_flow.addpkg(new_pkg, flow_class.flow.NORMAL, package_information['tcp_ack']
                                    , package_information['tcp_seq'], package_information['time'])
                    flows.append(flow)
                    inf[hash_pkg] = flows


if __name__ == "__main__":
    path = "D:/telegram/prediction/telegram_test.pcap"
    data_format(path, {})

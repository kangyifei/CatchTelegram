# coding:utf-8
from multiprocessing import Manager, Process, Pool, Queue

import time

from pandas import DataFrame, Series
from scapy.all import *
from sklearn import preprocessing
from sklearn.externals import joblib

import data_format
import flow_class
import get_online_pkg_information
import argparse


# 调用calculateStatistics计算流簇中的每个流
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


def worker_fuction(flow, clf):
    print "worker process: begin"
    pkgs = flow.get_packages()
    if pkgs is None:
        return
    sta = preprocessing.scale(dictToSeriesStatistics(pkgs))
    print "worker process: preprocess finished"
    res = clf.predict(sta)
    if res == 1:
        filename = "telegram_traffic_" + time.strftime('%Y%m%d%H%M', time.localtime(time.time())) + ".txt"
        with open(filename, "a+") as f:
            templist = []
            for pkg in pkgs:
                templist.append(str(pkg))
            f.write(";".join(templist))


def watching_inf_func(inf, pool):
    print "watching inf process:begin"
    # pool = Pool(max_worker)
    # pool.Process.daemon=True
    clf = joblib.load("random_forests_cls.pkl")
    print "watching inf process:init finished"
    while True:
        try:
            print "num of wuyuanzu", len(inf)
            for key, flows in inf.items():
                flows = inf[key]
                try:
                    for flow in flows[:]:
                        if abs(time.mktime(flow.gettime()) - time.mktime(time.localtime())) > 10:
                            pool.apply_async(worker_fuction, (flow, clf))
                            flows.remove(flow)
                        if flow.getstate() == flow_class.flow.END_4:
                            pool.apply_async(worker_fuction, (flow, clf))
                            flows.remove(flow)
                except Exception as e1:
                    print "watching inf process:", str(e1)
                    pass
        except Exception as e:
            print "watching inf process:", str(e)
            time.sleep(3)
            pass
        time.sleep(1)


def sniff_callback_func(pkg):
    # global inf
    # pkg.show()
    data_format.pkg2flow(get_online_pkg_information.get_pkg_information(pkg), inf)
    # print pkg


if __name__ == "__main__":
    print "main process: begin"
    # p=argparse.ArgumentParser("type",type=str,add_help="输入online或者offline")
    # args=p.parse_args()
    network_interface = "Realtek PCIe GBE Family Controller"
    manager = Manager()
    inf = manager.dict()
    max_worker = 4
    print "main process:try to begin watching inf process "
    pool = Pool(max_worker)
    pool.Process.daemon = True
    processing_inf = Process(target=watching_inf_func, args=(inf, pool))
    processing_inf.daemon = True
    processing_inf.start()
    # if args.type=="online":
    print "main process :enter online mode"
    sniff(iface=network_interface, store=0, filter="tcp", prn=sniff_callback_func)
    # elif args.type=="offline":
    #     print "main process :enter offline mode"
    #     path = "D:/telegram/prediction/telegram_test.pcap"
    #     print "main process :begin extracted pcap"
    #     data_format.data_format(path, inf)

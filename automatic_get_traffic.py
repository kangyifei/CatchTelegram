# coding=utf-8
import os
import subprocess

import signal

import time

from automatic_test import start_test

# writen by kyf
udid = 'CVH7N16B02000162'
if __name__ == "__main__":
    # 设定文件名
    filename = "tel_" + time.strftime('%Y%m%d%H%M', time.localtime(time.time())) + ".pcap"
    filepath = "/data/local/tmp/" + filename
    r = os.popen("adb devices")
    res = r.read()
    r.close()
    if res.index(udid) != -1:
        # 获取ROOT权限，不然TCPDUMP不能用
        cmd_root = ['adb', '-s', udid, 'root']
        root_process = subprocess.Popen(cmd_root, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        root_process.communicate()
        # 使用TCPdump获取流量
        cmd_tcpdump = ['adb', '-s', udid, 'shell', 'tcpdump', '-i',
                       'wlan0', '-s', '0', '-w', filepath, 'not', 'host', '10.0.2.2']
        print "".join(cmd_tcpdump)
        tcpdump_process = subprocess.Popen(cmd_tcpdump, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                           stderr=subprocess.PIPE)
        print tcpdump_process.stdout.readline()
        # 测试1000个动作
        start_test(1000)
        # 杀死tcpdump
        try:
            os.kill(tcpdump_process.pid, signal.SIGINT)
        except OSError as ex:
            print ex
        # 获取PCAP文件
        r = os.popen("adb -s " + udid + "pull " + filepath + " " + os.path.abspath('.') + "/telegram ")
        print r.read()

import time


def get_pkg_information(pkg):
    pkg_inf = {}
    try:
        pkg_inf['ip_src']=pkg.payload.src
        pkg_inf['ip_dst'] = pkg.payload.src
        pkg_inf['tcp_sport'] = pkg.payload.payload.sport
        pkg_inf['tcp_dport'] = pkg.payload.payload.dport
        pkg_inf['tcp_flags'] = str(pkg.payload.payload.flags)
        pkg_inf['tcp_ack'] = pkg.payload.payload.ack
        pkg_inf['tcp_seq'] = pkg.payload.payload.seq
        pkg_inf['time'] = time.localtime()
        pkg_inf['ip_len'] = pkg.payload.len
        print pkg_inf['ip_len']
        return pkg_inf
    except Exception as e:
        return None
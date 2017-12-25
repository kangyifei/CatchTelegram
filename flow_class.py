class flow(object):
    START_1 = 1
    START_2 = 2
    NORMAL = 4
    END_1 = 5
    END_2 = 6
    END_3 = 7
    END_4 = 8
    packages = []
    state = 0
    last_time = 0
    last_ack = 0
    last_seq = 0

    def addpkg(self, pkg, state, ack, seq, time):
        self.packages.append(pkg)
        self.state = state
        self.last_time = time
        self.last_ack = ack
        self.last_seq = seq

    def getstate(self):
        return self.state

    def gettime(self):
        return self.last_time

    def getack(self):
        return self.last_ack

    def getseq(self):
        return self.last_seq

    def get_packages(self):
        if (len(self.packages)) < 4:
            return None
        else:
            return self.packages

    def get_pkg_num(self):
        return len(self.packages)

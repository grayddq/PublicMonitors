# -*- coding: utf-8 -*-
import os, json, nmap, re
from Log import *

NAME, VERSION, AUTHOR, LICENSE = "Public Monitor", "V0.1", "咚咚呛", "Public (FREE)"


class PublicScan:
    def __init__(self, file, rate='2000'):
        self.file, self.rate = file, rate
        self.result_info, self.change_del_list, self.change_add_list, self.measscan_result = [], [], [], []
        self.ip_list = []

    def Public_masscan(self):
        if not os.path.exists('tmp'):
            os.mkdir('tmp')
        if os.path.exists('tmp/tempResult'):
            os.remove('tmp/tempResult')
        os.system('masscan -iL %s -p1-65535 --rate=%s -oJ tmp/tempResult' % (self.file, self.rate))

    def readResult(self):
        if os.path.exists('tmp/tempResult'):
            with open('tmp/tempResult') as f:
                for line in f:
                    if line:
                        if not 'finished' in line and len(line) > 5:
                            jsline = json.loads(line.strip("\n").strip(',').strip())
                            if jsline['ports'][0]['status'] == 'open':
                                self.measscan_result.append([jsline['ip'], jsline['ports'][0]['port']])
            return True
        else:
            return False

    def Public_nmap(self, ipinfo=None):
        for ip_port in self.measscan_result if not ipinfo else ipinfo:
            if ipinfo: ip_port = re.split('[:]', ip_port)
            if ip_port[0] in self.ip_list:
                scanner = nmap.PortScanner()
                port = ip_port[1] if isinstance(ip_port[1], int) else int(ip_port[1])
                scanner.scan(hosts=ip_port[0], arguments='-sS -T4 -p %d' % port)
                for targethost in scanner.all_hosts():
                    for proto in scanner[targethost].all_protocols():
                        lport = scanner[targethost][proto].keys()
                        lport.sort()
                        for port in lport:
                            if scanner[targethost][proto][port]['state'] == 'open':
                                temp = {}
                                temp['ip'] = targethost
                                temp['port'] = port
                                temp['server'] = scanner[targethost][proto][port]['name']
                                temp['state'] = 'open'
                                temp['protocol'] = proto
                                temp['product'] = scanner[targethost][proto][port]['product']
                                temp['product_version'] = scanner[targethost][proto][port]['version']
                                temp['product_extrainfo'] = scanner[targethost][proto][port]['extrainfo']
                                temp['reason'] = scanner[targethost][proto][port]['reason']
                                self.result_info.append("%s:%s:%s" % (temp['ip'], temp['port'], temp['server']))

    def diff(self):
        if os.path.exists('out/Result.txt'):
            oldlist = []
            with open('out/Result.txt') as f:
                for line in f:
                    oldlist.append(line.strip())
            old_change_list = list(set(oldlist).difference(set(self.result_info)))
            if old_change_list:
                self.Public_nmap(old_change_list)
                self.change_del_list = list(set(oldlist).difference(set(self.result_info)))
            self.change_add_list = list(set(self.result_info).difference(set(oldlist)))

    def callback(self):
        if not os.path.exists('out'):
            os.mkdir('out')
        fl = open('out/Result.txt', 'w')
        for i in self.result_info:
            fl.write(i)
            fl.write("\n")
        fl.close()

    def checkip(self, ip):
        p = re.compile('^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$')
        if p.match(ip):
            return True
        else:
            return False

    def get_ip_list(self):
        if os.path.exists(self.file):
            with open(self.file) as f:
                for line in f:
                    if line.strip():
                        if self.checkip(line.strip()):
                            self.ip_list.append(line.strip())
                        else:
                            return False
            return True
        else:
            return False

    def run(self):
        logger = LogInfo('log/process.log')
        logger.infostring('get ip list')
        if not self.get_ip_list():
            logger.infostring('IP files may be wrong.')
            logger.infostring('program exits')
            return [], [], ""

        logger.infostring('start Masscan process...')
        self.Public_masscan()
        logger.infostring('finsh Masscan')

        logger.infostring('start read results...')
        if not self.readResult():
            logger.infostring('masscan scanning problems, IP files may be wrong.')
            logger.infostring('program exits')
            return [], [], ""

        logger.infostring('start nmap scan service...')
        self.Public_nmap()
        logger.infostring('finsh nmap scan.')

        logger.infostring('compare with the last result')
        self.diff()

        logger.infostring('generate the result file')
        self.callback()
        return self.result_info, self.change_add_list, self.change_del_list

# -*- coding: utf-8 -*-
import os, subprocess, re
from Log import *

NAME, VERSION, AUTHOR, LICENSE = "Public Monitor", "V0.1", "咚咚呛", "Public (FREE)"


class Weakpass_Scan():
    # 初始化扫描状态
    def __init__(self, conf_info):
        self.target_file = 'out/Result.txt'
        self.user_file = conf_info['db_user']
        self.pass_file = conf_info['db_pass']
        self.infolist, self.weakpass_result = [], []
        self.logger = LogInfo('log/process.log')

    def brute(self, host, port, server):
        supported = ['asterisk', 'cisco', 'cisco-enable', 'ftp', 'ftps', 'http-proxy', 'imap', 'imaps', 'mssql',
                     'mysql', 'pcanywhere', 'vnc', 'pop3', 'pop3s', 'postgres', 'rdp', 'redis', 'rexec', 'rlogin',
                     'rsh', 'smb', 'smtp', 'smtps', 'smtp-enum', 'snmp', 'socks5', 'ssh', 'svn', 'teamspeak', 'telnet',
                     'telnets', 'vmauthd', 'vnc', 'xmpp']
        server_only_pass = ['cisco', 'cisco-enable', 'redis']

        if server not in supported:
            return
        try:
            # arg = ['medusa', '-h', self.host, '-U', self.user_file, '-P', self.pass_file, '-M', self.server, '-t', '5','-n', self.port, '-F', '-e', 'ns'] if BURST_TOOLS == 'medusa' else ['hydra', '-L', self.user_file,'-P', self.pass_file,'-s', self.port, '-f',self.host,self.server]
            arg = ['hydra', '-L', self.user_file, '-P', self.pass_file, '-s', port, '-f', host,
                   server] if server not in server_only_pass else ['hydra', '-P', self.pass_file, '-s', port, '-f',
                                                                   host, server]
            p = subprocess.Popen(
                arg, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=-1)

            for line in iter(p.stdout.readline, b''):
                if '[' + server + ']' in line:
                    if server in server_only_pass:
                        password = line.split('password: ')[1].strip()
                        self.logger.infostring(
                            'find weak pass host: %s, port: %s, server: %s, user: %s, password: %s' % (
                                host, port, server, "", password))
                        value = {'host': host, 'port': port, 'server': server, 'user': "", 'password': password}
                        self.weakpass_result.append(value)
                    # 解析hydra爆破成功结果
                    elif 'login:' in line:
                        user = line.split('login: ')[1].split('   ')[0].strip()
                        password = line.split('password: ')[1].strip()
                        self.logger.infostring(
                            'find weak pass host: %s, port: %s, server: %s, user: %s, password: %s' % (
                                host, port, server, user, password))
                        value = {'host': host, 'port': port, 'server': server, 'user': user, 'password': password}
                        self.weakpass_result.append(value)
        except Exception, e:
            print "hydra Error %s" % (str(e))

    def readInfo(self):
        if os.path.exists(self.target_file):
            self.logger.infostring('read scan reasult to weak pass')
            with open(self.target_file) as f:
                for line in f:
                    if line.strip(): self.infolist.append(line.strip())

    def callback(self):
        if not os.path.exists('out'):
            os.mkdir('out')
        f = open('out/Weakpass.txt', 'w')
        for weakpass in self.weakpass_result:
            f.write('host: %s, port: %s, server: %s, user: %s, password: %s\n' % (
                weakpass['host'], weakpass['server'], weakpass['port'], weakpass['user'], weakpass['password']))
        f.close()

    def run(self):
        self.logger.infostring('start weak pass thread')
        self.readInfo()
        self.logger.infostring('start weak pass scan...')
        for info in self.infolist:
            value = re.split('[:]', info)
            self.brute(value[0], value[1], value[2])
        self.callback()
        self.logger.infostring('finsh weak pass scan.')
        return self.weakpass_result

# -*- coding: utf-8 -*-
from publicScan import *
from publicEmail import *
from publicWeakpass import *
from createXLS import *
import os

NAME, VERSION, AUTHOR, LICENSE = "Public Monitor", "V0.1", "咚咚呛", "Public (FREE)"


def main(conf_info, syspath):
    conf_info['result_info'], conf_info['change_add_list'], conf_info['change_del_list'], conf_info['weakpass_result'], \
    conf_info['xlsfile'], = \
        [], [], [], [], ""

    if not os.path.exists(syspath + '/out'):
        os.mkdir(syspath + '/out')
    if not os.path.exists(syspath + '/log'):
        os.mkdir(syspath + '/log')
    if not os.path.exists(syspath + '/tmp'):
        os.mkdir(syspath + '/tmp')

    if conf_info['type'] != "weakpass":
        pscan = PublicScan(conf_info['ip_file'], conf_info['rate'], syspath)
        conf_info['result_info'], conf_info['change_add_list'], conf_info['change_del_list'] = pscan.run()

    if conf_info['type'] != "monitors" and conf_info['db_user'] and conf_info['db_pass']:
        conf_info['weakpass_result'] = Weakpass_Scan(conf_info, syspath).run()

    if conf_info['result_info'] or conf_info['weakpass_result']:
        conf_info['xlsfile'] = Create_Xls(conf_info, syspath).run()

    if conf_info['email_user'] and conf_info['email_pass'] and conf_info['target_email'] and conf_info['smtp_server']:
        Send_Email(conf_info, syspath).run()

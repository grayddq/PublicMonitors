# -*- coding: utf-8 -*-
from xlwt import *
import os, re, time
from Log import *

NAME, VERSION, AUTHOR, LICENSE = "Public Monitor", "V0.1", "咚咚呛", "Public (FREE)"


class Create_Xls:
    def __init__(self, conf_info):
        self.result_info, self.change_del_list, self.change_add_list, self.weakpass_result = \
            conf_info['result_info'], conf_info['change_del_list'], conf_info['change_add_list'], conf_info[
                'weakpass_result']
        self.logger = LogInfo('log/process.log')

    def create_xls(self):
        file = Workbook(encoding='utf-8')
        table = {}
        applications = [u'公网开发端口服务详情', u'新增端口服务详情', u'减少端口服务详情', u'弱口令风险']
        for application in applications:
            sheet_name = file.add_sheet(application)
            table[application] = sheet_name
            table[application + 'row'] = 1

            pattern = Pattern()  # Create the Pattern
            pattern.pattern = Pattern.SOLID_PATTERN
            pattern.pattern_fore_colour = 22
            style = XFStyle()  # Create the Pattern
            style.pattern = pattern  # Add Pattern to Style

            sheet_name.write(0, 0, u'IP地址', style)
            sheet_name.write(0, 1, u'端口', style)
            sheet_name.write(0, 2, u'服务名称', style)
            sheet_name.write(0, 3, u'协议' if application != u'弱口令风险' else u'账户', style)
            sheet_name.write(0, 4, u'状态' if application != u'弱口令风险' else u'密码', style)

            if application == u'公网开发端口服务详情':
                results = self.result_info
            elif application == u'新增端口服务详情':
                results = self.change_add_list
            elif application == u'减少端口服务详情':
                results = self.change_del_list
            else:
                results = self.weakpass_result
            for result in results:
                if application != u'弱口令风险':
                    value = re.split('[:]', result)
                    row = table[application + 'row']
                    table[application].write(row, 0, value[0])
                    table[application].write(row, 1, value[1])
                    table[application].write(row, 2, value[2])
                    table[application].write(row, 3, 'TCP')
                    table[application].write(row, 4, u'关闭' if application == u'减少端口服务详情' else u'对外开放')
                    table[application + 'row'] += 1
                else:
                    row = table[application + 'row']
                    table[application].write(row, 0, result['host'])
                    table[application].write(row, 1, result['port'])
                    table[application].write(row, 2, result['server'])
                    table[application].write(row, 3, result['user'])
                    table[application].write(row, 4, result['password'])
                    table[application + 'row'] += 1

        if not os.path.exists('out'):
            os.mkdir('out')
        filename = 'out/%s.xls' % time.strftime('%Y-%m-%d', time.localtime(time.time()))
        if os.path.exists(filename):
            os.remove(filename)
        file.save(filename)
        self.logger.infostring('generate the result file %s' % filename)
        return filename

    def run(self):
        return self.create_xls()

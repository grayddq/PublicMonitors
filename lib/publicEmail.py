# -*- coding: utf-8 -*-
import smtplib, re
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
from Log import *

NAME, VERSION, AUTHOR, LICENSE = "Public Monitor", "V0.1", "咚咚呛", "Public (FREE)"


class Send_Email:
    def __init__(self, conf):
        self.user, self.password, self.smtp_server, self.toemail, self.xlsfile, \
        self.change_add_list, self.change_del_list, self.weakpass_result = \
            conf['email_user'], conf['email_pass'], conf['smtp_server'], conf['target_email'], \
            conf['xlsfile'], conf['change_add_list'], conf['change_del_list'], conf['weakpass_result']

    def send(self):
        logger = LogInfo('log/process.log')
        logger.infostring('start sending mail...')
        msg = MIMEMultipart()
        msg["Subject"] = "每日端口服务信息详情"
        msg["From"] = self.user
        msg["To"] = self.toemail

        if self.change_add_list or self.change_del_list or self.weakpass_result:
            msgAlternative = MIMEMultipart('alternative')
            msg.attach(msgAlternative)
            html_format = """
            <p>{title}</p>
            <style>table,table tr th, table tr td {{border:1px solid #0094ff;}}
            table {{  min-height: 25px; line-height: 25px; text-align: center; border-collapse: collapse; padding:2px;}}</style>
            <table border="1" cellspacing="0"><tr><th>IP地址</th><th>端口</th><th>服务名称</th><th>{protocol}</th><th>{status}</th></tr>{info}</table>
              """
            add_port_info = ""
            for result in self.change_add_list:
                value = re.split('[:]', result)
                add_port_info += """<tr><td>%s</td><td>%s</td><td>%s</td><td>TCP</td><td>开放</td></tr>""" % (
                    value[0], value[1], value[2])
            html_add = html_format.format(title="新增端口服务如下：", protocol='协议', status='状态', info=add_port_info)

            del_port_info = ""
            for result in self.change_del_list:
                value = re.split('[:]', result)
                del_port_info += """<tr><td>%s</td><td>%s</td><td>%s</td><td>TCP</td><td>关闭</td></tr>""" % (
                    value[0], value[1], value[2])
            html_del = html_format.format(title="关闭端口服务如下：", protocol='协议', status='状态', info=del_port_info)

            if self.weakpass_result:
                weakpass_info = ""
                for result in self.weakpass_result:
                    weakpass_info += """<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>""" % (
                        result['host'], result['port'], result['server'], result['user'], result['password'])
                html_weak = html_format.format(title="弱口令端口服务信息如下：", protocol='账户', status='密码', info=weakpass_info)
            else:
                html_weak = "<p></p><p>不存在服务弱口令信息。</p>"

            msg_html = "<p>公网端口服务详情请参照附件信息。</p>"
            msg_html += html_add if add_port_info else ""
            msg_html += html_del if del_port_info else ""
            msg_html += html_weak

            msgAlternative.attach(MIMEText(msg_html, 'html', 'utf-8'))
        else:
            part = MIMEText("端口服务详情请参照附件信息。\n注：端口服务信息并未改变，且不存在弱口令信息")
            msg.attach(part)
        if self.xlsfile:
            part = MIMEApplication(open(self.xlsfile, 'rb').read())
            part.add_header('Content-Disposition', 'attachment', filename=self.xlsfile)
            msg.attach(part)
        error = 0
        while True:
            if error == 3:
                break
            try:
                s = smtplib.SMTP(self.smtp_server, timeout=30)
                s.login(self.user, self.password)
                s.sendmail(self.user, self.toemail, msg.as_string())
                s.close()
                break
            except smtplib.SMTPException, e:
                error += 1
                logger.infostring('sending mail failure,error: %s' % e.message)
                continue
        logger.infostring('sending mail success')

    def run(self):
        self.send()

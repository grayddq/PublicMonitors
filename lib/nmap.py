#!/usr/bin/env python3
# -*- coding: latin-1 -*-

"""
nmap.py - version and date, see below

Author : Alexandre Norman - norman at xael.org
Contributors: Steve 'Ashcrow' Milner - steve at gnulinux.net
              Brian Bustin - brian at bustin.us
              old.schepperhand
              Johan Lundberg 
Licence : GPL v3 or any later version


This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.


Test strings :
^^^^^^^^^^^^
>>> import nmap
>>> if __get_last_online_version() != __version__:
...     raise ValueError('Current version is {0} - Last published version is {1}'.format(__version__, __get_last_online_version()))
>>> nm = nmap.PortScanner()
>>> try:
...     nm.scan(arguments='-wrongargs')
... except nmap.PortScannerError:
...     pass
>>> 'error' in nm.scan('yahoo.fs', arguments='-sP')['nmap']['scaninfo']
True
>>> r=nm.scan('127.0.0.1', '22-443')
>>> nm.command_line()
'nmap -oX - -p 22-443 -sV 127.0.0.1'
>>> nm.scaninfo()
{'tcp': {'services': '22-443', 'method': 'syn'}}
>>> nm.all_hosts()
['127.0.0.1']
>>> nm['127.0.0.1'].hostname()
'localhost'
>>> nm['127.0.0.1'].state()
'up'
>>> nm['127.0.0.1'].all_protocols()
['tcp']
>>> nm['127.0.0.1']['tcp'].keys()
dict_keys([139, 111, 80, 53, 22, 25, 443])
>>> nm['127.0.0.1'].has_tcp(22)
True
>>> nm['127.0.0.1'].has_tcp(23)
False
>>> nm['127.0.0.1']['tcp'][22]
{'state': 'open', 'reason': 'syn-ack', 'name': 'ssh'}
>>> nm['127.0.0.1'].tcp(22)
{'state': 'open', 'reason': 'syn-ack', 'name': 'ssh'}
>>> nm['127.0.0.1']['tcp'][22]['state']
'open'
>>> nm.scanstats()['uphosts']
'1'
>>> nm.scanstats()['downhosts']
'0'
>>> nm.scanstats()['totalhosts']
'1'
>>> 'timestr' in nm.scanstats().keys()
True
>>> 'elapsed' in nm.scanstats().keys()
True
>>> nm.listscan('192.168.1.0/30')
['192.168.1.0', '192.168.1.1', '192.168.1.2', '192.168.1.3']
>>> nm.listscan('localhost/30')
['127.0.0.0', '127.0.0.1', '127.0.0.2', '127.0.0.3']
>>> r=nm.scan('127.0.0.1', arguments='-O')
>>> nm['127.0.0.1']['osclass']
[{'vendor': 'Linux', 'osfamily': 'Linux', 'type': 'general purpose', 'osgen': '2.6.X', 'accuracy': '96'}, {'vendor': 'AXIS', 'osfamily': 'Linux', 'type': 'webcam', 'osgen': '2.6.X', 'accuracy': '91'}, {'vendor': 'Crestron', 'osfamily': '2-Series', 'type': 'specialized', 'osgen': '', 'accuracy': ''}, {'vendor': 'Gemtek', 'osfamily': 'embedded', 'type': 'WAP', 'osgen': '', 'accuracy': ''}, {'vendor': 'Siemens', 'osfamily': 'embedded', 'type': 'WAP', 'osgen': '', 'accuracy': ''}, {'vendor': 'Linux', 'osfamily': 'Linux', 'type': 'general purpose', 'osgen': '2.4.X', 'accuracy': '88'}, {'vendor': 'Check Point', 'osfamily': 'embedded', 'type': 'firewall', 'osgen': '', 'accuracy': ''}, {'vendor': 'Check Point', 'osfamily': 'Linux', 'type': 'firewall', 'osgen': '2.4.X', 'accuracy': '88'}, {'vendor': 'Linux', 'osfamily': 'Linux', 'type': 'WAP', 'osgen': '2.4.X', 'accuracy': '88'}, {'vendor': 'Linux', 'osfamily': 'Linux', 'type': 'general purpose', 'osgen': '', 'accuracy': ''}, {'vendor': 'Linux', 'osfamily': 'Linux', 'type': 'WAP', 'osgen': '2.6.X', 'accuracy': '87'}, {'vendor': 'Vodavi', 'osfamily': 'embedded', 'type': 'PBX', 'osgen': '', 'accuracy': ''}, {'vendor': 'Lexmark', 'osfamily': 'embedded', 'type': 'printer', 'osgen': '', 'accuracy': ''}]
>>> nm['127.0.0.1']['fingerprint']
'OS:SCAN(V=5.21%D=11/23%OT=22%CT=1%CU=33028%PV=N%DS=0%DC=L%G=Y%TM=50AFE898%P\\nOS:=x86_64-unknown-linux-gnu)SEQ(SP=105%GCD=1%ISR=107%TI=Z%CI=Z%II=I%TS=8)O\\nOS:PS(O1=M400CST11NW6%O2=M400CST11NW6%O3=M400CNNT11NW6%O4=M400CST11NW6%O5=M\\nOS:400CST11NW6%O6=M400CST11)WIN(W1=8000%W2=8000%W3=8000%W4=8000%W5=8000%W6=\\nOS:8000)ECN(R=Y%DF=Y%T=40%W=8018%O=M400CNNSNW6%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O\\nOS:%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=\\nOS:0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%\\nOS:S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(\\nOS:R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=\\nOS:N%T=40%CD=S)\\n'
"""


__author__ = 'Alexandre Norman (norman@xael.org)'
__version__ = '0.2.6'
__last_modification__ = '2012.12.13'


import os
import re
import string
import subprocess
import sys
import types
import xml.dom.minidom
import shlex
import collections


try:
    from multiprocessing import Process
except ImportError:
    # For pre 2.6 releases
    from threading import Thread as Process

############################################################################

class PortScanner(object):
    """
    PortScanner allows to use nmap from python
    """
    
    def __init__(self, nmap_search_path=('nmap','/usr/bin/nmap','/usr/local/bin/nmap','/sw/bin/nmap','/opt/local/bin/nmap') ):
        """
        Initialize the module
        detects nmap on the system and nmap version
        may raise PortScannerError exception if nmap is not found in the path

        nmap_search_path = tupple of string where to search for nmap executable. Change this if you want to use a specific version of nmap.
        """

        self._nmap_path = ''                # nmap path
        self._scan_result = {}
        self._nmap_version_number = 0       # nmap version number
        self._nmap_subversion_number = 0    # nmap subversion number
        self._nmap_last_output = ''  # last full ascii nmap output
        is_nmap_found = False       # true if we have found nmap

        self.__process = None

        # regex used to detect nmap
        regex = re.compile('Nmap version [0-9]*\.[0-9]')
        # launch 'nmap -V', we wait after 'Nmap version 5.0 ( http://nmap.org )'
        # This is for Mac OSX. When idle3 is launched from the finder, PATH is not set so nmap was not found
        for nmap_path in nmap_search_path:
            try:
                p = subprocess.Popen([nmap_path, '-V'], bufsize=10000, stdout=subprocess.PIPE)
            except OSError:
                pass
            else:
                self._nmap_path = nmap_path # save path 
                break
        else:
            raise PortScannerError('nmap program was not found in path. PATH is : {0}'.format(os.getenv('PATH')))            


            
        self._nmap_last_output = bytes.decode(p.communicate()[0]) # store stdout
        for line in self._nmap_last_output.split('\n'):
            if regex.match(line) is not None:
                is_nmap_found = True
                # Search for version number
                regex_version = re.compile('[0-9]+')
                regex_subversion = re.compile('\.[0-9]+')

                rv = regex_version.search(line)
                rsv = regex_subversion.search(line)

                if rv is not None and rsv is not None:
                    # extract version/subversion
                    self._nmap_version_number = int(line[rv.start():rv.end()])
                    self._nmap_subversion_number = int(line[rsv.start()+1:rsv.end()])
                break

        if is_nmap_found == False:
            raise PortScannerError('nmap program was not found in path')

        return


    def get_nmap_last_output(self):
        """
        returns the last text output of nmap in raw text
        this may be used for debugging purpose
        """
        return self._nmap_last_output



    def nmap_version(self):
        """
        returns nmap version if detected (int version, int subversion)
        or (0, 0) if unknown
        """
        return (self._nmap_version_number, self._nmap_subversion_number)



    def listscan(self, hosts='127.0.0.1'):
        """
        do not scan but interpret target hosts and return a list a hosts
        """
        assert type(hosts) is str, 'Wrong type for [hosts], should be a string [was {0}]'.format(type(hosts))
        
        self.scan(hosts, arguments='-sL')
        return self.all_hosts()



    def scan(self, hosts='127.0.0.1', ports=None, arguments='-sV'):
        """
        Scan given hosts

        May raise PortScannerError exception if nmap output was not xml

        Test existance of the following key to know if something went wrong : ['nmap']['scaninfo']['error']
        If not present, everything was ok.

        hosts = string for hosts as nmap use it 'scanme.nmap.org' or '198.116.0-255.1-127' or '216.163.128.20/20'
        ports = string for ports as nmap use it '22,53,110,143-4564'
        arguments = string of arguments for nmap '-sU -sX -sC'
        """
        if sys.version_info[0]==2:
            assert type(hosts) in (str, unicode), 'Wrong type for [hosts], should be a string [was {0}]'.format(type(hosts))
        else:
            assert type(hosts) is str, 'Wrong type for [hosts], should be a string [was {0}]'.format(type(hosts))
        assert type(ports) in (str, type(None)), 'Wrong type for [ports], should be a string [was {0}]'.format(type(ports))
        assert type(arguments) is str, 'Wrong type for [arguments], should be a string [was {0}]'.format(type(arguments))

        #h_args = shlex.split(hosts)
        h_args = [hosts]
        f_args = shlex.split(arguments)
        
        # Launch scan
        args = [self._nmap_path, '-oX', '-'] + h_args + ['-p', ports]*(ports!=None) + f_args

        p = subprocess.Popen(args, bufsize=100000, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        # wait until finished
        # get output
        (self._nmap_last_output, nmap_err) = p.communicate()
        self._nmap_last_output = bytes.decode(self._nmap_last_output)
        nmap_err = bytes.decode(nmap_err)

        # If there was something on stderr, there was a problem so abort...  in
        # fact not always. As stated by AlenLPeacock :
        # This actually makes python-nmap mostly unusable on most real-life
        # networks -- a particular subnet might have dozens of scannable hosts,
        # but if a single one is unreachable or unroutable during the scan,
        # nmap.scan() returns nothing. This behavior also diverges significantly
        # from commandline nmap, which simply stderrs individual problems but
        # keeps on trucking.

        nmap_err_keep_trace = []
        if len(nmap_err) > 0:
            regex_warning = re.compile('^Warning: .*')
            for line in nmap_err.split('\n'):
                if len(line) > 0:
                    rgw = regex_warning.search(line)
                    if rgw is not None:
                        sys.stderr.write(line+'\n')
                        pass
                    else:
                        #raise PortScannerError(nmap_err)
                        nmap_err_keep_trace.append(nmap_err)

        # nmap xml output looks like :
        #  <host starttime="1267974521" endtime="1267974522">
        #  <status state="up" reason="user-set"/>
        #  <address addr="192.168.1.1" addrtype="ipv4" />
        #  <hostnames><hostname name="neufbox" type="PTR" /></hostnames>
        #  <ports>
        #    <port protocol="tcp" portid="22">
        #      <state state="filtered" reason="no-response" reason_ttl="0"/>
        #      <service name="ssh" method="table" conf="3" />
        #    </port>
        #    <port protocol="tcp" portid="25">
        #      <state state="filtered" reason="no-response" reason_ttl="0"/>
        #      <service name="smtp" method="table" conf="3" />
        #    </port>
        #  </ports>
        #  <times srtt="-1" rttvar="-1" to="1000000" />
        #  </host>



        scan_result = {}


        try:
            dom = xml.dom.minidom.parseString(self._nmap_last_output)
        except xml.parsers.expat.ExpatError:
            if len(nmap_err)>0:
                raise PortScannerError(nmap_err)
            else:
                raise PortScannerError(self._nmap_last_output)

        # nmap command line
        scan_result['nmap'] = {
            'command_line': dom.getElementsByTagName('nmaprun')[0].getAttributeNode('args').value,
            'scaninfo': {},
            'scanstats':{'timestr':dom.getElementsByTagName("finished")[0].getAttributeNode('timestr').value,
                         'elapsed':dom.getElementsByTagName("finished")[0].getAttributeNode('elapsed').value,
                         'uphosts':dom.getElementsByTagName("hosts")[0].getAttributeNode('up').value,
                         'downhosts':dom.getElementsByTagName("hosts")[0].getAttributeNode('down').value,
                         'totalhosts':dom.getElementsByTagName("hosts")[0].getAttributeNode('total').value}
            }

        # if there was an error
        if len(nmap_err_keep_trace)>0:
            scan_result['nmap']['scaninfo']['error'] = nmap_err_keep_trace

        # info about scan
        for dsci in dom.getElementsByTagName('scaninfo'):
            scan_result['nmap']['scaninfo'][dsci.getAttributeNode('protocol').value] = {                
                'method': dsci.getAttributeNode('type').value,
                'services': dsci.getAttributeNode('services').value
                }


        scan_result['scan'] = {}
        
        for dhost in  dom.getElementsByTagName('host'):
            # host ip
            host = dhost.getElementsByTagName('address')[0].getAttributeNode('addr').value
            hostname = ''
            for dhostname in dhost.getElementsByTagName('hostname'):
                hostname = dhostname.getAttributeNode('name').value
            scan_result['scan'][host] = PortScannerHostDict({'hostname': hostname})
            for dstatus in dhost.getElementsByTagName('status'):
                # status : up...
                scan_result['scan'][host]['status'] = {'state': dstatus.getAttributeNode('state').value,
                                               'reason': dstatus.getAttributeNode('reason').value}
            for dstatus in dhost.getElementsByTagName('uptime'):
                # uptime : seconds, lastboot
                scan_result['scan'][host]['uptime'] = {'seconds': dstatus.getAttributeNode('seconds').value,
                                                'lastboot': dstatus.getAttributeNode('lastboot').value}
            for dport in dhost.getElementsByTagName('port'):
                # protocol
                proto = dport.getAttributeNode('protocol').value
                # port number converted as integer
                port =  int(dport.getAttributeNode('portid').value)
                # state of the port
                state = dport.getElementsByTagName('state')[0].getAttributeNode('state').value
                # reason
                reason = dport.getElementsByTagName('state')[0].getAttributeNode('reason').value
                # name, product, version, extra info and conf if any
                name,product,version,extrainfo,conf = '','','','',''
                for dname in dport.getElementsByTagName('service'):
                    name = dname.getAttributeNode('name').value
                    if dname.hasAttribute('product'):
                        product = dname.getAttributeNode('product').value
                    if dname.hasAttribute('version'):
                        version = dname.getAttributeNode('version').value
                    if dname.hasAttribute('extrainfo'):
                        extrainfo = dname.getAttributeNode('extrainfo').value
                    if dname.hasAttribute('conf'):
                        conf = dname.getAttributeNode('conf').value
                # store everything
                if not proto in list(scan_result['scan'][host].keys()):
                    scan_result['scan'][host][proto] = {}
                scan_result['scan'][host][proto][port] = {'state': state,
                                                  'reason': reason,
                                                  'name': name,
                                                  'product': product,
                                                  'version': version,
                                                  'extrainfo': extrainfo,
                                                  'conf': conf}
                script_id = ''
                script_out = ''
                # get script output if any
                for dscript in dport.getElementsByTagName('script'):
                    script_id = dscript.getAttributeNode('id').value
                    script_out = dscript.getAttributeNode('output').value
                    if not 'script' in list(scan_result['scan'][host][proto][port].keys()):
                        scan_result['scan'][host][proto][port]['script'] = {}

                    scan_result['scan'][host][proto][port]['script'][script_id] = script_out

            for dport in dhost.getElementsByTagName('osclass'):
                # <osclass type="general purpose" vendor="Linux" osfamily="Linux" osgen="2.6.X" accuracy="98"/>
                ostype = ''
                vendor = ''
                osfamily = ''
                osgen = ''
                accuracy = ''
                try:
                    ostype = dport.getAttributeNode('type').value
                    vendor = dport.getAttributeNode('vendor').value
                    osfamily = dport.getAttributeNode('osfamily').value
                    osgen = dport.getAttributeNode('osgen').value
                    accuracy = dport.getAttributeNode('accuracy').value
                except AttributeError:
                    pass
                if not 'osclass' in list(scan_result['scan'][host].keys()):
                    scan_result['scan'][host]['osclass'] = []

                scan_result['scan'][host]['osclass'].append(
                    {
                        'type': ostype,
                        'vendor': vendor,
                        'osfamily': osfamily,
                        'osgen': osgen,
                        'accuracy': accuracy
                        }
                    )
                    


            for dport in dhost.getElementsByTagName('osmatch'):
                # <osmatch name="Linux 2.6.31" accuracy="98" line="30043"/>
                name = ''
                accuracy = ''
                line = ''
                try:
                    name = dport.getAttributeNode('name').value
                    accuracy = dport.getAttributeNode('accuracy').value
                    line = dport.getAttributeNode('line').value
                except AttributeError:
                    pass
                if not 'osmatch' in list(scan_result['scan'][host].keys()):
                    scan_result['scan'][host]['osmatch'] = []

                scan_result['scan'][host]['osmatch'].append(
                    {
                        'name': name,
                        'accuracy': accuracy,
                        'line': line,
                        }
                    )


            for dport in dhost.getElementsByTagName('osfingerprint'):
                # <osfingerprint fingerprint="OS:SCAN(V=5.50%D=11/[...]S)&#xa;"/>
                fingerprint = ''
                try:
                    fingerprint = dport.getAttributeNode('fingerprint').value
                except AttributeError:
                    pass

                scan_result['scan'][host]['fingerprint'] = fingerprint



        self._scan_result = scan_result # store for later use
        return scan_result


    
    def __getitem__(self, host):
        """
        returns a host detail
        """
        if sys.version_info[0]==2:
            assert type(host) in (str, unicode), 'Wrong type for [host], should be a string [was {0}]'.format(type(host))
        else:
            assert type(host) is str, 'Wrong type for [host], should be a string [was {0}]'.format(type(host))
        return self._scan_result['scan'][host]


    def all_hosts(self):
        """
        returns a sorted list of all hosts
        """
        if not 'scan' in list(self._scan_result.keys()):
            return []
        listh = list(self._scan_result['scan'].keys())
        listh.sort()
        return listh
        

    def command_line(self):
        """
        returns command line used for the scan

        may raise AssertionError exception if called before scanning
        """
        assert 'nmap' in self._scan_result, 'Do a scan before trying to get result !'
        assert 'command_line' in self._scan_result['nmap'], 'Do a scan before trying to get result !'

        return self._scan_result['nmap']['command_line']


    def scaninfo(self):
        """
        returns scaninfo structure
        {'tcp': {'services': '22', 'method': 'connect'}}

        may raise AssertionError exception if called before scanning
        """
        assert 'nmap' in self._scan_result, 'Do a scan before trying to get result !'
        assert 'scaninfo' in self._scan_result['nmap'], 'Do a scan before trying to get result !'

        return self._scan_result['nmap']['scaninfo']
            
        
    def scanstats(self):
        """
        returns scanstats structure
        {'uphosts': '3', 'timestr': 'Thu Jun  3 21:45:07 2010', 'downhosts': '253', 'totalhosts': '256', 'elapsed': '5.79'}

        may raise AssertionError exception if called before scanning
        """
        assert 'nmap' in self._scan_result, 'Do a scan before trying to get result !'
        assert 'scanstats' in self._scan_result['nmap'], 'Do a scan before trying to get result !'

        return self._scan_result['nmap']['scanstats']        


    def has_host(self, host):
        """
        returns True if host has result, False otherwise
        """
        assert type(host) is str, 'Wrong type for [host], should be a string [was {0}]'.format(type(host))
        assert 'scan' in self._scan_result, 'Do a scan before trying to get result !'

        if host in list(self._scan_result['scan'].keys()):
            return True

        return False




############################################################################


class PortScannerAsync(object):
    """
    PortScannerAsync allows to use nmap from python asynchronously
    for each host scanned, callback is called with scan result for the host
    """

    def __init__(self):
        """
        Initialize the module
        detects nmap on the system and nmap version
        may raise PortScannerError exception if nmap is not found in the path
        """
        self._process = None
        self._nm = PortScanner()
        return


    def __del__(self):
        """
        Cleanup when deleted
        """
        if self._process is not None and self._process.is_alive():
            self._process.terminate()
        return


    def scan(self, hosts='127.0.0.1', ports=None, arguments='-sV', callback=None):
        """
        Scan given hosts in a separate process and return host by host result using callback function

        PortScannerError exception from standard nmap is catched and you won't know about it

        hosts = string for hosts as nmap use it 'scanme.nmap.org' or '198.116.0-255.1-127' or '216.163.128.20/20'
        ports = string for ports as nmap use it '22,53,110,143-4564'
        arguments = string of arguments for nmap '-sU -sX -sC'
        callback = callback function which takes (host, scan_data) as arguments
        """

        assert type(hosts) is str, 'Wrong type for [hosts], should be a string [was {0}]'.format(type(hosts))
        assert type(ports) in (str, type(None)), 'Wrong type for [ports], should be a string [was {0}]'.format(type(ports))
        assert type(arguments) is str, 'Wrong type for [arguments], should be a string [was {0}]'.format(type(arguments))
        assert type(callback) in (types.FunctionType, type(None)), 'Wrong type for [callback], should be a function or None [was {0}]'.format(type(callback))
        
        def scan_progressive(self, hosts, ports, arguments, callback):
            for host in self._nm.listscan(hosts):
                try:
                    scan_data = self._nm.scan(host, ports, arguments)
                except PortScannerError:
                    pass
                if callback is not None and isinstance(callback, collections.Callable):
                    callback(host, scan_data)
            return

        self._process = Process(
            target=scan_progressive,
            args=(self, hosts, ports, arguments, callback)
            )
        self._process.daemon = True
        self._process.start()
        return


    def stop(self):
        """
        Stop the current scan process
        """
        if self._process is not None:
            self._process.terminate()
        return


    def wait(self, timeout=None):
        """
        Wait for the current scan process to finish, or timeout
        """

        assert type(timeout) in (int, type(None)), 'Wrong type for [timeout], should be an int or None [was {0}]'.format(type(timeout))

        self._process.join(timeout)
        return

    

    def still_scanning(self):
        """
        Return True if a scan is currently running, False otherwise
        """
        try:
            return self._process.is_alive()
        except:
            return False

    

############################################################################
    


class PortScannerHostDict(dict):
    """
    Special dictionnary class for storing and accessing host scan result
    """
    def hostname(self):
        """
        returns hostname
        """
        return self['hostname']

    def state(self):
        """
        returns host state
        """
        return self['status']['state']

    def uptime(self):
        """
        returns host state
        """
        return self['uptime']

    def all_protocols(self):
        """
        returns a list of all scanned protocols
        """
        lp = list(self.keys())
        lp.remove('status')
        lp.remove('hostname')
        lp.sort()
        return lp



    def all_tcp(self):
        """
        returns list of tcp ports
        """
        if 'tcp' in list(self.keys()):
            ltcp = list(self['tcp'].keys())
            ltcp.sort()
            return ltcp
        return []
            
    
    def has_tcp(self, port):
        """
        returns True if tcp port has info, False otherwise
        """
        assert type(port) is int, 'Wrong type for [port], should be an int [was {0}]'.format(type(port))
        
        if ('tcp' in list(self.keys())
            and port in list(self['tcp'].keys())):
            return True
        return False


    def tcp(self, port):
        """
        returns info for tpc port
        """
        assert type(port) is int, 'Wrong type for [port], should be an int [was {0}]'.format(type(port))
        return self['tcp'][port]


    def all_udp(self):
        """
        returns list of udp ports
        """
        if 'udp' in list(self.keys()):
            ludp = list(self['udp'].keys())
            ludp.sort()
            return ludp
        return []


    def has_udp(self, port):
        """
        returns True if udp port has info, False otherwise
        """
        assert type(port) is int, 'Wrong type for [port], should be an int [was {0}]'.format(type(port))

        if ('udp' in list(self.keys())
            and 'port' in list(self['udp'].keys())):
            return True
        return False


    def udp(self, port):
        """
        returns info for udp port
        """
        assert type(port) is int, 'Wrong type for [port], should be an int [was {0}]'.format(type(port))

        return self['udp'][port]


    def all_ip(self):
        """
        returns list of ip ports
        """
        if 'ip' in list(self.keys()):
            lip = list(self['ip'].keys())
            lip.sort()
            return lip
        return []


    def has_ip(self, port):
        """
        returns True if ip port has info, False otherwise
        """
        assert type(port) is int, 'Wrong type for [port], should be an int [was {0}]'.format(type(port))

        if ('ip' in list(self.keys())
            and port in list(self['ip'].keys())):
            return True
        return False


    def ip(self, port):
        """
        returns info for ip port
        """
        assert type(port) is int, 'Wrong type for [port], should be an int [was {0}]'.format(type(port))

        return self['ip'][port]


    def all_sctp(self):
        """
        returns list of sctp ports
        """
        if 'sctp' in list(self.keys()):
            lsctp = list(self['sctp'].keys())
            lsctp.sort()
            return lsctp
        return []


    def has_sctp(self, port):
        """
        returns True if sctp port has info, False otherwise
        """
        assert type(port) is int, 'Wrong type for [port], should be an int [was {0}]'.format(type(port))

        if ('sctp' in list(self.keys())
            and port in list(self['sctp'].keys())):
            return True
        return False


    def sctp(self, port):
        """
        returns info for sctp port
        """
        assert type(port) is int, 'Wrong type for [port], should be an int [was {0}]'.format(type(port))

        return self['sctp'][port]


    
############################################################################


class PortScannerError(Exception):
    """
    Exception error class for PortScanner class
    """
    def __init__(self, value):
        self.value = value


    def __str__(self):
        return repr(self.value)


############################################################################

def __get_last_online_version():
    """
    Gets last python-nmap published version
    WARNING : it does an http connection to http://xael.org/norman/python/python-nmap/python-nmap_CURRENT_VERSION.txt

    returns a string '0.2.3'
    """
    import http.client
    conn = http.client.HTTPConnection("xael.org")
    conn.request("GET", "/norman/python/python-nmap/python-nmap_CURRENT_VERSION.txt")
    online_version = bytes.decode(conn.getresponse().read()).strip()
    return online_version


############################################################################


# MAIN -------------------
if __name__ == '__main__':
    import doctest
    # non regression test
    doctest.testmod()


#<EOF>######################################################################


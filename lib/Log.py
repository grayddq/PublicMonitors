# -*- coding: utf-8 -*-
import logging
import logging.handlers

NAME, VERSION, AUTHOR, LICENSE = "Public Monitor", "V0.1", "咚咚呛", "Public (FREE)"


class LogInfo:
    def __init__(self, logfile):
        self.log_file = logfile
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(message)s'
        )
        self.logger = logging.getLogger('LogInfo')
        fh = logging.FileHandler(self.log_file)
        fh.setLevel(logging.INFO)
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(message)s')
        fh.setFormatter(formatter)
        self.logger.addHandler(fh)

    def infostring(self, infostring):
        self.logger.info(infostring)

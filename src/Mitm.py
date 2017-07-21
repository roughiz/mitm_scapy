# -*- coding: utf-8 -*-
from scapy.all import *
from scapy.layers import  *
from scapy.error import Scapy_Exception
import os,sys,threading,signal

from scapy.layers.l2 import *

#from  logger.colorizeStream import ColorizingStreamHandler
import logging







class MITM():

    def __init__(self):
        """
        Variables globales
        """
        self.ATTACK_INF = {}
        self.ATTACK_INF["GW_IP"] = ""
        self.ATTACK_INF["VM_IP"] = ""
        self.ATTACK_INF["IFACE"] = ""
        self.ATTACK_INF["HTTP_SCAN"] = False
        self.ATTACK_INF["SMTP_SCAN"] = False
        self.ATTACK_INF["PIC_SCAN"] = False
        self.ATTACK_INF["POP3_SCAN"] = False
        self.ATTACK_INF["IMAP_SCAN"] = False

# Color log
    def log_color(self):
        root = logging.getLogger()
        root.setLevel(logging.DEBUG)
        #root.addHandler(ColorizingStreamHandler())
        logging.debug('DEBUG')
        logging.info('INFO')
        logging.warning('WARNING')
        logging.error('ERROR')
        logging.critical('CRITICAL')

    def right_argument(self,input):
        if  input == "o" or input == "O":
            return True
        else:
            return False

    def network_scanner(self,cidr):
        res = ""
        unans = ""
        try:
            print "[*] Appuyez sur Ctrl+c pour arreter le scan\n "
            res, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=cidr),iface=self.ATTACK_INF["IFACE"],verbose=None,timeout=10)
            res.summary(lambda (s, r): r.sprintf("%Ether.src% %ARP.psrc%"))
        except KeyboardInterrupt:
            if res:
                res.summary(lambda (s, r): r.sprintf("%Ether.src% %ARP.psrc%"))

 # Intercept user choices
    def get_targets_informations(self):
        print "[*] Mitm roughiz tool\n "
        scan = raw_input("Voulez-vous scanner le réseau local pour trouver des cibles? (O/N) : ")
        self.ATTACK_INF["IFACE"] = raw_input("Veuillez-choisir le nom de l'interface :")
        arg  = raw_input("Voulez-vous scanner le protocol HTTP en vue de trouver des info d'authentifications? (O/N) : ")
        self.ATTACK_INF["HTTP_SCAN"] = self.right_argument(arg)
        arg  = raw_input("Voulez-vous scanner le protocol SMTP en vue de trouver des info d'authentifications? (O/N) : ")
        self.ATTACK_INF["SMTP_SCAN"] = self.right_argument(arg)
        arg  = raw_input("Voulez-vous scanner le protocol POP3 en vue de trouver des info d'authentifications? (O/N) : ")
        self.ATTACK_INF["POP3_SCAN"] =  self.right_argument(arg)
        arg  = raw_input("Voulez-vous scanner le protocol IMAP en vue de trouver des info d'authentifications? (O/N) : ")
        self.ATTACK_INF["IMAP_SCAN"] =  self.right_argument(arg)
        arg = raw_input("Voulez-vous récupérer les images qui transit de la victime? (O/N) : ")
        self.ATTACK_INF["PIC_SCAN"] =  self.right_argument(arg)

        if scan == "o" or scan == "O":
            cidr = raw_input("Veuillez-entrer le CIDR pour le scan, par exemple 192.168.3.5/16 :")
            return  self.network_scanner(cidr)
        else:
            self.ATTACK_INF["GW_IP"] = raw_input("Veuillez-entrer l'adresse ip de la Gateway :")
            self.ATTACK_INF["VM_IP"] = raw_input("Veuillez-entrer l'adresse ip de la victime :")
            return self.ATTACK_INF




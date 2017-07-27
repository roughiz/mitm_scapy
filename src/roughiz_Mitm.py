from Mitm import MITM
import threading

def main():

    #arp_poison(get_targets_informations())
    mitm = MITM()
    #mitm.log_color()
    #mitm.get_targets_informations()
    #mitm.start_attack()
    mitm.run_authentifacion_scanner()




if __name__ == '__main__':
    main()

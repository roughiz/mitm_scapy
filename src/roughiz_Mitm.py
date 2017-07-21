from Mitm import MITM


def main():

    #arp_poison(get_targets_informations())
    mitm = MITM()
    mitm.get_targets_informations()



if __name__ == '__main__':
    main()

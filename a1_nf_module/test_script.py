import sys
import os

valid_types = ['NULL', 'FIN', 'XMAS']
target_ip = "10.0.0.2"

if __name__ == '__main__':
    if not (2 <= len(sys.argv) <= 3) or (sys.argv[1] not in valid_types):
        print("Invalid arguments!\n" +
            "usage\t: ./test_script.py <type> <target_ip>\n" +
            "<type>\t: NULL, FIN, XMAS\n" +
            "<target_ip> is optional, default is 10.0.0.2")
        exit(0)

    if len(sys.argv) == 3:
        target_ip = sys.argv[2]

    if sys.argv[1] == 'NULL':
        os.system('sudo nmap -sN ' + target_ip)
    elif sys.argv[1] == 'FIN':
        os.system('sudo nmap -sF ' + target_ip)
    else:
        os.system('sudo nmap -sX ' + target_ip)

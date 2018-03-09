import os
import re
from pysnmp.entity.rfc3413.oneliner import cmdgen
f_3 = open("ip all.txt")
ip = []
ip = f_3.readline()
print(ip)
while ip:
    ip = f_3.readline()
    hostname = ip #example
    response = os.system("fping " + hostname)
    f_4 = open(r"ip ping.txt", 'a+')
    if response == 0:
        # ip = input('IP address ТКД: ')
        cmdGen = cmdgen.CommandGenerator()
        errorIndication, errorStatus, errorIndex, varBindTable = cmdGen.nextCmd(cmdgen.CommunityData('community'),
                                                                                cmdgen.UdpTransportTarget((ip, 161)),
                                                                                '1.3.6.1.2.1.17.7.1.2.2.1.2')
        f = open(r"log", "w")
        if errorIndication:
            print(errorIndication)
        else:
            if errorStatus:
                print('%s at %s' % (
                errorStatus.prettyPrint(), errorIndex and varBindTable[-1][int(errorIndex) - 1] or '?'))
            else:
                for varBindTableRow in varBindTable:
                    for name, val in varBindTableRow:
                        vivod = ('%s = %s' % (name.prettyPrint(), val.prettyPrint()))

                        f.writelines(vivod + '\n')
        f.close()
        file = open(r"log")
        file_read = str(file.read())
        regex = re.compile(r"^\S+2.17.7.1.2.2.1.2.(?P<vlan>\d+).(?P<mac>\d+.\d+.\d+.\d+.\d+.\d+)\s+=\s+(?P<port>\d+)",
                           re.MULTILINE)


        def find_re(f):
            f2 = open(r"log2", "w")
            for match in regex.finditer(file_read):
                r = []
                r += [{"vlan": match.group("vlan"),
                       "mac": match.group("mac"),
                       "port": match.group("port")}]
                for item in r:
                    b = item
                    b['ip'] = ip[:-1]
                    f2.write("{}\n".format(b))

            return r


        try:
            find_re(f)
        except UnboundLocalError:
            print("No SNMP")
        f3 = open(r"log2")
        read3 = f3.read()
        f3.close()

        file_1 = open(r"log2")
        file1_1 = file_1.readline()
        try:
            file2_1 = eval(file1_1)
        except SyntaxError:
            print("Error")

        # stroka = file2.get('mac')

        with open('log2') as f:
            for line in f:
                line = eval(line)
                stroka = line.get('mac')


                def getmac(line):
                    s = stroka.split('.')
                    result = list(map(int, s))
                    f2_1 = open(r"log3", "w")
                    for dec in result:
                        a = "0x{:02x}".format(dec)
                        f2_1.write("%s:" % a)
                    f2_1.close()

                    f3_1 = open(r"log3")
                    read_1 = f3_1.read()

                    read2_1 = re.sub(r"0x", '', read_1)
                    read3_1 = read2_1.upper()
                    read4_1 = re.sub(r":$", '', read3_1)
                    return read4_1


                getmac(line)
                line['mac'] = getmac(line)
                print(line)
                f_6 = f_4.write("%s\n" % (line))

        # f_5 = f_4.write(ip)

    else:
        print("%s is down!" % hostname)
f_3.close()

f_8 = open("ip ping.txt")
f_8read = f_8.read()
regex_8 = r"FC:EC:DA\S+.+|80:2A:A8\S+.+|F0:9F:C2\S+.+|DC:9F:DB\S+.+|B4:FB:E4\S+.+|78:8A:20\S+.+|68:72:51\S+.+|44:D9:E7\S+.+" \
          r"|24:A4:3C\S+.+|04:18:D6\S+.+|00:27:22\S+.+|00:15:6D\S+.+"
modif = re.findall(regex_8, f_8read)
f_9 = open(r"result.txt", 'a+')
f_9.write(modif)
f_9.close()

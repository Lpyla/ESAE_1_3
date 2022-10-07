from logging import exception
import ssl
import csv
import socket
from textwrap import wrap
from tkinter import W
from retry import retry
import ipaddress


def getBlockedNetworks(): #do it once so we're done with it and facilitates iterations later on
    global blockFilePath, blockedNetworks
    f = open(blockFilePath, 'r')
    reader=f.readlines()
    for line in reader:
        if line.__contains__('/'): #only lines with an ipv4 network have a /
            network = line[:len(line)-1] #\n at the end of the lines, we get rid of it
            network = ipaddress.ip_network(network) #use ipaddress module to ease everything, performance++ since they use bitwise comparison
            blockedNetworks.append(network)
    f.close()

def getBlockedDomains(): #same idea
    global blockFilePath, blockedDomains
    f=open(blockFilePath, 'r')
    reader=f.readlines()
    for line in reader:
        if line.__contains__('/'):
            continue
        else:
            domain=line[:len(line)-1]
            blockedDomains.append(domain)
    f.close()



def checkIpDomain(row): #checks if we are allowed to scan IP/domain name on said row
    global blockedDomains, blockedNetworks
    ip=row[1]
    ip=ipaddress.ip_address(ip)
    host=row[0]
    for i in blockedDomains:
        if i.__contains__(host):
            print(host + ' avoided')
            return False
    for j in blockedNetworks:
        if j.__contains__(ip):
            print("network " + str(j) + " avoided")
            return False
    return True





if __name__ == "__main__":

    global blockFilePath, blockedNetworks, blockedDomains

#Setting up filtering tools.
#We use lists to store the forbidden urls/IPs so we can just navigate through these lists instead of having to keep the file open

    blockFilePath = 'week3-blocklist.txt'
    blockedNetworks = []
    getBlockedNetworks()
    blockedDomains=[]
    getBlockedDomains()
    avoidedDomains=0

#using a "results" file to write every TLS version and certificate gotten
    res = open("results.csv", "w")
    res.truncate(0) #erase everything at each run
    resultWriter=csv.writer(res, lineterminator='\n') #csv format : hostname, TLS version, certificate


#counters
    totalConn=0
    connOK=0 #will count successful connection and validations
    connFailed=0 #will count errors (both timeouts, EOF, wrong certs...)
    wrongCert=0


#Certificate Authorities

    CAs = {}

#main loop
    with open('week3-input_testing.csv') as input:
        reader_input = csv.reader(input)
        for row in reader_input:
            hostname = row[0]
            port = 443
            serverAddress= (hostname, port)
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.minimum_version=ssl.TLSVersion.TLSv1
                context.maximum_version=ssl.TLSVersion.TLSv1_3
                context.load_verify_locations("C:\\Users\\Leo PYLA\\Desktop\\TC\\NL\\ESA&E\\Scanner\\week3-roots.pem")
            except Exception:
                continue

            if(checkIpDomain(row)):
                try:
                    sock.connect((hostname, port))
                    with context.wrap_socket(sock, server_hostname=hostname) as ssock:

                        ssock.settimeout(2) #relatively short timeout because without coroutines it gets slow
                        cert = ssock.getpeercert() #get the certificate, validation is automatic thx to OpenSSL, returns None if cert isn't valid
                        issuer = str(cert.get('issuer')[1][0][1]) #name of the CA who delivered the certificate

                        if issuer in CAs:
                            CAs[issuer]+=1
                        else:
                            CAs[issuer]=1
                            
                        toWrite = [hostname, str(ssock.version()), str(ssock.getpeercert())]
                        resultWriter.writerow(toWrite)
                        connOK+=1
                        print("ok")
                except Exception as e:
                    if type(e)==ssl.SSLCertVerificationError:
                        wrongCert+=1
                    connFailed+=1
            else:
                avoidedDomains+=1
            totalConn+=1


    #finally compute what we want to analyze
    res.close()
    errorRate = connFailed/totalConn*100
    percentageWrongCerts=wrongCert/totalConn*100
    print("number of successful connections : " + str(connOK) +'\n')
    print("number of failed connections : " + str(connFailed) +'\n')
    print("number of wrong certificates : " + str(wrongCert) +' --- ' + str(percentageWrongCerts) + '%' + '\n')

    #now analyze the number of tls versions observed, 2nd field in the results file

#counters for tls version used
    tls10=0
    tls11=0
    tls12=0
    tls13=0
    with open('results.csv') as f:
        version_reader=csv.reader(f)
        for row in version_reader:
            if row[1]=="TLSv1.3":
                tls13+=1
            if row[1]=="TLSv1.2":
                tls12+=1
            if row[1]=="TLSv1.1":
                tls12+=1
            if row[1]=="TLSv1":
                tls10+=1

#Manage the CAs now, need to get the 10 most used
    i=0
    while i!=10 and CAs:
        most_used_CA=max(CAs, key=CAs.get)
        times_used=CAs[most_used_CA]
        percentageValidCertsFromCA=times_used/connOK*100
        print('CA : ' + most_used_CA + ' was used for ' + str(percentageValidCertsFromCA) + '%' + ' of the times when ssl connection was successful')
        i+=1
        CAs.pop(most_used_CA)



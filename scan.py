import ssl
import csv
import socket
import ipaddress
import sys

#gets a list of forbidden networks to scan, stored in a variable since length is acceptable (600 lines total)
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


#checkIpDomains return True if the IP/Domain are clean, False if they are included in the blockList
def checkIpDomain(row): #checks if we are allowed to scan IP/domain name on said ro
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

    blockFilePath = str(sys.argv[2])
    blockedNetworks = [] #list of forbidden networks
    getBlockedNetworks() #fill it (see above)
    blockedDomains=[] #same idea
    getBlockedDomains()
    avoidedDomains=0 #useful during testing phase, not that relevant now

#using a "results" file to write every TLS version and certificate gotten, might be useful for later uses
    res = open("results.csv", "w")
    res.truncate(0) #erase everything at each run
    resultWriter=csv.writer(res, lineterminator='\n') #csv format : hostname, TLS version, certificate


#counters
    totalConn=0 #total attempts to connect
    connOK=0 #successful connections with certificate validation
    connFailed=0 #will count errors (timeouts, EOF, wrong certs...)
    wrongCert=0 #count the number of SSLCertVerificationError raised


#Certificate Authorities

    CAs = {} #will later be used as a list of most used CAs

#main loop
    rootStore = str(sys.argv[3]) #path to our root store
    inputFile = str(sys.argv[1]) #path to input file
    print('Input File : ' + inputFile) #printing sufficient information for user to notice if they misused the program
    print('Blocklist : ' + blockFilePath)
    print('Root store : ' + rootStore)

    with open(inputFile) as input:
        counter = 0 
        print('Running scan...')
        reader_input=csv.reader(input)
        for row in reader_input:
            counter +=1
            if counter==50:
                break
            hostname = row[0]
            port = 443
            serverAddress= (hostname, port)
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2) #2 seconds is arbitrary, not for the scan to take too long, considering than >200ms to connect to a domain is quite long. It gives slightly different numbers but we later catch the wrong cert exception, so timeouts errors should not be the interesting part
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT) #using this uses the highest supported tls version (defined up to 1.3), and automatically checks for the server hostname while verifying the certificate
                context.verify_mode=ssl.CERT_REQUIRED  
                context.minimum_version=ssl.TLSVersion.TLSv1
                context.maximum_version=ssl.TLSVersion.TLSv1_3
                context.load_verify_locations(rootStore) 
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
                        print('Connection : ' + str(totalConn+1) + ' success')
                except Exception as e:
                    print('Connection : ' + str(totalConn+1) + ' error ' + str(type(e)))
                    if type(e)==ssl.SSLCertVerificationError: #if we get a wrong certificate we increment our variable to count them at the end, else we assume the error either comes from a timeout (witnessed during testing phase), or the website not willing to communicate, or badly communicating (also witnessed). These exceptions aren't relevant to our scanner
                        wrongCert+=1
                    connFailed+=1
            else:
                avoidedDomains+=1 
            totalConn+=1

    #finally compute what we want to analyze
    res.close()

    #now we compute every interesting numbers relative to the scan, percentages of versions used etc.

    successRate = connOK/totalConn*100
    errorRate = connFailed/totalConn*100
    percentageWrongCerts=wrongCert/totalConn*100
    #print them for comfort, they will also be stored in a file
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
                tls11+=1
            if row[1]=="TLSv1":
                tls10+=1


#write every useful data in a separate file at the end
#chose to do it in this script (with many precautions, not to run a scan for it to crash at the end)
#didn't use a JSON or CSV here, since very few lines are needed, and everything remains very humanly readable

    with open('analysis.txt','w') as analysis:
        #get the 10 most used CAs from our dict
        CACounter = 0 
        while CACounter !=10 and CAs:
            most_used_CA=max(CAs, key=CAs.get)
            times_used=CAs[most_used_CA]
            percentageValidCertsFromCA=times_used/connOK*100
            analysis.write('CA : ' + str(most_used_CA) + ' issued ' + str(percentageValidCertsFromCA)+'%'+' of the validated certificates \n')
            CACounter+=1
            CAs.pop(most_used_CA)
        analysis.write('Total number of domains scanned : ' + str(totalConn) + '\n')
        analysis.write('Successful connections : ' + str(connOK) + ', or ' +str(successRate) +'%\n')
        analysis.write('Failed connections (including timeouts) : ' + str(connFailed) + ', or ' + str(errorRate) + '%\n')
        analysis.write('identified wrong certificates : ' + str(wrongCert)+ ', or ' + str(percentageWrongCerts)+'\n')
        analysis.write('tls 1.3 : ' + str(tls13)+'\n')
        analysis.write('tls 1.2 : ' + str(tls12)+'\n')
        analysis.write('tls 1.1 : ' + str(tls11)+'\n')
        analysis.write('tls 1.0 : ' + str(tls10)+'\n')

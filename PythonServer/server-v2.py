from flask import Flask, request
import hashlib
checked = False
app = Flask(__name__)

# CLASS: host
# ATTRIBUTES:
#       - (string) ip: the IP address of the host
#       - (string) time: the string value of the time and date of the first request sent by this host
#       - (integer) number: the number of validated requests exchanged with this host
#
# AIM: Each instance represents a different host with which the server is able to communicate
#      with and assess the legitimacy by comparing the received security hash with another one that
#      is generated each time locally.
#
# PROCESS: The main goal of this class is to generate a "Host" object that will be used to represent
#      a distant host with which the server is communicating.
#      The requests are counted as follows in the "number" value:
#      number is always equal to the number of requests that were declared legitimate PREVIOUSLY:
#          1. The first client request is calculated using number = 0
#          2. The server calculates the hash with number = 0 and the time put in the header
#          3. The server replies with a new security hash generated using number = 1 (one request was acknowledged as legitimate)
#          4. The client application calculates a security hash using number = 1 (only one request was acknowledged as legitimate)
#          5. The client application calculates a security hash usingnumber = 2 (two requests were declared legitimate)
#          6. The server receives a request and calculates a security hash using number = 2
#          ...
class host:
    ip = ""
    time = ""
    number = 0

    def __init__(self, ip, time, number):
        self.ip = ip
        self.time = time
        self.number = number
    
    def generateHash(self):
        print("TIME: " + self.time)
        print("NUMBER: " + str(self.number))
        timeHash = hashlib.sha256(self.time.encode()).hexdigest()
        toHash = timeHash.encode() + str(self.number).encode()
        checksum = hashlib.sha256(toHash).hexdigest()
        return(checksum)
    
    def increment(self):
        self.number += 1

hostsA = [] #List of hosts that sent a request to /hostA
hostsB = [] #List of hosts that sent a request to /hostB

# FUNCTION: respond((host) targetHost, (string) originPage, (bool) legit)
# RETURNS: Flask response with the appropriate security header (depending on whether the request
#          was acknowledged as a legitimate one) and a brief comment
# PARAMETERS:
#       - (host) targetHost: the Host to which the response must be sent
#       - (string) originPage: the page to which the host sent the request
#       - (bool) legit: the result of the security assessment of the request
#
# AIM: Generate the appropriate response to a request given the result of the security assessment
# of the said request
#
# PROCESS:
#       1. Check if the request is a legitimate one
#       2. If it is:
#           A. Increment the number of acknowledged requests for the targetHost to be able to
#              generate a correct response.
#           B. Add a brief comment to the response so that the client application can log the
#              event and notify the user
#           C. Generate the Flask response
#           D. Add the required checksum to the response
#           E. Increment the number of legitimate requests that were exchanged with the host
#       3. If it is not:
#           A. Add a brief comment to the response so that the client application can log the
#              event and notify the user
#           B. Generate the Flask response
#           C. Replace the correct checksum with another one to avoid any attempt to guess
#              what should be the content of the hash (thus preventing an attacker to catch
#              it and impersonate the user)
#       4. Return the Flask Response
def respond(targetHost, originPage, legit):
    global app
    if(legit): #STEP 1
        targetHost.increment() #STEP 2.A
        responseStr = "Host " + originPage + " - GRANTED - Packet no: " + str(targetHost.number) #STEP 2.B
        response = Flask.make_response(app, responseStr) #STEP 2.C
        response.headers['X-CheckSum'] = targetHost.generateHash() #STEP 2.D
        targetHost.increment() #STEP 2.E
    else:
        responseStr = "Host " + originPage + "- DENIED" #STEP 3.A
        response = Flask.make_response(app, responseStr) #STEP 3.B
        response.headers['X-CheckSum'] = "[YOU ARE NOT GETTING IT]" #STEP 3.C
    return response #STEP 4


########################################## GENERAL PROCESS FOR APPROUTES ##########################################
# Both approutes (or pages) accept 'GET' and 'POST' requests. Each page represents what would be a different host #
# in real life, as simulating various IPs at the same time was a difficult task that was not necessary in the con #
# -text of this experimentation                                                                                   #
#                                                                                                                 #
# The process is exactly the same for the two approutes, the only exception being that one is using the host list #
# hostsA when the other uses hostsB.                                                                              #
#                                                                                                                 #
#                                                       PROCESS                                                   #
# 1. Extract the necessary information (i.e., the ip address and the content of the X-Time-Sent header) from the  #
#    request                                                                                                      #
# 2. Look for the host in the list of saved hosts                                                                 #
# 3. If the host never contacted the approute, create an instance of the host class using the ip address and the  #
#    supplied time of the first request, then add it to the relevant hosts list                                   #
# 4. Generate a local checksum to be compared with the one sent by the client application                         #
# 5. Retrieve the value of the client checksum                                                                    #
# 6. Evaluate the request's security and call the method "respond" to generate the response                       #
###################################################################################################################


@app.route('/hostA', methods=['GET','POST'])
def resultA():
    global hostsA
    present = False
    ipAddr = request.remote_addr
    timeSent = request.headers.get('X-Time-Sent')
    for computer in hostsA:
        if computer.ip == ipAddr:
            present = True
            tempHost = computer
            break
    if(not(present)):
        print("Adding this host to A's list: ", ipAddr)
        tempHost = host(ipAddr, timeSent, 0)
        print("IP: ", ipAddr, " TIME : ", timeSent)
        hostsA.append(tempHost)
    expectedChecksum = str(tempHost.generateHash())
    receivedChecksum = str(request.headers.get('X-CheckSum'))
    checked = (expectedChecksum == receivedChecksum)
    return respond(tempHost, "A", checked)
    
@app.route('/hostB', methods=['GET','POST'])
def resultB():
    global hostsB
    present = False
    ipAddr = request.remote_addr
    timeSent = request.headers.get('X-Time-Sent')
    for computer in hostsB:
        if computer.ip == ipAddr:
            present = True
            tempHost = computer
            break
    if(not(present)):
        print("Adding this host to B's list: ", ipAddr)
        tempHost = host(ipAddr, timeSent, 0)
        print("IP: ", ipAddr, " TIME : ", timeSent)
        hostsB.append(tempHost)
    expectedChecksum = str(tempHost.generateHash())
    receivedChecksum = str(request.headers.get('X-CheckSum'))
    checked = (expectedChecksum == receivedChecksum)
    return respond(tempHost, "B", checked)

########################################## FLASK PARAMETERS ##########################################
# Two things were necessary to allow for a decent realism level in this experimentation              #
#       1. The connexion had to use the HTTPS protocol, which implies to use certificates            #
#       2. The IP address of the webserver had to be a static value, so that it could be apparented  #
#          to a real webserver                                                                       #
#                                                                                                    #
# Thus, the app is running with the following parameters:                                            #
#       - HOST = 192.168.0.17 (local IP of the PC used for the experimentation                       #
#       - SSL_CONTEXT: The server certificate (signed by the RootFiddler certificate using OpenSSL   #
#                      and the server private key are located in the "certs" folder of the working   #
#                      directory of this Flask web application                                       #
######################################################################################################
if __name__ == "__main__":
    app.run(host="192.168.0.17", ssl_context=("c:/Users/drahi/Desktop/Warwick/Dissertation-UNSYNC/PythonServer/certs/serverCert.pem","c:/Users/drahi/Desktop/Warwick/Dissertation-UNSYNC/PythonServer/certs/serverKey.pem"))
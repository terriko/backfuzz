import sys,socket,select,time,errno,base64

###################################################################################

def fileWrite(file,pattern):
	try:
		fileHandle = open(file, 'w')
		fileHandle.write(pattern)
		fileHandle.close()
	except:
		print "\n[-] Invalid directory or directory doesn't exist"
		exitProgram(4)

def fileInput(message):
	print message + "\n"
	user_input = ''
	try:
		while(1):
			user_input = user_input + raw_input()
			user_input = user_input + "\n"
	except KeyboardInterrupt:
			return user_input

###################################################################################

def fuzzUser(host,port,minim,maxm,salt,timeout,user,prot):
	printCommand(user)
	for length in range(minim, maxm+1, salt):
		payloadCount(minim,maxm,length)			
		pattern = createPattern(length)
		pattern = addCommandPattern(user,0,pattern) 
		sock = createSocketTCP(host,port,prot,pattern,length,timeout)
		sendDataTCP(sock,host,port,prot,pattern,length,timeout,1)

def fuzzPass(host,port,minim,maxm,salt,timeout,username,user,passwd,prot):
	printCommand(passwd)
	for length in range(minim, maxm+1, salt):
		payloadCount(minim,maxm,length)
		pattern = createPattern(length)
		pattern = addCommandPattern(passwd,0,pattern)
		sock = createSocketTCP(host,port,prot,pattern,length,timeout)
		sendCredential(sock,user,username,timeout)
		sendDataTCP(sock,host,port,prot,pattern,length,timeout,1)

###################################################################################

def fuzzTCP(host,port,minim,maxm,salt,timeout,prot):
		printCommand("TCP Socket")
		for length in range(minim, maxm+1, salt):
			payloadCount(minim,maxm,length)			
			pattern = createPattern(length)
			sock = createSocketTCP(host,port,prot,pattern,length,timeout)
			sendDataTCP(sock,host,port,prot,pattern,length,timeout,1)

def fuzzUDP(host,port,minim,maxm,salt,timeout,prot):
		printCommand("UDP Socket")
		for length in range(minim, maxm+1, salt):
			payloadCount(minim,maxm,length)			
			pattern = createPattern(length)
			sock = createSocketUDP(host,port,prot,pattern,length,timeout)
			sendDataUDP(sock,host,port,prot,pattern,pattern,length,timeout,1)

###################################################################################

def addCommandPattern(command,endcommand,pattern):
    return (str(command) + " " + str(pattern))

def addCommandNoSpace(command,endcommand,pattern):
    return (str(command) + str(pattern))

def addCommandPatternEmail(command,endcommand,pattern):
    return (str(command) + " " + "backfuzz@" + str(pattern) + ".com")
 
def addDoubleCommand(command,endcommand,pattern):
    return (str(command) + " " + str(pattern) + " " + str(endcommand))

def addDoubleCommandNoSpace(command,endcommand,pattern):
    return (str(command) + str(pattern) + " " + str(endcommand))


def fuzzCommands(sock,host,port,prot,minim,maxm,salt,timeout,commands,endcommand,type):
	for i in range(0,len(commands)):
		printCommand(commands[i])
		for length in range(minim, maxm+1, salt):
			payloadCount(minim,maxm,length)
			pattern = createPattern(length)
			Switch = { 
			"SingleCommand":addCommandPattern,
			"SingleCommandNoSpace":addCommandNoSpace,
			"Email":addCommandPatternEmail,
			"DoubleCommand":addDoubleCommand,
			"DoubleCommandNoSpace":addDoubleCommandNoSpace 
			}
 			pattern = Switch[type](commands[i],endcommand,pattern)
			if i == (len(commands) - 1) and (length+salt) > maxm:
				sendDataTCP(sock,host,port,prot,pattern,length,timeout,1)
			else:
				sendDataTCP(sock,host,port,prot,pattern,length,timeout,0)


###################################################################################

def createSocketTCP(host,port,prot,pattern,length,timeout):
	try:
		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		sock.settimeout(timeout)
		sock.connect((host, port))
		return sock
	except KeyboardInterrupt:
		exitProgram(6)
	except socket.error, err:
		error = err[0]
		if error == errno.ECONNREFUSED:
			print "[!] We got a connection refused, the service almost certainly crashed"
			showPayload(host,port,prot,pattern,length)
	except:
		print "[!] Another socket error, the service almost certainly crashed"
		showPayload(host,port,prot,pattern,length)

def sendDataTCP(sock,host,port,prot,pattern,length,timeout,close):
	try:
		time.sleep(timeout)
		sock.settimeout(timeout)
		pattern = pattern + "\r\n"
		sock.send(pattern)
		sock.recv(4096)
		if close == 1:
			sock.close()
		else:
			pass
	except KeyboardInterrupt:
		exitProgram(6)
	except socket.error, err:
		error = err[0]
		if error == errno.EPIPE:
			print "\n[!] We got a broken pipe, that is a *possible* crash. Checking if it really crashed ..."
			check_conn = createSocketTCP(host,port,prot,pattern,length,timeout)
			print "[!] The service has not really crashed, continuing fuzzing ...\n"
		if error == errno.ECONNREFUSED:
			print "\n[!] We got a connection refused, the service almost certainly crashed"
			showPayload(host,port,prot,pattern,length)
	except:
		print "[!] Another socket error, the service almost certainly crashed"
		showPayload(host,port,prot,pattern,length)

###################################################################################

def createSocketUDP(host,port,prot,pattern,length,timeout):
	try:
		sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		sock.settimeout(timeout)
		sock.connect((host, port))
		return sock
	except KeyboardInterrupt:
		exitProgram(6)
	except socket.error, err:
		error = err[0]
		if error == errno.ECONNREFUSED:
			print "\n[!] We got a connection refused, the service almost certainly crashed"
			showPayload(host,port,prot,pattern,length)
	except:
		print "[!] Another socket error, the service almost certainly crashed"
		showPayload(host,port,prot,pattern,length)

def sendDataUDP(sock,host,port,prot,pattern,spattern,length,timeout,close):
	try:
		time.sleep(timeout)
		sock.settimeout(timeout)
		sock.send(pattern)
		sock.recv(4096)
		if close == 1:
			sock.close()
		else:
			pass
	except KeyboardInterrupt:
		exitProgram(6)
	except socket.error, err:
		error = err[0]
		if error == errno.ECONNREFUSED:
			print "\n[!] We got a connection refused, the service almost certainly crashed"
			showPayload(host,port,prot,spattern,length)
	except:
		print "[!] Another socket error, the service almost certainly crashed"
		showPayload(host,port,prot,spattern,length)

###################################################################################

def sendCredential(sock,command,login,timeout):
	try:
		data = str(command) + " " + str(login) + "\r\n"
		sock.send(data)
	except:
		exitProgram(5)

def checkDefaultUser(username,password):
	if username == '':
		username = "anonymous"
	if password == '':
		password = "anonymous@test.com"
	else:
		pass
	return username,password

def createUser():
	try:
		username = raw_input("[!] Insert username (default: anonymous)> ")
		password = raw_input("[!] Insert password (default: anonymous@test.com)> ")
	except KeyboardInterrupt:
		exitProgram(6)
	return checkDefaultUser(username,password)

###################################################################################

def showPayload(host,port,prot,pattern,length):
	print "\n########################################"
	print "\nPayload details:\n================"
	print "Host: " + host
	print "Port: " + str(port)
	print "Type: " + prot
	print "Connection refused at: " + str(length)
	print "Payload: "
	print pattern
	print "########################################"
	exitProgram(4)

def printCommand(command):
	print "\n[!] " + str(command) + " fuzzing ...\n"

def payloadCount(minim,maxm,pos):
	print "MIN: " + str(minim) + " MAX: " + str(maxm) + " Giving it with: " + str(pos)

def exitProgram(code):
	if code==1:
		sys.exit("\n[!] Exiting help ...")
	if code==2:
		sys.exit("\n[!] End of fuzzing, exiting ...")
	if code==3:
		sys.exit("\n[-] Check your arguments, exiting with errors ...")
	if code==4:
		sys.exit("\n[!] Exiting ...")
	if code==5:
		sys.exit("\n[-] Error sending credentials, exiting ...")
	if code==6:
		sys.exit("\n[!] Keyboard Interrupt, exiting ...")

###################################################################################

def strToInt(convert,typeParam):
	try:
		value = int(convert)
		return value
	except:
		print "Number given in " + typeParam + " is invalid"
		exitProgram(3)

def strToFloat(convert,typeParam):
	try:
		value = float(convert)
		return value
	except:
		print "Number given in " + typeParam + " is invalid"
		exitProgram(3)

def checkMinMax(min,max):
	if min >= max:
		print "\n[-] MIN >= MAX"
		exitProgram(3)

###################################################################################

# Taken from mona.py / http://redmine.corelan.be/projects/mona , Copyright (c) 2011, Corelan GCV
def createPattern(size,args={}):
	char1="ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	char2="abcdefghijklmnopqrstuvwxyz"
	char3="0123456789"

	if "extended" in args:
		char3 += ",.;+=-_!&()#@'({})[]%"	# ascii, 'filename' friendly
	
	if "c1" in args:
		if args["c1"] != "":
			char1 = args["c1"]
	if "c2" in args:
		if args["c2"] != "":
			char2 = args["c2"]
	if "c3" in args:
		if args["c3"] != "":
			char3 = args["c3"]

	charcnt=0
	pattern=""
	max=int(size)
	while charcnt < max:
		for ch1 in char1:
			for ch2 in char2:
				for ch3 in char3:
					if charcnt<max:
						pattern=pattern+ch1
						charcnt=charcnt+1
					if charcnt<max:
						pattern=pattern+ch2
						charcnt=charcnt+1
					if charcnt<max:
						pattern=pattern+ch3
						charcnt=charcnt+1
	return pattern

###################################################################################
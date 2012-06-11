import sys,socket,select,time,errno,base64,random,globalvars

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

def fuzzUser(user):
	printCommand(user)
	for length in range(globalvars.minim, globalvars.maxm+1, globalvars.salt):
		payloadCount(length)			
		pattern = createPattern(length)
		pattern = addCommandPattern(user,0,pattern) 
		sock = createSocketTCP(pattern,length)
		sendDataTCP(sock,pattern,length,1)

def fuzzPass(username,user,passwd):
	printCommand(passwd)
	for length in range(globalvars.minim, globalvars.maxm+1, globalvars.salt):
		payloadCount(length)
		pattern = createPattern(length)
		pattern = addCommandPattern(passwd,0,pattern)
		sock = createSocketTCP(pattern,length)
		sendCredential(sock,user,username,timeout)
		sendDataTCP(sock,pattern,length,1)

###################################################################################

def fuzzTCP():
		printCommand("TCP Socket")
		for length in range(globalvars.minim, globalvars.maxm+1, globalvars.salt):
			payloadCount(length)			
			pattern = createPattern(length)
			sock = createSocketTCP(pattern,length)
			sendDataTCP(sock,pattern,length,1)

def fuzzUDP():
		printCommand("UDP Socket")
		for length in range(globalvars.minim, globalvars.maxm+1, globalvars.salt):
			payloadCount(length)			
			pattern = createPattern(length)
			sock = createSocketUDP(pattern,length)
			sendDataUDP(sock,pattern,pattern,length,1)

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


def fuzzCommands(sock,commands,endcommand,type):
	for i in range(0,len(commands)):
		printCommand(commands[i])
		for length in range(globalvars.minim, globalvars.maxm+1, globalvars.salt):
			payloadCount(length)
			pattern = createPattern(length)
			Switch = { 
			"SingleCommand":addCommandPattern,
			"SingleCommandNoSpace":addCommandNoSpace,
			"Email":addCommandPatternEmail,
			"DoubleCommand":addDoubleCommand,
			"DoubleCommandNoSpace":addDoubleCommandNoSpace 
			}
 			pattern = Switch[type](commands[i],endcommand,pattern)
			if i == (len(commands) - 1) and (length+globalvars.salt) > globalvars.maxm:
				sendDataTCP(sock,pattern,length,1)
			else:
				sendDataTCP(sock,pattern,length,0)


###################################################################################

def createSocketTCP(pattern,length):
	try:
		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		sock.settimeout(globalvars.timeout)
		sock.connect((globalvars.host, globalvars.port))
		return sock
	except KeyboardInterrupt:
		exitProgram(6)
	except socket.error, err:
		error = err[0]
		if error == errno.ECONNREFUSED:
			print "[!] We got a connection refused, the service almost certainly crashed"
			showPayload(pattern,length)
	except:
		print "[!] Another socket error, the service almost certainly crashed"
		showPayload(pattern,length)

def sendDataTCP(sock,pattern,length,close):
	try:
		time.sleep(globalvars.timeout)
		sock.settimeout(globalvars.timeout)
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
			check_conn = createSocketTCP(pattern,length)
			print "[!] The service has not really crashed, continuing fuzzing ...\n"
		if error == errno.ECONNREFUSED:
			print "\n[!] We got a connection refused, the service almost certainly crashed"
			showPayload(pattern,length)
	except:
		print "[!] Another socket error, the service almost certainly crashed"
		showPayload(pattern,length)

###################################################################################

def createSocketUDP(pattern,length):
	try:
		sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		sock.settimeout(globalvars.timeout)
		sock.connect((globalvars.host, globalvars.port))
		return sock
	except KeyboardInterrupt:
		exitProgram(6)
	except socket.error, err:
		error = err[0]
		if error == errno.ECONNREFUSED:
			print "\n[!] We got a connection refused, the service almost certainly crashed"
			showPayload(pattern,length)
	except:
		print "[!] Another socket error, the service almost certainly crashed"
		showPayload(pattern,length)

def sendDataUDP(sock,pattern,spattern,length,close):
	try:
		time.sleep(globalvars.timeout)
		sock.settimeout(globalvars.timeout)
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
			showPayload(spattern,length)
	except:
		print "[!] Another socket error, the service almost certainly crashed"
		showPayload(spattern,length)

###################################################################################

def sendCredential(sock,command,login):
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

def showPayload(pattern,length):
	print "\n######################################################################################"
	print "\nPayload details:\n================\n"
	print "Host: " + globalvars.host
	print "Port: " + str(globalvars.port)
	print "Type: " + globalvars.plugin_use
	print "Connection refused at: " + str(length)
	print "\nPayload:\n========\n"
	print pattern
	print "\n######################################################################################"
	exitProgram(4)

def printCommand(command):
	print "\n[!] " + str(command) + " fuzzing ...\n"

def payloadCount(pos):
	print "MIN: " + str(globalvars.minim) + " MAX: " + str(globalvars.maxm) + " Giving it with: " + str(pos)

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

# Colors for terminal
class colors:
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    RED = '\033[91m'
    ENDC = '\033[0m'

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

def checkFlavour(flavour):
	flavour_list = ["Cyclic", "CyclicExtended", "Single", "FormatString"]
	if flavour not in flavour_list:
		print "\n[-] Pattern-Flavour " + str(flavour) + " doesn't exist, check help"
		exitProgram(3)

###################################################################################

def createPatternSingle(size):
	return "A" * size


def createPatternFormat(size):
	pattern = ''
	for cont in range(1,size+1):
		pattern += "%" + random.choice('snx')
	return pattern


# Taken from mona.py / http://redmine.corelan.be/projects/mona , Copyright (c) 2011, Corelan GCV
def createPatternCyclic(size):
	
	char1="ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	char2="abcdefghijklmnopqrstuvwxyz"
	char3="0123456789"

	if globalvars.pattern_flavour == "CyclicExtended":
		char3 += ",.;+=-_!&()#@'({})[]%"	# ascii, 'filename' friendly
	
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

def createPattern(size):
	
	Switch = { 
			"Cyclic":createPatternCyclic,
			"CyclicExtended":createPatternCyclic,
			"Single":createPatternSingle,
			"FormatString":createPatternFormat,
			}
	
	pattern = Switch[globalvars.pattern_flavour](size)
	return pattern

###################################################################################

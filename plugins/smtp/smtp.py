import sys
from functions import *
"""SMTP Fuzzer"""
PROPERTY={}
PROPERTY['PROTOCOL']="SMTP"
PROPERTY['NAME']=": SMTP Fuzzer"
PROPERTY['DESC']="Fuzz an SMTP server"
PROPERTY['AUTHOR']='localh0t'

stage_1 = ['HELO','EHLO']
stage_2 = ['MAIL From:']
stage_3 = ['VRFY','EXP','AUTH PLAIN']
stage_4 = ['RCPT To:']
stage_5 = ['SIZE=', 'DATA']
special_stages = ['AUTH LOGIN','AUTH CRAM-MD5','AUTH CRAM-SHA1']

class FuzzerClass:
	def fuzzer(self,host,port,minim,maxm,salt,timeout):
		(username,password) = createUser()
		# Stage 0
		fuzzTCP(host,port,minim,maxm,salt,timeout,"SMTP")
		# Stage 1
		sock = createSocketTCP(host,port,"SMTP",0,0,timeout)
		fuzzCommands(sock,host,port,"SMTP",minim,maxm,salt,timeout,stage_1,0,"SingleCommand")
		# Stage 2
		sock = createSocketTCP(host,port,"SMTP",0,0,timeout)
		sendCredential(sock,"HELO","localh0t",timeout)
		sendCredential(sock,"AUTH LOGIN","",timeout)
		sendDataTCP(sock,host,port,"SMTP",base64.b64encode(username),0,timeout,0)
		sendDataTCP(sock,host,port,"SMTP",base64.b64encode(password),0,timeout,0)
		fuzzCommands(sock,host,port,"SMTP",minim,maxm,salt,timeout,stage_2,0,"Email")
		# Stage 3
		sock = createSocketTCP(host,port,"SMTP",0,0,timeout)
		sendCredential(sock,"HELO","localh0t",timeout)
		sendCredential(sock,"AUTH LOGIN","",timeout)
		sendDataTCP(sock,host,port,"SMTP",base64.b64encode(username),0,timeout,0)
		sendDataTCP(sock,host,port,"SMTP",base64.b64encode(password),0,timeout,0)
		fuzzCommands(sock,host,port,"SMTP",minim,maxm,salt,timeout,stage_3,0,"SingleCommand")
		# Stage 4
		sock = createSocketTCP(host,port,"SMTP",0,0,timeout)
		sendCredential(sock,"HELO","localh0t",timeout)
		sendCredential(sock,"AUTH LOGIN","",timeout)
		sendDataTCP(sock,host,port,"SMTP",base64.b64encode(username),0,timeout,0)
		sendDataTCP(sock,host,port,"SMTP",base64.b64encode(password),0,timeout,0)
		sendCredential(sock,"MAIL From:","backfuzz@localh0t.com.ar",timeout)
		fuzzCommands(sock,host,port,"SMTP",minim,maxm,salt,timeout,stage_4,0,"Email")
		# Stage 5
		sock = createSocketTCP(host,port,"SMTP",0,0,timeout)
		sendCredential(sock,"EHLO","localh0t",timeout)
		sendCredential(sock,"AUTH LOGIN","",timeout)
		sendDataTCP(sock,host,port,"SMTP",base64.b64encode(username),0,timeout,0)
		sendDataTCP(sock,host,port,"SMTP",base64.b64encode(password),0,timeout,0)
		sendCredential(sock,"MAIL From:","<backfuzz@localh0t.com.ar>",timeout)
		sendCredential(sock,"RCPT To:","<null@fuzz.com>",timeout)
		fuzzCommands(sock,host,port,"SMTP",minim,maxm,salt,timeout,stage_5,0,"SingleCommand")
		# Special Stages
		for command in special_stages:
			printCommand(command)
			for length in range(minim, maxm+1 ,salt):
			 	pattern = base64.b64encode(createPattern(length))	
			 	payloadCount(minim,maxm,length)	
 				sock = createSocketTCP(host,port,"SMTP",pattern,length,timeout)
 				sendCredential(sock,"EHLO","localh0t",timeout)
				sendCredential(sock,command,"",timeout)
				if command == 'AUTH LOGIN':
					sendDataTCP(sock,host,port,"SMTP",pattern,length,timeout,0)
				sendDataTCP(sock,host,port,"SMTP",pattern,length,timeout,1)
		exitProgram(2)
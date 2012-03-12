import sys
from functions import *
"""IMAP Fuzzer"""
PROPERTY={}
PROPERTY['PROTOCOL']="IMAP"
PROPERTY['NAME']=": IMAP Fuzzer"
PROPERTY['DESC']="Fuzz an IMAP server"
PROPERTY['AUTHOR']='localh0t'

user_stage = ['. login']
pass_stage = ['. login anonymous@test.com']
stage_1 = ['. list ""','. lsub ""', '. status INBOX','. examine','. select','. create','. delete', '. rename INBOX','. fetch 1','. store 1 flags', '. copy 1:2','. subscribe','. unsubscribe','. getquotaroot','. getacl']
stage_2 = ['. list', '. status','. rename','. fetch','. store 1','. copy','. lsub']
stage_3 = ['. store']

class FuzzerClass:
	def fuzzer(self,host,port,minim,maxm,salt,timeout):
		(username,password) = createUser()
		# Stage 0
		fuzzTCP(host,port,minim,maxm,salt,timeout,"IMAP")
		# User Stage
		sock = createSocketTCP(host,port,"IMAP",0,0,timeout)
		fuzzCommands(sock,host,port,"IMAP",minim,maxm,salt,timeout,user_stage,"test","DoubleCommand")
		# Pass Stage
		sock = createSocketTCP(host,port,"IMAP",0,0,timeout)
		fuzzCommands(sock,host,port,"IMAP",minim,maxm,salt,timeout,pass_stage,0,"SingleCommand")
		# Stage 1
		login = ". login " + str(username)
		sock = createSocketTCP(host,port,"IMAP",0,0,timeout)
		sendCredential(sock,login,password,timeout)
		fuzzCommands(sock,host,port,"IMAP",minim,maxm,salt,timeout,stage_1,0,"SingleCommand")
		# Stage 2
		sock = createSocketTCP(host,port,"IMAP",0,0,timeout)
		sendCredential(sock,login,password,timeout)
		fuzzCommands(sock,host,port,"IMAP",minim,maxm,salt,timeout,stage_2,1,"DoubleCommand")
		# Stage 3
		sock = createSocketTCP(host,port,"IMAP",0,0,timeout)
		sendCredential(sock,login,password,timeout)
		fuzzCommands(sock,host,port,"IMAP",minim,maxm,salt,timeout,stage_3,"+flags NonJunk","DoubleCommand")
		exitProgram(2)
from functions import *
"""POP3 Fuzzer"""
PROPERTY={}
PROPERTY['PROTOCOL']="POP3"
PROPERTY['NAME']=": POP3 Fuzzer"
PROPERTY['DESC']="Fuzz an POP3 server"
PROPERTY['AUTHOR']='localh0t'

commands = ['STAT','LIST','RETR','DELE','RSET','TOP','TOP 1','RPOP','RPOP test','APOP','APOP test']

class FuzzerClass:
	def fuzzer(self,host,port,minim,maxm,salt,timeout):
		(username,password) = createUser()
		fuzzTCP(host,port,minim,maxm,salt,timeout,"POP3")
		fuzzUser(host,port,minim,maxm,salt,timeout,"USER","POP3")
		fuzzPass(host,port,minim,maxm,salt,timeout,username,"USER","PASS","POP3")
		sock = createSocketTCP(host,port,"POP3",0,0,timeout)
		sendCredential(sock,"USER",username,timeout)
		sendCredential(sock,"PASS",password,timeout)
		fuzzCommands(sock,host,port,"POP3",minim,maxm,salt,timeout,commands,0,"SingleCommand")
		exitProgram(2)




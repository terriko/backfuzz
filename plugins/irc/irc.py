import sys
from functions import *
"""IRC Fuzzer"""
PROPERTY={}
PROPERTY['PROTOCOL']="IRC"
PROPERTY['NAME']=" : IRC Fuzzer "
PROPERTY['DESC']="Fuzz an IRC server "
PROPERTY['AUTHOR']='localh0t'

nick_stage = ['NICK']

user_stage_1 = ['USER ident test1 test2']
user_stage_2 = ['USER ident test1']
user_stage_3 = ['USER ident']

stage_1 = ['ACCEPT','ADMIN','AWAY','CAP REQ','CHALLENGE','CMODE','CNOTICE','CPRIVMSG','CREDITS','ERROR','EXTBAN','HELP','INDEXINFO','INVITE','ISON',
		   'KICK','KNOCK','LINKS','LIST','LUSERS','MAP','MOTD','NAMES','NOTICE','OPER','PASS','PING','PONG','PRIVMSG #ctest','STATS','TIME','TRACE',
		   'UMODE','USERHOST','VERSION','WHO #ctest','WHOIS','WHOWAS']

stage_2 = ['CAP', 'WHO', 'PRIVMSG']

numeral_stage = ['JOIN #' , 'MODE #', 'WHO #', 'PRIVMSG #', 'TOPIC #', 'USERS #', 'PART #']

class FuzzerClass:
	def fuzzer(self,host,port,minim,maxm,salt,timeout):
		# Stage 0
		fuzzTCP(host,port,minim,maxm,salt,timeout,"IRC")
		# Nick Stage
		sock = createSocketTCP(host,port,"IRC",0,0,timeout)
		fuzzCommands(sock,host,port,"IRC",minim,maxm,salt,timeout,nick_stage,0,"SingleCommand")
		# User Stages
		sock = createSocketTCP(host,port,"IRC",0,0,timeout)
		sendCredential(sock,"NICK","test",timeout)
		fuzzCommands(sock,host,port,"IRC",minim,maxm,salt,timeout,user_stage_1,0,"SingleCommand")
		fuzzCommands(sock,host,port,"IRC",minim,maxm,salt,timeout,user_stage_2,"test3","DoubleCommand")
		fuzzCommands(sock,host,port,"IRC",minim,maxm,salt,timeout,user_stage_3,"test2 test3","DoubleCommand")
		# Stage 1
		sock = createSocketTCP(host,port,"IRC",0,0,timeout)
		sendCredential(sock,"NICK","test",timeout)
		sendCredential(sock,"USER ident","test1 test2 test3",timeout)
		sendCredential(sock,"JOIN","#ctest",timeout)
		fuzzCommands(sock,host,port,"IRC",minim,maxm,salt,timeout,stage_1,0,"SingleCommand")
		# Stage 2
		sock = createSocketTCP(host,port,"IRC",0,0,timeout)
		sendCredential(sock,"NICK","test",timeout)
		sendCredential(sock,"USER ident","test1 test2 test3",timeout)
		sendCredential(sock,"JOIN","#ctest",timeout)
		fuzzCommands(sock,host,port,"IRC",minim,maxm,salt,timeout,stage_2,1,"DoubleCommand")
		# Numeral Stage
		sock = createSocketTCP(host,port,"IRC",0,0,timeout)
		sendCredential(sock,"NICK","test",timeout)
		sendCredential(sock,"USER ident","test1 test2 test3",timeout)
		fuzzCommands(sock,host,port,"IRC",minim,maxm,salt,timeout,numeral_stage,0,"SingleCommandNoSpace")
		exitProgram(2)

from functions import *
"""Telnet Fuzzer"""
PROPERTY={}
PROPERTY['PROTOCOL']="TNET"
PROPERTY['NAME']=": Telnet Fuzzer"
PROPERTY['DESC']="Fuzz a Telnet server"
PROPERTY['AUTHOR']='localh0t'

class FuzzerClass:
	def fuzzer(self,host,port,minim,maxm,salt,timeout):
		fuzzTCP(host,port,minim,maxm,salt,timeout,"TNET")
		fuzzUser(host,port,minim,maxm,salt,timeout,"USER","TNET")
		fuzzPass(host,port,minim,maxm,salt,timeout,"test","USER","PASS","TNET")
		exitProgram(2)
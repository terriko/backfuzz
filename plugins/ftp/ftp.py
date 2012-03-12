from functions import *
"""FTP Fuzzer"""
PROPERTY={}
PROPERTY['PROTOCOL']="FTP"
PROPERTY['NAME']=" : FTP Fuzzer "
PROPERTY['DESC']="Fuzz an FTP server "
PROPERTY['AUTHOR']='localh0t'

commands = ['ABOR','ACCT','ALLO','APPE','AUTH','CWD','CDUP','DELE','FEAT','HELP','HOST','LANG','LIST',
			'MDTM','MKD','MLST','MODE','NLST','NLST -al','NOOP','OPTS','PASV','PORT','PROT','PWD','REIN',
			'REST','RETR','RMD','RNFR','RNTO','SIZE','SITE','SITE CHMOD','SITE CHOWN','SITE EXEC','SITE MSG',
			'SITE PSWD','SITE ZONE','SITE WHO','SMNT','STAT','STOR','STOU','STRU','SYST','TYPE','XCUP',
			'XCRC','XCWD','XMKD','XPWD','XRMD']


class FuzzerClass:
	def fuzzer(self,host,port,minim,maxm,salt,timeout):
		(username,password) = createUser()
		fuzzTCP(host,port,minim,maxm,salt,timeout,"FTP")
		fuzzUser(host,port,minim,maxm,salt,timeout,"USER","FTP")
		fuzzPass(host,port,minim,maxm,salt,timeout,username,"USER","PASS","FTP")
		sock = createSocketTCP(host,port,"FTP",0,0,timeout)
		sendCredential(sock,"USER",username,timeout)
		sendCredential(sock,"PASS",password,timeout)
		fuzzCommands(sock,host,port,"FTP",minim,maxm,salt,timeout,commands,0,"SingleCommand")
		exitProgram(2)
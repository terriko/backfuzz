import time, sys, dircache
from functions import *

# Back to the FUZZ'er - protocol fuzzing toolkit
# Contact: mattdch0@gmail.com (suggerences, ideas, reviews)
# Follow: @mattdch
# Blog: www.localh0t.com.ar

VERSION = "0.2.1"

# Plugin read class
class Plugins:
	def __init__(self):
		self.plugins = []
    	def loadPlugins(self,directory):
        	filelist = dircache.listdir(directory)
        	for filename in filelist:
        		if not '.' in filename:
				sys.path.insert(0,directory + filename)
                		self.plugins += [__import__(filename)]
                		sys.path.remove(directory + filename)

listadoPlugins = Plugins()
listadoPlugins.loadPlugins("./plugins/")
listadoSpecial = Plugins()
listadoSpecial.loadPlugins("./special/")

# Start Fuzzer function
def startFuzzer(object,plugin_use,specialFlag):
	for plugin in object:
		if plugin.PROPERTY['PROTOCOL']==plugin_use:
			fuzzmaster = plugin.FuzzerClass()
			if specialFlag == 1:
				fuzzmaster.fuzzer(minim,maxm,salt,plugin_use)
			else:
				fuzzmaster.fuzzer(host,port,minim,maxm,salt,timeout)

# Show Help function
def showHelp():
	print "\n##################################################"
	print "# Back to the FUZZ'er - protocol fuzzing toolkit #"
	print "##################################################"
	print "\nVersion: " + VERSION
	print "\nUsage (Normal Plugins):\n=======================\n\npython", sys.argv[0], "-h [IP] -p [PORT] -min [START LENGHT] -max [END LENGHT] -s [SALT BETWEEN FUZZ STRINGS] -pl [PLUGIN TO USE] -t [TIMEOUT (Seconds) (Optional, default: 0.8)] \n"
	print "Usage (Special Plugins):\n========================\n\npython", sys.argv[0], "-pl [SPECIAL PLUGIN TO USE] -min [START LENGHT] -max [END LENGHT] -s [SALT BETWEEN FUZZ STRINGS] -SPECIAL \n"
	print "\nAvailable plugins:"
	print "==================\n"
	for plugin in listadoPlugins.plugins:
		print plugin.PROPERTY['PROTOCOL'], plugin.PROPERTY['NAME'], "|", plugin.PROPERTY['DESC'],"|","Author:", plugin.PROPERTY['AUTHOR']
	print "\nSpecial plugins:"
	print "================\n"
	for special in listadoSpecial.plugins:
		print special.PROPERTY['PROTOCOL'], special.PROPERTY['NAME'], "|", special.PROPERTY['DESC'],"|","Author:", special.PROPERTY['AUTHOR']

# Read Args function
def readArgs(arguments):
	count = 0
	timeout = 0.8
	for arg in arguments:
		try:
			if arg == "-h":
				host = arguments[count+1]
			elif arg == "-p":
				port = strToInt(arguments[count+1],"-p")
			elif arg == "-min":
				minim = strToInt(arguments[count+1],"-min")
			elif arg == "-max":
				maxm = strToInt(arguments[count+1],"-max")
			elif arg == "-s":
				salt = strToInt(arguments[count+1],"-s")
			elif arg == "-pl":
				plugin_use = arguments[count+1]
			elif arg == "-t":
				timeout = strToFloat(arguments[count+1],"-t")
			count+=1
		except:
			exitProgram(3)
	# Args check
	try:
		arglist = [host,port,minim,maxm,salt,plugin_use]
		checkMinMax(minim,maxm)
	except:
		exitProgram(3)

	return (host,port,minim,maxm,salt,plugin_use,timeout)

# Special Read Args function
def readArgsSpecial(arguments):
	count = 0
	for arg in arguments:
		try:
			if arg == "-min":
				minim = strToInt(arguments[count+1],"-min")
			elif arg == "-max":
				maxm = strToInt(arguments[count+1],"-max")
			elif arg == "-s":
				salt = strToInt(arguments[count+1],"-s")
			elif arg == "-pl":
				plugin_use = arguments[count+1]
			count+=1
		except:
			exitProgram(3)

	try:
		arglist = [minim,maxm,salt,plugin_use]
		checkMinMax(minim,maxm)
	except:
		exitProgram(3)

	return (minim,maxm,salt,plugin_use)


# Show Help
if len(sys.argv) <= 12 and "-SPECIAL" not in sys.argv:
	showHelp()
	exitProgram(1)

# Read Args & Start
if "-SPECIAL" in sys.argv:
	(minim,maxm,salt,plugin_use) = readArgsSpecial(sys.argv)
	startFuzzer(listadoSpecial.plugins,plugin_use,1)
else:
	(host,port,minim,maxm,salt,plugin_use,timeout) = readArgs(sys.argv)
	startFuzzer(listadoPlugins.plugins,plugin_use,0)
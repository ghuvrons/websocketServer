from Websck import *

class cSockHandler(ClientHandler):
	def onMessage(self, msg):
		print "MSG > "+msg

if __name__ == "__main__":
	ws = Websck("127.0.0.1",5000)
	ws.setClientClass(cSockHandler)
	ws.run()
	ws.close()

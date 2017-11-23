from Websck import Websck

if __name__ == "__main__":
    ws = Websck("127.0.0.1",5000)

    ws.run()

    ws.close()

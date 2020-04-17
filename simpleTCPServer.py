import socket
import threading

def Main():

    host = '127.0.0.1'
    port = 5000

    try:
        #Create socket and bind
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind((host,port))

        s.listen(1) #Allow 1 connection

        print(f"[*] Listening on {host}:{port}")

        #Server loop
        while True:
            client, addr = s.accept()

            print(f"[*] Accepted connection from {addr[0]}:{addr[1]}")

            #Create and start handler thread
            clientHandler = threading.Thread(target=handleClient, args=(client,))
            clientHandler.start()

    except Exception as e:
        print(str(e))

def handleClient(s):
    #Print data from client
    request = s.recv(1024)
    print(f"[*] Recieved {request}")

    #Send ack
    s.send(b"Ack")

    s.close()

if __name__ == '__main__':
    Main()

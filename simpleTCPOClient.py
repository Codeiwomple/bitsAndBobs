import socket
import sys

def Main():
    host = '127.0.0.1' #local host
    port = 5000
    message = "test"
    """ f"GET / HTTP/1.1\r\nHost: {host}{port}\r\n\r\n" """

    server = (host, port)

    try:
        #Create socket obj and connect
        #socket.AF_INET -> IPV4, socket.SOCK_STREAM -> TCP
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(server)

        #Send data
        s.send(message.encode('utf8'))

        #Recieve responce
        while True:
            response = s.recv(1024)
            print(response.decode('utf8'))
            if (len(response) < 1):
                break

        s.close()
        sys.exit()
    except Exception as e:
        print(str(e))
        s.close()
        sys.exit()

if __name__ == '__main__':
    Main()

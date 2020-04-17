import socket

def Main():
    host = '127.0.0.1' #Google local host
    port = 5000
    message = b"test"
    """ f"GET / HTTP/1.1\r\nHost: {host}{port}\r\n\r\n" """

    server = (host, port)

    try:
        #Create socket obj and connect
        #socket.AF_INET -> IPV4, socket.SOCK_DGRAM -> UDP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        #Send data
        s.sendto(message, server)
        print('sent')
        #Recieve responce
        response, add = s.recvfrom(4096)
        print(str(response))

    except Exception as e:
        print(str(e))

if __name__ == '__main__':
    Main()

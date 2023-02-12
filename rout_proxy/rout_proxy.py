import socket
from _thread import *
import ssl


class ProxyServer:
    
    def __init__(self) -> None:
        self.PORT = 5000
        self.NETWORK = "0.0.0.0"
        self.BUFFERSIZE = 8124

    def start(self):
        
        suscket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        suscket.bind((self.NETWORK, self.PORT))
        suscket.listen(5)
        
        print("[*] Proxy is running on {} and Port: {}".format(self.NETWORK, self.PORT))
        
        while True:
            connection, address = suscket.accept()
            data = connection.recv(self.BUFFERSIZE)
            print("[*] New connection from {}".format(address[0]))

            start_new_thread(self.get_request_data, (connection, data))
    
    def get_request_data(self, connection, data:bytes):
        data_dec = data.decode().split("\r")
        temp = data_dec[1].split(" ")[1].split(":")


        port = 80
        if len(temp) > 1:
            server, port = temp
            port = int(port)
        else:
            server = temp[0]


        if self.is_allowed(server):
            print("[*] Allowing request to {} on port: {}".format(server, port))
            start_new_thread(self.send_request_server, (server, port, data, connection))
        
    def send_request_server(self, server, port, data, client:socket.socket):
        
        if port == 443:
            ctxt = ssl.create_default_context()
            ctxt.check_hostname = True
            ctxt.verify_mode = ssl.CERT_REQUIRED
            server_sock = ctxt.wrap_socket(socket.socket(socket.AF_INET), server_hostname=server)
        else:
            server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            
        try:
            server_sock.connect((server, port))
            server_sock.sendall(data)
        except socket.gaierror as e:
            print(e)
            print("[*] Can't connect to Host")
        
        response = b''
        while True:
            reply = server_sock.recv(self.BUFFERSIZE)
            if len(reply) == 0:
                break
            response += reply
        
        client.sendall(response)
        
        print("[*] Succesfully transmitted data")
        server_sock.close()
        client.close()
        
    def is_allowed(self, server):
        return True
        
        
if __name__ == "__main__":
    ProxyServer().start()
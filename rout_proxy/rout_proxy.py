import socket
import threading
import select


SOCKS_VERSION = 5

class ProxyServer:
    
    def __init__(self) -> None:
        self.password = "password"
        self.username = "username"
    
    def handle_client(self, connection:socket.socket):
        version, nmethods = connection.recv(2)
        
        methods = self.get_available_methods(nmethods, connection)
        
        if 2 not in set(methods):
            connection.close()
            return
            
        connection.sendall(bytes([SOCKS_VERSION, 2]))
        
        if not self.verify_credentials(connection):
            return
        
        version, cmd, _, address_type = connection.recv(4)
        
        if address_type == 1:
            adress = socket.inet_ntoa(connection.recv(4))
        elif address_type == 3:
            domain_length = connection.recv(1)[0]
            adress = connection.recv(domain_length)
            adress = socket.gethostbyname(adress)
            
        port = int.from_bytes(connection.recv(2), 'big', signed=False)
        
        try:
            if cmd == 1:
                remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                remote.connect((adress, port))
                bind_adress = remote.getsockname()
                print("* CONNECTED to {} {}".format(adress, port))
            else:
                connection.close()
            address = int.from_bytes(socket.inet_aton(bind_adress[0]), 'big', signed=False)
            port = int(bind_adress[1])
            
            reply = b''.join([
                SOCKS_VERSION.to_bytes(1, 'big'),
                int(0).to_bytes(1, 'big'),
                int(0).to_bytes(1, 'big'),
                int(1).to_bytes(1, 'big'),
                address.to_bytes(4, 'big'),
                port.to_bytes(2, 'big')
            ])
        except Exception as e: #<-- Omg this is horrible
            print("* Oh no an Error!!!")
            reply = self.generate_failed_reply(address_type, 5)
        
        connection.sendall(reply)
        
        if reply[1] == 0 and cmd == 1:
            self.exchange_loop(connection, remote)
            
        connection.close()
    
    def exchange_loop(self, client:socket.socket, remote:socket.socket):
        while True:
            r, w, e = select.select([client, remote], [], [])

            if client in r:
                data = client.recv(4096)
                if not data:
                    break
                if remote.send(data) <= 0:
                    break

            if remote in r:
                data = remote.recv(4096)
                if not data:
                    break
                if client.send(data) <= 0:
                    break
                        
    
    def generate_failed_reply(address_type:int, error_number:int):
        return b''.join([
                SOCKS_VERSION.to_bytes(1, 'big'),
                error_number.to_bytes(1, 'big'),
                int(0).to_bytes(1, 'big'),
                int(1).to_bytes(1, 'big'), # <-- address_type should be set to 1
                int(0).to_bytes(1, 'big'),
                int(0).to_bytes(1, 'big')
        ])
        
    def verify_credentials(self, connection:socket.socket):
        version = ord(connection.recv(1))
        
        username_len = ord(connection.recv(1))
        username = connection.recv(username_len).decode('utf-8')
        
        password_len = ord(connection.recv(1))
        password = connection.recv(password_len).decode('utf-8')
        
        if username == self.username and password == self.password:
            response = bytes([version, 0])
            connection.sendall(response)
            return True
        
        response = bytes([version, 0xFF])
        connection.sendall(response)
        connection.close()
        return False
        
    def get_available_methods(self, nmethods, connection:socket.socket):
        methods = []
        for i in range(nmethods):
            methods.append(ord(connection.recv(1)))
        return methods
    
    def run(self, host, port):
        session = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        session.bind((host, port))
        session.listen()
        
        print("* Proxy listening on Port: {}".format(port))
        
        while True:
            connection, address = session.accept()
            print("* Got a new connection from {}".format(address))
            thread = threading.Thread(target=self.handle_client, args=(connection, ))
            thread.start()
            
if __name__ == "__main__":
    proxy = ProxyServer()
    proxy.run("0.0.0.0", 5000)
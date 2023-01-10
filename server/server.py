import socket
import random

connected_nodes = []


def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(('172.17.0.1', 12300))
        sock.listen()
        while True:
            connection, client_address = sock.accept()
            msg = connection.recv(1024)
            address = msg.decode()
            if address in connected_nodes:
                connection.send(b'0')
            else:
                addresses = ';'.join(random.sample(
                    connected_nodes,
                    min(3, len(connected_nodes))))
                m = addresses.encode(encoding='utf-8')
                connection.send(m)
                connected_nodes.append(
                    f'{client_address[0]}:{str(client_address[1])}')
            connection.close()


if __name__ == '__main__':
    main()

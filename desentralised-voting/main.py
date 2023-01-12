# import the GossipNode class
from GossipNode import GossipNode
import socket


def main():
    name = input("Enter your name: ")
    host = socket.gethostbyname(socket.gethostname())
    port = 5000

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect(('172.17.0.2', 123))
        sock.send(f'{host}:{port}'.encode(encoding='utf-8'))
        data = sock.recv(1024).decode()
        if len(data) == 0:
            to_connect = []
        else:
            str_addresses = data.split(';')
            to_connect = list(map(lambda x: x.split(':'), str_addresses))
            to_connect = list(map(lambda x: (x[0], int(x[1])), to_connect))

    if len(to_connect) == 0:
        print("You are an initiator of the voting, "
              "please write down your conditions")
        print("Voting will start and finish today")
        print("Please input time in HH:MM format.")
        enter_end_time = input("Enter end time: ")
        voting_end_time = input("Voting end time: ")
        print("Candidates:")
        candidates = []
        while True:
            candidate = input()
            if candidate == '':
                break
            candidates.append(candidate)
        node = GossipNode(host, port, to_connect, name,
                          enter_end_time, voting_end_time, candidates)
    else:
        node = GossipNode(host, port, to_connect, name)


if __name__ == '__main__':
    main()

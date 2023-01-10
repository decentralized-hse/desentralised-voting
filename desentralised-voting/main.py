# import the GossipNode class
from GossipNode import GossipNode
import requests
from time import time
import socket

# port for this node
host = socket.gethostbyname(socket.gethostname())
port = 5000
# ports for the nodes connected to this node
# to_connect = []


def main():
    # response = requests.get('http://jackalpoe.pythonanywhere.com/',
    #                         params={'input': f'{host}:{port}'})
    # nodes_to_connect = list(map(lambda x: tuple(x), response.json()['addresses']))
    nodes_to_connect = []
    name = input("Enter your name: ")
    if len(nodes_to_connect) == 0:
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
        node = GossipNode(host, port, nodes_to_connect, name,
                          enter_end_time, voting_end_time, candidates)
    else:
        node = GossipNode(host, port, nodes_to_connect, name)


if __name__ == '__main__':
    main()

# import the GossipNode class
from GossipNode import GossipNode
import requests

# port for this node
host = '127.0.0.1'
port = 5000
# ports for the nodes connected to this node
# to_connect = []


def main():
    response = requests.get('http://jackalpoe.pythonanywhere.com/',
                            params={'input': f'{host}:{port}'})
    nodes_to_connect = list(map(lambda x: tuple(x), response.json()['addresses']))
    node = GossipNode(host, port, nodes_to_connect, "first")


# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    main()

# See PyCharm help at https://www.jetbrains.com/help/pycharm/

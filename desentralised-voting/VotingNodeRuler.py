import socket
from GossipNode import GossipNode


class VotingNodeRuler:
    def __init__(self, port, host=None):
        server_address = ('127.0.0.1', 12345)
        if host is None:
            host = socket.gethostname()
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect(server_address)
            sock.send(f'{host}:{port};add'.encode(encoding='utf-8'))
            data = sock.recv(1024).decode()
            if len(data) == 0:
                to_connect = []
            else:
                str_addrs = data.split(';')
                to_connect = list(map(lambda x: x.split(':'), str_addrs))
            self.node = GossipNode(host, port, to_connect)

    def get_notifications(self):
        return self.node.enter_messages

    def answer_enter_request(self, request_sender: str, is_accepted: bool):
        self.node.enter_messages.remove(request_sender)
        if is_accepted:
            accept_vote = Vote(request_sender, str(self.node.port))
            self.node.input_message(accept_vote)
        pass


if __name__ == '__main__':
    connector = VotingNodeRuler(12345, '127.0.0.1')
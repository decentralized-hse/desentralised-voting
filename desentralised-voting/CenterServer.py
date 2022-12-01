import json
import socket
from datetime import datetime
from threading import Thread
import time


class CenterServer:
    def __init__(self, port=12345, host='127.0.0.1'):
        self.server_node = socket.socket(type=socket.SOCK_DGRAM)
        self.port = port
        self.host = host
        self.server_node.bind((self.host, self.port))
        self.move_number = 0
        self.move_time_left_sec = 4

        '''
        номер хода
        оставшееся время хода
        '''
        self.start_threads()

    def set_timer(self):
        while True:
            while self.move_time_left_sec:
                time.sleep(1)
                self.move_time_left_sec -= 1

            self.move_number += 1
            self.move_time_left_sec = 4

    def built_message(self):
        message = {'move_number': self.move_number, 'move_time_left_sec': self.move_time_left_sec}
        return json.dumps(message).encode('ascii')

    def receive_message(self):
        while True:
            message_to_forward, address = self.server_node.recvfrom(2048)
            self.server_node.sendto(self.built_message(), address)
            print('sent')

    def start_threads(self):
        Thread(target=self.receive_message).start()
        Thread(target=self.set_timer).start()


if __name__ == '__main__':
    node = CenterServer()

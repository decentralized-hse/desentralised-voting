from __future__ import annotations
from threading import Thread


class ThreadWithReturn(Thread):
    def __init__(self, function):
        Thread.__init__(self)
        self.function = function
        self.value = None

    def run(self, *args):
        self.value = self.function(*args)

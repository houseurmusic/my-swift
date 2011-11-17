# To change this template, choose Tools | Templates
# and open the template in the editor.


from subprocess import Popen
from subprocess import PIPE
from threading import Thread
import sys

#queue code from:
#http://stackoverflow.com/questions/375427/non-blocking-read-on-a-subprocess-pipe-in-python

try:
    from Queue import Queue, Empty
except ImportError:
    from queue import Queue, Empty

class My_gpg():
    ON_POSIX = 'posix' in sys.builtin_module_names 

    def __init__(self, encrypt_or_decrypt, user = None, passphrase = None):
        if(encrypt_or_decrypt[0] == 'e'):
            cmd = 'gpg -r ' + user + ' -e'
        else:
            cmd = 'gpg -d --batch --passphrase-fd 0'
        self.p = Popen(cmd, shell=True, stdin=PIPE, stdout=PIPE, stderr=PIPE, bufsize = 1024)

        self.stdin = self.p.stdin
        self.stdout = self.p.stdout

        if(encrypt_or_decrypt[0] == 'd'):
            self.stdin.write(passphrase + '\n')

        self.q = Queue()
        self.t = Thread(target = self._enqueue_output_, args = (self.stdout, self.q))
        self.t.daemon = True
        self.t.start()
        self.buffer = ""


    def _enqueue_output_(self, out, queue):
        for line in iter(out.readline, ''):
            queue.put(line)
        out.close()

    def digest(self, chunk):
        self.stdin.write(chunk)  

    def dump_buffer(self, timeout = 0):
        """Dumps any data that gpg has piped to stdout
        specify a timout to ensure that gpg has had
        enough time to digest"""
        data = ""
        while(True):
            try:
                if(self.has_buffer()):
                    data += self.q.get()
                else:
                    data += self.q.get(timeout = timeout)
            except Empty:
                break
        return data

    def has_buffer(self):
        return not self.q.empty()

    def close_and_dump(self, timeout = .1):
        self.stdin.close()
        data = self.dump_buffer(timeout)
        #self.stdout.close()
        return data

    def close(self):
        self.stdin.close()
        #self.stdout.close()
	
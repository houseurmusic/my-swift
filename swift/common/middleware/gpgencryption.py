import threading

#TODO ON SEGMENTED FILES PAD THE CHUNKS TO 64K

# Copyright (c) 2010-2011 OpenStack, LLC.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Imports used by class GPGEncryption
import sys
import traceback
import os
import time
from subprocess import Popen
from subprocess import PIPE
from threading import Thread
import threading

from asyncproc import Process

from swift.common.exceptions import ChunkReadTimeout, \
    ChunkWriteTimeout, ConnectionTimeout

#queue code from:
#http://stackoverflow.com/questions/375427/non-blocking-read-on-a-subprocess-pipe-in-python

#TODO CHECK IF BUFFER IS BEING CLOSE!

#CHUNK_SIZE MUST BE SHARED BETWEEN ALL CLASSES
CHUNK_SIZE = 65536
class GPGEncryption():

    def __init__(self, encrypt_or_decrypt, iterable = None, user = None, passphrase = None, test_branch = False):
        self.test_branch = test_branch
        print 'initing gpg'
        cmd = 'gpg -a -r ' + user + ' -e'
        #cmd = 'cat'
        self.term_char = chr(0)
        self.chunk_size = CHUNK_SIZE
        self.stream_iter = iterable
        self.stream_iter_read = iterable.read
        self.gpg_closed = False
        self.padded = False
        self.finished_read = False
        self.first_read = True
        #shared variable between threads
        self.finished_write = False
        self.p = Popen(cmd, shell=True, stdin=PIPE, stdout=PIPE, stderr=PIPE, close_fds = True, bufsize = CHUNK_SIZE)

        self.my_buffer = ''
        self.finished_write = False
        self.finished_read = False
        self.semaphore = threading.Semaphore()


    def print_errors(self):
        print self.p.readerr()

    def stringIterate(self, text, chunk_size):
        index = 0
        while index < len(text):
            yield text[index : index + chunk_size]
            index += chunk_size

    def padder(self, text, div, pad = chr(0)):
            size = (div - len(text) % div) + len(text)
            diff = size - len(text)
            text += pad * diff
            return text

    def readFromStream(self, read_size):
        chunk = self.stream_iter_read(read_size)
        while chunk:
            self.p.stdin.write(chunk)
            chunk = self.stream_iter_read(read_size)
        self.p.stdin.close()

    def read(self, read_size):
        read_size = self.chunk_size
        if self.first_read:
            self.first_read = False
            t = Thread(target = self.readFromStream, args = (read_size, ))
            t.start()
        chunk = self.p.stdout.read(read_size)
        if chunk and len(chunk) < read_size:
            chunk = self.padder(chunk, read_size)
        #print 'returning chunk = ' + chunk
        return chunk

#queue code from:
#http://stackoverflow.com/questions/375427/non-blocking-read-on-a-subprocess-pipe-in-python

try:
    from Queue import Queue, Empty
except ImportError:
    from queue import Queue, Empty

class GPGDecrypt:
    def __init__(self, passphrase, chunk_size = 65536):
        #cmd = 'cat'
        cmd = 'gpg -d --batch --passphrase-fd 0'
        ON_POSIX = 'posix' in sys.builtin_module_names
        self.passphrase = passphrase
        #should be divisible by chunk_size:
        self.buff_read_size = CHUNK_SIZE
        self.chunk_size = CHUNK_SIZE
        self.p = Popen(cmd, shell=True, stdin=PIPE, stdout=PIPE, stderr=PIPE, close_fds = True, bufsize = CHUNK_SIZE)
        self.p.stdin.write(self.passphrase + '\n')
        self.q = Queue()
        self.t = Thread(target = self._enqueue_output_, args = (self.p.stdout, self.q))
        self.t.daemon = True
        self.t.start()
        self.semaphore = threading.BoundedSemaphore()
        self.buffer = ''
        self.count = 0
    def _enqueue_output_(self, out, queue):
        #block until size of chunk is read or close
        def readChunk():
            return out.read(self.buff_read_size)
            #return out.readline()

        for chunk in iter(readChunk, b''):
            queue.put(chunk)
        self.semaphore.acquire()
        #print 'DONE READING!'
        out.close()
        self.semaphore.release()

    def digest(self, chunk):
        self.p.stdin.write(chunk)
        self.p.stdin.flush()
        
    def get_chunk(self, chunk_size = None, timeout = 0):
        try:
            chunk = self.q.get(timeout = .01)
        except Empty:
            return ''
        return chunk


    def close(self):
        self.p.stdin.close()

    def has_buffer(self):
        return not self.q.empty()

    def done(self):
        print 'in done'
        self.semaphore.acquire()
        closed = self.p.stdout.closed
        self.semaphore.release()
        print closed
        print self.q.empty()
        return closed and self.q.empty()

    
class DecryptionIterable:
    def __init__(self, response = None, user = None, passphrase = None, test_branch = False):
        #self.passphrase = passphrase
        if not passphrase:
            self.passphrase = 'test-swift'
        else:
            self.passphrase = passphrase
        self.chunk_size = CHUNK_SIZE
        self.stream_iter = response.app_iter
        self.term_char = chr(0)
        self.cmd = 'gpg -d --batch --passphrase-fd 0'
        self.iter_done = False

    def next(self):
        return iter(self).next()

    #need to optimize this!
    def stringIterate(self, text, chunk_size):
        index = 0
        while index < len(text):
            yield text[index : index + chunk_size]
            index += chunk_size


    def __iter__(self):
        gpg = GPGDecrypt(self.passphrase, self.chunk_size)
        print 'after init'
        iter_done = False
        chunk = ''
        while True:
            try:
                chunk = self.stream_iter.next()
                print 'read chunk size = ' + str(len(chunk))
            except StopIteration:
                print 'stop iter exception reached'
                iter_done = True
            if not iter_done:
                if chunk[len(chunk) - 1] == self.term_char:
                    gpg.digest(chunk)
                    gpg.close()
                    while(not gpg.done()):
                        d_chunk = gpg.get_chunk()
                        if d_chunk:
                            yield d_chunk
                    gpg = GPGDecrypt(self.passphrase, self.chunk_size)
                else:
                    gpg.digest(chunk)
                    d_chunk = gpg.get_chunk()
                    if d_chunk:
                        yield d_chunk
            else:
                while(gpg.has_buffer()):
                    d_chunk = gpg.get_chunk()
                    if d_chunk:
                        yield d_chunk
                break









#

##
##
###TODO; make semaphore with read_done and buffer length inside
###use this to know when we are done reading in the iter function!
##class DecryptionIterable:
##    def __init__(self, response = None, user = None, passphrase = None, test_branch = False):
##        self.stream_iter = response.app_iter
##        self.term_char = chr(0)
##        #self.passphrase = passphrase
##        self.passphrase = 'test-swift'
##        self.chunk_size = 65536
##
##
##    def next(self):
##        return iter(self).next()
##
##    def __iter__(self):
##        gpg = GPGDecrypt(self.passphrase, self.chunk_size)
##        gpg_final = False
##        while True:
##            try:
##                chunk = self.stream_iter.next()
##                if chunk[len(chunk) - 1] == self.term_char:
##                    chunk = chunk.rstrip(self.term_char)
##                    gpg_final = True
##                    gpg.close_gpg_input()
##                print 'digesting chunk = ' + chunk
##                print 'gpg_final = ' + str(gpg_final)
##                gpg.digest(chunk)
##                print 'here'
##                if gpg.hasBuffer():
##                    decrypted_chunk = gpg.read()
##                    print 'yeilding: ' + decrypted_chunk
##                    yield decrypted_chunk
##                if gpg_final:
##                    time.sleep(1)
##                    print 'here'
##                    while not gpg.done_read:
##                        decrypted_chunk = gpg.read()
##                        print 'yeilding: ' + decrypted_chunk
##                        yield decrypted_chunk
##                    gpg = GPGDecrypt(self.passphrase, self.chunk_size)
##                    gpg_final = False
##            except StopIteration:
##                break
##
#
#
#
#
#
#
#

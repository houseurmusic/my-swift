#tony wtf is going on here
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
from subprocess import Popen
from subprocess import PIPE
from threading import Thread
import sys
import traceback

from swift.common.exceptions import ChunkReadTimeout, \
    ChunkWriteTimeout, ConnectionTimeout

#queue code from:
#http://stackoverflow.com/questions/375427/non-blocking-read-on-a-subprocess-pipe-in-python

try:
    from Queue import Queue, Empty
except ImportError:
    from queue import Queue, Empty

class GPGEncryption():
    ON_POSIX = 'posix' in sys.builtin_module_names 

    def __init__(self, encrypt_or_decrypt, iterable = None, user = None, passphrase = None):
        if(encrypt_or_decrypt[0] == 'e'):
            #cmd = ['/usr/bin/gpg', '--no-tty', '--homedir', '/etc/swift/gnupg', '-r', user, '-e']
            cmd = ['tr', 'a', 'A']
            self.stream_iter = iterable
            self.stream_iter_read = iterable.read
        else:
            #cmd = ['gpg', '--no-tty', '--homedir', '/etc/swift/gnupg', '-d', '--batch', '--passphrase-fd', '0']
            cmd = ['tr', 'd', 'D']

        #self.p = Popen(cmd, shell=True, stdin=PIPE, stdout=PIPE, stderr=PIPE, bufsize = 1024)
        # TODO send stderr output to the logs
#        self.p = Popen(cmd, stdin=PIPE, stdout=PIPE, stderr=PIPE, bufsize = 1024)
        self.p = Popen(cmd, stdin=PIPE, stdout=PIPE, bufsize = 4096)

        if(encrypt_or_decrypt[0] == 'd'):
            self.p.stdin.write(passphrase + '\n')

        self.q = Queue()
        self.t = Thread(target = self._enqueue_output_, args = (self.p.stdout, self.q))
        self.t.daemon = True
        self.t.start()

    def read(self,count):
        encrypted_chunk = ''
        encrypted_chunk_size = 0
        #print "Entering encrypted read"
        while encrypted_chunk_size < count:
            chunk = self.stream_iter_read(count) 

            if len(chunk) == 0:
                print "End of stream, closing"
                encrypted_chunk += self.close_and_dump()
                encrypted_chunk_size = len(encrypted_chunk)
                break
            else:
                self.digest(chunk)
                encrypted_chunk += self.dump_buffer()
                encrypted_chunk_size = len(encrypted_chunk)

        print "Encrypted read: WT  F Size requested %s, Size returned %s" % (count, encrypted_chunk_size)
        #self.print_errors()
        return encrypted_chunk

    def print_errors(self):
        for line in iter(self.p.stderr.readline, ''):
            print line
      
    def _enqueue_output_(self, out, queue):
        for line in iter(out.readline, ''):
            queue.put(line)
        out.close()

    def digest(self, chunk):
        print "Writing %s to gpg" % len(chunk)
        self.p.stdin.write(chunk)  
        print "digest chunk write complete"
        self.p.stdin.flush()
        print "digest flush complete"

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
        print "dump_buffer returning %s" % len(data)
        return data

    def has_buffer(self):
        return not self.q.empty()

    def close_and_dump(self, timeout = .1):
        if self.p.stdin:
            try:
                self.p.stdin.close()
            except IOError:
                print "IOError returned when closing"
        data = self.dump_buffer(timeout)
        #self.p.stdout.close()
        return data

    def close(self):
        self.p.stdin.close()
        #self.p.stdout.close()

class DecryptionIterable:
    def __init__(self, response = None, user = None, passphrase = None):
        self.stream_iter = response.app_iter
        self.gpg = GPGEncryption('d', self.stream_iter, user, passphrase)
        self.response = response
        self.has_input = True

    def next(self):
        return iter(self).next()

    def __iter__(self):
        print "Decryption __iter__ calling self.decrypt"
        decrypted_chunk = ''
        chunk = ''
        decrypted_chunk_size = 0
        #print "Entering encrypted read"
        while self.has_input:
            if self.stream_iter:
                while True:
                    # Read a chunk and digest it
                    try:
                        print "Calling stream_iter.next()"
                        #traceback.print_stack()
                        chunk = self.stream_iter.next()
                        self.gpg.digest(chunk)
                        break
                    except StopIteration:
                        self.gpg.close()
                        self.has_input = False
                        break

                if self.gpg.has_buffer():
                    print "DEDUG DecryptionIterable.__iter__: We have a buffer"
                    decrypted_chunk = self.gpg.dump_buffer() 
                    yield decrypted_chunk 
            else:
                self.has_input = False
                break

        print "Decryption __iter__: All done, goodbye"

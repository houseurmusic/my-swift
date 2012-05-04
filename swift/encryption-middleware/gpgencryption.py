import thread
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
from asyncproc import Process


from swift.common.exceptions import ChunkReadTimeout, \
    ChunkWriteTimeout, ConnectionTimeout

#queue code from:
#http://stackoverflow.com/questions/375427/non-blocking-read-on-a-subprocess-pipe-in-python

#TODO CHECK IF BUFFER IS BEING CLOSE!

class GPGEncryption():

    def __init__(self, encrypt_or_decrypt, iterable = None, user = None, passphrase = None, test_branch = False):
        self.test_branch = test_branch
        print 'initing gpg'
        if(encrypt_or_decrypt[0] == 'e'):
            #print "user = " + user
            #cmd = ['/usr/bin/gpg', '--no-tty', '--homedir', '/etc/swift/gnupg', '-r', user, '-e']
            #cmd = ['tr', 'a', 'A']
            #-a for ascii armor
            #cmd = 'gpg -a -r ' + user + ' -e'
            cmd = 'cat'
            #cmd = '/home/amedeiro/bin/MyCat.py'
            #cmd = '/home/amedeiro/bin/python MyCat.py'
            self.term_char = chr(0)
            self.stream_iter = iterable
            self.stream_iter_read = iterable.read
            self.buffer = ""
            self.gpg_closed = False
            self.padded = False
            self.first_read = True
        else:
            #cmd = ['gpg', '-d', '--batch', '--passphrase-fd', '0']
            #cmd = ['gpg', '--no-tty', '--homedir', '/etc/swift/gnupg', '-d', '--batch', '--passphrase-fd', '0']
            #cmd = ['tr', 'd', 'D']
            #cmd = 'gpg -d --batch --passphrase-fd 0'
            cmd = 'cat'
            #cmd = '/home/amedeiro/bin/python MyCat.py'
        #self.str_iter = stringIterate(self.buffer, read_size)
        self.p = Process(cmd, shell=True, bufsize = 2)
        # TODO send stderr output to the logs
        #self.p = Popen(cmd, stdin=PIPE, stdout=PIPE, stderr=PIPE, bufsize = 1024)
        #self.p = Popen(cmd, stdin=PIPE, stdout=PIPE, bufsize = 4096)
        if(encrypt_or_decrypt[0] == 'd'):
            self.p.write('test-swift' + '\n')

        self.my_buffer = ''


    def print_errors(self):
        print self.p.readerr()

    def stringIterate(self, text, chunk_size):
        index = 0
        while index < len(text):
            yield text[index : index + chunk_size]
            index += chunk_size


     def readFromStream():
            chunk = self.stream_iter_read(read_size)
            while chunk:
                self.p.stdin.write(chunk)
                chunk = self.stream_iter_read(read_size)
            self.p.stdin.close()
            
     def read(self, read_size):
        def padder(text, div, pad = chr(0)):
            print 'padder reading ' + text
            size = (div - len(text) % div) + len(text)
            diff = size - len(text)
            text += pad * diff
            return text

        if self.first_read:
            self.first_read = False
            t = Thread(target = readFromStream)
            t.start()

        return self.p.stdout.read(read_size)

    def digest(self, chunk):
        print "digesting chunk = " + chunk
        self.p.write(chunk)

    def dump_buffer(self):
        buf = self.p.read()
        print 'dump buffer returning: ' + buf
        return buf

    def close_and_dump(self, timeout = .2):
        print 'close and dump called'
        self.p.closeinput()
        time.sleep(timeout)
        #self.p.closeinput()
        buf = ''
        #as long as there was a non blank string digested before this is called,
        #we can wait for the process to dump its last output... Might be a problem
        #if output dumps
        #poll = self.p.wait(os.WNOHANG)
        print 'entering close and dump loop'
        count = 0
        while buf == '' and count < 100:
            buf = self.dump_buffer()
            time.sleep(.01)
            print self.p.readerr()
            poll = self.p.wait(os.WNOHANG)
            count = count + 1
        print 'leaving close and dump loop'
        poll = self.p.wait(os.WNOHANG)
        print poll
        return buf


class DecryptionIterable:
    def __init__(self, response = None, user = None, passphrase = None, test_branch = False):
        self.stream_iter = response.app_iter
        #print "in decryptionit init"
        self.passphrase = passphrase
        self.user = user
        self.initGPG()
        self.response = response
        self.has_input = True
        self.chunk_size = 65536
        self.test_branch = test_branch

    def initGPG(self):
        self.gpg = GPGEncryption('d', self.stream_iter, self.user, self.passphrase)
    def next(self):
        return iter(self).next()


    def __iter__(self):
        #print "Decryption __iter__ calling self.decrypt!!"
        decrypted_chunk = ''
        chunk = ''
        total_read = 0
        print 'here'
        def stringIterate(text, chunk_size):
            index = 0
            #print "in stringIterate text = " + text
            while index < len(text):
                yield text[index : index + chunk_size]
                index += chunk_size

        if self.stream_iter:
            if self.test_branch:
                while True:
                    try:
                        chunk = trimChunk(self.stream_iter.next())
                        #print 'yielding in test_branchca: ' + chunk
                        yield chunk
                    except StopIteration:
                        #print "STOP ITERATION EXCEPTION: " + str(StopIteration)
                        self.has_input = False
                        break
            else:
                gpg_final = False
                while True:
                    # Read a chunk and digest it
                    try:
                        #print "Calling stream_iter.next()"
                        #traceback.print_stack()
                        chunk = self.stream_iter.next()
                        #print "chunk size = " + str(len(chunk))
                        gpg_final = chunk[len(chunk) - 1] == chr(0)
                        chunk = chunk.strip(chr(0))
                        #print "chunk = " + chunk
                        if len(chunk) > 0:
                            print 'GPG_FINAL = ' + str(gpg_final)
                        total_read += len(chunk)
                        #print "chunk length read: " + str(len(chunk))
                        #print "total read: " + str(total_read)
                        #print chunk
                        '''
                        if chunk == "[]" or chunk == "":
                            print "WARNING DECRYPTION MAY HAVE BEEN CALLED WHEN NOT INTENDED"
                            yield chunk
                            continue'''
                        if len(chunk) > 0:
                            self.gpg.digest(chunk)
                        if gpg_final:
                            #print "in gpg final"
                            decrypted_chunk = self.gpg.close_and_dump(0)
                            self.gpg.print_errors()
                            gpg_final = False
                            self.initGPG()
                        else:
                            decrypted_chunk = self.gpg.dump_buffer(0)
                        if(decrypted_chunk != ""):
                            str_iter = stringIterate(decrypted_chunk, self.chunk_size)
                            #print "decrypted chunk = " + decrypted_chunk
                            for c in str_iter:
                                #print "yieldeing: " + c
                                yield c
                    except StopIteration:
                        #print "STOP ITERATION EXCEPTION: " + str(StopIteration)
                        self.has_input = False
                        break
        else:
            self.has_input = False

# To change this template, choose Tools | Templates
# and open the template in the editor.

import time

class GPGEncryption():
    ON_POSIX = 'posix' in sys.builtin_module_names

    def __init__(self, encrypt_or_decrypt, iterable = None, user = None, passphrase = None, test_branch = False):
        self.test_branch = test_branch
        if(encrypt_or_decrypt[0] == 'e'):
            print "user = " + user
            #cmd = ['/usr/bin/gpg', '--no-tty', '--homedir', '/etc/swift/gnupg', '-r', user, '-e']
            #cmd = ['tr', 'a', 'A']
            #-a for ascii armor
            cmd = 'gpg -a -r ' + user + ' -e'
            self.stream_iter = iterable
            self.stream_iter_read = iterable.read
            self.buffer = ""
            self.gpg_closed = False
            self.finished_file = False
        else:
            #cmd = ['gpg', '-d', '--batch', '--passphrase-fd', '0']
            #cmd = ['gpg', '--no-tty', '--homedir', '/etc/swift/gnupg', '-d', '--batch', '--passphrase-fd', '0']
            #cmd = ['tr', 'd', 'D']
            cmd = 'gpg -d --batch --passphrase-fd 0'
        self.p = Popen(cmd, shell=True, stdin=PIPE, stdout=PIPE, stderr=PIPE, bufsize = 1024)
        # TODO send stderr output to the logs
        #self.p = Popen(cmd, stdin=PIPE, stdout=PIPE, stderr=PIPE, bufsize = 1024)
        #self.p = Popen(cmd, stdin=PIPE, stdout=PIPE, bufsize = 4096)

        if(encrypt_or_decrypt[0] == 'd'):
            self.p.stdin.write('test-swift' + '\n')

        self.q = Queue()
        self.t = Thread(target = self._enqueue_output_, args = (self.p.stdout, self.q))
        self.t.daemon = True
        self.t.start()

    #padding seems to be working maybe do a little more testing
    def read(self,read_size):
        chunk = ''
        encrypted_chunk = ''
        print "Entering encrypted read_size = " + str(read_size)
        while len(self.buffer) < read_size and (not self.gpg_closed or self.test_branch):
            chunk = self.stream_iter_read(read_size)
            if self.test_branch:
                #print 'uploading ' + chunk
                self.buffer += chunk
                break
            if len(chunk) == 0:
                print "End of stream, closing"
                self.buffer += self.close_and_dump()
                self.gpg_closed = True
                break
            else:
                self.digest(chunk)
                self.buffer += self.dump_buffer()
        #TODO encrypted chunk always be the read_size, the final character will be
        #some delimeter saying EOF and padsize!
        if len(self.buffer) < read_size - 1:
            encrypted_chunk = self.buffer
            self.buffer = ""
        else:
            encrypted_chunk = self.buffer[0 : read_size]
            self.buffer = self.buffer[read_size : len(self.buffer)]
        if(len(encrypted_chunk) < read_size):
            diff = read_size - len(encrypted_chunk)
            dig = digits(diff)
            #print "diff " + str(diff) + " dig = " + str(dig)
            encrypted_chunk += (diff - dig) * ' ' + str(diff) + chr(0)
            self.finished_file = True

        print "Encrypted read: Size requested %s" % (read_size)
        #self.print_errors()
        #print "encrypted_chunk = " + encrypted_chunk
        #print "finished_file = " + repr(self.finished_file)
        #return chunk
        return encrypted_chunk

    def print_errors(self):
        for line in iter(self.p.stderr.readline, ''):
            print line

    def _enqueue_output_(self, out, queue):
        for line in iter(out.readline, ''):
            queue.put(line)
        out.close()

    def digest(self, chunk):
        #print "Writing to %s" %repr(self.p.stdin)
        self.p.stdin.write(chunk)
        #print "digest chunk write complete"
        #self.p.stdin.flush()
        #print "digest flush complete"

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
        self.close()
        data = self.dump_buffer(timeout)
        print 'close and dump called returning len: ' + str(len(data))
        #self.p.stdout.close()
        return data

    def close(self):
        print "close callded p.stdin = " + repr(self.p.stdin)
        if self.p.stdin:
            try:
                print "BUFFER CLOSING"
                self.p.stdin.close()
            except IOError:
                print "IOError returned when closing"

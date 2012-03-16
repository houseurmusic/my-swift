#from Tools.Scripts.texi2html import next
from webob import Request, Response
from swift.common.utils import split_path, TRUE_VALUES
#from swift.common.middleware.gpgencryption import GPGEncryption, DecryptionIterable

class EncryptionMiddleware(object):

    def __init__(self, app, *args, **kwargs):
        self.app = app
        self.encryption_on = True
        print "in init"

    def __call__(self, env, start_response):

        print "in call"
        req = Request(env)
        version, account, container, obj = split_path(req.path, 1, 4, True)
        d = dict(version=version,
                account_name=account,
                container_name=container,
                object_name=obj)
        if obj and container and account:
            iterable = req.environ['wsgi.input']
            gpg = gpgIter(iterable)
            print "DEDUG: Encryption handle_request method %s and the path has a obj, cont, and account path: %s" % (req.method, req.path)
            resp = req.get_response(self.app)
            resp.app_iter
            print "after response %s", type(resp)
            req.environ['wsgi.input'].read = gpg.next
            return resp(env, start_response)
            #print resp
        def start_encryption(status, response_headers, exc_info = None):
            write = start_response(status, response_headers, exc_info)
            return write

        return self.app(env, start_response)



    def handle_request(self, req):
        print "in handle_request"
        return self.app

class gpgIter:
    def __init__(self, input_stream):
        self.input = input_stream
        self.input_read = input_stream.read
        print 'in gpgIter init'
        #self._next = iter(result).next

    def __iter__(self):
        self

    def read(self, count):
        chunk = self.input_read(count)
        print "in gpgIter chunk = %s", chunk
        return chunk
    
    def next(self):
        chunk = self.input.next()
        print "in gpgIter chunk = %s", chunk
        yield self.input.next()

    
def filter_factory(global_conf, **local_conf):
    def encryption_filter(app):
        return EncryptionMiddleware(app)
    return encryption_filter


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

class MyGpg():
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

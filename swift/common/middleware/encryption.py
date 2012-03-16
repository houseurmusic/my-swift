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

# Imports used by class EncryptionMiddleware
from webob import Request, Response
from swift.common.utils import split_path, TRUE_VALUES
from swift.common.middleware.gpgencryption import GPGEncryption, DecryptionIterable

#TODO Content length for downlaod is being read wrong! Had this problem before
#otherwise its working
class EncryptionMiddleware(object):
    """
    Encryption middleware encrypts object data as it is uploaded and decrypts the data on download.
    """

    def __init__(self, app, *args, **kwargs):
        self.app = app
        self.decrypt_response = False
#        self.encryption = conf.get('encryption', 'no').lower() in TRUE_VALUES
#        self.encryption_key = conf.get('encryption-key','')
#        self.encryption_user = conf.get('encryption-user','')
        #self.encryption = True
        self.encryption = True
        self.test_branch = False
        self.encryption_key = 'test-swift'
        self.encryption_user = 'test-swift'

        if self.encryption:
            if len(self.encryption_user) == 0 or len(self.encryption_key) == 0:
                #print "Encryption set to true, but encryption_user and encryption_key are not set"
                self.encryption = False

    def __call__(self, env, start_response):
        if self.test_branch:
            print "testing_branch on decryption response: " + repr(self.decrypt_response)
        if self.encryption:
            req = Request(env)
            resp = req.get_response(self.handle_request(req))
            #print resp.headers
            if self.decrypt_response:
                    # Check the status code of the response
                    # If the status code is between 200 - 299, then we pass the response to decrypt
                    if resp.status_int // 100 == 2:
                        # Replace the content length header with the original content length, encryption will change the content-length
                        #resp.headers['Content-Length'] = resp.headers['x-object-meta-original-content-length']
                        self.decrypt(resp)
            return resp(env, start_response)
        else:
            return self.app(env, start_response)

    def handle_request(self, req):
        """
        :returns: tuple of (controller class, path dictionary)
        :raises: ValueError (thrown by split_path) id given invalid path
        """
        self.decrypt_response = False
        version, account, container, obj = split_path(req.path, 1, 4, True)
        d = dict(version=version,
                account_name=account,
                container_name=container,
                object_name=obj)
        if obj and container and account:
                #print "DEDUG: Encryption handle_request method %s and the path has a obj, cont, and account path: %s" % (req.method, req.path)
                # If the request is a GET request, we flag it for decryption later.
                # Adding this to avoid swauth encryption
                if account != 'AUTH_.auth':
                    if req.method == 'GET':
                        self.decrypt_response = True
                    if req.method == 'PUT':
                        self.encrypt(req)
        return self.app

    #reference: http://www.python.org/dev/peps/pep-0333/
    def decrypt(self,resp):
        #print "headers = " + repr(resp.headers)
        oct = -1
        octet_stream = False
        #get needed keys
        key_content_length = ""
        #key_etag = ""
        for key, value in resp.headers.iteritems():
            #print key, value
            if key.lower() == 'content-type' and value.lower() == 'application/octet-stream':
                octet_stream = True
                #print "decrypting octet-stream"
            if key.lower() == 'content-length':
                key_content_length = key
            if key.lower() == 'etag':
                key_etag = key
                del resp.headers[key]
        if octet_stream:
            #resp.headers[key_content_length] = resp.headers['x-object-meta-original-content-length']
            del resp.headers[key_content_length]
        oct = 'x-object-meta-original-content-length'
        '''code to replace content length, but I dont think this works because
        the server is still expecting to send
        if octet_stream:
            if resp.headers[oct] and key_content_length:
                print key_content_length
                print 'has original content length'
                resp.headers[key_content_length] = resp.headers[oct]
            elif key_content_length:
                del resp.headers[key_content_length]
            #code if we decided to implement etags
            oet = 'x-object-meta-original-etag'
            if resp.headers[oet] and key_etag:
                print 'has original etag'
                resp.headers[key_etag] = resp.headers[oet]
                del resp.headers[oet]'''
        #gpg = DecryptionIterable('decrypt', iterable=resp.app_iter, user=self.encryption_user, passphrase=self.encryption_key)
        if octet_stream:
            resp.app_iter = DecryptionIterable(response=resp, user=self.encryption_user, passphrase=self.encryption_key, test_branch = self.test_branch)

    def encrypt(self,req):
        self.gpg = GPGEncryption('encrypt', iterable=req.environ['wsgi.input'], user=self.encryption_user, passphrase=self.encryption_key, test_branch = self.test_branch)
        # For encryption we remove content length since it will change
        #print "in encrypt headers: " + repr(req.headers)
        for key, value in req.headers.iteritems():
            if key.lower() == 'content-length':
                req.headers['x-object-meta-original-content-length'] = req.headers[key]
                del req.headers[key]
                break
            if key.lower() == 'etag':
                #print 'storing original etag'
                req.headers['x-object-meta-original-etag'] = req.headers[key]
        req.headers['x-object-meta-encryption-version'] = 'GPGPipe:0.1'
        req.headers['Transfer-Encoding'] = 'chunked'
        req.environ['wsgi.input'].read = self.gpg.read
        #print "req headers: " + str(req.headers)
        #print "DEDUG: Encryption encrypt method called req.method ", req.method

def filter_factory(global_conf, **local_conf):
    def encryption_filter(app):
        return EncryptionMiddleware(app)
    return encryption_filter

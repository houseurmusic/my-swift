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
        dfa
        self.encryption = False
#        self.encryption = False
        self.encryption_key = 'swift-key'
        self.encryption_user = 'swift-gpg-user'

        if self.encryption:
            if len(self.encryption_user) == 0 or len(self.encryption_key) == 0:
                print "Encryption set to true, but encryption_user and encryption_key are not set"
                self.encryption = False

    def __call__(self, env, start_response):
        print "DEDUG: Entering Encryption __call__"
        if self.encryption:
            print "Encryption enabled."
            req = Request(env)
            print "Decrypt response before handle_request is: ", self.decrypt_response
            resp = req.get_response(self.handle_request(req))
            print "Decrypt response after handle_request is: ", self.decrypt_response
            if self.decrypt_response:
                    # Check the status code of the response
                    # If the status code is between 200 - 299, then we pass the response to decrypt 
                    if resp.status_int // 100 == 2:
                        # Replace the content length header with the original content length, encryption will change the content-length
                        #resp.headers['Content-Length'] = resp.headers['x-object-meta-original-content-length']
                        self.decrypt(resp)
            return resp(env, start_response)
        else: 
            print "Encryption disabled."
            return self.app(env, start_response)

    def handle_request(self, req):
        """
        :returns: tuple of (controller class, path dictionary)
        :raises: ValueError (thrown by split_path) id given invalid path
        """
        print "Entering handle_request"
        self.decrypt_response = False
        version, account, container, obj = split_path(req.path, 1, 4, True)
        d = dict(version=version,
                account_name=account,
                container_name=container,
                object_name=obj)
        if obj and container and account:
                print "DEDUG: Encryption handle_request method %s and the path has a obj, cont, and account path: %s" % (req.method, req.path)
                # If the request is a GET request, we flag it for decryption later.
                # Adding this to avoid swauth encryption
                if account != 'AUTH_.auth':
                    if req.method == 'GET':
                        self.decrypt_response = True
                    if req.method == 'PUT':
                        self.encrypt(req)
        return self.app

    def decrypt(self,resp):
        print "DEDUG: Encryption decrypt method called on response with status: ", resp.status
#        gpg = DecryptionIterable('decrypt', iterable=resp.app_iter, user=self.encryption_user, passphrase=self.encryption_key)
        resp.app_iter = DecryptionIterable(response=resp, user=self.encryption_user, passphrase=self.encryption_key)
        print "DEDUG: Response body after gpg creation."

    def encrypt(self,req):
        gpg = GPGEncryption('encrypt', iterable=req.environ['wsgi.input'], user=self.encryption_user, passphrase=self.encryption_key)
        # For encryption we remove content length since it will change
        req.headers['x-object-meta-original-content-length'] = req.headers['Content-Length']
        req.headers['x-object-meta-encryption-version'] = 'GPGPipe:0.1'
        del req.headers['Content-Length']
        req.headers['Transfer-Encoding'] = 'chunked'
        req.environ['wsgi.input'].read = gpg.read
        print "DEDUG: Encryption encrypt method called req.method ", req.method

def filter_factory(global_conf, **local_conf):
    def encryption_filter(app):
        return EncryptionMiddleware(app)
    return encryption_filter

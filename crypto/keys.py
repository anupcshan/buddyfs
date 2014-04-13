#!/usr/bin/python

import gnupg

class KeyManager(object):
    def __init__(self, key_id):
        self.gpg = gnupg.GPG()
        self.test_key(key_id)

    def test_key(self, key_id):
        self.gpg_key = filter (lambda x :
                x.get('keyid').find(key_id) >= 0, self.gpg.list_keys(True))
        if len(self.gpg_key) != 1:
            raise 'Invalid or non-existent GPG key specified'

        self.gpg_key = self.gpg_key[0]
        test_encrypt = self.gpg.encrypt('0xDEADBEEF', self.gpg_key['fingerprint'])
        
        if not test_encrypt.ok:
            raise 'Unable to encrypt to provided fingerprint'

        test_decrypt = self.gpg.decrypt(test_encrypt.data)

        if not test_decrypt.ok:
            raise 'Unable to decrypt messages to provided fingerprint'

        if test_decrypt.data != '0xDEADBEEF':
            raise 'GPG binaries unable to encrypt or decrypt accurately'

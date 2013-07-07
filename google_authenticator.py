"""A back-end module to use with Google Authenticator mobile app written in Python 3

An implementation of two factor authentication provided by Google Authenticator mobile app
More info on the app: http://en.wikipedia.org/wiki/Google_Authenticator

Allows to set up the app to work with your user accounts via manual input or QR code, and also to verify codes supplied by users.
Both HOTP (incremented counter based) and TOTP (time based) authentication modes are supported.

RFC4226 implementation code based on https://github.com/gingerlime/hotpie/blob/master/hotpie.py

Author: Yuriy Akopov (akopov@hotmail.co.uk)
Date:   2013-07-05

Usage example:

	import google_authenticator
	
    secret = google_authenticator.new_secret() # when a new user is registered or signed up for 2 factor authentication, returned value should be stored
    url = google_authenticator.qr_url(google_authenticator.MODE_TOTP, secret, 'John Doe', 'Acme', 200) # build url for QR code image so user can set up their Google Authenticator

    # then on login attempt, where code is supposedly Google Authenticator code supplied by user
    if google_authenticator.auth(google_authenticator.MODE_TOTP, secret, code):   # mode should be the same as supplied to qr_url above
        your_login_func() # authentication successfull

If run directly, module will unit test itself.

"""
import base64
import random
import time
import hmac
import hashlib
import struct
from urllib.parse import quote as urlquote, urlencode

"""authentication modes"""
MODE_TOTP = 'totp'  # changing part of the seed is going to be current time
MODE_HOTP = 'hotp'  # changing part of the seed is going to be counter incremented on every login attempt

_modes = (MODE_TOTP, MODE_HOTP)

_TOTP_PRECISION = 30    # length of the "one tick" interval (in which system produces the same code) for TOTP
_SECRET_LENGTH  = 16    # length of the secret code required by Google Authenticator app
_CODE_LENGTH    = 6     # length of codes produced by Google Authenticator app

def new_secret():
    """Generates and returns a random secret key which should be used when a new user is created in the outside code and stored with it.
    It is needes to initialise user's Google Authenticator app and then every time user needs to be authenticated.

    As required by Google Authenticator app, the secret is generated 16 base32 alphabet characters long

    """
    secret = b''.join(random.choice(base64._b32alphabet) for x in range(_SECRET_LENGTH))

    return secret.decode()

def qr_url(mode, secret, label_user, label_issuer = '', size = 100):
    """"Returns URL to Google Chart API producing a QR code image to initialise user's Google Authenticator app

    :param mode:            authentication mode
    :type mode:             string, value should be either MODE_TOTP or MODE_HOTP

    :param secret:          secret key of the user which needs to be authenticated
    :type secret:           string received from new_secret() or another 16-chars long base32 string

    :param label_user:      identifier to appear in user's app against the generated code
    :type label_user:       string with no colons in it

    :param label_issuer:    additional non-mandatory part of the identifier (will apper in the app separated with a colon)
    :type label_issuer:     string with no colons in it

    :param size:            size of the QR code image in pixels (it's square so one dimension is enough)
    :type size:             positive integer
     
    """    
    if (not(mode in _modes)):
        raise ValueError('Invalid mode')

    if (len(label_user) == 0):
        raise ValueError('Label that identifies the account being authenticated is required to be displayed in Google Authenticator')

    if ((':' in label_user) or (':' in label_issuer)):
        raise ValueError('Labels to be diplayed in the app cannot contain a colon')

    """Building URI for Google basing on which it can build a QR code for user to initialise their Google Authenticator app
    It's what we will encode in our QR code
    Format is explained at http://code.google.com/p/google-authenticator/wiki/KeyUriFormat
    """

    label = [label_user]
    params = {'secret': secret}
    if len(label_issuer):
        label.insert(0, label_issuer)
        params['issuer'] = label_issuer

    if mode == MODE_HOTP:
        params['counter'] = 0   # if user will be authenticated by counter, start it with zero

    uri = 'otpauth://' + mode + '/' + urlquote(':'.join(label)) + '?' + urlencode(params)

    """Google Chart instructions are ready, building the image request URL - it's https because sensitive information (secret) is supplied"""
    return 'https://chart.googleapis.com/chart?' + urlencode({'cht': 'qr', 'chs': size, 'chl': uri})

def _truncate(hmac_sha1, digits = _CODE_LENGTH):
    """Converts an HMAC-SHA-1 value into an HOTP value as defined in Section 5.3.
    http://tools.ietf.org/html/rfc4226#section-5.3
 
    """
    offset = int(hmac_sha1[-1], 16)
    binary = int(hmac_sha1[(offset * 2):((offset * 2) + 8)], 16) & 0x7fffffff

    return str(binary)[-digits:]

def _code(secret, c, digits = _CODE_LENGTH):
    """Returns HOTP code for the given secret part of the key and counter value
    To get TOTP code, supply timestamp divided by 30 sec as c

    """
    secret_bytes = base64.b32decode(secret)     # this bit is often missed - secret is expected to be base32-encoded string, and should be decoded before hashing
    c_bytes = struct.pack('>Q', c)              # converting a number into an array of bytes representing it as if it was 8 bytes long (same bits, different context)
    hmac_sha1 = hmac.new(key=secret_bytes, msg=c_bytes, digestmod=hashlib.sha1).hexdigest()  # hashing binary secret and number
    return _truncate(hmac_sha1, digits)     # converting hash to digits and cutting out the requested number of tralining ones (as they change most often)

def auth(mode, secret, code, var = None, tolerance = 2):
    """Compares the code supplied by user with the expected, returns boolean value with the authentication result
    *In HOTP mode, don't forget to increse your stored counter value var!* 

    :param mode:        authentication mode
    :type mode:         string, value should be either MODE_TOTP or MODE_HOTP

    :param secret:      secret key of the user which needs to be authenticated
    :type secret:       string received from new_secret() or another 16-chars long base32 string

    :param code:        code supplied by user (generated by their Google Authenticator app)
    :type code:         numeric string

    :param var:         varying part of the secret key
                        in HOTP mode counter value is expected (0 if None)
                        in TOTP mode timestamp is expected (current system timestamp if None)
    :type var:          int

    :param tolerance:   keys is which interval of the var value are still accepted
                        in HOTP mode means number of of attempts to allow *after* the supplied counter value
                        in TOTP mode means number of 30 (_TOTP_PRECISION) sec intervals to allow *before* and *after* the supplied time
                        (e.g. 2 means one minute back and forth)
    :type tolerance:    int

    """
    if mode == MODE_HOTP:
        """Using timestamp as a varying part of the key"""

        c = 1 if var == None else var   # Google Authenticator starts its counter with 1, not 0

        """with HOTP we assume that user counter could go ahead of the server one, but the opposite is not possible"""
        tolerance_from = c
        tolerance_to = c + tolerance    # if user was clicking 'next code' in their app without actually logging in

    elif mode == MODE_TOTP:
        """Using counter value as a varying part of the key"""

        ts = int(time.time()) if var == None else var   # use current timestamp by default
        
        """TOTP measures time in 30 sec intervals and tolerance means by how many of those intervals we allow
        user clock to be different from ours"""
        ticks = int(ts / _TOTP_PRECISION)

        tolerance_from = ticks - tolerance
        tolerance_to = ticks + tolerance

    else:
        raise ValueError('Unsupported mode')

    for c in range(tolerance_from, (tolerance_to + 1)):
        if (code == _code(secret, c)):
            return True

    return False

import unittest
from urllib.request import urlopen

class ClientTest(unittest.TestCase):
    """Unit test for the functionality implemented in this module

    """
    def setUp(self):
        self.secret = 'WO2CHK7ULXM5AIGT'

    def test_secret(self):
        secret = new_secret()
        self.assertEqual(len(secret), _SECRET_LENGTH, 'Invalid generated secret length')

        for c in secret:    
            self.assertTrue(c.encode() in base64._b32alphabet.values(), 'Invalid character ' + c + ' generated secret')

    def test_qr_code(self):
        try:
            url = qr_url(MODE_HOTP, 'test', 'Yuriy', 'Acme', 100)   # testing all parameters
            urlopen(url)

            url = qr_url(MODE_TOTP, 'test', 'Yuriy')   # testing minimal parameters
            urlopen(url)

        except Exception:
            self.fail('Error while retrieving the QR codes')

    def test_hotp(self):
        valid_codes = {1: '238295', 2: '821933', 3: '648071'}
        for c in valid_codes:
            self.assertEqual(_code(self.secret, c), valid_codes[c])                     # checking if codes are equal
            self.assertTrue(auth(MODE_HOTP, self.secret, valid_codes[c], c, 1))         # checking if tolerance works when the counter value is precise

        self.assertTrue(auth(MODE_HOTP, self.secret, valid_codes[2], 1, 1))   # checking if tolerance works when the counter value is within tolerance
        self.assertFalse(auth(MODE_HOTP, self.secret, valid_codes[3], 1, 1))  # checking if tolerance works when the counter value is outside of tolerance#

        self.assertFalse(auth(MODE_HOTP, self.secret, '123456', 1, 10))       # checking for failure on an invalid code with bigger tolerance

    def test_totp(self):
        valid_codes = {1373197332 : '180958', 1373197362  : '944666', 1373197393 : '177781'}
        for ts in valid_codes:
            ticks = int(ts / _TOTP_PRECISION)
            self.assertEqual(_code(self.secret, ticks), valid_codes[ts])                        # checking if codes are equal
            self.assertTrue(auth(MODE_TOTP, self.secret, valid_codes[ts], ts, 1))               # checking if tolerance works when the counter value is precise

        self.assertTrue(auth(MODE_TOTP, self.secret, valid_codes[1373197362], 1373197332, 1))   # checking if tolerance works when the counter value is within tolerance
        self.assertFalse(auth(MODE_TOTP, self.secret, valid_codes[1373197393], 1373197332, 1))  # checking if tolerance works when the counter value is outside of tolerance#

        self.assertFalse(auth(MODE_TOTP, self.secret, '123456', 1373197332, 10))       # checking for failure on an invalid code with bigger tolerance

        pass

if __name__ == '__main__':
    unittest.main()
A back-end module to use with Google Authenticator mobile app written in Python 3

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
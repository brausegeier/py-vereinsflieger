################################################################################
# py-vereinsflieger/credentials.py
#
# Copyright Alexander Bleitner, 2021.
#
# License: GPL-3.0-or-later
################################################################################


class Credentials():
    def __init__(self):

        # Vereinsflieger login
        self.vf_user_id     = ''
        self.vf_user_pwd    = ''

        # reCAPTCHA site key
        self.rc_secret      = ''

        # banking information
        self.bank_holder    = ''
        self.bank_iban      = ''
        self.bank_bic       = ''

        # webserver SSL certificate/keys
        self.ssl_cert_file = ''


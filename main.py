#!/usr/bin/python3

################################################################################
# py-vereinsflieger/main.py
#
# Copyright Alexander Bleitner, 2021.
#
# License: GPL-3.0-or-later
################################################################################


import voucher_server
from credentials      import Credentials as cred


vs = voucher_server.VoucherServer(hostname='0.0.0.0', port=8080)

vs.vf_api.set_credentials(cred().vf_user_id, cred().vf_user_pwd)
vs.rc.set_credentials(cred().rc_secret)

#vs.enableSSL('<secure-location>/cert-and-key.pem')

vs.run()
#vs.single_shot()


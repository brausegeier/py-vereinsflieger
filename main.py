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


#
# Instantiate server
#
vs = voucher_server.VoucherServer(hostname='0.0.0.0', port=8080)

#
# Provide all credentials
#
vs.vf_api.set_credentials(cred().vf_user_id, cred().vf_user_pwd)
vs.rc.set_credentials(cred().rc_secret)
vs.ms.set_credentials(cred().mail_user_id, cred().mail_pwd)
vs.set_banking_data(cred().bank_holder, cred().bank_iban, cred().bank_bic, cred().bank_name)

#
# Enable SSL
#
vs.enable_SSL(cred().ssl_cert_file)

#
# Let the server run
#
vs.run()
#vs.single_shot()


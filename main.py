#!/usr/bin/python3

import voucher_server
from credentials import credentials as cred


vs = voucher_server.VoucherServer(debug=1)

vs.vf_api.set_credentials(cred().vf_user_id, cred().vf_user_pwd)
vs.rc.set_credentials(cred().rc_secret)

#vs.enableSSL('./cert-and-key.pem')

#vs.run()
vs.single_shot()


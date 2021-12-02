#!/usr/bin/python3

import vf_api
from credentials import credentials as cred

print("#### INIT")
vf = vf_api.VF_API(debug=1)
print("#### LOGIN")
vf.login(cred().user_id, cred().user_pwd)
#vf.create_voucher()
print("#### LOOUT")
vf.logout()
print("#### LOGIN")
vf.login(cred().user_id, cred().user_pwd)
print("#### LOGIN")
vf.login(cred().user_id, cred().user_pwd)
print("#### LOOUT")
vf.logout()
print("#### LOOUT")
vf.logout()
print("#### LOGIN")
vf.login(cred().user_id, cred().user_pwd)
print("#### LOOUT")
vf.logout()
print("#### LOOUT")
vf.logout()



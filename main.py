#!/usr/bin/python3

import vf_api
from credentials import credentials as cred

test_data = {
        "type"      : "SF",
#        "type"      : "TMG",
        "amount"    : "1",
        "firstname" : "Max",
        "lastname"  : "Mustermann",
        "email"     : "max.mustermann@example.com",
        "ip"        : "xx.xx.xx.xx"
    }

print("#### INIT")
vf = vf_api.VF_API(debug=0)
print("#### LOGIN")
vf.login(cred().user_id, cred().user_pwd)
voucher = vf.create_voucher(test_data)
print("#### LOOUT")
vf.logout()
print("Voucher:\n%s" % (voucher))
#print("#### LOGIN")
#vf.login(cred().user_id, cred().user_pwd)
#print("#### LOGIN")
#vf.login(cred().user_id, cred().user_pwd)
#print("#### LOOUT")
#vf.logout()
#print("#### LOOUT")
#vf.logout()
#print("#### LOGIN")
#vf.login(cred().user_id, cred().user_pwd)
#print("#### LOOUT")
#vf.logout()
#print("#### LOOUT")
#vf.logout()



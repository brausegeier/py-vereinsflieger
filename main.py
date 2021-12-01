#!/usr/bin/python3

import vf_api

user_id = ''
user_pwd = ''

vf = vf_api.VF_API(debug=1)
vf.login(user_id, user_pwd)
#vf.create_voucher()
vf.logout()



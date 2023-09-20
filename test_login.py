#!/usr/bin/python3

################################################################################
# py-vereinsflieger/test_login.py
#
# Copyright Alexander Bleitner, 2022.
#
# License: GPL-3.0-or-later
################################################################################


import vf_api
from credentials      import Credentials as cred


#
# Instantiate API
#
api = vf_api.VF_API(debug=6)

#
# Provide all credentials
#
api.set_credentials(cred().vf_user_id, cred().vf_user_pwd)

#
# Test Login
#

success = api.login()
api.logout()

if success:
    print("\n\n####################");
    print("# Login successful #")
    print("####################");
else:
    print("\n\n################");
    print("# Login FAILED #")
    print("################");


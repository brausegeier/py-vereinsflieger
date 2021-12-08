#!/usr/bin/python3

################################################################################
# py-vereinsflieger/decode_error_msg.py
#
# Copyright Alexander Bleitner, 2021.
#
# License: GPL-3.0-or-later
################################################################################


from base64 import b64decode
from sys    import argv


dec = b64decode(argv[1].encode('ascii')).decode('utf-8')
print("Base64 decoded message: \"%s\"" % dec)


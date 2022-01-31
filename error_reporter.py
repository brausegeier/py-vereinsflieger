#!/usr/bin/python3

################################################################################
# py-vereinsflieger/error_reporter.py
#
# Copyright Alexander Bleitner, 2022.
#
# License: GPL-3.0-or-later
################################################################################


import vf_api
import smtplib
import sys
from credentials    import Credentials as cred
from email.message  import EmailMessage
from io             import StringIO
from time           import sleep, strftime, gmtime
from random         import randint


#
# Captureing of stdout for reporting in case of error
# from https://stackoverflow.com/questions/16571150/how-to-capture-stdout-output-from-a-python-function-call
#
class Capturing(list):
    def __enter__(self):
        self._stdout = sys.stdout
        sys.stdout = self._stringio = StringIO()
        return self

    def __exit__(self, *args):
        self.extend(self._stringio.getvalue().splitlines())
        del self._stringio    # free up some memory
        sys.stdout = self._stdout


#
# Error reporting method
#
def report_error(error_msg):
    # create email
    msg = EmailMessage()
    msg["Subject"]  = "VF_API(): Error"
    msg["From"]     = cred().mail_report
    msg["To"]       = cred().mail_report
    msg_content     = "The following error occured while checking the VF_API():\n\nEOF <<<\n"
    for line in error_msg:
        msg_content = msg_content + line + "\n"
    msg_content = msg_content + "<<< EOF\n\nReported by py-vereinsflieger/error_reporter.py\n"
            % error_msg)
    msg.set_content(msg_content)

    # send the email
    server = smtplib.SMTP_SSL(cred().mail_server, cred().mail_port)
    server.login(cred().mail_user_id, cred().mail_user_pwd)
    server.send_message(msg)
    server.quit()

    return 0


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

while (True):
    # redirect outptut to error_msg
    with Capturing() as error_msg:
        login_works = api.login()
    if login_works:
        print("%s: Login works" % strftime("%a, %d %b %Y %H:%M:%S +0000", gmtime()))
        with Capturing() as quiet:
            api.logout()
    else:
        print("%s: Login failed!" % strftime("%a, %d %b %Y %H:%M:%S +0000", gmtime()))
        print(error_msg)
        report_error(error_msg)

    # repeat after 1 to 24 hours
    sleep(randint(3600, 24*3600))



#!/usr/bin/python3

import http.server
import vf_api
import recaptcha_validate
import ssl
import threading
import base64

import inspect, sys


class VoucherServer():
    ####################
    # public interface #
    ####################

    def __init__(self, hostname = 'localhost', port = 8000, debug = 0):
        self._debug = debug
        self._hostname = hostname
        self._port = port

        self.vf_api = vf_api.VF_API(self._debug)
        self.rc = recaptcha_validate.RecaptchaValidate(self._debug)
        self._lock = threading.Lock()

        self.server = http.server.HTTPServer((self._hostname, self._port), ReqHandler)
        self.server.debug = self._debug
        self.server.vf_api = self.vf_api
        self.server.rc = self.rc
        self.server.vf_lock = self._lock


    def enableSSL(self, certfile):
        self.server.socket = ssl.wrap_socket(self.server.socket, certfile=certfile, server_side=True)


    def run(self):
        if self.server.debug > 0:
            print("%s: Server running on: \"%s:%d\"" % (sys._getframe().f_code.co_name, self._hostname, self._port))
        self.server.serve_forever()
        if self.server.debug > 0:
            print("%s: Server stoped." % (sys._getframe().f_code.co_name))


    def single_shot(self):
        if self.server.debug > 0:
            print("%s: Server running on: \"%s:%d\"" % (sys._getframe().f_code.co_name, self._hostname, self._port))
        self.server.handle_request()
        if self.server.debug > 0:
            print("%s: Server stoped." % (sys._getframe().f_code.co_name))



class ReqHandler(http.server.BaseHTTPRequestHandler):

    def log_message(self, format, *args):
        # Silence output log
        if self.server.debug > 1:
            super().log_message(format, *args)


    def do_HEAD(self):
        self._ignore_request("HEAD")


    def do_GET(self):
        self._ignore_request("GET")


    def do_PUT(self):
        self._ignore_request("PUT")


    def do_POST(self):
        #
        # Only repsond to POST requests, ignore other request types
        #

        # parse data from GET request
        [rc_response, voucher_data] = self._extract_data()
        # failed to get required data
        if rc_response is None and voucher_data is None:
            return self._respond_internal_error(user_desc="Interner Systemfehler.", admin_desc="Could not parse GET request")
        # voucher data contains errors
        if rc_response is None:
            return self._respond_internal_error(user_desc="Interner Systemfehler, Gutscheindaten konnten nicht richtig übermittelt werden.",
                admin_desc=("Invalid request voucher data: \"%s\"" % voucher_data))

        # check, if the user solved the recaptcha correctly
        [allowed, provider] = self.server.rc.validate(rc_response)
        if not allowed:
            return self._respond_recaptcha_failed()

        # insert location of the order form into log data
        if provider is not None:
            voucher_data["provider"] = provider

        # Create the new voucher (locking as vf_api is not thread safe!)
        self.server.vf_lock.acquire()
        [valid, voucher] = self.server.vf_api.create_voucher(voucher_data)
        self.server.vf_lock.release()

        if valid:
            return self._respond_voucher_success(voucher)

        return self._respond_internal_error(user_desc="Interner Systemfehler, Gutschein konnte nicht erstellt werden.",
            admin_desc=("Failed to create voucher with data: \"%s\"" % voucher))



    #############
    # internals #
    #############

    #######
    def _extract_data(self):
    #######
        return [None, ""]
        if self.server.debug > 2:
            for h in self.headers:
                print("%s: Header: \"%s\"" % (sys._getframe().f_code.co_name, h))

        # get content length for varous capitalizations
        length_names = ['Content-Length', 'Content-length', 'content-Length', 'content-length']
        content_len = -1
        for name in length_names:
            if name in self.headers.keys():
                content_len = int(self.headers[name])
        if content_len < 0:
            if self.server.debug > 0:
                print("%s: Invalid request. No \"Content-Length\" in headers: %s" % (sys._getframe().f_code.co_name, self.headers))
            return [None, None]

        post_body = self.rfile.read(content_len)
        print("Post body: %s" % post_body)

        #
        # TODO: implement data extraction
        #
        ################
        rc_response = ""
        voucher_data = {
                "type"      : "SF",
        #        "type"      : "TMG",
                "amount"    : "1",
                "firstname" : "Max",
                "lastname"  : "Mustermann",
                "email"     : "max.mustermann@example.com",
                "ip"        : "xx.xx.xx.xx"
            }
        ################
        return [rc_response, voucher_data]


    #######
    def _respond_recaptcha_failed(self):
    #######
        if self.server.debug > 0:
            print("%s:" % (sys._getframe().f_code.co_name))
            print("%s: #####################" % (sys._getframe().f_code.co_name))
            print("%s: # Recaptcha FAILED! #" % (sys._getframe().f_code.co_name))
            print("%s: #####################" % (sys._getframe().f_code.co_name))
            print("%s:" % (sys._getframe().f_code.co_name))

        #
        # Response -> redirect to failed page
        #
        self.send_response(http.server.HTTPStatus.FOUND)
        self.send_header('Location','https://brausegeier.de/gutscheinbestellung-recaptcha-fehlgeschlagen/')
        self.end_headers()


    #######
    def _respond_internal_error(self, user_desc, admin_desc):
    #######
        if self.server.debug > -1:
            print("%s:" % (sys._getframe().f_code.co_name))
            print("%s: #########################" % (sys._getframe().f_code.co_name))
            print("%s: # INTERNAL SERVER ERROR #" % (sys._getframe().f_code.co_name))
            print("%s: #########################" % (sys._getframe().f_code.co_name))
            print("%s:" % (sys._getframe().f_code.co_name))
        if self.server.debug > 1:
            print("%s: %s" % (sys._getframe().f_code.co_name, voucher))

        #
        # pack admin description, which can contain "bad" characters
        #
        admin_desc = base64.b64encode(admin_desc.encode('utf-8')).decode('ascii')
        if self.server.debug > 0:
            print("%s: Base64 encoded message: \"%s\"" % (sys._getframe().f_code.co_name, admin_desc))

        # decode example:
        if self.server.debug > 0:
            admin_desc_dec = base64.b64decode(admin_desc.encode('ascii')).decode('utf-8')
            print("%s: Base64 decode(encoded message): \"%s\"" % (sys._getframe().f_code.co_name, admin_desc_dec))

        #
        # Response -> redirect to failed page
        #
        self.send_response(http.server.HTTPStatus.FOUND)
        self.send_header('Location','https://brausegeier.de/gutscheinbestellung-fehlgeschlagen/?error_desc='+user_desc+'&error_code='+admin_desc)
        self.end_headers()


    #######
    def _respond_voucher_success(self, voucher):
    #######
        if self.server.debug > 0:
            print("%s:" % (sys._getframe().f_code.co_name))
            print("%s: ######################" % (sys._getframe().f_code.co_name))
            print("%s: # SUCCESSFUL Voucher #" % (sys._getframe().f_code.co_name))
            print("%s: ######################" % (sys._getframe().f_code.co_name))
            print("%s:" % (sys._getframe().f_code.co_name))
        if self.server.debug > 1:
            print("%s: %s" % (sys._getframe().f_code.co_name, voucher))

        #
        # Response -> redirect to success page (and display voucher / payment description)
        #
        self.send_response(http.server.HTTPStatus.FOUND)
        self.send_header('Location','https://brausegeier.de/gutscheinbestellung-erfolgreich/?message='+voucher_message)
        self.end_headers()


    #######
    def _respond_error(self, err_code, description):
    #######
        if self.server.debug > 0:
            print("%s:" % (sys._getframe().f_code.co_name))
            print("%s: ############################" % (sys._getframe().f_code.co_name))
            print("%s: # Unspecified SERVER ERROR #" % (sys._getframe().f_code.co_name))
            print("%s: ############################" % (sys._getframe().f_code.co_name))
            print("%s:" % (sys._getframe().f_code.co_name))
            print("%s: ########" % (sys._getframe().f_code.co_name))
            print("%s: # \"%s\" -> Sending code %d" % (sys._getframe().f_code.co_name, description, error_code))
            print("%s: ########" % (sys._getframe().f_code.co_name))

        #
        # Response -> just the error code
        #
        self.send_response(error_code)
        self.end_headers()


    ########
    def _ignore_request(self, type_str):
    ########
        if self.server.debug > 0:
            print("%s: Ignoring %s request." % (sys._getframe().f_code.co_name, type_str))
        self.send_response(http.server.HTTPStatus.BAD_REQUEST)
        self.end_headers()


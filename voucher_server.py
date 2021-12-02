#!/usr/bin/python3

import http.server
import vf_api
import recaptcha_validate
import ssl
import threading

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

    def do_GET(self):
        if self.server.debug > 0:
            print("%s: Ignoring GET request." % (sys._getframe().f_code.co_name))
        return 0


    def do_POST(self):
        [rc_response, voucher_data] = self._extract_data()

        [allowed, provider] = self.server.rc.validate(rc_response)
        if not allowed:
            return self._respond_recaptcha_failed()

        if provider is not None:
            voucher_data["provider"] = provider

        self.server.vf_lock.acquire()
        [valid, voucher] = self.server.vf_api.create_voucher(voucher_data)
        self.server.vf_lock.release()

        if not valid:
            return self._respond_voucher_failed(voucher)

        return self._respond_voucher_success(voucher)



    #############
    # internals #
    #############

    #######
    def _extract_data(self):
    #######
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
        return 0


    #######
    def _respond_voucher_failed(self, voucher):
    #######
        if self.server.debug > 0:
            print("%s:" % (sys._getframe().f_code.co_name))
            print("%s: ###################" % (sys._getframe().f_code.co_name))
            print("%s: # Voucher FAILED! #" % (sys._getframe().f_code.co_name))
            print("%s: ###################" % (sys._getframe().f_code.co_name))
            print("%s:" % (sys._getframe().f_code.co_name))
        if self.server.debug > 1:
            print("%s: %s" % (sys._getframe().f_code.co_name, voucher))
        return 0


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
        return 0


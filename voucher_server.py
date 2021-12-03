################################################################################
# py-vereinsflieger/voucher_server.py
#
# Copyright Alexander Bleitner, 2021.
#
# License: GPL-3.0-or-later
################################################################################


import http.server
import vf_api
import recaptcha_validate
from ssl          import wrap_socket
from threading    import Lock
from base64       import b64encode, b64decode
from math         import ceil
from urllib.parse import quote, unquote
from sys          import _getframe as s_frame


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
        self._lock = Lock()

        self.server = http.server.HTTPServer((self._hostname, self._port), ReqHandler)
        self.server.debug = self._debug
        self.server.vf_api = self.vf_api
        self.server.rc = self.rc
        self.server.vf_lock = self._lock


    def enableSSL(self, certfile):
        self.server.socket = wrap_socket(self.server.socket, certfile=certfile, server_side=True)


    def run(self):
        if self.server.debug > 0:
            print("%s: Server running on: \"%s:%d\"" % (s_frame().f_code.co_name, self._hostname, self._port))
        self.server.serve_forever()
        if self.server.debug > 0:
            print("%s: Server stoped." % (s_frame().f_code.co_name))


    def single_shot(self):
        if self.server.debug > 0:
            print("%s: Server running on: \"%s:%d\"" % (s_frame().f_code.co_name, self._hostname, self._port))
        self.server.handle_request()
        if self.server.debug > 0:
            print("%s: Server stoped." % (s_frame().f_code.co_name))



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
            return self._respond_internal_error(user_desc="Interner Systemfehler, Gutscheindaten konnten nicht richtig übermittelt werden.", admin_desc="Could not parse GET request")

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
        if self.server.debug > 2:
            for h in self.headers:
                print("%s: Header: \"%s\"" % (s_frame().f_code.co_name, h))

        #
        # get content length for various capitalizations
        #
        length_names = ['Content-Length', 'Content-length', 'content-Length', 'content-length', 'CONTENT-LENGTH']
        content_len = -1
        for name in length_names:
            if name in self.headers.keys():
                content_len = int(self.headers[name])
        if content_len < 0:
            if self.server.debug > 0:
                print("%s: Invalid request. No \"Content-Length\" in headers: %s" % (s_frame().f_code.co_name, self.headers))
            return [None, None]

        #
        # read submitted data and split it into individual values
        #
        data_pairs = str(unquote(self.rfile.read(content_len).decode('utf-8'))).split('&')
        post_data = {}
        for pair in data_pairs:
            data_split = pair.split('=')
            key = data_split[0]
            value = data_split[1]
            post_data[key] = value
            if self.server.debug > 3:
                print("%s: POST data (k,v) pair: \"%s\" = \"%s\"" % (s_frame().f_code.co_name, key, value))

        if self.server.debug > 2:
            print("%s: POST data: \"%s\"" % (s_frame().f_code.co_name, post_data))

        #
        # check and interpret received data
        #
        required_keys = ["voucher_kind", "voucher_duration",
                "buyer_firstname", "buyer_lastname", "buyer_email",
                "beneficiary_firstname", "beneficiary_lastname",
                "beneficiary_street", "beneficiary_zipcode", "beneficiary_city", # not required by script but by policy
                "g-recaptcha-response"]
        key_missing = False
        for key in required_keys:
            if key not in post_data.keys():
                if self.server.debug > 0:
                    print("%s: Invalid request. Key \"%s\" missing in POST data." % (s_frame().f_code.co_name, key))
                key_missing = True
        if key_missing:
            return [None, None]

        # recaptcha id (used as an error flag for voucher data if that is invalid)
        rc_response = post_data["g-recaptcha-response"]
        voucher_data = {}

        # decode kind into type and amount
        if post_data["voucher_kind"] == "1":
            voucher_data["type"] = "SF"
            voucher_data["amount"] = "35"
        elif post_data["voucher_kind"] == "2":
            voucher_data["type"] = "TMG"
            duration = int(post_data["voucher_duration"])
            if duration < 30 or duration > 120:
                if self.server.debug > 0:
                    print("%s: Invalid voucher duration: \"%s\"" % (s_frame().f_code.co_name, post_data["voucher_duration"]))
                rc_response = None
            duration = "%d" % (15 * int(ceil(duration / 15.0)))
            voucher_data["amount"] = duration

        # contact info
        voucher_data["buyer_firstname"] = post_data["buyer_firstname"]
        voucher_data["buyer_lastname"]  = post_data["buyer_lastname"]
        voucher_data["buyer_email"]     = post_data["buyer_email"]
        voucher_data["guest_firstname"] = post_data["beneficiary_firstname"]
        voucher_data["guest_lastname"]  = post_data["beneficiary_lastname"]

        # buyer IP for abuse protection / prevention
        voucher_data["ip"] = self.address_string()

        if self.server.debug > 1:
            print("%s: Voucher data: \"%s\"" % (s_frame().f_code.co_name, voucher_data))

        return [rc_response, voucher_data]


    #######
    def _respond_recaptcha_failed(self):
    #######
        if self.server.debug > 0:
            print("%s:" % (s_frame().f_code.co_name))
            print("%s: #####################" % (s_frame().f_code.co_name))
            print("%s: # Recaptcha FAILED! #" % (s_frame().f_code.co_name))
            print("%s: #####################" % (s_frame().f_code.co_name))
            print("%s:" % (s_frame().f_code.co_name))

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
            print("%s:" % (s_frame().f_code.co_name))
            print("%s: #########################" % (s_frame().f_code.co_name))
            print("%s: # INTERNAL SERVER ERROR #" % (s_frame().f_code.co_name))
            print("%s: #########################" % (s_frame().f_code.co_name))
            print("%s:" % (s_frame().f_code.co_name))
        if self.server.debug > 1:
            print("%s: User description:  %s" % (s_frame().f_code.co_name, user_desc))
            print("%s: Admin description: %s" % (s_frame().f_code.co_name, admin_desc))

        #
        # pack admin description, which can contain "bad" characters
        #
        admin_desc = b64encode(admin_desc.encode('utf-8')).decode('ascii')
        if self.server.debug > 0:
            print("%s: Base64 encoded message: \"%s\"" % (s_frame().f_code.co_name, admin_desc))

        # decode example:
        if self.server.debug > 0:
            admin_desc_dec = b64decode(admin_desc.encode('ascii')).decode('utf-8')
            print("%s: Base64 decode(encoded message): \"%s\"" % (s_frame().f_code.co_name, admin_desc_dec))

        #
        # Response -> redirect to failed page
        #
        self.send_response(http.server.HTTPStatus.FOUND)
        self.send_header('Location','https://brausegeier.de/gutscheinbestellung-fehlgeschlagen/?error_desc='+quote(user_desc)+'&error_code='+admin_desc)
        self.end_headers()


    #######
    def _respond_voucher_success(self, voucher):
    #######
        if self.server.debug > 0:
            print("%s:" % (s_frame().f_code.co_name))
            print("%s: ######################" % (s_frame().f_code.co_name))
            print("%s: # SUCCESSFUL Voucher #" % (s_frame().f_code.co_name))
            print("%s: ######################" % (s_frame().f_code.co_name))
            print("%s:" % (s_frame().f_code.co_name))
        if self.server.debug > 1:
            print("%s: %s" % (s_frame().f_code.co_name, voucher))

        #
        # Compose response mesage
        #
        if voucher["type"] == "SF":
            voucher_type = "Segelflug"
            voucher_amount = 35
        elif voucher["type"] == "TMG":
            voucher_minutes = int(voucher["amount"].split(",")[0])
            voucher_amount = int(110 * (voucher_minutes / 60.0))
            voucher_type = ("Motorsegler (%d Minuten)" % voucher_minutes)
        else:
            voucher_type = "!Fehler!"
            voucher_amount = 0

        voucher_message = ('''
        Hallo %s %s,</br>
        Sie haben einen %s Gutschein für %s %s bestellt. Bitte überweisen Sie den Betrag von %d Euro auf das folende Konto um den Gutschein zu aktivieren:</br>
        Inhaber: ...</br>
        IBAN: DE ...</br>
        BIC: ...</br>
        Verwendungszweck: %s
        ''' % (voucher["buyer_firstname"], voucher["buyer_lastname"], voucher_type, voucher["guest_firstname"], voucher["guest_lastname"], voucher_amount,
                voucher["id"]))

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
            print("%s:" % (s_frame().f_code.co_name))
            print("%s: ############################" % (s_frame().f_code.co_name))
            print("%s: # Unspecified SERVER ERROR #" % (s_frame().f_code.co_name))
            print("%s: ############################" % (s_frame().f_code.co_name))
            print("%s:" % (s_frame().f_code.co_name))
            print("%s: ########" % (s_frame().f_code.co_name))
            print("%s: # \"%s\" -> Sending code %d" % (s_frame().f_code.co_name, description, error_code))
            print("%s: ########" % (s_frame().f_code.co_name))

        #
        # Response -> just the error code
        #
        self.send_response(error_code)
        self.end_headers()


    ########
    def _ignore_request(self, type_str):
    ########
        if self.server.debug > 0:
            print("%s: Ignoring %s request." % (s_frame().f_code.co_name, type_str))
        self.send_response(http.server.HTTPStatus.BAD_REQUEST)
        self.end_headers()


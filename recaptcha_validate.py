#!/usr/bin/python3

import requests
import json

import inspect, sys


class RecaptchaValidate():
    ####################
    # public interface #
    ####################

    def __init__(self, debug = 0):
        self._debug = debug
        self._secret = None


    def set_credentials(self, secret):
        self._secret = secret


    def validate(self, challenge_response, request_ip = None):
        session = requests.Session()

        post_data = {
                "secret" : self._secret,
                "response"  : challenge_response
            }
        if request_ip is not None:
            post_data["remoteip"] = request_ip
            if self._debug > 1:
                print("%s: Verifying with IP: \"%s\"" % (sys._getframe().f_code.co_name, request_ip))

        #
        # perform check
        #
        response = session.post('https://www.google.com/recaptcha/api/siteverify', data=post_data)
        response_data = response.content.decode('utf-8')
        self._debug_page(response, sys._getframe().f_code.co_name, response_data)

        #
        # extract result
        #
        result = json.loads(response_data)
        if self._debug > 2:
            print("%s: Recaptcha response: %s" % (sys._getframe().f_code.co_name, result))

        return [result.get('success', None), result.get('hostname', None)]



    #############
    # internals #
    #############

    #######
    def _throw_error(self, error_id, text, func_name):
    #######
        print("%s: %s" % (func_name, text))
        self._error = error_id
        return error_id


    #######
    def _debug_page(self, resp, func_name, content = None):
    #######
        if not isinstance(resp, requests.Response):
            return self._throw_error(-1, "Invalid response: %s" % (resp), func_name)

        if self._debug > 1:
            print("%s: url: %s" % (func_name, resp.url))
            print("%s: Result code: %s" % (func_name, resp.status_code))
            if self._debug > 3:
                print("%s: Headers: %s" % (func_name, resp.headers))
                if self._debug > 4:
                    if content is None:
                        content = resp.content.decode('utf-8')
                    print("%s: Site data:" % (func_name))
                    print(content)


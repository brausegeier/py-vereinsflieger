#!/usr/bin/python3

import requests
import hashlib
import re
import time

import inspect, sys


class VF_API():
    ####################
    # public interface #
    ####################

    def __init__(self, debug = 0):
        self._debug = debug
        self._cleanup()
        self._session = requests.Session()


    def login(self, user_id, user_pwd, login_timeout = 1.5):
        if self._logged_in == 1:
            print("%s: Already logged in with user \"%s\"" % (sys._getframe().f_code.co_name, self._user_id))
            return self._logged_in

        self._user_id = user_id
        self._user_pwd_hash = hashlib.md5(user_pwd.encode()).hexdigest()

        self._scrape_login_page()
        self._get_useless_files()
        self._scrape_signin_js()
        self._get_pwdsalt()
        self._calc_login_data()

        if self._error < 0:
            return self._error

        if self._debug > 0:
            print("%s: Waiting for %s seconds ..." % (sys._getframe().f_code.co_name, login_timeout))
        time.sleep(login_timeout)

        return self._request_login()


    def create_voucher(self, voucher_type, voucher_name):
        if self._logged_in == 0:
            print("%s: Login first!" % (sys._getframe().f_code.co_name))
            return -1

        voucher_id = None

#        https://vereinsflieger.de/member/community/voucher/

        return voucher_id


    def logout(self):
        if self._logged_in == 0:
            print("%s: Not logged in. Logging out anyway..." % (sys._getframe().f_code.co_name))

        self._request_logout()
        self._cleanup()
        self._session.close()



    #############
    # internals #
    #############

    #######
    def _throw_error(self, error_id, text, func_name):
    #######
        print("%s: %s" % (func_name, text))
        self._error = error_id
        return error_id

    ########
    def _cleanup(self):
    ########
        self._logged_in = 0
        self._error = 0
        self._user_id = None
        self._user_pwd_hash = None
        self._input_kv = None
        self._js_version_id = None
        self._css_version_id_0 = None
        self._css_version_id_1 = None
        self._signin_js_id = None
        self._pwdsalt_site = None
        self._magic_id_0 = None
        self._magic_id_1 = None


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
                if not isinstance(self._session, requests.Session):
                    print("%s: Invalid Session: %s" % (func_name, self._session))
                else:
                    print("%s: Cookies: %s" % (func_name, self._session.cookies.get_dict()))
                if self._debug > 4:
                    if content is None:
                        content = resp.content.decode('utf-8')
                    print("%s: Site data:" % (func_name))
                    print(content)


    #######
    def _scrape_login_page(self):
    #######
        if self._error < 0:
            return self._error
        if not isinstance(self._session, requests.Session):
            return self._throw_error(-1, "Invalid session: %s" % (resp), sys._getframe().f_code.co_name)

        #login_page = s.get('https://vereinsflieger.de', cookies={"clientwidth" : "1920"})
        login_page = self._session.get('https://vereinsflieger.de')
        login_page_data = login_page.content.decode('utf-8')
        self._debug_page(login_page, sys._getframe().f_code.co_name, login_page_data)

        #
        # extract all input parameters
        #
        form_inputs = re.findall('<input type="hidden" name="[0-9a-z]+"[^<>]*value="[0-9a-z]+"[^<>]*/>', login_page_data)
        if self._debug > 3:
            print("%s: html form input query result: %s" % (sys._getframe().f_code.co_name, form_inputs))
        
        # populate input parameters
        self._input_kv = {}
        self._input_kv["user"] = ""
        self._input_kv["pwinput"] = ""
        self._input_kv["pw"] = ""
        for line in form_inputs:
            single_input = re.search('name="([0-9a-z]+)".*value="([0-9a-z]+)"', line)
            self._input_kv[single_input.group(1)] = single_input.group(2)
        if self._debug > 3:
            print("%s: html form input values: %s" % (sys._getframe().f_code.co_name, self._input_kv))

        #
        # check, if the login page contained a pwdsalt
        #
        if "pwdsalt" not in self._input_kv.keys():
            return self._throw_error(-2, "No pwdsalt found in html input form keys!", sys._getframe().f_code.co_name)

        #
        # search for various version ids
        #
        self._js_version_id     = re.search('<script src="/js/default\?v=(.+)"></script>', login_page_data).group(1)
        self._css_version_id_0  = re.search('href="/css/publicDefault\?v=(.+)" />', login_page_data).group(1)
        self._css_version_id_1  = re.search('href="/signin.css\?v=(.+)" />', login_page_data).group(1)
        self._signin_js_id      = re.search('<script src="signinjs\?v=(.+)"></script>', login_page_data).group(1)

        #
        # check, if those various version ids were sucessfully extracted
        #
        if self._js_version_id is None:
            return self._throw_error(-2, "No JS version ID found!", sys._getframe().f_code.co_name)
        if self._css_version_id_0 is None:
            return self._throw_error(-2, "No CSS version ID 0 found!", sys._getframe().f_code.co_name)
        if self._css_version_id_1 is None:
            return self._throw_error(-2, "No CSS version ID 1 found!", sys._getframe().f_code.co_name)
        if self._signin_js_id is None:
            return self._throw_error(-2, "No signin JS ID found!", sys._getframe().f_code.co_name)

        return 0


    #######
    def _get_useless_files(self):
    #######
        if self._error < 0:
            return self._error
        if not isinstance(self._session, requests.Session):
            return self._throw_error(-1, "Invalid session: %s" % (resp), sys._getframe().f_code.co_name)

        #
        # get those useless files that are required to get for the login to work
        #
        urls = [str('https://vereinsflieger.de/js/default?v='+self._js_version_id),
                str('https://vereinsflieger.de/js/public.js?v='+self._js_version_id),
                str('https://vereinsflieger.de/css/publicDefault?v='+self._css_version_id_0),
                str('https://vereinsflieger.de/signin.css?v='+self._css_version_id_1)]
        for url in urls:
            resp = self._session.get(url)
            if self._debug > 3:
                debug = self._debug
                # print the contents of those files only if it is really important (It goes up to 11!)
                if self._debug > 4 and self._debug < 11:
                    self._debug = 4
                self._debug_page(resp, sys._getframe().f_code.co_name)
                self._debug = debug

        return 0


    #######
    def _scrape_signin_js(self):
    #######
        if self._error < 0:
            return self._error
        if not isinstance(self._session, requests.Session):
            return self._throw_error(-1, "Invalid session: %s" % (resp), sys._getframe().f_code.co_name)

        if self._debug > 2:
            print("%s: Initial input form pwdsalt: \"%s\"" % (sys._getframe().f_code.co_name, self._input_kv["pwdsalt"]))
        if self._debug > 0:
            print("%s: Getting /signinjs with ID \"%s\"" % (sys._getframe().f_code.co_name, self._signin_js_id))

        #
        # get signin_js file
        #
        signin_js = self._session.get('https://vereinsflieger.de/signinjs?v='+self._signin_js_id)
        signin_js_data = signin_js.content.decode('utf-8')
        self._debug_page(signin_js, sys._getframe().f_code.co_name, signin_js_data)

        #
        # search for pwdsalt site and magic ids in signin js
        #
        self._pwdsalt_site = re.search('vfbase.loadContentX\(\'([a-z]+)\'\, \'post\'', signin_js_data).group(1)
        magic_ids = re.search('document.signin.([a-z]+).value = md5\(document.signin.pw.value\+"([0-9a-z]+)"\+document.signin.pwdsalt.value\);', signin_js_data)
        self._magic_id_0 = magic_ids.group(1)
        self._magic_id_1 = magic_ids.group(2)

        #
        # check, if we got a valid pwdsalt site and form inputs are available
        #
        if self._pwdsalt_site is None:
            return self._throw_error(-2, "No pwdsalt site found!", sys._getframe().f_code.co_name)
        if self._magic_id_0 is None:
            return self._throw_error(-2, "No magic id 0 found!", sys._getframe().f_code.co_name)
        if self._magic_id_1 is None:
            return self._throw_error(-2, "No magic id 1 found!", sys._getframe().f_code.co_name)
        if str(self._magic_id_0) not in self._input_kv.keys():
            return self._throw_error(-3, "Magic id 0 \"%s\" not present in input form keys!" % (self._magic_id_0), sys._getframe().f_code.co_name)
        if self._debug > 2:
            print("%s: pwdsalt_site ID: \"%s\"" % (sys._getframe().f_code.co_name, self._pwdsalt_site))
            print("%s: Magic ID 0: \"%s\"" % (sys._getframe().f_code.co_name, self._magic_id_0))
            print("%s: Magic ID 1: \"%s\"" % (sys._getframe().f_code.co_name, self._magic_id_1))
            if self._debug > 3:
                print("%s: Magic IDs search string: \"%s\"" % (sys._getframe().f_code.co_name, magic_ids.group()))
                print("%s: html form input values: %s" % (sys._getframe().f_code.co_name, self._input_kv))

        return 0


    #######
    def _get_pwdsalt(self):
    #######
        if self._error < 0:
            return self._error
        if not isinstance(self._session, requests.Session):
            return self._throw_error(-1, "Invalid session: %s" % (resp), sys._getframe().f_code.co_name)

        if self._debug > 0:
            print("%s: Getting actual pwdsalt from /\"pwdsalt_site\" with ID \"%s\"" % (sys._getframe().f_code.co_name, self._pwdsalt_site))

        #
        # get pwdsalt file
        #
        pwdsalt = self._session.post('https://vereinsflieger.de/'+self._pwdsalt_site, data=self._input_kv)
        pwdsalt_data = pwdsalt.content.decode('utf-8')
        self._debug_page(pwdsalt, sys._getframe().f_code.co_name, pwdsalt_data)

        #
        # check, if we got a valid pwdsalt
        #
        pwdsalt_len = len(pwdsalt_data)
        if pwdsalt_len != 32:
            return self._throw_error(-3, "Failed to get new pwdsalt, length mismatch. Expected 32 != %d actual." % (pwdsalt_len),
                    sys._getframe().f_code.co_name)
        self._input_kv["pwdsalt"] = pwdsalt_data

        if self._debug > 2:
            print("%s: New pwdsalt: \"%s\"" % (sys._getframe().f_code.co_name, self._input_kv["pwdsalt"]))
            if self._debug > 3:
                print("%s: html form input values: %s" % (sys._getframe().f_code.co_name, self._input_kv))

        return 0


    #######
    def _calc_login_data(self):
    #######
        if self._error < 0:
            return self._error
        if self._user_id is None:
            print("%s: No user_id given!" % (sys._getframe().f_code.co_name))
            self._error = -5
        if self._user_pwd_hash is None:
            print("%s: No user_pwd given!" % (sys._getframe().f_code.co_name))
            self._error = -5
        if self._error < 0:
            return self._throw_error(self._error, "No credentials available!", sys._get_frame().f_code.co_name)
        if "pwdsalt" not in self._input_kv.keys():
            return self._throw_error(-2, "No pwdsalt in html form inputs!", sys._get_frame().f_code.co_name)

        if self._debug > 0:
            print("%s: Calculating new magic value 0." % (sys._getframe().f_code.co_name))
            if self._debug > 2:
                print("%s: Old magic value 0: \"%s\"" % (sys._getframe().f_code.co_name, self._input_kv[self._magic_id_0]))

        #
        # calculate new magic_id_0 value
        #
        md5_input = str(self._user_pwd_hash)+str(self._magic_id_1)+str(self._input_kv["pwdsalt"])
        self._input_kv[self._magic_id_0] = hashlib.md5(md5_input.encode()).hexdigest()
        if self._debug > 2:
            print("%s: User pwd hash: \"%s\"" % (sys._getframe().f_code.co_name, self._user_pwd_hash))
            print("%s: MD5 input: \"%s\"" % (sys._getframe().f_code.co_name, md5_input))
            print("%s: New magic value 0: \"%s\"" % (sys._getframe().f_code.co_name, self._input_kv[self._magic_id_0]))

        #
        # set/clear other form input values
        #
        self._input_kv["user"] = str(self._user_id)
        self._input_kv["pwinput"] = ""
        self._input_kv["pw"] = str(self._user_pwd_hash)
        #self._input_kv["stayloggedin"] = "0"

        if self._debug > 3:
            print("%s: html form input values: %s" % (sys._getframe().f_code.co_name, self._input_kv))

        return 0


    #######
    def _request_login(self):
    #######
        if self._error < 0:
            return self._error
        if not isinstance(self._session, requests.Session):
            return self._throw_error(-1, "Invalid session: %s" % (resp), sys._getframe().f_code.co_name)

        if self._debug > 0:
            print("%s: Performing login request" % (sys._getframe().f_code.co_name))

        #
        # login, i.e. do a post request with encoded pwd values
        #
        main_page = self._session.post('https://vereinsflieger.de', data=self._input_kv)#, cookies=login_cookies)
        main_page_data = main_page.content.decode('utf-8')
        self._debug_page(main_page, sys._getframe().f_code.co_name, main_page_data)

        #
        # check if it worked
        #
        #if re.search('<form id="signin" name="signin"', main_page_data) is None:
        if main_page.url == 'https://vereinsflieger.de/member/overview/overview':
            self._logged_in = 1
            if self._debug > 0:
                print("%s:" % (sys._getframe().f_code.co_name))
                print("%s: ####################" % (sys._getframe().f_code.co_name))
                print("%s: # SUCCESSFUL login #" % (sys._getframe().f_code.co_name))
                print("%s: ####################" % (sys._getframe().f_code.co_name))
                print("%s:" % (sys._getframe().f_code.co_name))
        else:
            self._logged_in = 0
            if self._debug > 0:
                print("%s:" % (sys._getframe().f_code.co_name))
                print("%s: ################" % (sys._getframe().f_code.co_name))
                print("%s: # Login FAILED #" % (sys._getframe().f_code.co_name))
                print("%s: ################" % (sys._getframe().f_code.co_name))
                print("%s:" % (sys._getframe().f_code.co_name))

        if self._debug > 3:
            print("%s: html form input values: %s" % (sys._getframe().f_code.co_name, self._input_kv))
            
        return self._logged_in


    ########
    def _request_logout(self):
    ########
        if self._error < 0:
            return self._error
        if not isinstance(self._session, requests.Session):
            return self._throw_error(-1, "Invalid session: %s" % (resp), sys._getframe().f_code.co_name)

        if self._debug > 0:
            print("%s: Logging out" % (sys._getframe().f_code.co_name))

        #
        # log out
        #
        resp = self._session.get('https://vereinsflieger.de/signout.php?signout=1')
        self._debug_page(resp, sys._getframe().f_code.co_name)
            
        return 0


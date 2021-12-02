#!/usr/bin/python3

import requests
import hashlib
import re
import pandas as pd
from io import StringIO
import time

import inspect, sys


class VF_API():
    ####################
    # public interface #
    ####################

    def __init__(self, debug = 0):
        self._cleanup()
        self._debug = debug
        self._session = requests.Session()


    def login(self, user_id, user_pwd, login_timeout = 2.0):
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


    def create_voucher(self, voucher_data):
        self._cleanup_voucher()
        if self._logged_in == 0:
            print("%s: Login first!" % (sys._getframe().f_code.co_name))
            return -1

        self._voucher_data = voucher_data
        self._voucher_data["valid"] = False
        self._get_voucher_list()
        self._generate_next_voucher_id()
        self._register_voucher()
        self._validate_voucher()
        res = [self._voucher_valid, self._voucher_data]
        self._cleanup_voucher()
        return res


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
        self._error = 0
        self._cleanup_login()
        self._cleanup_voucher()


    ########
    def _cleanup_login(self):
    ########
        self._logged_in = 0
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


    ########
    def _cleanup_voucher(self):
    ########
        self._voucher_valid = False
        self._voucher_list = None
        self._voucher_data = None


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
        # check, if those various version ids were successfully extracted
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
        main_page = self._session.post('https://vereinsflieger.de', data=self._input_kv)
        main_page_data = main_page.content.decode('utf-8')
        self._debug_page(main_page, sys._getframe().f_code.co_name, main_page_data)

        #
        # check if it worked
        #
        if re.search('onclick="document.location.href=\'/signout.php\?signout=1\'">Abmelden<', main_page_data).group() is not None:
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


    ########
    def _get_voucher_list(self):
    ########
        if self._error < 0:
            return self._error
        if not isinstance(self._session, requests.Session):
            return self._throw_error(-1, "Invalid session: %s" % (resp), sys._getframe().f_code.co_name)

        if self._debug > 0:
            print("%s: Getting voucher list" % (sys._getframe().f_code.co_name))

        #
        # get voucher list csv file, extract encoding type from http headers
        #
        voucher_list = self._session.get('https://vereinsflieger.de/member/community/voucher/voucher.php?output=csv&exportlistid=96')
        voucher_encoding = re.search('\'Content-Type\': \'application/octet-stream;charset=([a-zA-Z0-9-]+);\', \'Content-Length\'', str(voucher_list.headers)).group(1)

        if self._debug > 2:
            print("%s: Voucher list encoding: \"%s\"" % (sys._getframe().f_code.co_name, voucher_encoding))
        if self._debug > 0:
            print("%s: Decoding voucher list" % (sys._getframe().f_code.co_name))

        #
        # decode data
        #
        #self._voucher_list = csv.reader(voucher_list.content.decode(voucher_encoding), delimiter=';')
        self._voucher_list = pd.read_csv(StringIO(voucher_list.content.decode(voucher_encoding)), delimiter=';')
        self._debug_page(voucher_list, sys._getframe().f_code.co_name, self._voucher_list)

        if self._debug > 3:
            print("%s: Voucher list column names: \"%s\"" % (sys._getframe().f_code.co_name, self._voucher_list.columns))

        #
        # some sanity checks on the received data
        #
        if self._voucher_list.ndim != 2 or "Ausgestellt am" not in self._voucher_list.columns:
            self._voucher_list = None
            return self._throw_error(-3, "Failed to get valid voucher list", sys._getframe().f_code.co_name)

        return 0


    ########
    def _generate_next_voucher_id(self):
    ########
        if self._error < 0:
            return self._error
        if not isinstance(self._voucher_list, pd.DataFrame):
            return self._throw_error(-3, "Invalid voucher list: %s" % (self._voucher_list), sys._getframe().f_code.co_name)

        self._voucher_data["id"] = None

        if self._debug > 0:
            print("%s: Generating new voucher ID" % (sys._getframe().f_code.co_name))

        #
        # filter by voucher type and sort by id to get latest / highest id
        # 
        vl = self._voucher_list.copy()
        vl = vl[vl.Nummer.str.startswith(self._voucher_data["type"]+"-")]
        vl.sort_values(by="Nummer", inplace=True, ascending=False)

        #
        # split voucher id into components
        #
        voucher_id = vl.iloc[0].Nummer
        if self._debug > 1:
            print("%s: Latest voucher ID of type %s: \"%s\"" % (sys._getframe().f_code.co_name, self._voucher_data["type"], voucher_id))
        
        voucher_id_split = re.search('^[^-]+-([0-9]+)-([0-9]+)', voucher_id)
        voucher_year = voucher_id_split.group(1)
        voucher_number = voucher_id_split.group(2)
#        #voucher_id_split = re.search('^[^-]+-([0-9]+)-([0-9]+)-([2-9A-HJ-NP-Z]*)', voucher_id)
#        #voucher_hash = voucher_id_split.group(3)

        # 
        # generate next voucher id
        #
        current_year = time.strftime("%Y")
        if int(current_year) > int(voucher_year):
            # new year, start over
            voucher_number = 1
        else:
            voucher_number = int(voucher_number) + 1

        #
        # check, if the new id is not already in use for some obscure reason
        #
        while (True):
            if voucher_number > 999:
                return self._throw_error(-10, "Maximum number of vouchers reached (%d). No more vouchers available this year." % (voucher_number-1), sys._getframe().f_code.co_name)
    
            voucher_id = self._voucher_data["type"]+"-"+current_year+("-%03d" % voucher_number)
            if self._debug > 1:
                print("%s: Checking if voucher ID \"%s\" already exists." % (sys._getframe().f_code.co_name, voucher_id))

            # check if it exists already
            if voucher_id in self._voucher_list.Nummer.values:
                if self._debug > 1:
                    print("%s: Voucher ID \"%s\" is already present." % (sys._getframe().f_code.co_name, voucher_id))
                voucher_number = voucher_number + 1
            else:
                if self._debug > 1:
                    print("%s: Voucher ID \"%s\" is still free." % (sys._getframe().f_code.co_name, voucher_id))
                self._voucher_data["id"] = voucher_id
                break

#        #
#        # add 4 digit alphanumeric "hash" (leave out digits 0,1, and letters O,I)
#        #
#        voucher_hash = "A4QV"
#        self._voucher_data["id"] = self._voucher_data["id"]+"-"+voucher_hash
        if self._debug > 0:
            print("%s: New voucher ID: \"%s\"" % (sys._getframe().f_code.co_name, voucher_id))

        return 0


    ########
    def _register_voucher(self):
    ########
        if self._error < 0:
            return self._error
        if not isinstance(self._session, requests.Session):
            return self._throw_error(-1, "Invalid session: %s" % (resp), sys._getframe().f_code.co_name)

        if self._debug > 0:
            print("%s: Creating voucher with ID: \"%s\"" % (sys._getframe().f_code.co_name, self._voucher_data["id"]))
            if self._debug > 1:
                print("%s: Submitting form querry request." % (sys._getframe().f_code.co_name))

        #
        # get preset voucher variables
        #
        voucher_page = self._session.get('https://vereinsflieger.de/member/community/voucher/addvid')
        voucher_page_data = voucher_page.content.decode('utf-8')
        self._debug_page(voucher_page, sys._getframe().f_code.co_name, voucher_page_data)

        # extract input parameters
        form_inputs = re.findall('<input.*name=\'[^\']+\'.*value=\'[^\']*\'.*[/]*>', voucher_page_data)
        if self._debug > 3:
            print("%s: voucher form input query result: %s" % (sys._getframe().f_code.co_name, form_inputs))
        # populate input parameters
        voucher_data = {}
        for line in form_inputs:
            single_input = re.search('name=\'([^\']+)\'.*value=\'([^\']*)\'', line)
            if self._debug > 3:
                print("%s: single input: %s" % (sys._getframe().f_code.co_name, single_input))
            voucher_data[single_input.group(1)] = single_input.group(2)

#        # extract "select" parameters
#        form_inputs = re.findall('<select.*name=\'[^\']+\'', voucher_page_data)
#        if self._debug > 3:
#            print("%s: voucher form select query result: %s" % (sys._getframe().f_code.co_name, form_inputs))
#        # populate "select" parameters
#        for line in form_inputs:
#            single_input = re.search('name=\'([^\']+)\'', line)
#            if self._debug > 3:
#                print("%s: single select: %s" % (sys._getframe().f_code.co_name, single_input))
#            voucher_data[single_input.group(1)] = ""

        if self._debug > 2:
            print("%s: extracted voucher form data: %s" % (sys._getframe().f_code.co_name, voucher_data))

        #
        # fill in data
        #
        voucher_data["frm_email"]       = str(self._voucher_data["email"])
        voucher_data["frm_firstname"]   = str(self._voucher_data["firstname"])
        voucher_data["frm_lastname"]    = str(self._voucher_data["lastname"])
        voucher_data["frm_voucherid"]   = str(self._voucher_data["id"])
        voucher_data["frm_value"]       = str(self._voucher_data["amount"])+",00"
        voucher_data["frm_title"]       = "Gutschein"
        voucher_data["frm_status"]      = "1" # "Erstellt"
        voucher_data["uid_browse"]      = "" # Do not prepopulate voucher user data
        voucher_data["action"]          = "saveclose" # Create the voucher

        # for comment
        voucher_provider = "brausegeier.de"
        voucher_date = time.strftime("%d.%m.%Y")
        voucher_time = time.strftime("%H:%M")
        # Optional logging of IP address to prevent / investigate abuse
        voucher_ip = ""
        if "ip" in self._voucher_data.keys():
            voucher_ip = " von IP "+str(self._voucher_data["ip"])
        voucher_data["frm_comment"] = "Automatisch erstellt über %s am %s um %s Uhr%s. Zahlungsaufforderung gesendet an %s" % (voucher_provider, voucher_date,
                voucher_time, voucher_ip, voucher_data["frm_email"])


        if self._debug > 1:
            print("%s: Submitting creation request." % (sys._getframe().f_code.co_name))
            if self._debug > 2:
                print("%s: Submitting voucher form data: %s" % (sys._getframe().f_code.co_name, voucher_data))

        #
        # submit voucher creation request
        #
        voucher_request = self._session.post('https://vereinsflieger.de/member/community/voucher/addvid', data=voucher_data)
        self._debug_page(voucher_request, sys._getframe().f_code.co_name)

        return 0


    ########
    def _validate_voucher(self):
    ########
        self._voucher_valid = False
        self._voucher_data["valid"] = False

        if self._error < 0:
            return self._error
        if "id" not in self._voucher_data or self._voucher_data["id"] is None:
            return self._throw_error(-3, "Invalid voucher ID", sys._getframe().f_code.co_name)

        if self._debug > 0:
            print("%s: Verifying voucher with ID: \"%s\"" % (sys._getframe().f_code.co_name, self._voucher_data["id"]))

        #
        # Get (new) voucher list and check if new id is present
        #
        self._get_voucher_list()

        # validate list
        if not isinstance(self._voucher_list, pd.DataFrame):
            return self._throw_error(-3, "Invalid voucher list: %s" % (self._voucher_list), sys._getframe().f_code.co_name)

        if self._debug > 0:
            print("%s: Voucher ID: \"%s\"" % (sys._getframe().f_code.co_name, self._voucher_data["id"]))
            print("%s:" % (sys._getframe().f_code.co_name))

        # check for presence of voucher id
        if self._voucher_data["id"] in self._voucher_list.Nummer.values:
            self._voucher_valid = True
            self._voucher_data["valid"] = True
            if self._debug > 0:
                print("%s: #################" % (sys._getframe().f_code.co_name))
                print("%s: # VALID voucher #" % (sys._getframe().f_code.co_name))
                print("%s: #################" % (sys._getframe().f_code.co_name))
        else:
            self._voucher_valid = False
            self._voucher_data["valid"] = False
            if self._debug > 0:
                print("%s: ###################" % (sys._getframe().f_code.co_name))
                print("%s: # voucher INVALID #" % (sys._getframe().f_code.co_name))
                print("%s: ###################" % (sys._getframe().f_code.co_name))

        if self._debug > 0:
            print("%s:" % (sys._getframe().f_code.co_name))

        return 0


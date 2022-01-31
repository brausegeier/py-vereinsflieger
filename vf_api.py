################################################################################
# py-vereinsflieger/vf_api.py
#
# Copyright Alexander Bleitner, 2021.
#
# License: GPL-3.0-or-later
################################################################################


import re
from requests   import Session, Response
from hashlib    import md5
from pandas     import DataFrame, read_csv
from io         import StringIO
from time       import sleep, strftime
from sys        import _getframe as s_frame


class VF_API():
    ####################
    # public interface #
    ####################

    def __init__(self, debug = 0):
        self._cleanup()
        self._debug = debug
        self._session = Session()
        self._user_id = None
        self._user_pwd_hash = None
        self._invoice_caid = None
        self._invoice_caid_field = None


    def set_credentials(self, user_id, user_pwd):
        if self._logged_in:
            if self._debug > 0:
                print("%s: Logging out previous user \"%s\"." % (s_frame().f_code.co_name, self._user_id))
            self.logout()

        self._user_id = user_id
        self._user_pwd_hash = md5(user_pwd.encode()).hexdigest()


    def set_invoice_ids(self, caid, caid_field):
        self._invoice_caid = caid
        self._invoice_caid_field = caid_field


    def create_voucher(self, voucher_data, create_invoice = True):
        self._cleanup_voucher()
        if not self._logged_in:
            if self._debug > 0:
                print("%s: Logging in." % (s_frame().f_code.co_name))
            self.login()

        if not self._logged_in:
            if self._debug > 0:
                print("%s: Login failed!" % (s_frame().f_code.co_name))
            return [None, None]

        self._voucher_data = voucher_data
        self._voucher_data["valid"] = False
        self._get_voucher_list()
        self._generate_next_voucher_id()
        self._register_voucher()
        self._validate_voucher()
        if create_invoice:
            self._create_invoice()
        res = [self._voucher_valid, self._voucher_data]
        self._cleanup_voucher()

        self.logout()

        return res


    def login(self, user_id = None, user_pwd = None, login_timeout = 2.0):
        if self._logged_in:
            print("%s: Already logged in with user \"%s\". Logout first!" % (s_frame().f_code.co_name, self._user_id))
            return self._logged_in

        if user_id is not None:
            self._user_id = user_id
        if user_pwd is not None:
            self._user_pwd_hash = md5(user_pwd.encode()).hexdigest()

        self._scrape_login_page()
        self._get_useless_files()
        self._scrape_signin_js()
        self._get_pwdsalt()
        self._calc_login_data()

        if self._error < 0:
            return self._error

        if self._debug > 0:
            print("%s: Waiting for %s seconds ..." % (s_frame().f_code.co_name, login_timeout))
        sleep(login_timeout)

        return self._request_login()


    def logout(self):
        if not self._logged_in:
            if self._debug > 0:
                print("%s: Not logged in. Logging out anyway..." % (s_frame().f_code.co_name))

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
        self._logged_in = False
        self._input_kv = None
        self._js_version_id = None
        self._css_version_id_0 = None
        self._css_version_id_1 = None
        self._signin_js_id = None
        self._signin_js_file = None
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
        if not isinstance(resp, Response):
            return self._throw_error(-1, "Invalid response: %s" % (resp), func_name)

        if self._debug > 1:
            print("%s: url: %s" % (func_name, resp.url))
            print("%s: Result code: %s" % (func_name, resp.status_code))
            if self._debug > 3:
                print("%s: Headers: %s" % (func_name, resp.headers))
                if not isinstance(self._session, Session):
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
        if not isinstance(self._session, Session):
            return self._throw_error(-1, "Invalid session: %s" % (resp), s_frame().f_code.co_name)

        login_page = self._session.get('https://vereinsflieger.de')
        login_page_data = login_page.content.decode('utf-8')
        self._debug_page(login_page, s_frame().f_code.co_name, login_page_data)

        #
        # extract all input parameters
        #
        form_inputs = re.findall('<input type="hidden" name="[0-9a-z]+"[^<>]*value="[0-9a-z]+"[^<>]*/>', login_page_data)
        if self._debug > 3:
            print("%s: html form input query result: %s" % (s_frame().f_code.co_name, form_inputs))
        
        # populate input parameters
        self._input_kv = {}
        self._input_kv["user"] = ""
        self._input_kv["pwinput"] = ""
        self._input_kv["pw"] = ""
        for line in form_inputs:
            single_input = re.search('name="([0-9a-z]+)".*value="([0-9a-z]+)"', line)
            if single_input is None:
                return self._throw_error(-1, "Failed to extract any input tag.", s_frame().f_code.co_name)
            self._input_kv[single_input.group(1)] = single_input.group(2)
        if self._debug > 3:
            print("%s: html form input values: %s" % (s_frame().f_code.co_name, self._input_kv))

        #
        # check, if the login page contained a pwdsalt
        #
        if "pwdsalt" not in self._input_kv.keys():
            return self._throw_error(-2, "No pwdsalt found in html input form keys!", s_frame().f_code.co_name)

        #
        # search for various version ids
        #
        self._js_version_id     = re.search('<script src="/js/default\?v=(.+)"></script>', login_page_data)
        self._css_version_id_0  = re.search('href="/css/publicDefault\?v=(.+)" />', login_page_data)
        self._css_version_id_1  = re.search('href="/signin.css\?v=(.+)" />', login_page_data)
        self._signin_js_id      = re.search('<script src="([a-zA-Z]+)\?v=(.+)"></script>', login_page_data)

        if self._js_version_id is None:
            return self._throw_error(-1, "Failed to extract js_version_id.", s_frame().f_code.co_name)
        if self._css_version_id_0 is None:
            return self._throw_error(-1, "Failed to extract css_version_id_0.", s_frame().f_code.co_name)
        if self._css_version_id_1 is None:
            return self._throw_error(-1, "Failed to extract css_version_id_1.", s_frame().f_code.co_name)
        if self._signin_js_id is None:
            return self._throw_error(-1, "Failed to extract signin_js_id.", s_frame().f_code.co_name)
        self._js_version_id     = self._js_version_id.group(1)
        self._css_version_id_0  = self._css_version_id_0.group(1)
        self._css_version_id_1  = self._css_version_id_1.group(1)
        self._signin_js_file    = self._signin_js_id.group(1)
        self._signin_js_id      = self._signin_js_id.group(2)

        #
        # check, if those various version ids were successfully extracted
        #
        if self._js_version_id is None:
            return self._throw_error(-2, "No JS version ID found!", s_frame().f_code.co_name)
        if self._css_version_id_0 is None:
            return self._throw_error(-2, "No CSS version ID 0 found!", s_frame().f_code.co_name)
        if self._css_version_id_1 is None:
            return self._throw_error(-2, "No CSS version ID 1 found!", s_frame().f_code.co_name)
        if self._signin_js_file is None:
            return self._throw_error(-2, "No signin JS file found!", s_frame().f_code.co_name)
        if self._signin_js_id is None:
            return self._throw_error(-2, "No signin JS ID found!", s_frame().f_code.co_name)

        return 0


    #######
    def _get_useless_files(self):
    #######
        if self._error < 0:
            return self._error
        if not isinstance(self._session, Session):
            return self._throw_error(-1, "Invalid session: %s" % (resp), s_frame().f_code.co_name)

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
                self._debug_page(resp, s_frame().f_code.co_name)
                self._debug = debug

        return 0


    #######
    def _scrape_signin_js(self):
    #######
        if self._error < 0:
            return self._error
        if not isinstance(self._session, Session):
            return self._throw_error(-1, "Invalid session: %s" % (resp), s_frame().f_code.co_name)

        if self._debug > 2:
            print("%s: Initial input form pwdsalt: \"%s\"" % (s_frame().f_code.co_name, self._input_kv["pwdsalt"]))
        if self._debug > 0:
            print("%s: Getting /signinjs (%s) with ID \"%s\"" % (s_frame().f_code.co_name, self._signin_js_file, self._signin_js_id))

        #
        # get signin_js file
        #
        signin_js = self._session.get('https://vereinsflieger.de/'+self._signin_js_file+'?v='+self._signin_js_id)
        signin_js_data = signin_js.content.decode('utf-8')
        self._debug_page(signin_js, s_frame().f_code.co_name, signin_js_data)

        #
        # search for pwdsalt site and magic ids in signin js
        #
        self._pwdsalt_site = re.search('vfbase.loadContentX\(\'([a-z]+)\'\, \'post\'', signin_js_data)
        magic_ids = re.search('document.signin.([a-z]+).value = md5\(document.signin.pw.value\+"([0-9a-z]+)"\+document.signin.pwdsalt.value\);', signin_js_data)
        if self._pwdsalt_site is None:
            return self._throw_error(-1, "Failed to extract pwdsalt_site.", s_frame().f_code.co_name)
        if magic_ids is None:
            return self._throw_error(-1, "Failed to extract magic_ids.", s_frame().f_code.co_name)
        self._pwdsalt_site = self._pwdsalt_site.group(1)
        self._magic_id_0 = magic_ids.group(1)
        self._magic_id_1 = magic_ids.group(2)

        #
        # extract substring parameters
        #
        substr_search = re.search('resultdata.response.substr\(([0-9]+),([0-9]+)\);', signin_js_data)
        if substr_search is None:
            return self._throw_error(-1, "Failed to extract substr data from pwdsalt_site.", s_frame().f_code.co_name)
        self._substr_start = int(substr_search.group(1))
        self._substr_end = self._substr_start + int(substr_search.group(2))

        #
        # check, if we got a valid pwdsalt site and form inputs are available
        #
        if self._pwdsalt_site is None:
            return self._throw_error(-2, "No pwdsalt site found!", s_frame().f_code.co_name)
        if self._magic_id_0 is None:
            return self._throw_error(-2, "No magic id 0 found!", s_frame().f_code.co_name)
        if self._magic_id_1 is None:
            return self._throw_error(-2, "No magic id 1 found!", s_frame().f_code.co_name)
        if str(self._magic_id_0) not in self._input_kv.keys():
            return self._throw_error(-3, "Magic id 0 \"%s\" not present in input form keys!" % (self._magic_id_0), s_frame().f_code.co_name)
        if self._debug > 2:
            print("%s: pwdsalt_site ID: \"%s\"" % (s_frame().f_code.co_name, self._pwdsalt_site))
            print("%s: Magic ID 0: \"%s\"" % (s_frame().f_code.co_name, self._magic_id_0))
            print("%s: Magic ID 1: \"%s\"" % (s_frame().f_code.co_name, self._magic_id_1))
            print("%s: Substr start: \"%d\"" % (s_frame().f_code.co_name, self._substr_start))
            print("%s: Substr end:   \"%d\"" % (s_frame().f_code.co_name, self._substr_end))
            if self._debug > 3:
                print("%s: Magic IDs search string: \"%s\"" % (s_frame().f_code.co_name, magic_ids.group()))
                print("%s: html form input values: %s" % (s_frame().f_code.co_name, self._input_kv))

        return 0


    #######
    def _get_pwdsalt(self):
    #######
        if self._error < 0:
            return self._error
        if not isinstance(self._session, Session):
            return self._throw_error(-1, "Invalid session: %s" % (resp), s_frame().f_code.co_name)

        if self._debug > 0:
            print("%s: Getting actual pwdsalt from /\"pwdsalt_site\" with ID \"%s\"" % (s_frame().f_code.co_name, self._pwdsalt_site))

        #
        # get pwdsalt file
        #
        pwdsalt = self._session.post('https://vereinsflieger.de/'+self._pwdsalt_site, data=self._input_kv)
        pwdsalt_data = pwdsalt.content.decode('utf-8')
        self._debug_page(pwdsalt, s_frame().f_code.co_name, pwdsalt_data)

        #
        # check, if we got a valid pwdsalt
        #
        pwdsalt_len = len(pwdsalt_data)
        if pwdsalt_len < self._substr_end:
            return self._throw_error(-3, "Failed to get new pwdsalt, length too short. Expected at least %d > %d actual." % (self._substr_end, pwdsalt_len),
                    s_frame().f_code.co_name)
	#
	# Extract requested substring
	#
        self._input_kv["pwdsalt"] = pwdsalt_data[self._substr_start:self._substr_end]

        if self._debug > 2:
            print("%s: New pwdsalt: \"%s\"" % (s_frame().f_code.co_name, self._input_kv["pwdsalt"]))
            print("%s: New pwdsalt length: \"%d\"" % (s_frame().f_code.co_name, len(self._input_kv["pwdsalt"])))
            if self._debug > 3:
                print("%s: html form input values: %s" % (s_frame().f_code.co_name, self._input_kv))

        return 0


    #######
    def _calc_login_data(self):
    #######
        if self._error < 0:
            return self._error
        if self._user_id is None:
            print("%s: No user_id given!" % (s_frame().f_code.co_name))
            self._error = -5
        if self._user_pwd_hash is None:
            print("%s: No user_pwd given!" % (s_frame().f_code.co_name))
            self._error = -5
        if self._error < 0:
            return self._throw_error(self._error, "No credentials available!", sys._get_frame().f_code.co_name)
        if "pwdsalt" not in self._input_kv.keys():
            return self._throw_error(-2, "No pwdsalt in html form inputs!", sys._get_frame().f_code.co_name)

        if self._debug > 0:
            print("%s: Calculating new magic value 0." % (s_frame().f_code.co_name))
            if self._debug > 2:
                print("%s: Old magic value 0: \"%s\"" % (s_frame().f_code.co_name, self._input_kv[self._magic_id_0]))

        #
        # calculate new magic_id_0 value
        #
        md5_input = str(self._user_pwd_hash)+str(self._magic_id_1)+str(self._input_kv["pwdsalt"])
        self._input_kv[self._magic_id_0] = md5(md5_input.encode()).hexdigest()
        if self._debug > 2:
            print("%s: User pwd hash: \"%s\"" % (s_frame().f_code.co_name, self._user_pwd_hash))
            print("%s: MD5 input: \"%s\"" % (s_frame().f_code.co_name, md5_input))
            print("%s: New magic value 0: \"%s\"" % (s_frame().f_code.co_name, self._input_kv[self._magic_id_0]))

        #
        # set/clear other form input values
        #
        self._input_kv["user"] = str(self._user_id)
        self._input_kv["pwinput"] = ""
        self._input_kv["pw"] = str(self._user_pwd_hash)
        #self._input_kv["stayloggedin"] = "0"

        if self._debug > 3:
            print("%s: html form input values: %s" % (s_frame().f_code.co_name, self._input_kv))

        return 0


    #######
    def _request_login(self):
    #######
        if self._error < 0:
            return self._error
        if not isinstance(self._session, Session):
            return self._throw_error(-1, "Invalid session: %s" % (resp), s_frame().f_code.co_name)

        if self._debug > 0:
            print("%s: Performing login request" % (s_frame().f_code.co_name))

        #
        # login, i.e. do a post request with encoded pwd values
        #
        main_page = self._session.post('https://vereinsflieger.de', data=self._input_kv)
        main_page_data = main_page.content.decode('utf-8')
        self._debug_page(main_page, s_frame().f_code.co_name, main_page_data)

        #
        # check if it worked
        #
        if re.search('onclick="document.location.href=\'/signout.php\?signout=1\'">Abmelden<', main_page_data) is not None:
            self._logged_in = 1
            if self._debug > 0:
                print("%s:" % (s_frame().f_code.co_name))
                print("%s: ####################" % (s_frame().f_code.co_name))
                print("%s: # SUCCESSFUL login #" % (s_frame().f_code.co_name))
                print("%s: ####################" % (s_frame().f_code.co_name))
                print("%s:" % (s_frame().f_code.co_name))
        else:
            self._logged_in = 0
            if self._debug > 0:
                print("%s:" % (s_frame().f_code.co_name))
                print("%s: ################" % (s_frame().f_code.co_name))
                print("%s: # Login FAILED #" % (s_frame().f_code.co_name))
                print("%s: ################" % (s_frame().f_code.co_name))
                print("%s:" % (s_frame().f_code.co_name))

        if self._debug > 3:
            print("%s: html form input values: %s" % (s_frame().f_code.co_name, self._input_kv))
            
        return self._logged_in


    ########
    def _request_logout(self):
    ########
        if self._error < 0:
            return self._error
        if not isinstance(self._session, Session):
            return self._throw_error(-1, "Invalid session: %s" % (resp), s_frame().f_code.co_name)

        if self._debug > 0:
            print("%s: Logging out" % (s_frame().f_code.co_name))

        #
        # log out
        #
        resp = self._session.get('https://vereinsflieger.de/signout.php?signout=1')
        self._debug_page(resp, s_frame().f_code.co_name)
            
        return 0


    ########
    def _get_voucher_list(self):
    ########
        if self._error < 0:
            return self._error
        if not isinstance(self._session, Session):
            return self._throw_error(-1, "Invalid session: %s" % (resp), s_frame().f_code.co_name)

        if self._debug > 0:
            print("%s: Getting voucher list" % (s_frame().f_code.co_name))

        #
        # get voucher list csv file, extract encoding type from http headers
        #
        voucher_list = self._session.get('https://vereinsflieger.de/member/community/voucher/voucher.php?output=csv&exportlistid=96')
        voucher_encoding = re.search('\'Content-Type\': \'application/octet-stream;charset=([a-zA-Z0-9-]+);\', \'Content-Length\'', str(voucher_list.headers))
        if voucher_encoding is None:
            return self._throw_error(-1, "Failed to extract encoding.", s_frame().f_code.co_name)
        voucher_encoding = voucher_encoding.group(1)

        if self._debug > 2:
            print("%s: Voucher list encoding: \"%s\"" % (s_frame().f_code.co_name, voucher_encoding))
        if self._debug > 0:
            print("%s: Decoding voucher list" % (s_frame().f_code.co_name))

        #
        # decode data
        #
        #self._voucher_list = csv.reader(voucher_list.content.decode(voucher_encoding), delimiter=';')
        self._voucher_list = read_csv(StringIO(voucher_list.content.decode(voucher_encoding)), delimiter=';')
        self._debug_page(voucher_list, s_frame().f_code.co_name, self._voucher_list)

        if self._debug > 3:
            print("%s: Voucher list column names: \"%s\"" % (s_frame().f_code.co_name, self._voucher_list.columns))

        #
        # some sanity checks on the received data
        #
        if self._voucher_list.ndim != 2 or "Ausgestellt am" not in self._voucher_list.columns:
            self._voucher_list = None
            return self._throw_error(-3, "Failed to get valid voucher list", s_frame().f_code.co_name)

        return 0


    ########
    def _generate_next_voucher_id(self):
    ########
        if self._error < 0:
            return self._error
        if not isinstance(self._voucher_list, DataFrame):
            return self._throw_error(-3, "Invalid voucher list: %s" % (self._voucher_list), s_frame().f_code.co_name)

        self._voucher_data["id"] = None

        if self._debug > 0:
            print("%s: Generating new voucher ID" % (s_frame().f_code.co_name))

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
            print("%s: Latest voucher ID of type %s: \"%s\"" % (s_frame().f_code.co_name, self._voucher_data["type"], voucher_id))
        
        voucher_id_split = re.search('^[^-]+-([0-9]+)-([0-9]+)([-2-9A-HJ-NP-Z]*)', voucher_id)
        if voucher_id_split is None:
            return self._throw_error(-3, "Failed to split voucher ID: %s" % (voucher_id), s_frame().f_code.co_name)
        voucher_year = voucher_id_split.group(1)
        voucher_number = voucher_id_split.group(2)
        #voucher_hash = voucher_id_split.group(3)

        # 
        # generate next voucher id
        #
        current_year = strftime("%Y")
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
                return self._throw_error(-10, "Maximum number of vouchers reached (%d). No more vouchers available this year." % (voucher_number-1), s_frame().f_code.co_name)
    
            voucher_id = self._voucher_data["type"]+"-"+current_year+("-%03d" % voucher_number)
            if self._debug > 1:
                print("%s: Checking if voucher ID \"%s\" already exists." % (s_frame().f_code.co_name, voucher_id))

            # check if it exists already
            if any(self._voucher_list.Nummer.str.startswith(voucher_id)):
                if self._debug > 1:
                    print("%s: Voucher ID \"%s\" is already present." % (s_frame().f_code.co_name, voucher_id))
                voucher_number = voucher_number + 1
            else:
                if self._debug > 1:
                    print("%s: Voucher ID \"%s\" is still free." % (s_frame().f_code.co_name, voucher_id))
                self._voucher_data["id"] = voucher_id
                break

        #
        # add 4 digit alphanumeric "hash" (leave out digits 0,1, and letters O,I)
        #
        voucher_date = strftime("%d.%m.%Y")
        voucher_time = strftime("%H:%M")
        voucher_seed = strftime("%s")
        voucher_hash = str(md5((voucher_date+voucher_time+voucher_seed).encode()).hexdigest())
        voucher_hash = voucher_hash.upper()
        voucher_hash = voucher_hash.replace("0", "")
        voucher_hash = voucher_hash.replace("1", "")
        voucher_hash = voucher_hash.replace("O", "")
        voucher_hash = voucher_hash.replace("I", "")
        voucher_hash = voucher_hash = voucher_hash[0:4]
        self._voucher_data["time"] = voucher_time
        self._voucher_data["date"] = voucher_date
        self._voucher_data["hash"] = voucher_hash
        self._voucher_data["id"] = self._voucher_data["id"]+"-"+voucher_hash
        if self._debug > 0:
            print("%s: New voucher ID: \"%s\"" % (s_frame().f_code.co_name, voucher_id))

        return 0


    ########
    def _register_voucher(self):
    ########
        if self._error < 0:
            return self._error
        if not isinstance(self._session, Session):
            return self._throw_error(-1, "Invalid session: %s" % (resp), s_frame().f_code.co_name)

        if self._debug > 0:
            print("%s: Creating voucher with ID: \"%s\"" % (s_frame().f_code.co_name, self._voucher_data["id"]))
            if self._debug > 1:
                print("%s: Submitting form querry request." % (s_frame().f_code.co_name))

        #
        # get preset voucher variables
        #
        voucher_page = self._session.get('https://vereinsflieger.de/member/community/voucher/addvid')
        voucher_page_data = voucher_page.content.decode('utf-8')
        self._debug_page(voucher_page, s_frame().f_code.co_name, voucher_page_data)

        # extract input parameters
        form_inputs = re.findall('<input.*name=\'[^\']+\'.*value=\'[^\']*\'.*[/]*>', voucher_page_data)
        if self._debug > 3:
            print("%s: voucher form input query result: %s" % (s_frame().f_code.co_name, form_inputs))
        # populate input parameters
        voucher_data = {}
        for line in form_inputs:
            single_input = re.search('name=\'([^\']+)\'.*value=\'([^\']*)\'', line)
            if single_input is None:
                return self._throw_error(-1, "Failed to extract any input tag.", s_frame().f_code.co_name)
            if self._debug > 3:
                print("%s: single input: %s" % (s_frame().f_code.co_name, single_input))
            voucher_data[single_input.group(1)] = single_input.group(2)

#        # extract "select" parameters
#        form_inputs = re.findall('<select.*name=\'[^\']+\'', voucher_page_data)
#        if self._debug > 3:
#            print("%s: voucher form select query result: %s" % (s_frame().f_code.co_name, form_inputs))
#        # populate "select" parameters
#        for line in form_inputs:
#            single_input = re.search('name=\'([^\']+)\'', line)
#            if single_input is None:
#                return self._throw_error(-1, "Failed to extract any select tag.", s_frame().f_code.co_name)
#            if self._debug > 3:
#                print("%s: single select: %s" % (s_frame().f_code.co_name, single_input))
#            voucher_data[single_input.group(1)] = ""

        if self._debug > 2:
            print("%s: extracted voucher form data: %s" % (s_frame().f_code.co_name, voucher_data))

        #
        # fill in data
        #
        voucher_data["frm_email"]       = str(self._voucher_data["buyer_email"])
        # have guest name here instead of buyer as this is the name shown when redeeming the voucher
        # buyer is mentioned in comment field
        voucher_data["frm_firstname"]   = str(self._voucher_data["guest_firstname"])
        voucher_data["frm_lastname"]    = str(self._voucher_data["guest_lastname"])
        voucher_data["frm_street"]      = str(self._voucher_data["buyer_street"])
        voucher_data["frm_zipcode"]     = str(self._voucher_data["buyer_zip"])
        voucher_data["frm_town"]        = str(self._voucher_data["buyer_city"])
        voucher_data["frm_voucherid"]   = str(self._voucher_data["id"])
        voucher_data["frm_value"]       = str(self._voucher_data["amount"])
        voucher_data["frm_passenger"]   = str(self._voucher_data["guest_firstname"]+" "+self._voucher_data["guest_lastname"])
        voucher_data["frm_title"]       = "Gutschein"
        voucher_data["frm_status"]      = "1" # "Erstellt"
        voucher_data["frm_adduser"]     = "0" # Do NOT create new user account!
        voucher_data["uid_browse"]      = "" # Do not prepopulate voucher user data
        voucher_data["action"]          = "saveclose" # Create the voucher

        # for comment
        if "provider" in self._voucher_data.keys():
            voucher_provider = self._voucher_data["provider"]
        else:
            voucher_provider = "'py-vereinsflieger.VF_API()'"
        # Optional logging of IP address to prevent / investigate abuse
        voucher_ip = ""
        if "ip" in self._voucher_data.keys():
            voucher_ip = " von IP "+str(self._voucher_data["ip"])
        voucher_data["frm_comment"] = "Automatisch erstellt über %s am %s um %s Uhr%s. Zahlungsaufforderung gesendet an Käufer %s %s -> %s" % (voucher_provider,
                str(self._voucher_data["date"]), str(self._voucher_data["time"]), voucher_ip,
                str(self._voucher_data["buyer_firstname"]), str(self._voucher_data["buyer_lastname"]), voucher_data["frm_email"])


        if self._debug > 1:
            print("%s: Submitting creation request." % (s_frame().f_code.co_name))
            if self._debug > 2:
                print("%s: Submitting voucher form data: %s" % (s_frame().f_code.co_name, voucher_data))

        #
        # submit voucher creation request
        #
        voucher_request = self._session.post('https://vereinsflieger.de/member/community/voucher/addvid', data=voucher_data)
        self._debug_page(voucher_request, s_frame().f_code.co_name)

        return 0


    ########
    def _validate_voucher(self):
    ########
        self._voucher_valid = False
        self._voucher_data["valid"] = False

        if self._error < 0:
            return self._error
        if "id" not in self._voucher_data or self._voucher_data["id"] is None:
            return self._throw_error(-3, "Invalid voucher ID", s_frame().f_code.co_name)

        if self._debug > 0:
            print("%s: Verifying voucher with ID: \"%s\"" % (s_frame().f_code.co_name, self._voucher_data["id"]))

        #
        # Get (new) voucher list and check if new id is present
        #
        self._get_voucher_list()

        # validate list
        if not isinstance(self._voucher_list, DataFrame):
            return self._throw_error(-3, "Invalid voucher list: %s" % (self._voucher_list), s_frame().f_code.co_name)

        if self._debug > 0:
            print("%s: Voucher ID: \"%s\"" % (s_frame().f_code.co_name, self._voucher_data["id"]))
            print("%s:" % (s_frame().f_code.co_name))

        # check for presence of voucher id
        if self._voucher_data["id"] in self._voucher_list.Nummer.values:
            self._voucher_valid = True
            self._voucher_data["valid"] = True
            if self._debug > 0:
                print("%s: #################" % (s_frame().f_code.co_name))
                print("%s: # VALID voucher #" % (s_frame().f_code.co_name))
                print("%s: #################" % (s_frame().f_code.co_name))
        else:
            self._voucher_valid = False
            self._voucher_data["valid"] = False
            if self._debug > 0:
                print("%s: ###################" % (s_frame().f_code.co_name))
                print("%s: # voucher INVALID #" % (s_frame().f_code.co_name))
                print("%s: ###################" % (s_frame().f_code.co_name))

        if self._debug > 0:
            print("%s:" % (s_frame().f_code.co_name))

        return 0


    ########
    def _create_invoice(self):
    ########
        if self._error < 0:
            return self._error
        if "id" not in self._voucher_data or self._voucher_data["id"] is None:
            return self._throw_error(-3, "Invalid voucher ID", s_frame().f_code.co_name)

        if self._debug > 0:
            print("%s: Generating invoice for voucher with ID: \"%s\"" % (s_frame().f_code.co_name, self._voucher_data["id"]))

        #
        # get preset invoice variables
        #
        invoice_page = self._session.get('https://vereinsflieger.de/member/finance/addcashsale.php?frm_urlreferer=userinvoice.php')
        invoice_page_data = invoice_page.content.decode('utf-8')
        self._debug_page(invoice_page, s_frame().f_code.co_name, invoice_page_data)

        # extract input parameters
        form_inputs = re.findall('<input.*name=\'[^\']+\'.*value=\'[^\']*\'.*[/]*>', invoice_page_data)
        if self._debug > 3:
            print("%s: invoice form input query result: %s" % (s_frame().f_code.co_name, form_inputs))
        # populate input parameters
        invoice_data = {}
        for line in form_inputs:
            single_input = re.search('name=\'([^\']+)\'.*value=\'([^\']*)\'', line)
            if single_input is None:
                return self._throw_error(-1, "Failed to extract any input tag.", s_frame().f_code.co_name)
            if self._debug > 3:
                print("%s: single input: %s" % (s_frame().f_code.co_name, single_input))
            invoice_data[single_input.group(1)] = single_input.group(2)

        if self._debug > 2:
            print("%s: extracted invoice form data: %s" % (s_frame().f_code.co_name, invoice_data))

        #
        # fill in data
        #
        # internal accounting data
        invoice_data["frm_caid"]                = self._invoice_caid
        invoice_data["caid_inputinput_field"]   = self._invoice_caid_field
        # buyer data
        invoice_data["frm_community"]   = str(self._voucher_data["buyer_firstname"]) + " " + str(self._voucher_data["buyer_lastname"])
        invoice_data["frm_email"]       = str(self._voucher_data["buyer_email"])
        invoice_data["frm_street"]      = str(self._voucher_data["buyer_street"])
        invoice_data["frm_zipcode"]     = str(self._voucher_data["buyer_zip"])
        invoice_data["frm_town"]        = str(self._voucher_data["buyer_city"])
        # item data
        if self._voucher_data["type"] == "TMG":
            invoice_data["frm_subtitle"]    = "Gutschein Motorsegler"
            invoice_data["frm_article_1"]   = "Gutschein Motorseglerflug"
            invoice_data["frm_supid_1"]     = "1579"
            invoice_data["frm_amount_1"]    = "%0.2f" % (float(self._voucher_data["duration"]) / 60.0)
        elif self._voucher_data["type"] == "SF":
            invoice_data["frm_subtitle"]    = "Gutschein Segelflug"
            invoice_data["frm_article_1"]   = "Gutschein Segelflug"
            invoice_data["frm_supid_1"]     = "1578"
            invoice_data["frm_amount_1"]    = "1.00"
        invoice_data["frm_total_1"]     = str(self._voucher_data["amount"])
        invoice_data["frm_fdid_1"]      = "0"
        invoice_data["frm_counter_1"]   = ""
        # add voucher id
        invoice_data["frm_callsign_1"]  = "Gutscheinnummer: "+str(self._voucher_data["id"])
        # data of unused items
        for idx in range(2, 100):
            invoice_data["frm_article_%d" % idx]  = ""
            invoice_data["frm_supid_%d" % idx]    = "0"
            invoice_data["frm_amount_%d" % idx]   = ""
            invoice_data["frm_total_%d" % idx]    = ""
            invoice_data["frm_fdid_%d" % idx]     = "0"
            invoice_data["frm_counter_%d" % idx]  = ""
            invoice_data["frm_callsign_%d" % idx] = ""
        # footer text
        invoice_data["frm_footer"]      = '''Der Breisgauverein für Segelflug bedankt sich recht herzlich und wünscht allzeit einen guten Flug.

Sofern nicht bereits geschehen überweisen Sie bitte den offenen Betrag innerhalb von 14 Tagen auf das oben angegebene Konto.'''
        # do NOT finalize invoice -> can still be edited afterwards
        if "frm_lockmode" in invoice_data:
            del invoice_data["frm_lockmode"]
        # misc options
        invoice_data["frm_invoicedate"] = str(self._voucher_data["date"])
        invoice_data["frm_servicedate"] = ""
        invoice_data["frm_invoiceusertype"]    = "1"
        invoice_data["frm_uid"]         = "0"
        invoice_data["frm_uidname"]     = ""
        invoice_data["action"]          = "save" # Create the invoice

        if self._debug > 1:
            print("%s: Submitting creation request." % (s_frame().f_code.co_name))
            if self._debug > 2:
                print("%s: Submitting invoice form data: %s" % (s_frame().f_code.co_name, invoice_data))

        #
        # submit invoice creation request and extract invoice id
        #
        invoice_request = self._session.post('https://vereinsflieger.de/member/finance/addcashsale.php?frm_urlreferer=userinvoice.php', data=invoice_data)
        self._debug_page(invoice_request, s_frame().f_code.co_name)

        #
        # check result and extract invoice id
        #
        uiid_matches = re.findall('uiid=[0-9]+', invoice_request.url)
        if self._debug > 3:
            print("%s: uiid match: %s" % (s_frame().f_code.co_name, uiid_matches))
        for match in uiid_matches:
            single_match = re.search('uiid=([0-9]+)', match)
            if single_match is None:
                return self._throw_error(-1, "Failed to extract any uiid.", s_frame().f_code.co_name)
            if self._debug > 3:
                print("%s: single uiid match: %s" % (s_frame().f_code.co_name, single_match))
            uiid = int(single_match.group(1))
            if uiid > 0:
                if self._debug > 2:
                    print("%s: Found invoice uiid: \"%s\"" % (s_frame().f_code.co_name, str(uiid)))
                self._voucher_data["invoice_uiid"] = str(uiid)
            elif uiid == 0:
                pass
            else:
                return self._throw_error(-8, "Received ill invoice uid: \"%s\"" % (uid), s_frame().f_code.co_name)

        if "invoice_uiid" not in self._voucher_data.keys():
            return self._throw_error(-1, "Failed to extract invoice id from creation response.", s_frame().f_code.co_name)

        #
        # download pdf invoice
        #
        invoice_pdf = self._session.get('https://vereinsflieger.de/member/finance/printuserinvoice.php?uiid='+str(self._voucher_data["invoice_uiid"]))
        self._debug_page(invoice_pdf, s_frame().f_code.co_name)
        # check file type
        if invoice_pdf.headers.get('Content-Type') == 'application/pdf':
            self._voucher_data["invoice_pdf"] = invoice_pdf.content
            # extract filename / invoice id
            match_str = invoice_pdf.headers.get('Content-Disposition')
            invoice_id = re.search('filename=Rechnung_([0-9]+).pdf', match_str)
            print("id match: %s" % invoice_id)
            if invoice_id is not None:
                invoice_id = invoice_id.group(1)
                self._voucher_data["invoice_id"] = str(invoice_id)
        else:
            return self._throw_error(-1, "Failed to download invoice with uiid \"%s\"." % (self._voucher_data["invoice_uiid"]), s_frame().f_code.co_name)

        return 0


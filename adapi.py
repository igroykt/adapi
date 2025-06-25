import os
import re
import ldap
import ldap.filter
from decouple import config
from contextlib import contextmanager
from datetime import datetime
from OpenSSL import crypto

class ADApi:

    def __init__(self):
        self.ldap_server = config('LDAP_SERVER')
        self.ldap_user = config('LDAP_USER')
        self.ldap_pass = config('LDAP_PASS')
        self.base_dn = config('BASE_DN')
        self.search_dn = config('SEARCH_DN')
        if self.ldap_server.lower().startswith('ldaps://'):
            self.ca_cert = config('CA_CERT')
            os.environ['SSL_CERT_FILE'] = os.path.abspath(self.ca_cert)

    def err2dict(self, err):
        err_str = str(err)
        match = re.search(r"desc: ([^}]+)", err_str)
        return {'desc': match.group(1)} if match else {'desc': str(err)}

    def dn2domain(self, dn):
        domain = str(dn).replace("dc=", "").replace(",", ".")
        return domain

    def login2un(self, login):
        domain = self.dn2domain(self.base_dn)
        return f"{login}@{domain}"

    def convert_ldaptimestamp(self, timestamp):
        try:
            if not timestamp or not re.match(r'^\d{14}', timestamp):
                return False
            dt = datetime.strptime(timestamp[:14], '%Y%m%d%H%M%S')
            return dt.strftime('%H:%M:%S %d-%m-%Y')
        except ValueError:
            return False

    def connect(self):
        try:
            self.ldap_user = self.login2un(self.ldap_user)
            con = ldap.initialize(self.ldap_server)
            con.set_option(ldap.OPT_REFERRALS, 0)
            con.set_option(ldap.OPT_NETWORK_TIMEOUT, 10)
            # Check if protocol is ldaps
            if self.ldap_server.lower().startswith('ldaps://'):
                # LDAPS connection (secure by default, no additional START_TLS needed)
                con.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_DEMAND)
            elif not self.ldap_server.lower().startswith('ldap://') and self.ldap_server.lower().endswith('636'):
                # Non-LDAPS (ldap://), attempt START_TLS for security
                try:
                    con.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_DEMAND)
                    con.start_tls_s()
                except ldap.LDAPError as e:
                    raise Exception(f"START_TLS failed, proceeding with insecure LDAP connection: {e}")
            con.simple_bind_s(self.ldap_user, self.ldap_pass)
            return con
        except ldap.INVALID_CREDENTIALS:
            raise Exception("connect: Invalid credentials")
        except ldap.LDAPError as e:
            e = self.err2dict(e)
            raise Exception(f"connect: {e['desc']}")

    def disconnect(self, con):
        try:
            con.unbind_s()
        except ldap.LDAPError as e:
            raise Exception(f"Failed to disconnect LDAP: {e}")

    @contextmanager
    def ldap_connection(self):
        con = self.connect()
        try:
            yield con
        finally:
            self.disconnect(con)

    def unpack_users_list(self, users_list):
        tmp = []
        try:
            for record in users_list:
                for i,v in record[1].items():
                    if not v[0].decode().endswith('$'):
                        tmp.append(v[0].decode().lower())
        except:
            pass
        return tmp

    def list_users(self, con, by="username"):
        filter = "(objectClass=user)"
        attrs = ['sAMAccountName'] if by == "username" else ['mail']
        try:
            page_control = ldap.controls.SimplePagedResultsControl(True, size=1000, cookie='')
            result_set = []
            while True:
                response = con.search_ext(self.base_dn, ldap.SCOPE_SUBTREE, filter, attrs, serverctrls=[page_control])
                rtype, rdata, rmsgid, serverctrls = con.result3(response)
                unpacked_data = self.unpack_users_list(rdata)
                result_set.extend(unpacked_data)
                controls = [control for control in serverctrls if control.controlType == ldap.controls.SimplePagedResultsControl.controlType]
                if not controls or not controls[0].cookie:
                    break
                page_control.cookie = controls[0].cookie
            result_set.sort()
            return result_set if result_set else False
        except ldap.LDAPError as e:
            e = self.err2dict(e)
            if isinstance(e, dict) and 'desc' in e:
                raise Exception(f"list_users: {e['desc']}")

    def is_user(self, con, login):
        login = ldap.filter.escape_filter_chars(login)
        filter = f"(&(objectClass=user)(sAMAccountName={login}))"
        attrs = ["*"]
        try:
            result = con.search_s(self.base_dn, ldap.SCOPE_SUBTREE, filter, attrs)
            for data in result:
                if isinstance(data[1], dict):
                    obj = int(data[1]['userAccountControl'][0].decode("utf-8", errors="replace"))
                    if obj & 512 or obj == 66048:  # Enabled or normal account
                        return True
            return False
        except ldap.LDAPError as e:
            e = self.err2dict(e)
            raise Exception(f"is_user: {e['desc']}")

    def is_authenticated(self, con, login, password):
        try:
            if not password or len(password) < 8:
                raise Exception(f"Invalid password length for user: {login}")
            login = self.login2un(login)
            con.simple_bind_s(login, password)
            return True
        except ldap.INVALID_CREDENTIALS:
            raise Exception(f"Authentication failed for user: {login}")
        except ldap.LDAPError as e:
            raise Exception(f"LDAP error during authentication for {login}: {e}")

    def get_data(self, con, login, attribute):
        filter = "(&(objectClass=user)(sAMAccountName="+login+"))"
        attrs = [attribute]
        try:
            result = con.search_s(self.base_dn, ldap.SCOPE_SUBTREE, filter, attrs)
        except ldap.LDAPError as e:
            e = self.err2dict(e)
            if type(e) is dict and 'desc' in e:
                raise Exception(f"get_data: {e['desc']}")
        if result:
            for data in result:
                if type(data[1]) is dict:
                    obj = data[1][attribute]
                    return obj
        return False

    def get_denied_dialer(self, con, login, attribute):
        filter = "(&(objectClass=user)(sAMAccountName="+login+")(msNPAllowDialin=FALSE))"
        attrs = [attribute]
        try:
            result = con.search_s(self.base_dn, ldap.SCOPE_SUBTREE, filter, attrs)
        except ldap.LDAPError as e:
            e = self.err2dict(e)
            if type(e) is dict and 'desc' in e:
                raise Exception(f"get_data: {e['desc']}")
        if result:
            for data in result:
                if type(data[1]) is dict:
                    obj = data[1][attribute]
                    return obj
        return False

    def get_name(self, con, login):
        try:
            username = self.get_data(con, login, "givenName")
            if username:
                username = username[0].decode("utf-8", errors="replace")
                if username:
                    return username
            return False
        except ldap.LDAPError as e:
            raise Exception(f"get_name: {e}")
        except UnicodeDecodeError as e:
            raise Exception(f"get_name: Invalid encoding")

    def get_principalname(self, con, login):
        try:
            userdn = self.get_data(con, login, "userPrincipalName")
            if userdn:
                userdn = userdn[0].decode("utf-8", errors="replace")
                if userdn:
                    return userdn
            return False
        except Exception as e:
            raise Exception(f'get_principalname: {e}')

    def get_fullname(self, con, login):
        try:
            userdn = self.get_data(con, login, "distinguishedName")
            if userdn:
                userdn = userdn[0].decode("utf-8", errors="replace")
                userdn = userdn.split(",")
                userdn = userdn[0].split("=")
                userdn = userdn[1]
                if userdn:
                    return userdn
            return False
        except Exception as e:
            raise Exception(f'get_fullname: {e}')

    def get_mail(self, con, login):
        try:
            mail = self.get_data(con, login, "mail")
            if mail:
                mail = mail[0].decode("utf-8", errors="replace")
                if mail:
                    return mail
            return False
        except Exception as e:
            raise Exception(f'get_mail: {e}')

    def get_description(self, con, login):
        try:
            desc = self.get_data(con, login, "description")
            if desc:
                desc = desc[0].decode("utf-8", errors="replace")
                if desc:
                    return desc
            return False
        except Exception as e:
            raise Exception(f'get_description: {e}')

    def get_created(self, con, login):
        try:
            timestamp = self.get_data(con, login, "whenCreated")
            if timestamp:
                timestamp = timestamp[0].decode("utf-8", errors="replace")
                when = self.convert_ldaptimestamp(timestamp)
                if when:
                    return when
            return False
        except Exception as e:
            raise Exception(f'get_created: {e}')

    def get_changed(self, con, login):
        try:
            timestamp = self.get_data(con, login, "whenChanged")
            if timestamp:
                timestamp = timestamp[0].decode("utf-8", errors="replace")
                when = self.convert_ldaptimestamp(timestamp)
                if when:
                    return when
            return False
        except Exception as e:
            raise Exception(f'get_changed: {e}')

    def get_groups(self, con, login):
        try:
            data = []
            groups = self.get_data(con, login, "memberOf")
            if groups:
                groups = list(dict.fromkeys(groups))
                for group in groups:
                    group = group.decode("utf-8", errors="replace")
                    group = group.split(",")
                    group = group[0].split("=")
                    data.append(group[1])
                if data:
                    return data
            return False
        except Exception as e:
            raise Exception(f'get_groups: {e}')

    def get_failcount(self, con, login):
        try:
            count = self.get_data(con, login, "badPwdCount")
            if count:
                count = count[0].decode("utf-8", errors="replace")
                if count:
                    return int(count)
            return False
        except Exception as e:
            raise Exception(f'get_failcount: {e}')

    def get_lastfail(self, con, login):
        try:
            timestamp = self.get_data(con, login, "badPasswordTime")
            if timestamp:
                timestamp = timestamp[0].decode("utf-8", errors="replace")
                timestamp = (int(timestamp) / 10000000) - 11644473600
                lastfail = datetime.fromtimestamp(timestamp)
                lastfail = lastfail.strftime('%H:%M:%S %d-%m-%Y')
                if lastfail:
                    return lastfail
            return False
        except Exception as e:
            raise Exception(f'get_lastfail: {e}')

    def get_lastlogin(self, con, login):
        try:
            timestamp = self.get_data(con, login, "lastLogon")
            if timestamp:
                timestamp = timestamp[0].decode("utf-8", errors="replace")
                timestamp = (int(timestamp) / 10000000) - 11644473600
                lastlogin = datetime.fromtimestamp(timestamp)
                lastlogin = lastlogin.strftime('%H:%M:%S %d-%m-%Y')
                if lastlogin:
                    return lastlogin
            return False
        except Exception as e:
            raise Exception(f'get_lastlogin: {e}')

    def get_lastpwdset(self, con, login):
        try:
            timestamp = self.get_data(con, login, "pwdLastSet")
            if timestamp:
                timestamp = timestamp[0].decode("utf-8", errors="replace")
                timestamp = (int(timestamp) / 10000000) - 11644473600
                lastpwd = datetime.fromtimestamp(timestamp)
                lastpwd = lastpwd.strftime('%H:%M:%S %d-%m-%Y')
                if lastpwd:
                    return lastpwd
            return False
        except Exception as e:
            raise Exception(f'get_lastpwdset: {e}')

    def is_admin(self, con, login):
        try:
            isadmin = self.get_data(con, login, "adminCount")
            if isadmin:
                isadmin = isadmin[0].decode("utf-8", errors="replace")
                if int(isadmin) == 1:
                    return True
            return False
        except Exception as e:
            raise Exception(f'is_admin: {e}')

    def get_expires(self, con, login):
        try:
            timestamp = self.get_data(con, login, "accountExpires")
            if timestamp:
                timestamp = timestamp[0].decode("utf-8", errors="replace")
                timestamp = (int(timestamp) / 10000000) - 11644473600
                expires = datetime.fromtimestamp(timestamp)
                expires = expires.strftime('%H:%M:%S %d-%m-%Y')
                if expires:
                    return expires
        except Exception as e:
            return False

    def get_logincount(self, con, login):
        try:
            count = self.get_data(con, login, "logonCount")
            if count:
                count = count[0].decode("utf-8", errors="replace")
                if count:
                    return int(count)
            return False
        except Exception as e:
            raise Exception(f'get_logincount: {e}')

    def get_login(self, con, login):
        try:
            login = self.get_data(con, login, "sAMAccountName")
            if login:
                login = login[0].decode("utf-8", errors="replace")
                if login:
                    return login
            return False
        except Exception as e:
            raise Exception(f'get_login: {e}')

    def get_phonenumber(self, con, login):
        try:
            mobile = self.get_data(con, login, "mobile")
            if mobile:
                mobile = mobile[0].decode("utf-8", errors="replace")
                if mobile:
                    return mobile
            return False
        except Exception as e:
            raise Exception(f'get_phonenumber: {e}')

    def get_certificate(self, con, login, action):
        try:
            certs = self.get_data(con, login, "userCertificate")
            if certs:
                data = []
                for cert in certs:
                    x509 = crypto.load_certificate(crypto.FILETYPE_ASN1, cert)
                    if not x509.has_expired():
                        if "subject" in action:
                            data.append(x509.get_subject())
                        if "serial" in action:
                            data.append(x509.get_serial_number())
                        if "dump" in action:
                            der = crypto.dump_certificate(crypto.FILETYPE_PEM, x509)
                            data.append(der.decode("utf-8"))
                if data:
                    return data
            return False
        except Exception as e:
            raise Exception(f'get_certificate: {e}')

    def is_radius_blocked(self, con, login):
        try:
            radius = self.get_denied_dialer(con, login, "sAMAccountName")
            if radius:
                return True
            return False
        except Exception as e:
            raise Exception(f'is_radius: {e}')
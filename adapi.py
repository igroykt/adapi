import os
import re
import sys
import ldap
import ldap.sasl
import ast
import datetime
from OpenSSL import crypto

class ADApi:
    ldap_server = ""
    ldap_user = ""
    ldap_pass = ""
    base_dn = ""
    search_dn = ""

    def __init__(self, ldap_server, ldap_user, ldap_pass, base_dn, search_dn):
        self.ldap_server = ldap_server
        self.ldap_user = ldap_user
        self.ldap_pass = ldap_pass
        self.base_dn = base_dn
        self.search_dn = search_dn

    def err2dict(self, err):
        err = re.sub(r'^.*?{', '{', str(err))
        err = ast.literal_eval(err)
        return err

    def dn2domain(self, dn):
        domain = str(dn)
        domain = domain.replace("dc=", "")
        domain = domain.replace(",", ".")
        return domain

    def login2un(self, login):
        domain = self.dn2domain(self.base_dn)
        un = f"{login}@{domain}"
        return str(un)

    def convert_ldaptimestamp(self, timestamp):
        timestamp = timestamp.split(".")
        timestamp = str(timestamp[0])
        year = timestamp[0]+timestamp[1]+timestamp[2]+timestamp[3]
        month = timestamp[4]+timestamp[5]
        day = timestamp[6]+timestamp[7]
        hour = timestamp[8]+timestamp[9]
        minutes = timestamp[10]+timestamp[11]
        seconds = timestamp[12]+timestamp[13]
        readable = f"{hour}:{minutes}:{seconds} {day}-{month}-{year}"
        if readable:
            return readable
        return False

    def connect(self):
        try:
            self.ldap_user = self.login2un(self.ldap_user)
            con = ldap.initialize(self.ldap_server)
            con.set_option(ldap.OPT_REFERRALS, 0)
            con.set_option(ldap.OPT_PROTOCOL_VERSION, 3)
            con.simple_bind_s(self.ldap_user, self.ldap_pass)
            return con
        except ldap.INVALID_CREDENTIALS as e:
            raise Exception(f"connect: Invalid credentials")
        except ldap.LDAPError as e:
            e = self.err2dict(e)
            if type(e) is dict and 'desc' in e:
                raise Exception(f"connect: {e['desc']}")
        return False

    def disconnect(self, con):
        try:
            con.unbind_s()
        except Exception:
            pass

    def is_user(self, login):
        filter = "(&(objectClass=user)(sAMAccountName="+login+"))"
        attrs = ["*"]
        try:
            result = self.con.search_s(self.base_dn, ldap.SCOPE_SUBTREE, filter, attrs)
        except ldap.LDAPError as e:
            e = self.err2dict(e)
            if type(e) is dict and 'desc' in e:
                raise Exception(f"is_user: {e['desc']}")
        if result:
            for data in result:
                if type(data[1]) is dict:
                    obj = self.dekodirui_suka(data[1]['userAccountControl'])
                    if obj == "66048":
                        return True
        return False

    def is_authenticated(self, con, login, password):
        try:
            login = self.login2un(login)
            test = None
            try:
                if len(password) > 0: #looks like simple_bind_s pass empty passwords
                    test = con.simple_bind_s(login, password)
            except ldap.LDAPError as e:
                e = self.err2dict(e)
                if type(e) is dict and 'desc' in e:
                    return False
            if test is not None:
                return True
        except ldap.INVALID_CREDENTIALS:
            return False

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

    def get_name(self, con, login):
        try:
            username = self.get_data(con, login, "givenName")
            if username:
                username = username[0].decode("utf-8")
                if username:
                    return username
            return False
        except Exception as e:
            raise Exception(f'get_name: {e}')

    def get_principalname(self, con, login):
        try:
            userdn = self.get_data(con, login, "userPrincipalName")
            if userdn:
                userdn = userdn[0].decode("utf-8")
                if userdn:
                    return userdn
            return False
        except Exception as e:
            raise Exception(f'get_principalname: {e}')

    def get_fullname(self, con, login):
        try:
            userdn = self.get_data(con, login, "distinguishedName")
            if userdn:
                userdn = userdn[0].decode("utf-8")
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
                mail = mail[0].decode("utf-8")
                if mail:
                    return mail
            return False
        except Exception as e:
            raise Exception(f'get_mail: {e}')

    def get_description(self, con, login):
        try:
            desc = self.get_data(con, login, "description")
            if desc:
                desc = desc[0].decode("utf-8")
                if desc:
                    return desc
            return False
        except Exception as e:
            raise Exception(f'get_description: {e}')

    def get_created(self, con, login):
        try:
            timestamp = self.get_data(con, login, "whenCreated")
            if timestamp:
                timestamp = timestamp[0].decode("utf-8")
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
                timestamp = timestamp[0].decode("utf-8")
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
                    group = group.decode("utf-8")
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
                count = count[0].decode("utf-8")
                if count:
                    return int(count)
            return False
        except Exception as e:
            raise Exception(f'get_failcount: {e}')

    def get_lastfail(self, con, login):
        try:
            timestamp = self.get_data(con, login, "badPasswordTime")
            if timestamp:
                timestamp = timestamp[0].decode("utf-8")
                timestamp = (int(timestamp) / 10000000) - 11644473600
                lastfail = datetime.datetime.fromtimestamp(timestamp)
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
                timestamp = timestamp[0].decode("utf-8")
                timestamp = (int(timestamp) / 10000000) - 11644473600
                lastlogin = datetime.datetime.fromtimestamp(timestamp)
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
                timestamp = timestamp[0].decode("utf-8")
                timestamp = (int(timestamp) / 10000000) - 11644473600
                lastpwd = datetime.datetime.fromtimestamp(timestamp)
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
                isadmin = isadmin[0].decode("utf-8")
                if int(isadmin) == 1:
                    return True
            return False
        except Exception as e:
            raise Exception(f'is_admin: {e}')

    def get_expires(self, con, login):
        try:
            timestamp = self.get_data(con, login, "accountExpires")
            if timestamp:
                timestamp = timestamp[0].decode("utf-8")
                timestamp = (int(timestamp) / 10000000) - 11644473600
                expires = datetime.datetime.fromtimestamp(timestamp)
                expires = expires.strftime('%H:%M:%S %d-%m-%Y')
                if expires:
                    return expires
            return False
        except Exception as e:
            raise Exception(f'get_expires: {e}')

    def get_logincount(self, con, login):
        try:
            count = self.get_data(con, login, "logonCount")
            if count:
                count = count[0].decode("utf-8")
                if count:
                    return int(count)
            return False
        except Exception as e:
            raise Exception(f'get_logincount: {e}')

    def get_login(self, con, login):
        try:
            login = self.get_data(con, login, "sAMAccountName")
            if login:
                login = login[0].decode("utf-8")
                if login:
                    return login
            return False
        except Exception as e:
            raise Exception(f'get_login: {e}')

    def get_phonenumber(self, con, login):
        try:
            mobile = self.get_data(con, login, "mobile")
            if mobile:
                mobile = mobile[0].decode("utf-8")
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

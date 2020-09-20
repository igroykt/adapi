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
            raise SystemExit(f"Error: Invalid credentials")
        except ldap.LDAPError as e:
            e = self.err2dict(e)
            if type(e) is dict and 'desc' in e:
                raise SystemExit(f"Error: {e['desc']}")
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
                raise SystemExit(f"Error: {e['desc']}")
        if result:
            for data in result:
                if type(data[1]) is dict:
                    obj = self.dekodirui_suka(data[1]['userAccountControl'])
                    if obj == "66048":
                        return True
        return False

    def is_authenticated(self, login, password):
        try:
            login = self.login2un(login)
            try:
                test = self.con.simple_bind_s(login, password)
            except ldap.LDAPError as e:
                e = self.err2dict(e)
                if type(e) is dict and 'desc' in e:
                    raise SystemExit(f"Error: {e['desc']}")
            if test:
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
                raise SystemExit(f"Error: {e['desc']}")
        if result:
            for data in result:
                if type(data[1]) is dict:
                    obj = data[1][attribute]
                    return obj
        return False

    def get_name(self, con, login):
        try:
            username = self.get_data(con, login, "givenName")
            username = username[0].decode("utf-8")
            if username:
                return username
        except Exception:
            return False
        return False

    def get_fullname(self, con, login):
        try:
            userdn = self.get_data(con, login, "distinguishedName")
            userdn = userdn[0].decode("utf-8")
            userdn = userdn.split(",")
            userdn = userdn[0].split("=")
            userdn = userdn[1]
            if userdn:
                return userdn
        except Exception:
            return False
        return False

    def get_mail(self, con, login):
        try:
            mail = self.get_data(con, login, "mail")
            mail = mail[0].decode("utf-8")
            if mail:
                return mail
        except Exception:
            return False
        return False

    def get_description(self, con, login):
        try:
            desc = self.get_data(con, login, "description")
            desc = desc[0].decode("utf-8")
            if desc:
                return desc
        except Exception:
            return False
        return False

    def get_created(self, con, login):
        try:
            timestamp = self.get_data(con, login, "whenCreated")
            timestamp = timestamp[0].decode("utf-8")
            when = self.convert_ldaptimestamp(timestamp)
            if when:
                return when
        except Exception:
            return False
        return False

    def get_changed(self, con, login):
        try:
            timestamp = self.get_data(con, login, "whenChanged")
            timestamp = timestamp[0].decode("utf-8")
            when = self.convert_ldaptimestamp(timestamp)
            if when:
                return when
        except Exception:
            return False
        return False

    def get_groups(self, con, login):
        try:
            data = []
            groups = self.get_data(con, login, "memberOf")
            groups = list(dict.fromkeys(groups))
            for group in groups:
                group = group.decode("utf-8")
                group = group.split(",")
                group = group[0].split("=")
                data.append(group[1])
            return data
        except Exception:
            return False
        return False

    def get_failcount(self, con, login):
        try:
            count = self.get_data(con, login, "badPwdCount")
            count = count[0].decode("utf-8")
            return int(count)
        except Exception:
            return False
        return False

    def get_lastfail(self, con, login):
        try:
            timestamp = self.get_data(con, login, "badPasswordTime")
            timestamp = timestamp[0].decode("utf-8")
            timestamp = (int(timestamp) / 10000000) - 11644473600
            lastfail = datetime.datetime.fromtimestamp(timestamp)
            lastfail = lastfail.strftime('%H:%M:%S %d-%m-%Y')
            if lastfail:
                return lastfail
        except Exception:
            return False
        return False

    def get_lastlogin(self, con, login):
        try:
            timestamp = self.get_data(con, login, "lastLogon")
            timestamp = timestamp[0].decode("utf-8")
            timestamp = (int(timestamp) / 10000000) - 11644473600
            lastlogin = datetime.datetime.fromtimestamp(timestamp)
            lastlogin = lastlogin.strftime('%H:%M:%S %d-%m-%Y')
            if lastlogin:
                return lastlogin
        except Exception:
            return False
        return False

    def get_lastpwdset(self, con, login):
        try:
            timestamp = self.get_data(con, login, "pwdLastSet")
            timestamp = timestamp[0].decode("utf-8")
            timestamp = (int(timestamp) / 10000000) - 11644473600
            lastpwd = datetime.datetime.fromtimestamp(timestamp)
            lastpwd = lastpwd.strftime('%H:%M:%S %d-%m-%Y')
            if lastpwd:
                return lastpwd
        except Exception:
            return False
        return False

    def is_admin(self, con, login):
        try:
            isadmin = self.get_data(con, login, "adminCount")
            isadmin = isadmin[0].decode("utf-8")
            if int(isadmin) == 1:
                return True
        except Exception:
            return False
        return False

    def get_expires(self, con, login):
        try:
            timestamp = self.get_data(con, login, "accountExpires")
            timestamp = timestamp[0].decode("utf-8")
            timestamp = (int(timestamp) / 10000000) - 11644473600
            expires = datetime.datetime.fromtimestamp(timestamp)
            expires = expires.strftime('%H:%M:%S %d-%m-%Y')
            if expires:
                return expires
        except Exception:
            return False
        return False

    def get_logincount(self, con, login):
        try:
            count = self.get_data(con, login, "logonCount")
            count = count[0].decode("utf-8")
            return int(count)
        except Exception:
            return False
        return False

    def get_login(self, con, login):
        try:
            login = self.get_data(con, login, "sAMAccountName")
            login = login[0].decode("utf-8")
            if login:
                return login
        except Exception:
            return False
        return False

    def get_phonenumber(self, con, login):
        try:
            mobile = self.get_data(con, login, "mobile")
            mobile = mobile[0].decode("utf-8")
            if mobile:
                return mobile
        except Exception:
            return False
        return False

    def get_certs(self, con, login):
        certs = self.get_data(con, login, "userCertificate")
        for cert in certs:
            print(type(cert))
        if certs:
            return certs
        return False
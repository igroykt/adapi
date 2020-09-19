import os
import re
import sys
import ldap
import ldap.sasl
import ast

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

    def dekodirui_suka(self, blyat):
        val = str(blyat)
        val = val.replace("[", "")
        val = val.replace("b'", "")
        val = val.replace("']", "")
        return val

    def connect(self):
        try:
            self.ldap_user = self.login2un(self.ldap_user)
            con = ldap.initialize(self.ldap_server)
            con.set_option(ldap.OPT_REFERRALS, 0)
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
                    obj = self.dekodirui_suka(data[1][attribute])
                    return obj
        return False

    def get_username(self, con, login):
        username = self.get_data(con, login, "givenName")
        if username:
            return username
        return False

    def get_userdn(self, con, login):
        userdn = self.get_data(con, login, "distinguishedName")
        userdn = userdn.split(",")
        userdn = userdn[0].split("=")
        userdn = userdn[1]
        if userdn:
            return userdn
        return False

    def get_usermail(self, con, login):
        mail = self.get_data(con, login, "mail")
        if mail:
            return mail
        return False
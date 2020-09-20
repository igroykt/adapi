import os
import re
import sys
import ldap
import ldap.sasl
import ast
import datetime

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
        username = self.get_data(con, login, "givenName")
        username = username[0].decode("utf-8")
        if username:
            return username
        return False

    def get_fullname(self, con, login):
        userdn = self.get_data(con, login, "distinguishedName")
        userdn = userdn[0].decode("utf-8")
        userdn = userdn.split(",")
        userdn = userdn[0].split("=")
        userdn = userdn[1]
        if userdn:
            return userdn
        return False

    def get_mail(self, con, login):
        mail = self.get_data(con, login, "mail")
        mail = mail[0].decode("utf-8")
        if mail:
            return mail
        return False

    def get_description(self, con, login):
        desc = self.get_data(con, login, "description")
        desc = desc[0].decode("utf-8")
        if desc:
            return desc
        return False

    def get_created(self, con, login):
        timestamp = self.get_data(con, login, "whenCreated")
        timestamp = timestamp[0].decode("utf-8")
        when = self.convert_ldaptimestamp(timestamp)
        if when:
            return when
        return False

    def get_changed(self, con, login):
        timestamp = self.get_data(con, login, "whenChanged")
        timestamp = timestamp[0].decode("utf-8")
        when = self.convert_ldaptimestamp(timestamp)
        if when:
            return when
        return False

    def get_groups(self, con, login):
        data = []
        groups = self.get_data(con, login, "memberOf")
        groups = list(dict.fromkeys(groups))
        for group in groups:
            group = group.decode("utf-8")
            group = group.split(",")
            group = group[0].split("=")
            data.append(group[1])
        return data

    def get_certs(self, con, login):
        certs = self.get_data(con, login, "userCertificate")
        if certs:
            return certs
        return False
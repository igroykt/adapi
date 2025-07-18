# ADApi
Active Directory библиотека для Python

## Зависимости
* Python 3.x
* OpenSSL 3.x

## Установка
```
git clone https://github.com/igroykt/adapi
pip3 install -r adapi/requirements.txt
```

## Пример
Пример инициализации для протокола ldaps:
```bash
from adapi import ADApi

adapi = ADApi(
    ldap_server='ldaps://myserver.ad.example.com:636',
    ldap_user='serviceuser',
    ldap_pass='servicepass',
    base_dn='dc=ad,dc=example,dc=com',
    search_dn='cn=users,dc=ad,dc=example,dc=com',
    ca_cert='/path/to/ca_cert.pem'
    )
```

Пример инициализации для протокола ldap:
```bash
from adapi import ADApi

adapi = ADApi(
    ldap_server='ldap://192.168.1.9:389',
    ldap_user='serviceuser',
    ldap_pass='servicepass',
    base_dn='dc=ad,dc=example,dc=com',
    search_dn='cn=users,dc=ad,dc=example,dc=com'
    )
```

Пример запроса данных:
```python
con = adapi.connect()
username = adapi.get_name(con, "test2")
usermail = adapi.get_mail(con, "test2")
dumpcerts = adapi.get_certificate(con, "test2", "dump")
adapi.disconnect(con)
print(f"Name: {username}\nEmail: {usermail}")
for dump in dumpcerts:
    print(dump)
```

## Методы
* connect() none -> подключение к базе данных
* disconnect(handler) none -> отключение базы данных
* list_users(handler, by) list -> возвращает сортированный список пользователей (значения by: username, email)
* is_user(handler, login) bool -> проверка пользователя на существование/блокировку
* is_authenticated(handler, login, password) bool -> проверка на аутентификацию
* is_admin(handler, login) bool -> состоит ли пользователь в административных группах
* get_name(handler, login) string -> имя пользователя
* get_principalname(handler, login) string -> userPrincipalName
* get_fullname(handler, login) string -> полное имя
* get_mail(handler, login) string -> адрес почты
* get_description(handler, login) string -> описание
* get_created(handler, login) string -> дата регистрации пользователя
* get_changed(handler, login) string -> дата изменения пользователя
* get_groups(handler, login) list -> список групп пользователя
* get_failcount(handler, login) int -> число неудачных попыток аутентификации
* get_lastfail(handler, login) string -> дата последней неудачной аутентификации
* get_lastlogin(handler, login) string -> дата последней аутентификации
* get_lastpwdset(handler, login) string -> дата последней установки пароля
* get_expires(handler, login) string -> дата истечения срока аккаунта (False значит "никогда")
* get_logincount(handler, login) int -> количество аутентификаций
* get_login(handler, login) string -> логин пользователя
* get_phonenumber(handler, login) string -> номер телефона пользователя
* get_certificate(handler, login, action {subject, serial, dump}) list -> запрос субъекта, серийного номера, дампа сертификатов пользователя в формате PEM
* is_radius_blocked(handler, login) bool -> проверка доступа пользователя к radius серверу (True значит запрещен Dial-in)


## Заметка
2 дня не мог понять в чем проблема с openldap 2.6 и openssl 3.x.

Сперва получал ошибку:
```bash
ImportError: /lib64/libldap.so.2: undefined symbol: EVP_md2, version OPENSSL_3.0.0
```
Помогло обновление пакетов посредством пакетного менеджера.

Далее получал ошибки связанные не то с путями, не то с OpenSSL STORE:
```bash
Exception: connect: {'result': -1, 'desc': "Can't contact LDAP server", 'ctrls': [], 'info': 'error:16000069:STORE routines::unregistered scheme'}
```
Оказалось, что путь к корневому сертификату (который CA) надо указывать через переменную окружения SSL_CERT_FILE, иначе иблиотека ldap не хавает путь.

Если путь указать в месте отличном от функции __init__, то скрипт не будет успевать подгрузить переменную окружения по таймингу и просто будете получать ошибку аналогичную OpenSSL STORE.

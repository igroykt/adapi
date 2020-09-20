# ADApi
Active Directory библиотека для Python

## Зависимости
* Python 3.x

## Установка
```
git clone https://github.com/igroykt/adapi
pip3 install -r adapi/requirements.txt
```

## Инициализация
```python
from adapi import ADApi

adapi = ADApi("ldap://server_ip",
                "username",
                "password",
                "dc=example,dc=com",
                "cn=Users,dc=example,dc=com"
            )
```

## Пример
```python
adapi = ADApi("ldap://192.168.1.100",
                "test",
                "123123",
                "dc=contoso,dc=com",
                "cn=Users,dc=contoso,dc=com"
            )
con = adapi.connect()
username = adapi.get_name(con, "test2")
usermail = adapi.get_mail(con, "test2")
dumpcerts = adapi.get_certificate(con, "test2", "dump")
adapi.disconnect(con)
print(f"Name: {username} Email: {usermail}")
for dump in dumpcerts:
    print(dump)
```

## Методы
* connect() none -> подключение к базе данных
* disconnect(handler) none -> отключение базы данных
* is_user(handler, login) bool -> проверка пользователя на существование/блокировку
* is_authenticated(login, password) bool -> проверка на аутентификацию
* is_admin(handler, login) bool -> состоит ли пользователь в административных группах
* get_name(handler, login) string -> имя пользователя
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
# adapi-py
Active Directory библиотека для Python

## Инициализация
```
from adapi import ADApi

adapi = ADApi("ldap://server_ip",
                "username",
                "password",
                "dc=example,dc=com",
                "cn=Users,dc=example,dc=com"
            )
```

## Пример
```
adapi = ADApi("ldap://192.168.1.100",
                "test",
                "123123",
                "dc=contoso,dc=com",
                "cn=Users,dc=contoso,dc=com"
            )
con = adapi.connect()
username = adapi.get_username(con, "test2")
adapi.disconnect(con)
print(username)
```

## Методы
* connect() -> подключение к базе данных
* disconnect(handler) -> отключение базы данных
* is_user(handler, login) -> проверка пользователя на существование/блокировку
* is_authenticated(login, password) -> проверка на аутентификацию
* get_username(handler, login) -> запрос имени пользователя
* get_userdn(handler, login) -> запрос полного имени пользователя
* get_usermail(handler, login) -> запрос почты пользователя
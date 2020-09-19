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
* disconnect() -> отключение базы данных
* is_user(<login>) -> проверка пользователя на существование/блокировку
* is_authenticated(<login>) -> проверка на аутентификацию
* get_username(<login>) -> запрос имени пользователя
* get_userdn(<login>) -> запрос полного имени пользователя
* get_usermail(<login>) -> запрос почты пользователя
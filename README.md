# adapi-py
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
adapi.disconnect(con)
print(f"Name: {username} Email: {usermail}")
```

## Методы
* connect() -> подключение к базе данных
* disconnect(handler) -> отключение базы данных
* is_user(handler, login) -> проверка пользователя на существование/блокировку
* is_authenticated(login, password) -> проверка на аутентификацию
* get_name(handler, login) -> запрос имени пользователя
* get_fullname(handler, login) -> запрос полного имени пользователя
* get_mail(handler, login) -> запрос почты пользователя
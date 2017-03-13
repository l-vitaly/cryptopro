CryptoPro Lib
=============

## Установка

Скачайте [CryptoPro](https://www.cryptopro.ru/products/csp/downloads) 


## Установка ключа
 
Проверте, что у текущего пользователя существует хранилище для сертифкатов:
 
``` bash 
$ csptest -keyset -enum_cont -fqcn -verifyc
``` 

Если хранилища HDIMAGE нет, то его надо создать. Создается оно с правами пользователя root:
 
``` bash 
cpconfig -hardware reader -add HDIMAGE store
```
 
- Скопируйте папку вместе со всеми файлами в каталог /var/opt/cprocsp/keys/username, проверте, что в хранилище появился новый контейнер

``` bash 
$ csptest -keyset -enum_cont -fqcn -verifyc
``` 

должен появиться новый контейнер:

```
\\.\HDIMAGE\my1
```

- Проверте данный контейнер и ключи в нем на корректность

``` bash
$ csptest -keyset -check -cont '\\.\HDIMAGE\my1'
```

- Установка сертификата

```
certmgr -inst -file newkeys.crt -cont '\\.\HDIMAGE\cert1'
```

- Вывод списка сертификатов

``` bash
$ certmgr -list
```

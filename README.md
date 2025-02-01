
# SSH Key Generator and Linode Connection

![Python](https://img.shields.io/badge/Python-3.8%2B-blue)
![Flask](https://img.shields.io/badge/Flask-2.0%2B-green)
![Paramiko](https://img.shields.io/badge/Paramiko-2.9%2B-orange)
![Linode](https://img.shields.io/badge/Linode-API-v4-red)

Этот проект представляет собой веб-приложение на Flask, которое позволяет:
1. Генерировать SSH-ключи (приватный и публичный).
2. Добавлять публичный ключ на сервер Linode через API.
3. Проверять подключение к серверу Linode с использованием сгенерированного приватного ключа.
4. Перенаправлять пользователя на YouTube в случае успешного подключения.

---

## Оглавление

- [Установка](#установка)
- [Использование](#использование)
- [Как это работает](#как-это-работает)
- [Зависимости](#зависимости)
- [Лицензия](#лицензия)
- [Автор](#автор)

---

## Установка

1. Клонируйте репозиторий:
   ```bash
   git clone https://github.com/sdf5h/hjgfk/blob/main/README.md#%D0%B8%D1%81%D0%BF%D0%BE%D0%BB%D1%8C%D0%B7%D0%BE%D0%B2%D0%B0%D0%BD%D0%B8%D0%B5
   cd ssh-linode-connection
   
2. Установите зависимости:
     pip install -r requirements.txt
   
3. Настройте переменные окружения:
   Создайте файл .env в корне проекта и добавьте следующие переменные:
     LINODE_API_KEY=ваш_api_ключ_linode
   LINODE_INSTANCE_ID=ваш_id_сервера
   LINODE_USERNAME=ваш_username
   
4. Запустите приложение:
     python app.py
   
5. Откройте браузер и перейдите по адресу:
     http://127.0.0.1:5000/
   
---

## Использование

1. Генерация SSH-ключей:
   - Нажмите кнопку "Сгенерировать SSH-ключи".
   - На экране появятся сгенерированные приватный и публичный ключи.

2. Подключение к Linode:
   - Нажмите кнопку "Подключиться к Linode".
   - Приложение добавит публичный ключ на сервер Linode через API.
   - Попытается подключиться к серверу Linode с использованием приватного ключа.
   - Если подключение успешно, вы будете перенаправлены на YouTube.
   - Если подключение не удалось, вы увидите сообщение об ошибке.

---

## Как это работает

### Генерация SSH-ключей
Приложение использует библиотеку cryptography для генерации пары SSH-ключей (приватный и публичный). Ключи отображаются на экране в форматах PEM и OpenSSH.

### Добавление ключа на Linode
Публичный ключ добавляется на сервер Linode через API Linode. Для этого используется API-ключ Linode и ID сервера.

### Подключение к серверу Linode
Приложение использует библиотеку paramiko для подключения к серверу Linode с использованием сгенерированного приватного

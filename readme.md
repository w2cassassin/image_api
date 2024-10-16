## 1.Настройка приложения
#### 1. Загрузить исходники приложения
```
cd /var/www/
git clone https://github.com/w2cassassin/image_api
cd image_api
mkdir uploads
sudo chown -R www-data:www-data /var/www/image_api/uploads
sudo chmod -R 755 /var/www/image_api/uploads
```
#### 2.Переименовать файл .env.example в .env и заполнить все переменные
Описание переменных:
```
UPLOAD_DIR — директория внутри контейнера для сохранения загруженных изображений. (лучше не менять)
LOCAL_SERVER_DOMAIN — домен основного сервера.
REMOTE_SERVER — IP-адрес удаленного бэкап-сервера.
REMOTE_USER — имя пользователя для подключения к бэкап-серверу.
REMOTE_PORT — порт SSH на бэкап-сервере.
REMOTE_PASSWORD — пароль пользователя на бэкап-сервере.
REMOTE_DIR — директория на бэкап-сервере для хранения файлов.
CLAMD_HOST — хост сервиса ClamAV. (можно не менять)
CLAMD_PORT — порт сервиса ClamAV. (можно не менять)
APP_PORT — порт Docker контейнера. (можно не менять)
```
#### 3.Собрать и запустить контейнеры
``` 
sudo docker-compose up -d --build
```
## 2.Настройка nginx
#### 1.Создать конфигурацию Nginx

Создайте файл ```/etc/nginx/sites-available/yourdomain.com``` со следующим содержимым:
```
server {
    listen 80;
    server_name yourdomain.com; # заменить на ваш домен
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl;
    server_name yourdomain.com; # заменить на ваш домен

    client_max_body_size 50M;

    ssl_certificate путь к сертификату letsencrypt;
    ssl_certificate_key путь к ключу letsencrypt;

    location / {
        proxy_pass http://127.0.0.1:8012;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }

    location /u/ {
        alias /var/www/image_api/uploads/;
        autoindex off;
        add_header Cache-Control "public, max-age=31536000, immutable";
    }
}
```
#### 2.Активировать конфигурацию и перезапустить Nginx
``` 
sudo ln -s /etc/nginx/sites-available/yourdomain.com /etc/nginx/sites-enabled/
sudo nginx -t 
sudo systemctl restart nginx
```
## 3.Настройка бэкап сервера
#### 1. Создать директорию для загрузок на бэкап-сервере
REMOTE_DIR  в .env файле
```
sudo mkdir -p /home/uploads
 ``` 

## Документация доступна по адресу:
```
https://yourdomain.com/docs
``` 
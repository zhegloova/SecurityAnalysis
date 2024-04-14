SecurityAnalysis - проект на Python, который анализирует безопасность конкретного веб-сайта, проверяя его заголовки HTTP и записи DNS. Скрипт формирует отчет о безопасности с рекомендациями по устранению потенциальных уязвимостей.

#### Установка
`pip install requests beautifulsoup4 dnspython`

#### Пример работы программы
```C:\Users\dbaby\PycharmProjects\SecurityAnalysis\venv\Scripts\python.exe C:\Users\dbaby\PycharmProjects\SecurityAnalysis\main.py 
Введите URL-адрес для анализа:https://colorscheme.ru/color-converter.html

Отчет о безопасности:
Наименование                   Статус          Сложность  Рекомендации
--------------------------------------------------------------------------------
Meta Referrer                  Отсутствует     Низкая     Добавьте Мeta-тег 'referrer' с 'no-referrer', чтобы предотвратить использование одних и тех же сценариев сайта.
DMARC запись                   Отсутствует     Низкая     Добавьте запись DMARC в настройки DNS вашего домена, чтобы защитить его от подмены электронной почты и фишинга.
X-Content-Type-Options         Включен         Средняя    Внедрите политику безопасности контента (CSP) для предотвращения межсайтового скриптинга (XSS) и других атак с внедрением кода.
X-Content-Type-Options         Включен         Средняя    Установите для заголовка 'X-Content-Type-Options' значение 'nosniff', чтобы предотвратить перехват типа MIME.
X-Frame-Options                Включен         Средняя    Установите для заголовка 'X-Frame-Options' значение 'DENY' или 'SAMEORIGIN', чтобы защитить от перехвата кликов.
X-XSS-Protection               Включен         Средняя    Установите для заголовка 'X-XSS-Protection' значение '1; mode=block', чтобы включить защиту XSS в старых браузерах.
Set-Cookie                     Небезопасно     Высокая    Установите 'Secure' и 'HttpOnly' для файлов cookie, чтобы защитить их от перехвата и доступа с помощью JavaScript.
Content-Type/X-Content-Type-Options Небезопасно     Средняя    Установите для заголовка 'X-Content-Type-Options' значение 'nosniff' при отображении HTML-контента, чтобы предотвратить перехват типа MIME.
Управление кэшем               Небезопасно     Средняя    Установите заголовок 'Cache-Control' на 'no-store, private' для конфиденциальных ресурсов, чтобы предотвратить кэширование.


Process finished with exit code 0```

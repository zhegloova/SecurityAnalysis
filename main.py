import requests
from bs4 import BeautifulSoup
import dns.resolver
import dns.exception


def analyze_headers(url):
    try:
        response = requests.get(url)
    except requests.exceptions.RequestException:
        print(f"Ошибка: Не удалось получить URL-адрес.")
        return

    security_report = []
    headers = response.headers

    def check_dns_record(record_type, domain):
        try:
            answers = dns.resolver.resolve(domain, record_type)
            return True if answers else False
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
            return False

    # 1. Same Site Scripting
    soup = BeautifulSoup(response.content, "html.parser")
    if not soup.find("meta", {"name": "referrer", "content": "no-referrer"}):
        security_report.append(("Meta Referrer", "Отсутствует", "Низкая",
                                "Добавьте Мeta-тег 'referrer' с 'no-referrer', чтобы предотвратить использование одних и тех же сценариев сайта."))

    # 2. SPF records
    domain = url.split('/')[2]
    if not check_dns_record("TXT", domain):
        security_report.append(("SPF запись", "Отсутствует", "Низкая",
                                "Добавьте запись SPF в настройки DNS вашего домена, чтобы предотвратить подмену электронной почты."))

    # 3. DMARC records
    if not check_dns_record("TXT", f"_dmarc.{domain}"):
        security_report.append(("DMARC запись", "Отсутствует", "Низкая",
                                "Добавьте запись DMARC в настройки DNS вашего домена, чтобы защитить его от подмены электронной почты и фишинга."))

    # 4. Public Admin Page
    admin_page = f"{url}/admin"
    try:
        admin_response = requests.get(admin_page)
        if admin_response.status_code == 200:
            security_report.append(("Общедоступная страница администратора", "Доступный", "Высокая",
                                    "Ограничьте доступ к вашей странице администратора определенными IP-адресами и/или включите аутентификацию."))
    except requests.exceptions.RequestException:
        pass

    # 5. Directory Listing
    try:
        dir_response = requests.get(url + "/test_non_existent_directory")
        if "Index of" in dir_response.text:
            security_report.append(("Список каталогов", "Включен", "Средняя",
                                    "Отключите список каталогов, чтобы предотвратить несанкционированный доступ к файлам и папкам вашего веб-сайта."))
    except requests.exceptions.RequestException:
        pass

    # 6. Missing security headers
    security_headers = [
        ("X-Content-Type-Options",
         "Внедрите политику безопасности контента (CSP) для предотвращения межсайтового скриптинга (XSS) и других атак с внедрением кода."),
        ("X-Content-Type-Options",
         "Установите для заголовка 'X-Content-Type-Options' значение 'nosniff', чтобы предотвратить перехват типа MIME."),
        ("X-Frame-Options",
         "Установите для заголовка 'X-Frame-Options' значение 'DENY' или 'SAMEORIGIN', чтобы защитить от перехвата кликов."),
        ("X-XSS-Protection",
         "Установите для заголовка 'X-XSS-Protection' значение '1; mode=block', чтобы включить защиту XSS в старых браузерах."),
        ("Strict-Transport-Security", "Внедрите строгую транспортную безопасность (HSTS) для обеспечения защищенных подключений."),
    ]

    for header, fix in security_headers:
        if header not in headers:
            security_report.append((header, "Включен", "Средняя", fix))

    # 7. Insecure cookie settings
    set_cookie = headers.get("Set-Cookie", "")
    if "Secure" not in set_cookie or "HttpOnly" not in set_cookie:
        security_report.append(("Set-Cookie", "Небезопасно", "Высокая",
                                "Установите 'Secure' и 'HttpOnly' для файлов cookie, чтобы защитить их от перехвата и доступа с помощью JavaScript."))

    # 8. Information disclosure
    info_disclosure_headers = [
        ("Сервер", "Удалите заголовок 'Server', чтобы избежать раскрытия информации о сервере."),
        ("X-Powered-By",
         "Удалите или заголовок 'X-Powered-By', чтобы избежать раскрытия информации о технологическом стеке."),
        ("X-AspNet-Version",
         "Удалите заголовок 'X-AspNet-Version', чтобы избежать раскрытия информации о версии ASP.NET."),
    ]

    for header, fix in info_disclosure_headers:
        if header in headers:
            security_report.append((header, f"Значение: {headers[header]}", "Низкая", fix))

    # 9. Cross-Origin Resource Sharing (CORS) misconfigurations
    access_control_allow_origin = headers.get("Access-Control-Allow-Origin", "")
    if access_control_allow_origin == "*":
        security_report.append(("Контроль доступа", "Неправильно сконфигурированный", "Высокий",
                                "Ограничьте заголовок 'Access-Control-Allow-Origin' определенными доверенными доменами или избегайте использования подстановочного знака "*"."))

    # 10. Content-Type sniffing
    content_type = headers.get("Content-Type", "")
    x_content_type_options = headers.get("X-Content-Type-Options", "")
    if content_type.startswith("text/html") and x_content_type_options != "nosniff":
        security_report.append(("Content-Type/X-Content-Type-Options", "Небезопасно", "Средняя",
                                "Установите для заголовка 'X-Content-Type-Options' значение 'nosniff' при отображении HTML-контента, чтобы предотвратить перехват типа MIME."))

    # 11. Cache control
    cache_control = headers.get("Cache-Control", "")
    if "no-store" not in cache_control.lower() or "private" not in cache_control.lower():
        security_report.append(("Управление кэшем", "Небезопасно", "Средняя",
                                "Установите заголовок 'Cache-Control' на 'no-store, private' для конфиденциальных ресурсов, чтобы предотвратить кэширование."))

    return security_report


def format_security_report(security_report):
    output = f"{'Наименование':<30} {'Статус':<15} {'Сложность':<10} {'Рекомендации'}\n"
    output += "-" * 80 + "\n"

    for header, status, severity, recommendation in security_report:
        output += f"{header:<30} {status:<15} {severity:<10} {recommendation}\n"

    return output

if __name__ == "__main__":
    url = input("Введите URL-адрес для анализа:")
    security_report = analyze_headers(url)
    if security_report:
        print("\nОтчет о безопасности:")
        print(format_security_report(security_report))
    else:
        print("В заголовках запроса и ответа не обнаружено проблем с безопасностью.")
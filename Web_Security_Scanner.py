import requests
from bs4 import BeautifulSoup
import urllib3 
import urllib.parse

# Suppress warnings about SSL certifications
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def check_https(url):
    if url.startswith("https://"):
        return True
    else:
        return False
    
def check_sql_injection(url):
    payloads = ["'OR '1'='1", '" Or "1"="1', "' UNION SELECT NULL, NULL, NULL --"]
    for payload in payloads:
        # Use proper URL encoding for the payload
        encoded_payload = urllib.parse.quote(payload)
        test_url = f"{url}?test={encoded_payload}"  # Assume 'test' is a parameter
        try:
            response = requests.get(test_url, verify=False)
            if "error" in response.text.lower() or "syntax" in response.text.lower():
                return True  # Possible SQL injection vulnerability
        except requests.exceptions.RequestException as e:
            print(f"Error testing SQL injection with payload {payload}: {e}")
    return False

def check_xss(url):
    payloads = ['<script>alert("XSS")</script>', '"><script>alert("XSS")</script>']
    for payload in payloads:
        response = requests.get(url + payload, verify=False)
        if payload in response.text:
            return True  # XSS vulnerability
    return False

def check_http_headers(url):
    response = requests.get(url, verify=False)
    headers = response.headers
    missing_headers = []

    if 'Strict-Transport-Security' not in headers:
        missing_headers.append('Strict-Transport-Security')
    if 'X-Content-Type-Options' not in headers:
        missing_headers.append('X-Content-Type-Options')
    if 'X-Frame-Options' not in headers:
        missing_headers.append('X-Frame-Options')

    return missing_headers

def scan_website(url):
    print(f"Scanning {url}...\n")

    # Check HTTPS
    if not check_https(url):
        print("Warning: Website is not using HTTPS.")
    
    # Check for SQL Injection vulnerability
    if check_sql_injection(url):
        print("Warning: Potential SQL Injection vulnerability detected.")

    # Check for XSS vulnerability
    if check_xss(url):
        print("Warning: Potential XSS vulnerability detected.")

    # Check for missing HTTP headers
    missing_headers = check_http_headers(url)
    if missing_headers:
        print(f"Warning: Missing important HTTP headers: {', '.join(missing_headers)}")
    
    print("\nScan completed.\n")

if __name__ == "__main__":
    website = input("Enter the Website URL to scan: ")
    scan_website(website)

from flask import Flask, request, jsonify, render_template, redirect
from flask_cors import CORS  # Import Flask-CORS
import requests
from bs4 import BeautifulSoup
import re
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager
from selenium.webdriver.chrome.options import Options
import os
import time

app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

# Force HTTPS redirect
@app.before_request
def force_https():
    if not request.is_secure:
        return redirect(request.url.replace("http://", "https://"), code=301)

@app.route('/favicon.ico')
def favicon():
    return ('', 204)  # Return an empty response with status code 204 (No Content)

def sanitize_url(url):
    if not re.match(r'^(https?://)[a-zA-Z0-9.-]+\.[a-zA-Z]{2,6}(/\S*)?$', url):
        return None
    return url

def fetch_page_source(url):
    options = Options()
    options.add_argument("--headless")
    options.add_argument("--disable-gpu")
    options.add_argument("--no-sandbox")

    try:
        service = Service(ChromeDriverManager().install())
        driver = webdriver.Chrome(service=service, options=options)
        driver.get(url)
        time.sleep(3)
        page_source = driver.page_source
    except Exception as e:
        return f"Error: {str(e)}"
    finally:
        driver.quit()
    
    return page_source

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    data = request.json
    url = data.get('url')
    
    url = sanitize_url(url)
    if not url:
        return jsonify({"error": "Invalid or Malicious URL"}), 400
    
    vulnerabilities = []
    try:
        page_source = fetch_page_source(url)
        if "Error:" in page_source:
            return jsonify({"error": page_source}), 500
        
        soup = BeautifulSoup(page_source, 'html.parser')
        
        security_headers = {
            "Content-Security-Policy": "Prevents XSS by restricting source of scripts.",
            "X-Frame-Options": "Prevents Clickjacking attacks.",
            "X-XSS-Protection": "Mitigates reflected XSS attacks.",
            "Strict-Transport-Security": "Forces HTTPS.",
            "Referrer-Policy": "Controls referrer info.",
            "Permissions-Policy": "Restricts browser features.",
            "Expect-CT": "Ensures SSL/TLS certificate logging."
        }
        
        try:
            response_headers = requests.head(url, timeout=5).headers
            for header, reason in security_headers.items():
                if header not in response_headers:
                    vulnerabilities.append(f"❌ Missing security header: {header} - {reason}")
        except requests.exceptions.RequestException:
            vulnerabilities.append("⚠️ Unable to fetch security headers.")
        
        for input_tag in soup.find_all("input"):
            if not input_tag.get("maxlength"):
                vulnerabilities.append("⚠️ Input field has no maxlength attribute, may be vulnerable to XSS.")
        
        sql_payloads = ["'", '"', "' OR 1=1 --", "\" OR 1=1 --", "' AND 1=0 --"]
        sql_errors = [
            "You have an error in your SQL syntax", 
            "SQLSTATE[42000]",  
            "Unclosed quotation mark after the character string",  
            "syntax error at or near",  
            "ORA-00933: SQL command not properly ended"  
        ]
        
        for form in soup.find_all("form"):
            for input_tag in form.find_all("input"):
                input_name = input_tag.get("name", "unknown")
                if input_name:
                    for payload in sql_payloads:
                        test_url = f"{url}?{input_name}={payload}"
                        try:
                            test_response = requests.get(test_url, timeout=5)
                            if any(error in test_response.text for error in sql_errors):
                                vulnerabilities.append(f"❗ Error-Based SQL Injection in input: {input_name}")
                        except requests.exceptions.RequestException:
                            pass
        
    except requests.exceptions.RequestException as e:
        return jsonify({"error": f"Request failed: {str(e)}"}), 500
    
    return jsonify({
        "status": "Scan Completed",
        "url": url,
        "vulnerabilities": vulnerabilities
    })

if __name__ == '__main__':
    cert_file = "certificate.crt"
    key_file = "private.key"

    if os.path.exists(cert_file) and os.path.exists(key_file):
        app.run(host='0.0.0.0', port=5000, ssl_context=(cert_file, key_file), debug=True)
    else:
        print("⚠️ SSL certificate not found! Running in HTTP mode.")
        app.run(host='0.0.0.0', port=5000, debug=True)



import requests
from bs4 import BeautifulSoup
import re
import mysql.connector
import smtplib
from email.mime.text import MIMEText
import time
import pickle
from sklearn.ensemble import RandomForestClassifier
from datetime import datetime


### 1. Fetch Vulnerabilities from Website
def fetch_vulnerabilities(url):
    try:
        response = requests.get(url)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')
        vulnerabilities = []

        for vuln in soup.find_all(string=re.compile(r'CVE-\d{4}-\d+')):
            cve_id = vuln.strip()
            description = vuln.find_next('p').text
            published_date = vuln.find_next('span', class_='published-date').text
            severity = vuln.find_next('span', class_='severity').text
            mitigation = vuln.find_next('p', class_='mitigation').text

            vulnerabilities.append({
                'cve_id': cve_id,
                'description': description,
                'published_date': published_date,
                'severity': severity,
                'mitigation': mitigation,
            })

        return vulnerabilities
    except Exception as e:
        print(f"Error fetching vulnerabilities: {e}")
        return []


### 2. Save Vulnerabilities to MySQL Database
def save_to_database(vuln_data):
    db = mysql.connector.connect(
        host="localhost",
        user="your_username",
        password="your_password",
        database="vulnerability_db"
    )
    cursor = db.cursor()

    for vuln in vuln_data:
        query = ("INSERT INTO vulnerabilities (cve_id, description, published_date, severity, mitigation) "
                 "VALUES (%s, %s, %s, %s, %s)")
        values = (vuln['cve_id'], vuln['description'], vuln['published_date'], vuln['severity'], vuln['mitigation'])
        cursor.execute(query, values)

    db.commit()
    cursor.close()
    db.close()


### 3. Train AI Model for Future Vulnerability Prediction
# def train_model(data):
#     # Example: Preprocessed data should be provided here
#     model = RandomForestClassifier()
#     model.fit(data['features'], data['labels'])
#     with open('vulnerability_model.pkl', 'wb') as file:
#         pickle.dump(model, file)
#
#
# def predict_vulnerability(data):
#     with open('vulnerability_model.pkl', 'rb') as file:
#         model = pickle.load(file)
#     return model.predict(data)
#

### 4. Send Email Alert
def send_email_alert(vulnerability):
    msg = MIMEText(f"""
    New Vulnerability Detected:
    CVE ID: {vulnerability['cve_id']}
    Severity: {vulnerability['severity']}
    Published Date: {vulnerability['published_date']}
    Description: {vulnerability['description']}
    Mitigation: {vulnerability['mitigation']}
    """)
    msg['Subject'] = 'Critical Vulnerability Alert'
    msg['From'] = 'alert@vulnscanner.com'
    msg['To'] = 'admin@example.com'

    with smtplib.SMTP('smtp.example.com', 587) as server:
        server.login('your_email', 'your_password')
        server.sendmail(msg['From'], [msg['To']], msg.as_string())


### 5. 24/7 Monitoring Scheduler
def monitor_vulnerabilities():
    while True:
        url = "https://www.srcas.ac.in/"
        vulnerabilities = fetch_vulnerabilities(url)
        if vulnerabilities:
            save_to_database(vulnerabilities)
            for vuln in vulnerabilities:
                if vuln['severity'].lower() in ['high', 'critical']:
                    send_email_alert(vuln)

        #time.sleep(3600)  # Run every hour


# Start monitoring
monitor_vulnerabilities()

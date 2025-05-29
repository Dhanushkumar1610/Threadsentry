import sqlite3
import os
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash
import pandas as pd
import xml.etree.ElementTree as ET
import json
import re
import pdfplumber
from bs4 import BeautifulSoup

app = Flask(__name__)
app.secret_key = 'supersecretkey'
DATABASE = 'vulnerabilities.db'

# Initialize the database
def init_db():
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS app_vulnerabilities
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  name TEXT, severity TEXT, description TEXT, risk_score INTEGER,
                  remediation TEXT, scan_date TEXT, url TEXT, cwe_id TEXT,
                  status TEXT, source_tool TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS remediation_history
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  vuln_name TEXT, vuln_type TEXT, action TEXT, date TEXT)''')
    conn.commit()
    conn.close()

# Ensure the source_tool column exists
def ensure_source_tool_column():
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute("PRAGMA table_info(app_vulnerabilities)")
    columns = [col[1] for col in c.fetchall()]
    if 'source_tool' not in columns:
        c.execute("ALTER TABLE app_vulnerabilities ADD COLUMN source_tool TEXT")
    conn.commit()
    conn.close()

# Normalize severity values
def normalize_severity(severity):
    severity = severity.lower()
    if severity in ['critical', 'blocker']:
        return 'Critical'
    elif severity in ['high', 'major']:
        return 'High'
    elif severity == 'medium':
        return 'Medium'
    elif severity in ['low', 'minor']:
        return 'Low'
    else:
        return 'Informational'

# Normalize vulnerability data
def normalize_vuln_data(vuln):
    return {
        'name': str(vuln.get('name', 'Unknown')),
        'severity': normalize_severity(vuln.get('severity', 'Medium')),
        'description': str(vuln.get('description', '')),
        'risk_score': int(vuln.get('risk_score', 50)),
        'remediation': str(vuln.get('remediation', '')),
        'url': str(vuln.get('url', '')),
        'cwe_id': str(vuln.get('cwe_id', '')),
        'scan_date': vuln.get('scan_date', datetime.now().strftime('%Y-%m-%d %H:%M:%S')),
        'status': str(vuln.get('status', 'Open')),
        'source_tool': str(vuln.get('source_tool', 'Unknown'))
    }

# Parse OWASP ZAP CSV report
def parse_owasp_zap_csv(file_path):
    df = pd.read_csv(file_path, on_bad_lines='skip')
    vulnerabilities = []
    header_mapping = {
        'vulnerability': 'name', 'risk': 'severity', 'description': 'description',
        'solution': 'remediation', 'url': 'url', 'cweid': 'cwe_id', 'alert': 'name'
    }
    df = df.rename(columns={k: v for k, v in header_mapping.items() if k in df.columns})
    risk_scores = {'Critical': 90, 'High': 70, 'Medium': 50, 'Low': 30, 'Informational': 10}
    for _, row in df.iterrows():
        vuln = row.to_dict()
        vuln['severity'] = normalize_severity(vuln.get('severity', 'Medium'))
        vuln['risk_score'] = risk_scores.get(vuln['severity'], 50)
        vuln['source_tool'] = 'OWASP ZAP'
        vulnerabilities.append(normalize_vuln_data(vuln))
    return vulnerabilities

# Parse Burp Suite XML report
def parse_burp_xml(file_path):
    tree = ET.parse(file_path)
    root = tree.getroot()
    vulnerabilities = []
    risk_scores = {'Critical': 90, 'High': 70, 'Medium': 50, 'Low': 30, 'Informational': 10}
    for issue in root.findall('.//issue'):
        vuln = {
            'name': issue.find('name').text if issue.find('name') is not None else 'Unknown',
            'severity': issue.find('severity').text if issue.find('severity') is not None else 'Medium',
            'description': issue.find('issueDetail').text if issue.find('issueDetail') is not None else '',
            'remediation': issue.find('remediation').text if issue.find('remediation') is not None else '',
            'url': issue.find('host').text if issue.find('host') is not None else '',
            'cwe_id': issue.find('cweid').text if issue.find('cweid') is not None else '',
            'source_tool': 'Burp Suite'
        }
        vuln['severity'] = normalize_severity(vuln['severity'])
        vuln['risk_score'] = risk_scores.get(vuln['severity'], 50)
        vulnerabilities.append(normalize_vuln_data(vuln))
    return vulnerabilities

# Parse OWASP Dependency-Check report (XML or JSON)
def parse_dependency_check(file_path):
    vulnerabilities = []
    risk_scores = {'Critical': 90, 'High': 70, 'Medium': 50, 'Low': 30, 'Informational': 10}
    if file_path.endswith('.xml'):
        tree = ET.parse(file_path)
        root = tree.getroot()
        for dependency in root.findall('.//dependency'):
            for vuln in dependency.findall('.//vulnerability'):
                vuln_data = {
                    'name': vuln.find('name').text if vuln.find('name') is not None else 'Unknown',
                    'severity': vuln.find('severity').text if vuln.find('severity') is not None else 'Medium',
                    'description': vuln.find('description').text if vuln.find('description') is not None else '',
                    'source_tool': 'OWASP Dependency-Check'
                }
                vuln_data['severity'] = normalize_severity(vuln_data['severity'])
                vuln_data['risk_score'] = risk_scores.get(vuln_data['severity'], 50)
                vulnerabilities.append(normalize_vuln_data(vuln_data))
    else:  # JSON
        with open(file_path, 'r') as f:
            data = json.load(f)
        for dependency in data.get('dependencies', []):
            for vuln in dependency.get('vulnerabilities', []):
                vuln_data = {
                    'name': vuln.get('name', 'Unknown'),
                    'severity': vuln.get('severity', 'Medium'),
                    'description': vuln.get('description', ''),
                    'source_tool': 'OWASP Dependency-Check'
                }
                vuln_data['severity'] = normalize_severity(vuln_data['severity'])
                vuln_data['risk_score'] = risk_scores.get(vuln_data['severity'], 50)
                vulnerabilities.append(normalize_vuln_data(vuln_data))
    return vulnerabilities

# Parse SonarQube JSON report
def parse_sonarqube_json(file_path):
    with open(file_path, 'r') as f:
        data = json.load(f)
    vulnerabilities = []
    risk_scores = {'Critical': 90, 'High': 70, 'Medium': 50, 'Low': 30, 'Informational': 10}
    for issue in data.get('issues', []):
        if issue.get('type') == 'VULNERABILITY':
            vuln = {
                'name': issue.get('message', 'Unknown'),
                'severity': issue.get('severity', 'Medium'),
                'description': issue.get('message', ''),
                'source_tool': 'SonarQube'
            }
            vuln['severity'] = normalize_severity(vuln['severity'])
            vuln['risk_score'] = risk_scores.get(vuln['severity'], 50)
            vulnerabilities.append(normalize_vuln_data(vuln))
    return vulnerabilities

# Parse Bandit JSON report
def parse_bandit_json(file_path):
    with open(file_path, 'r') as f:
        data = json.load(f)
    vulnerabilities = []
    risk_scores = {'Critical': 90, 'High': 70, 'Medium': 50, 'Low': 30, 'Informational': 10}
    for result in data.get('results', []):
        vuln = {
            'name': result.get('test_id', 'Unknown'),
            'severity': result.get('issue_severity', 'Medium'),
            'description': result.get('issue_text', ''),
            'source_tool': 'Bandit'
        }
        vuln['severity'] = normalize_severity(vuln['severity'])
        vuln['risk_score'] = risk_scores.get(vuln['severity'], 50)
        vulnerabilities.append(normalize_vuln_data(vuln))
    return vulnerabilities

# Parse PDF report (assumes a table format)
def parse_pdf_report(file_path):
    vulnerabilities = []
    risk_scores = {'Critical': 90, 'High': 70, 'Medium': 50, 'Low': 30, 'Informational': 10}
    with pdfplumber.open(file_path) as pdf:
        for page in pdf.pages:
            table = page.extract_table()
            if table:
                headers = table[0]  # Assume first row is headers
                header_mapping = {
                    'vulnerability': 'name', 'risk': 'severity', 'description': 'description',
                    'solution': 'remediation', 'url': 'url', 'cwe': 'cwe_id', 'alert': 'name'
                }
                normalized_headers = [header_mapping.get(h.lower(), h.lower()) for h in headers]
                for row in table[1:]:  # Skip header row
                    vuln = dict(zip(normalized_headers, row))
                    vuln['severity'] = normalize_severity(vuln.get('severity', 'Medium'))
                    vuln['risk_score'] = risk_scores.get(vuln['severity'], 50)
                    vuln['source_tool'] = 'PDF Report'
                    vulnerabilities.append(normalize_vuln_data(vuln))
    return vulnerabilities

# Parse HTML report (assumes a table format)
def parse_html_report(file_path):
    vulnerabilities = []
    risk_scores = {'Critical': 90, 'High': 70, 'Medium': 50, 'Low': 30, 'Informational': 10}
    with open(file_path, 'r', encoding='utf-8') as f:
        soup = BeautifulSoup(f, 'html.parser')
    table = soup.find('table')
    if table:
        headers = [th.text.lower() for th in table.find_all('th')]
        header_mapping = {
            'vulnerability': 'name', 'risk': 'severity', 'description': 'description',
            'solution': 'remediation', 'url': 'url', 'cwe': 'cwe_id', 'alert': 'name'
        }
        normalized_headers = [header_mapping.get(h, h) for h in headers]
        for row in table.find_all('tr')[1:]:  # Skip header row
            cols = [td.text.strip() for td in row.find_all('td')]
            vuln = dict(zip(normalized_headers, cols))
            vuln['severity'] = normalize_severity(vuln.get('severity', 'Medium'))
            vuln['risk_score'] = risk_scores.get(vuln['severity'], 50)
            vuln['source_tool'] = 'HTML Report'
            vulnerabilities.append(normalize_vuln_data(vuln))
    return vulnerabilities

# Insert vulnerabilities into the database
def insert_vulnerabilities(vulnerabilities):
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    for vuln in vulnerabilities:
        c.execute('''INSERT INTO app_vulnerabilities
                     (name, severity, description, risk_score, remediation, scan_date, url, cwe_id, status, source_tool)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                  (vuln['name'], vuln['severity'], vuln['description'], vuln['risk_score'],
                   vuln['remediation'], vuln['scan_date'], vuln['url'], vuln['cwe_id'],
                   vuln['status'], vuln['source_tool']))
    conn.commit()
    conn.close()

# Get severity counts for the graph (kept for potential future use)
def get_severity_counts():
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute("SELECT severity, COUNT(*) as count FROM app_vulnerabilities WHERE status != 'Deleted' GROUP BY severity")
    rows = c.fetchall()
    conn.close()
    severity_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Informational': 0}
    for row in rows:
        severity = row[0]
        count = row[1]
        if severity in severity_counts:
            severity_counts[severity] = count
    print(f"Severity Counts: {severity_counts}")  # Debug log
    return severity_counts

# Get status counts for the pie chart
def get_status_counts():
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute("SELECT status, COUNT(*) as count FROM app_vulnerabilities GROUP BY status")
    rows = c.fetchall()
    conn.close()
    status_counts = {'Open': 0, 'Fixed': 0, 'Deleted': 0}
    for row in rows:
        status = row[0]
        count = row[1]
        if status in status_counts:
            status_counts[status] = count
    print(f"Status Counts: {status_counts}")  # Debug log
    return status_counts

@app.route('/')
def index():
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute("SELECT * FROM app_vulnerabilities WHERE status != 'Deleted'")
    vulnerabilities = c.fetchall()
    conn.close()
    return render_template('index.html', vulnerabilities=vulnerabilities)

@app.route('/analytics')
def analytics():
    status_counts = get_status_counts()
    return render_template('analytics.html', status_counts=status_counts)

@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        if 'file' not in request.files:
            return render_template('error.html', error='No file part')
        file = request.files['file']
        if file.filename == '':
            return render_template('error.html', error='No selected file')
        if file:
            file_path = os.path.join('uploads', file.filename)
            if not os.path.exists('Uploads'):
                os.makedirs('Uploads')
            file.save(file_path)
            try:
                if file.filename.endswith('.csv'):
                    vulnerabilities = parse_owasp_zap_csv(file_path)
                elif file.filename.endswith('.xml') and 'dependency-check' in file.filename.lower():
                    vulnerabilities = parse_dependency_check(file_path)
                elif file.filename.endswith('.xml'):
                    vulnerabilities = parse_burp_xml(file_path)
                elif file.filename.endswith('.json') and 'sonarqube' in file.filename.lower():
                    vulnerabilities = parse_sonarqube_json(file_path)
                elif file.filename.endswith('.json') and 'bandit' in file.filename.lower():
                    vulnerabilities = parse_bandit_json(file_path)
                elif file.filename.endswith('.json'):
                    vulnerabilities = parse_dependency_check(file_path)
                elif file.filename.endswith('.pdf'):
                    vulnerabilities = parse_pdf_report(file_path)
                elif file.filename.endswith('.html'):
                    vulnerabilities = parse_html_report(file_path)
                else:
                    return render_template('error.html', error='Unsupported file format')
                insert_vulnerabilities(vulnerabilities)
                flash('File successfully uploaded and processed')
                return redirect(url_for('index'))
            except Exception as e:
                return render_template('error.html', error=f'Error processing file: {str(e)}')
    return render_template('upload.html')

@app.route('/delete/<int:vuln_id>')
def delete_vulnerability(vuln_id):
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute("SELECT name FROM app_vulnerabilities WHERE id = ?", (vuln_id,))
    vuln_name = c.fetchone()[0]
    c.execute("UPDATE app_vulnerabilities SET status = 'Deleted' WHERE id = ?", (vuln_id,))
    c.execute("INSERT INTO remediation_history (vuln_name, vuln_type, action, date) VALUES (?, ?, ?, ?)",
              (vuln_name, 'App', 'Deleted', datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
    conn.commit()
    conn.close()
    flash('Vulnerability deleted')
    return redirect(url_for('index'))

@app.route('/fix/<int:vuln_id>')
def fix_vulnerability(vuln_id):
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute("SELECT name FROM app_vulnerabilities WHERE id = ?", (vuln_id,))
    vuln_name = c.fetchone()[0]
    c.execute("UPDATE app_vulnerabilities SET status = 'Fixed' WHERE id = ?", (vuln_id,))
    c.execute("INSERT INTO remediation_history (vuln_name, vuln_type, action, date) VALUES (?, ?, ?, ?)",
              (vuln_name, 'App', 'Fixed', datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
    conn.commit()
    conn.close()
    flash('Vulnerability marked as fixed')
    return redirect(url_for('index'))

@app.route('/remediation_history')
def remediation_history():
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute("SELECT * FROM remediation_history ORDER BY date DESC")
    history = c.fetchall()
    conn.close()
    return render_template('remediation_history.html', history=history)

@app.route('/export_report')
def export_report():
    try:
        export_format = request.args.get('format', 'csv')  # Default to CSV
        timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M')
        filename_base = f'vulnerability_report_{timestamp}'
        export_path = os.path.join('exports', filename_base)

        conn = sqlite3.connect(DATABASE)
        query = "SELECT * FROM app_vulnerabilities WHERE status != 'Deleted'"
        df = pd.read_sql_query(query, conn)
        conn.close()

        if not os.path.exists('exports'):
            os.makedirs('exports')

        if export_format == 'csv':
            export_path = f'{export_path}.csv'
            df.to_csv(export_path, index=False)
        elif export_format == 'json':
            export_path = f'{export_path}.json'
            df.to_json(export_path, orient='records', indent=4)
        elif export_format == 'excel':
            export_path = f'{export_path}.xlsx'
            df.to_excel(export_path, index=False, engine='openpyxl')
        elif export_format == 'pdf':
            export_path = f'{export_path}.tex'
            # Generating LaTeX content for PDF
            latex_content = r"""
\documentclass[a4paper,10pt]{article}
\usepackage[utf8]{inputenc}
\usepackage{geometry}
\geometry{margin=1in}
\usepackage{booktabs}
\usepackage{longtable}
\usepackage{array}
\usepackage{xcolor}
\definecolor{headergray}{RGB}{220,220,220}

\title{Vulnerability Report}
\author{ThreadSentry}
\date{Generated on \today}

\begin{document}

\maketitle

\section*{Vulnerability Report}
This report contains all non-deleted vulnerabilities as of the generation date.

\begin{longtable}{|>{\raggedright}p{0.5cm}|>{\raggedright}p{2cm}|>{\raggedright}p{1.5cm}|>{\raggedright}p{3cm}|>{\raggedright}p{1cm}|>{\raggedright}p{2cm}|>{\raggedright}p{2cm}|>{\raggedright}p{2cm}|>{\raggedright}p{1cm}|>{\raggedright}p{1cm}|>{\raggedright}p{2cm}|}
\hline
\rowcolor{headergray}
\textbf{ID} & \textbf{Name} & \textbf{Severity} & \textbf{Description} & \textbf{Risk Score} & \textbf{Remediation} & \textbf{Scan Date} & \textbf{URL} & \textbf{CWE ID} & \textbf{Status} & \textbf{Source Tool} \\
\hline
\endhead
"""
            for _, row in df.iterrows():
                row_values = [
                    str(row['id']),
                    str(row['name']).replace('&', '\\&').replace('_', '\\_'),
                    str(row['severity']),
                    str(row['description']).replace('&', '\\&').replace('_', '\\_'),
                    str(row['risk_score']),
                    str(row['remediation']).replace('&', '\\&').replace('_', '\\_'),
                    str(row['scan_date']),
                    str(row['url']).replace('&', '\\&').replace('_', '\\_'),
                    str(row['cwe_id']),
                    str(row['status']),
                    str(row['source_tool'])
                ]
                latex_content += " & ".join(row_values) + " \\\\\n\\hline\n"
            latex_content += r"""
\end{longtable}

\end{document}
"""
            with open(export_path, 'w', encoding='utf-8') as f:
                f.write(latex_content)
            export_path = f'{export_path[:-4]}.pdf'  # Change extension to .pdf for flash message
        else:
            flash('Unsupported export format')
            return redirect(url_for('index'))

        flash(f'Report exported successfully as {os.path.basename(export_path)}')
    except Exception as e:
        flash(f'Error exporting report: {str(e)}')
    return redirect(url_for('index'))

if __name__ == '__main__':
    init_db()
    ensure_source_tool_column()
    app.run(debug=True)
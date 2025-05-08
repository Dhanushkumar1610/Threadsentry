from flask import Flask, request, flash, redirect, url_for, render_template, jsonify
import pandas as pd
import sqlite3
from datetime import datetime
import logging
import os
import xml.etree.ElementTree as ET
import json
import re

# Initialize the Flask app
app = Flask(__name__)
app.secret_key = 'your-secret-key-here'  # Required for flash messages

# Set up logging
logging.basicConfig(filename='threadsentry.log', level=logging.INFO)

# Database setup
def init_db():
    conn = sqlite3.connect('vulnerabilities.db')
    cursor = conn.cursor()
    # Create app_vulnerabilities table with source_tool column
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS app_vulnerabilities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            severity TEXT,
            description TEXT,
            risk_score INTEGER,
            remediation TEXT,
            scan_date TEXT,
            url TEXT,
            cwe_id TEXT,
            status TEXT,
            source_tool TEXT
        )
    ''')
    # Create remediation_history table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS remediation_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            vuln_name TEXT,
            vuln_type TEXT,
            action TEXT,
            date TEXT
        )
    ''')
    conn.commit()
    conn.close()

# Ensure the source_tool column exists before proceeding
def ensure_source_tool_column():
    conn = sqlite3.connect('vulnerabilities.db')
    cursor = conn.cursor()
    try:
        # Check if source_tool column exists
        cursor.execute("PRAGMA table_info(app_vulnerabilities)")
        columns = [info[1] for info in cursor.fetchall()]
        if 'source_tool' not in columns:
            logging.info("Adding source_tool column to app_vulnerabilities table.")
            cursor.execute('ALTER TABLE app_vulnerabilities ADD COLUMN source_tool TEXT')
            cursor.execute("UPDATE app_vulnerabilities SET source_tool = 'Unknown' WHERE source_tool IS NULL")
            conn.commit()
            logging.info("Successfully added source_tool column.")
    except sqlite3.Error as e:
        logging.error(f"Failed to add source_tool column: {str(e)}")
        raise
    finally:
        conn.close()

# Initialize the database and ensure schema is up-to-date
init_db()
ensure_source_tool_column()

# Helper function to normalize severity levels
def normalize_severity(severity):
    if not severity:
        return 'Informational'
    severity = str(severity).lower()
    if 'crit' in severity:
        return 'Critical'
    elif 'high' in severity:
        return 'High'
    elif 'med' in severity or 'moderate' in severity:
        return 'Medium'
    elif 'low' in severity:
        return 'Low'
    else:
        return 'Informational'

# Helper function to extract CWE ID
def extract_cwe_id(text):
    if not text:
        return ''
    match = re.search(r'CWE-(\d+)', text, re.IGNORECASE)
    return match.group(1) if match else ''

# Normalize vulnerability data to prevent database errors
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

# Parser for Burp Suite XML
def parse_burp_xml(file):
    try:
        tree = ET.parse(file)
        root = tree.getroot()
        vulnerabilities = []
        
        for issue in root.findall('issue'):
            name = issue.find('name').text if issue.find('name') is not None else 'Unknown'
            severity = issue.find('severity').text if issue.find('severity') is not None else 'Medium'
            description = issue.find('issueDetail').text if issue.find('issueDetail') is not None else ''
            remediation = issue.find('remediation').text if issue.find('remediation') is not None else ''
            url = issue.find('host').text if issue.find('host') is not None else ''
            cwe_id = extract_cwe_id(description)
            risk_score = {'critical': 90, 'high': 70, 'medium': 50, 'low': 30, 'informational': 10}.get(severity.lower(), 50)
            
            vuln = {
                'name': name,
                'severity': severity,
                'description': description,
                'risk_score': risk_score,
                'remediation': remediation,
                'url': url,
                'cwe_id': cwe_id,
                'scan_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'status': 'Open',
                'source_tool': 'Burp Suite'
            }
            vulnerabilities.append(normalize_vuln_data(vuln))
        
        return vulnerabilities
    except ET.ParseError as e:
        logging.error(f"Failed to parse Burp Suite XML: {str(e)}")
        raise ValueError(f"Invalid Burp Suite XML format: {str(e)}")

# Parser for OWASP Dependency-Check (XML or JSON)
def parse_dependency_check(file, file_type):
    vulnerabilities = []
    
    if file_type == 'xml':
        try:
            tree = ET.parse(file)
            root = tree.getroot()
            for dep in root.findall('.//dependency'):
                for vuln in dep.findall('vulnerabilities/vulnerability'):
                    name = vuln.find('name').text if vuln.find('name') is not None else 'Unknown'
                    severity = vuln.find('severity').text if vuln.find('severity') is not None else 'Medium'
                    description = vuln.find('description').text if vuln.find('description') is not None else ''
                    remediation = 'Update the dependency to a secure version.'
                    url = ''
                    cwe_id = extract_cwe_id(description)
                    risk_score = {'critical': 90, 'high': 70, 'medium': 50, 'low': 30, 'informational': 10}.get(severity.lower(), 50)
                    
                    vuln = {
                        'name': name,
                        'severity': severity,
                        'description': description,
                        'risk_score': risk_score,
                        'remediation': remediation,
                        'url': url,
                        'cwe_id': cwe_id,
                        'scan_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                        'status': 'Open',
                        'source_tool': 'OWASP Dependency-Check'
                    }
                    vulnerabilities.append(normalize_vuln_data(vuln))
        except ET.ParseError as e:
            logging.error(f"Failed to parse OWASP Dependency-Check XML: {str(e)}")
            raise ValueError(f"Invalid OWASP Dependency-Check XML format: {str(e)}")
    else:  # JSON
        try:
            data = json.load(file)
            for dep in data.get('dependencies', []):
                for vuln in dep.get('vulnerabilities', []):
                    name = vuln.get('name', 'Unknown')
                    severity = vuln.get('severity', 'Medium')
                    description = vuln.get('description', '')
                    remediation = 'Update the dependency to a secure version.'
                    url = ''
                    cwe_id = extract_cwe_id(description)
                    risk_score = {'critical': 90, 'high': 70, 'medium': 50, 'low': 30, 'informational': 10}.get(severity.lower(), 50)
                    
                    vuln = {
                        'name': name,
                        'severity': severity,
                        'description': description,
                        'risk_score': risk_score,
                        'remediation': remediation,
                        'url': url,
                        'cwe_id': cwe_id,
                        'scan_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                        'status': 'Open',
                        'source_tool': 'OWASP Dependency-Check'
                    }
                    vulnerabilities.append(normalize_vuln_data(vuln))
        except json.JSONDecodeError as e:
            logging.error(f"Failed to parse OWASP Dependency-Check JSON: {str(e)}")
            raise ValueError(f"Invalid OWASP Dependency-Check JSON format: {str(e)}")
    
    return vulnerabilities

# Parser for SonarQube JSON
def parse_sonarqube_json(file):
    try:
        data = json.load(file)
        vulnerabilities = []
        
        for issue in data.get('issues', []):
            if issue.get('type') != 'VULNERABILITY':
                continue
            name = issue.get('message', 'Unknown')
            severity = issue.get('severity', 'MEDIUM')
            description = issue.get('message', '')
            remediation = 'Review and fix the code as per SonarQube recommendations.'
            url = issue.get('component', '')
            cwe_id = extract_cwe_id(description)
            risk_score = {'blocker': 90, 'critical': 90, 'major': 70, 'minor': 30, 'info': 10}.get(severity.lower(), 50)
            
            vuln = {
                'name': name,
                'severity': severity,
                'description': description,
                'risk_score': risk_score,
                'remediation': remediation,
                'url': url,
                'cwe_id': cwe_id,
                'scan_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'status': 'Open',
                'source_tool': 'SonarQube'
            }
            vulnerabilities.append(normalize_vuln_data(vuln))
        
        return vulnerabilities
    except json.JSONDecodeError as e:
        logging.error(f"Failed to parse SonarQube JSON: {str(e)}")
        raise ValueError(f"Invalid SonarQube JSON format: {str(e)}")

# Parser for Bandit JSON
def parse_bandit_json(file):
    try:
        data = json.load(file)
        vulnerabilities = []
        
        for issue in data.get('results', []):
            name = issue.get('test_id', 'Unknown')
            severity = issue.get('issue_severity', 'MEDIUM')
            description = issue.get('issue_text', '')
            remediation = issue.get('more_info', 'Review Bandit documentation for remediation steps.')
            url = issue.get('filename', '')
            cwe_id = extract_cwe_id(description)
            risk_score = {'high': 70, 'medium': 50, 'low': 30}.get(severity.lower(), 50)
            
            vuln = {
                'name': name,
                'severity': severity,
                'description': description,
                'risk_score': risk_score,
                'remediation': remediation,
                'url': url,
                'cwe_id': cwe_id,
                'scan_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'status': 'Open',
                'source_tool': 'Bandit'
            }
            vulnerabilities.append(normalize_vuln_data(vuln))
        
        return vulnerabilities
    except json.JSONDecodeError as e:
        logging.error(f"Failed to parse Bandit JSON: {str(e)}")
        raise ValueError(f"Invalid Bandit JSON format: {str(e)}")

# Upload route with enhanced error handling
@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if request.method == 'POST':
        file = request.files['file']

        # Validate inputs
        if not file:
            flash('Please upload a file.', 'error')
            return redirect(url_for('upload'))

        filename = file.filename.lower()
        if not (filename.endswith('.csv') or filename.endswith('.xml') or filename.endswith('.json')):
            flash('Unsupported file format. Please upload a CSV, XML, or JSON file.', 'error')
            return redirect(url_for('upload'))

        # Ensure the source_tool column exists before proceeding
        try:
            ensure_source_tool_column()
        except Exception as e:
            flash(f"Failed to initialize database schema: {str(e)}", 'error')
            return redirect(url_for('upload'))

        # Initialize database connection
        conn = sqlite3.connect('vulnerabilities.db')
        cursor = conn.cursor()

        try:
            vulnerabilities = []

            if filename.endswith('.csv'):
                # Process CSV file with improved error handling
                try:
                    df = pd.read_csv(file, encoding='utf-8', on_bad_lines='skip')
                except Exception as e:
                    logging.error(f"Failed to read CSV file: {str(e)}")
                    flash(f"Failed to read CSV file: {str(e)}", 'error')
                    conn.close()
                    return redirect(url_for('upload'))

                expected_headers = ['name', 'severity', 'description', 'risk_score', 'remediation', 'url', 'cwe_id']
                header_mappings = {
                    'name': ['vulnerability', 'title', 'issue', 'name'],
                    'severity': ['risk', 'level', 'priority', 'severity'],
                    'description': ['details', 'summary', 'description'],
                    'risk_score': ['score', 'impact', 'risk_score', 'riskscore', 'confidence'],
                    'remediation': ['fix', 'solution', 'recommendation', 'remediation'],
                    'url': ['link', 'uri', 'endpoint', 'url'],
                    'cwe_id': ['cwe', 'cwe-id', 'cweid', 'cwe_id']
                }

                actual_headers = {header.lower(): header for header in df.columns}
                header_map = {}
                missing_headers = []
                for expected in expected_headers:
                    found = False
                    for alias in header_mappings[expected]:
                        for actual_lower, actual_original in actual_headers.items():
                            if alias.lower() in actual_lower:
                                header_map[actual_original] = expected
                                found = True
                                break
                        if found:
                            break
                    if not found:
                        missing_headers.append(expected)

                if missing_headers:
                    for missing in missing_headers:
                        df[missing] = ''

                df.rename(columns=header_map, inplace=True)

                if not all(header in df.columns for header in expected_headers):
                    flash(f"Invalid CSV format. Expected headers: {', '.join(expected_headers)}.", 'error')
                    conn.close()
                    return redirect(url_for('upload'))

                for header in expected_headers:
                    df[header] = df[header].fillna('')

                df['risk_score'] = pd.to_numeric(df['risk_score'], errors='coerce').fillna(0).astype(int)

                if 'scan_date' not in df.columns:
                    df['scan_date'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                if 'status' not in df.columns:
                    df['status'] = 'Open'

                for _, row in df.iterrows():
                    vuln = {
                        'name': row['name'],
                        'severity': row['severity'],
                        'description': row['description'],
                        'risk_score': row['risk_score'],
                        'remediation': row['remediation'],
                        'url': row['url'],
                        'cwe_id': row['cwe_id'],
                        'scan_date': row['scan_date'],
                        'status': row['status'],
                        'source_tool': 'OWASP ZAP'
                    }
                    vulnerabilities.append(normalize_vuln_data(vuln))

            elif filename.endswith('.xml'):
                file.seek(0)
                content = file.read().decode('utf-8', errors='ignore')
                file.seek(0)
                if 'issues' in content and 'burpVersion' in content:
                    vulnerabilities = parse_burp_xml(file)
                elif 'dependency-check' in content:
                    vulnerabilities = parse_dependency_check(file, 'xml')
                else:
                    flash('Unsupported XML format. Supported tools: Burp Suite, OWASP Dependency-Check.', 'error')
                    conn.close()
                    return redirect(url_for('upload'))

            elif filename.endswith('.json'):
                file.seek(0)
                content = file.read().decode('utf-8', errors='ignore')
                file.seek(0)
                try:
                    data = json.loads(content)
                except json.JSONDecodeError as e:
                    flash(f"Invalid JSON format: {str(e)}", 'error')
                    conn.close()
                    return redirect(url_for('upload'))

                # Log the JSON structure for debugging
                logging.info(f"JSON structure: {json.dumps(data, indent=2)[:1000]}...")

                # Check for SonarQube
                if 'issues' in data:
                    issues = data.get('issues', [])
                    if isinstance(issues, list) and any(issue.get('type') == 'VULNERABILITY' for issue in issues):
                        file.seek(0)
                        vulnerabilities = parse_sonarqube_json(file)
                        logging.info("Identified as SonarQube JSON")
                    else:
                        flash('JSON does not contain SonarQube vulnerabilities (missing "type": "VULNERABILITY" in issues).', 'error')
                        conn.close()
                        return redirect(url_for('upload'))

                # Check for OWASP Dependency-Check
                elif 'dependencies' in data:
                    file.seek(0)
                    vulnerabilities = parse_dependency_check(file, 'json')
                    logging.info("Identified as OWASP Dependency-Check JSON")

                # Check for Bandit
                elif 'results' in data and 'metrics' in data:
                    file.seek(0)
                    vulnerabilities = parse_bandit_json(file)
                    logging.info("Identified as Bandit JSON")

                else:
                    flash('Unsupported JSON format. Supported tools: SonarQube (requires "issues" with "type": "VULNERABILITY"), OWASP Dependency-Check (requires "dependencies"), Bandit (requires "results" and "metrics").', 'error')
                    conn.close()
                    return redirect(url_for('upload'))

            # Insert vulnerabilities into the database
            for vuln in vulnerabilities:
                cursor.execute('''
                    INSERT INTO app_vulnerabilities (name, severity, description, risk_score, remediation, scan_date, url, cwe_id, status, source_tool)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    vuln['name'],
                    vuln['severity'],
                    vuln['description'],
                    vuln['risk_score'],
                    vuln['remediation'],
                    vuln['scan_date'],
                    vuln['url'],
                    vuln['cwe_id'],
                    vuln['status'],
                    vuln['source_tool']
                ))

            conn.commit()
            conn.close()

            flash('File processed successfully!', 'success')
            return redirect(url_for('index'))

        except Exception as e:
            logging.error(f"Error processing file: {str(e)}")
            flash(f"Error processing file: {str(e)}", 'error')
            conn.close()
            return redirect(url_for('upload'))

    return render_template('upload.html')

# Index route with filtering
@app.route('/')
def index():
    selected_severity = request.args.get('severity', 'all')
    conn = sqlite3.connect('vulnerabilities.db')
    cursor = conn.cursor()

    if selected_severity == 'all':
        cursor.execute("SELECT * FROM app_vulnerabilities")
    else:
        cursor.execute("SELECT * FROM app_vulnerabilities WHERE severity = ?", (selected_severity,))
    app_vulnerabilities = cursor.fetchall()

    deduplicated_vuln_count = len(set(v[1] for v in app_vulnerabilities))
    attack_surface_score = 75
    attack_surface_factors = ["Critical vulnerabilities", "Outdated software"]

    conn.close()

    return render_template('index.html',
                         app_vulnerabilities=app_vulnerabilities,
                         deduplicated_vuln_count=deduplicated_vuln_count,
                         attack_surface_score=attack_surface_score,
                         attack_surface_factors=attack_surface_factors,
                         selected_severity=selected_severity,
                         search_query='')

@app.route('/export_report')
def export_report():
    flash('Export report functionality not implemented yet.', 'info')
    return redirect(url_for('index'))

@app.route('/remediation_history')
def remediation_history():
    conn = sqlite3.connect('vulnerabilities.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM remediation_history")
    history = cursor.fetchall()
    conn.close()
    return render_template('remediation_history.html', history=history)

@app.route('/summary')
def summary():
    return jsonify({
        'Critical': 5,
        'High': 10,
        'Medium': 15,
        'Low': 20,
        'Informational': 25
    })

@app.route('/trend')
def trend():
    return jsonify({
        'dates': ['2025-04-01', '2025-04-15', '2025-04-30'],
        'counts': [50, 45, 40]
    })

@app.route('/search')
def search():
    query = request.args.get('q', '')
    conn = sqlite3.connect('vulnerabilities.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM app_vulnerabilities WHERE name LIKE ? OR description LIKE ?", (f'%{query}%', f'%{query}%'))
    app_vulnerabilities = cursor.fetchall()
    conn.close()
    return render_template('index.html', app_vulnerabilities=app_vulnerabilities, search_query=query)

@app.route('/quick_fix/<int:id>', methods=['POST'])
def quick_fix(id):
    conn = sqlite3.connect('vulnerabilities.db')
    cursor = conn.cursor()
    cursor.execute("UPDATE app_vulnerabilities SET status = 'Fixed' WHERE id = ?", (id,))
    cursor.execute("INSERT INTO remediation_history (vuln_name, vuln_type, action, date) VALUES (?, ?, ?, ?)",
                   ('Unknown', 'App', 'Fixed', datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
    conn.commit()
    conn.close()
    flash('Vulnerability marked as fixed.', 'success')
    return redirect(url_for('index'))

@app.route('/delete/<int:id>/<type>')
def delete(id, type):
    conn = sqlite3.connect('vulnerabilities.db')
    cursor = conn.cursor()
    cursor.execute("DELETE FROM app_vulnerabilities WHERE id = ?", (id,))
    cursor.execute("INSERT INTO remediation_history (vuln_name, vuln_type, action, date) VALUES (?, ?, ?, ?)",
                   ('Unknown', type.capitalize(), 'Deleted', datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
    conn.commit()
    conn.close()
    flash('Vulnerability deleted.', 'success')
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)

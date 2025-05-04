from flask import Flask, request, flash, redirect, url_for, render_template, jsonify
import pandas as pd
import sqlite3
from datetime import datetime
import logging
import os

# Initialize the Flask app
app = Flask(__name__)
app.secret_key = 'your-secret-key-here'  # Required for flash messages

# Set up logging
logging.basicConfig(filename='threadsentry.log', level=logging.INFO)

# Database setup
def init_db():
    conn = sqlite3.connect('vulnerabilities.db')
    cursor = conn.cursor()
    # Create app_vulnerabilities table
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
            status TEXT
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

# Initialize the database when the app starts
init_db()

# Upload route without Nmap scanning
@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if request.method == 'POST':
        file = request.files['file']

        # Validate inputs
        if not file or not file.filename.endswith('.csv'):
            flash('Please upload a valid CSV file.', 'error')
            return redirect(url_for('upload'))

        # Initialize database connection
        conn = sqlite3.connect('vulnerabilities.db')
        cursor = conn.cursor()

        try:
            # Process the CSV file for application vulnerabilities
            df = pd.read_csv(file)

            # Define expected headers
            expected_headers = ['name', 'severity', 'description', 'risk_score', 'remediation', 'url', 'cwe_id']

            # Define possible aliases for each header (case-insensitive matching)
            header_mappings = {
                'name': ['vulnerability', 'title', 'issue', 'name'],
                'severity': ['risk', 'level', 'priority', 'severity'],
                'description': ['details', 'summary', 'description'],
                'risk_score': ['score', 'impact', 'risk_score', 'riskscore', 'confidence'],
                'remediation': ['fix', 'solution', 'recommendation', 'remediation'],
                'url': ['link', 'uri', 'endpoint', 'url'],
                'cwe_id': ['cwe', 'cwe-id', 'cweid', 'cwe_id']
            }

            # Convert all CSV headers to lowercase for case-insensitive matching
            actual_headers = {header.lower(): header for header in df.columns}

            # Map CSV headers to expected headers
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

            # Silently add missing headers with default values
            if missing_headers:
                for missing in missing_headers:
                    df[missing] = ''

            # Rename headers in the DataFrame to match expected headers
            df.rename(columns=header_map, inplace=True)

            # Ensure all expected headers are present after mapping
            if not all(header in df.columns for header in expected_headers):
                flash(f"Invalid CSV format. Expected headers: {', '.join(expected_headers)}. Please check your CSV file and try again.", 'error')
                conn.close()
                return redirect(url_for('upload'))

            # Clean and validate the DataFrame
            for header in expected_headers:
                df[header] = df[header].fillna('')

            # Ensure risk_score is numeric; set to 0 if invalid
            df['risk_score'] = pd.to_numeric(df['risk_score'], errors='coerce').fillna(0).astype(int)

            # Add scan_date and status columns if not present
            if 'scan_date' not in df.columns:
                df['scan_date'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            if 'status' not in df.columns:
                df['status'] = 'Open'

            # Insert application vulnerabilities into the database
            for _, row in df.iterrows():
                cursor.execute('''
                    INSERT INTO app_vulnerabilities (name, severity, description, risk_score, remediation, scan_date, url, cwe_id, status)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    row['name'],
                    row['severity'],
                    row['description'],
                    row['risk_score'],
                    row['remediation'],
                    row['scan_date'],
                    row['url'],
                    row['cwe_id'],
                    row['status']
                ))

            # Commit application vulnerabilities
            conn.commit()

            # Close the database connection
            conn.close()

            # Provide feedback to the user
            flash('CSV file processed successfully!', 'success')
            return redirect(url_for('index'))

        except Exception as e:
            flash(f"Error processing CSV file: {str(e)}", 'error')
            conn.close()
            return redirect(url_for('upload'))

    return render_template('upload.html')

# Index route with filtering
@app.route('/')
def index():
    # Get the severity filter from the query parameters (default to 'all')
    selected_severity = request.args.get('severity', 'all')

    # Connect to the database
    conn = sqlite3.connect('vulnerabilities.db')
    cursor = conn.cursor()

    # Fetch application vulnerabilities with severity filter
    if selected_severity == 'all':
        cursor.execute("SELECT * FROM app_vulnerabilities")
    else:
        cursor.execute("SELECT * FROM app_vulnerabilities WHERE severity = ?", (selected_severity,))
    app_vulnerabilities = cursor.fetchall()

    # Calculate deduplicated vulnerability count
    deduplicated_vuln_count = len(set(v[1] for v in app_vulnerabilities))

    # Dummy data for attack surface score
    attack_surface_score = 75
    attack_surface_factors = ["Critical vulnerabilities", "Outdated software"]

    conn.close()

    # Render the template with filtered data and selected severity
    return render_template('index.html',
                         app_vulnerabilities=app_vulnerabilities,
                         deduplicated_vuln_count=deduplicated_vuln_count,
                         attack_surface_score=attack_surface_score,
                         attack_surface_factors=attack_surface_factors,
                         selected_severity=selected_severity,
                         search_query='')

# Placeholder for the export_report route
@app.route('/export_report')
def export_report():
    # Placeholder logic
    flash('Export report functionality not implemented yet.', 'info')
    return redirect(url_for('index'))

# Placeholder for the remediation_history route
@app.route('/remediation_history')
def remediation_history():
    conn = sqlite3.connect('vulnerabilities.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM remediation_history")
    history = cursor.fetchall()
    conn.close()
    return render_template('remediation_history.html', history=history)

# Placeholder for summary and trend routes (for charts)
@app.route('/summary')
def summary():
    # Dummy data for severity chart
    return jsonify({
        'Critical': 5,
        'High': 10,
        'Medium': 15,
        'Low': 20,
        'Informational': 25
    })

@app.route('/trend')
def trend():
    # Dummy data for trend chart
    return jsonify({
        'dates': ['2025-04-01', '2025-04-15', '2025-04-30'],
        'counts': [50, 45, 40]
    })

# Placeholder for search route
@app.route('/search')
def search():
    query = request.args.get('q', '')
    conn = sqlite3.connect('vulnerabilities.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM app_vulnerabilities WHERE name LIKE ? OR description LIKE ?", (f'%{query}%', f'%{query}%'))
    app_vulnerabilities = cursor.fetchall()
    conn.close()
    return render_template('index.html', app_vulnerabilities=app_vulnerabilities, search_query=query)

# Placeholder for quick_fix and delete routes
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
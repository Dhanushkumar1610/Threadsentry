

# **ThreadSentry (MiniVulnManager)**

**ThreadSentry**, also known as **MiniVulnManager**, is a lightweight, open-source vulnerability management system designed for small to medium-sized development teams. It centralizes, analyzes, and tracks security findings from multiple tools, providing actionable insights through a clean and intuitive web interface.

ThreadSentry supports various formats (CSV, XML, JSON) and aggregates vulnerabilities from both SAST and DAST tools, making it an ideal solution for teams looking to introduce structured vulnerability management without the complexity of enterprise platforms.

---

## 🔑 Key Features

* **Multi-Tool Support**: Supports OWASP ZAP, Burp Suite, OWASP Dependency-Check, SonarQube, and Bandit.
* **Automated Parsing**: Normalizes and stores vulnerability data in a unified format.
* **Web Interface (Flask)**: Dashboard to view, filter, search, and manage vulnerabilities.
* **Remediation Tracking**: Logs actions like marking vulnerabilities as "Fixed" or "Deleted."
* **GitHub Integration**: Tracks remediation status via GitHub commit references.

---

## 🛡️ Supported Tools & Vulnerabilities

| Tool                       | Format(s) | Example Vulnerabilities                             |
| -------------------------- | --------- | --------------------------------------------------- |
| **OWASP ZAP**              | CSV       | XSS, SQLi, CSRF, IDOR                               |
| **Burp Suite**             | XML       | SSRF, Insecure Deserialization, SQLi                |
| **OWASP Dependency-Check** | XML, JSON | CVEs (e.g., Log4Shell), outdated dependencies       |
| **SonarQube**              | JSON      | Hardcoded Credentials, Insecure Cryptography        |
| **Bandit**                 | JSON      | Command Injection, eval usage, Insecure File Access |

---

## ⚙️ Installation

### **Prerequisites**

* Python 3.9+
* Git
* Web browser (Chrome, Firefox, etc.)

### **Setup Instructions**

1. **Clone the Repository**:

   ```bash
   git clone https://github.com/Dhanushkumar1610/Threadsentry.git
   cd Threadsentry
   ```

2. **Set Up Virtual Environment**:

   ```bash
   python -m venv venv
   source venv/bin/activate        # Windows: venv\Scripts\activate
   ```

3. **Install Dependencies**:

   ```bash
   pip install -r requirements.txt
   ```

   **`requirements.txt`**:

   ```
   flask==2.0.1
   pandas==1.3.0
   ```

4. **Initialize the Database**:

   * On first run, `vulnerabilities.db` is automatically created.
   * If schema issues occur (e.g., missing `source_tool` column), run:

     ```bash
     python add_source_tool_column.py
     ```

5. **Start the Application**:

   ```bash
   python app.py
   ```

   Open your browser at: [http://localhost:5000](http://localhost:5000)

---

## 🧭 Usage

### **1. Upload Reports**

* Go to [http://localhost:5000/upload](http://localhost:5000/upload)
* Upload supported files (`CSV`, `XML`, `JSON`)
* Reports will be parsed and stored in the database

### **2. View Dashboard**

* Visit [http://localhost:5000](http://localhost:5000)
* Filter by severity or search by vulnerability name
* View detailed information: description, risk score, remediation, source tool, etc.

### **3. Track Remediation**

* From the dashboard, mark vulnerabilities as **Fixed** or **Deleted**
* Visit the [Remediation History](http://localhost:5000/remediation_history) to track changes

---

## 🧪 Sample Files

Test the application using provided reports:

* `owasp_zap_sample.csv`
* `burp_suite_sample.xml`
* `dependency_check_sample.xml`
* `dependency_check_sample.json`
* `sonarqube_sample.json`
* `bandit_sample.json`

---

## 🧱 Technical Architecture

### **Stack**

* **Framework**: Flask
* **Database**: SQLite
* **Data Processing**: Pandas
* **Frontend**: HTML templates with Flask routing

### **Workflow**

1. **Upload** → File is received via `/upload`
2. **Parsing** → Detected tool determines parser (e.g., `parse_burp_xml`)
3. **Normalization** → `normalize_vuln_data()` ensures consistent schema
4. **Storage** → Stored in `app_vulnerabilities` table
5. **Visualization** → Displayed in `index.html` with filters/search
6. **Remediation Actions** → Stored in `remediation_history` table

---

## 🗃️ Database Schema

### **app\_vulnerabilities**

| Field        | Description                                   |
| ------------ | --------------------------------------------- |
| id           | Primary Key                                   |
| name         | Vulnerability name                            |
| severity     | Critical, High, Medium, Low                   |
| description  | Detailed vulnerability description            |
| risk\_score  | Normalized integer score (e.g., 70)           |
| remediation  | Suggested mitigation                          |
| scan\_date   | Date of report upload                         |
| url          | Affected URL or file path                     |
| cwe\_id      | Common Weakness Enumeration ID (e.g., CWE-79) |
| status       | `Open`, `Fixed`, `Deleted`                    |
| source\_tool | Source tool name (e.g., OWASP ZAP)            |

### **remediation\_history**

| Field      | Description               |
| ---------- | ------------------------- |
| id         | Primary Key               |
| vuln\_name | Name of the vulnerability |
| vuln\_type | Always "App"              |
| action     | `Fixed`, `Deleted`        |
| date       | Timestamp of the action   |

---

## 🔧 Example Code: `normalize_vuln_data`

```python
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
```

---

## 🚧 Limitations

### Technical:

* Single-user mode (no authentication or RBAC)
* Local-only; lacks cloud or multi-instance support
* SQLite not suitable for very large datasets or concurrent users
* Slower performance on large reports (>10,000 entries)

### Functional:

* Limited to CSV, XML, JSON formats
* No automated vulnerability scanning
* Basic remediation support (no AI suggestions)
* Limited third-party integrations

---

## 🚀 Future Enhancements

* ✅ **Additional Report Formats** (PDF, HTML)
* ✅ **AI-Based Remediation Suggestions**
* ✅ **Cloud Deployment** (e.g., AWS, Heroku)
* ✅ **Attack Surface Calculator** inspired by WAVER formula
  *(e.g., `External Interfaces × Code Complexity ÷ Authentication Strength`)*
* ✅ **ThreadFix and Security Platform Integration**

---

## 🤝 Contributing

We welcome contributions from the community!

1. Fork the repo
2. Create a new branch

   ```bash
   git checkout -b feature/your-feature
   ```
3. Commit and push changes

   ```bash
   git commit -m "Add your feature"
   git push origin feature/your-feature
   ```
4. Open a pull request describing your update

📌 **Note**: Follow style guidelines and include appropriate test coverage.

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).

---

## 🙏 Acknowledgments

* Research inspiration: *“Quantifying the Attack Surface of a Web Application”* (ResearchGate, 2010)
* Tools: OWASP ZAP, Burp Suite, SonarQube, Bandit, Flask, Pandas, SQLite
* Thanks to the cybersecurity and open-source community for continuous support

---

## 📬 Contact

**Dhanush Kumar N**
📧 [dhanushkumar1605@gmail.com](mailto:dhanushkumar1605@gmail.com)
🔗 GitHub: [ThreadSentry Repo](https://github.com/Dhanushkumar1610/Threadsentry)

---


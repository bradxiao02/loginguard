# LoginGuard

LoginGuard is a Python-based login attempt monitoring system designed to demonstrate authentication monitoring, failed-login detection, suspicious activity identification, and basic security reporting.

The system records login events in a SQLite database and analyzes authentication activity to identify patterns that may indicate brute-force attacks or account-targeting activity.

## Features

* Login attempt simulation
* Successful and failed authentication logging
* SQLite database storage
* Username and IP address tracking
* Detection of repeated failed login attempts
* Detection of multiple accounts targeted from one IP address
* Security alerts for suspicious authentication activity
* Recent login attempt viewer
* Security statistics and summary
* Timestamped security reports
* Simple command-line interface

## Detection Rules

LoginGuard currently monitors three main patterns:

### 1. Single-account brute force

An alert is generated when the same username and IP address record at least **5 failed attempts**.

### 2. High-volume activity from an IP

An alert is generated when an IP address records at least **10 failed login attempts**.

### 3. Multiple targeted accounts

An alert is generated when the same IP address records failed attempts against at least **3 different usernames**.

These thresholds are configurable in `login_monitor.py`.

## Technologies

* Python
* SQLite
* SQL
* Command-line interface

## Project Structure

```text
loginguard/
│
├── login_monitor.py
├── requirements.txt
├── README.md
├── .gitignore
│
└── login_attempts.db
```

The SQLite database is generated automatically when the application is started.

## Installation

Clone the repository:

```bash
git clone https://github.com/YOUR_USERNAME/loginguard.git
```

Enter the project directory:

```bash
cd loginguard
```

Create a virtual environment if desired:

```bash
python -m venv venv
```

Activate it on Windows:

```powershell
venv\Scripts\activate
```

There are no external Python dependencies for the current version.

## Running LoginGuard

Start the application:

```bash
python login_monitor.py
```

The application displays the following menu:

```text
1. Attempt Login
2. View Recent Attempts
3. View Security Summary
4. Generate Security Report
5. Exit
```

## Demonstration Credentials

The application uses demonstration credentials:

```text
Username: admin
Password: Admin@123
```

These credentials are included only for local demonstration purposes.

## Example Brute-Force Test

Use:

```text
Username: admin
Password: wrong
IP Address: 192.168.1.50
```

Repeat the failed login five times.

LoginGuard will identify the repeated failures and display a security alert.

Example:

```text
SECURITY ALERT
- Possible brute-force attack against a single account.

Username failures : 5
IP failures       : 5
Accounts targeted : 1
```

## Multiple Account Detection

Use the same IP address with different usernames:

```text
admin1
admin2
admin3
admin4
```

with incorrect passwords.

LoginGuard can identify activity involving multiple accounts from the same IP address.

## Database

Login attempts are stored in:

```text
login_attempts.db
```

The database contains the following fields:

| Field      | Description                            |
| ---------- | -------------------------------------- |
| id         | Unique login attempt identifier        |
| username   | Username used during authentication    |
| ip_address | IP address associated with the attempt |
| status     | SUCCESS or FAILED                      |
| reason     | Reason for the authentication result   |
| timestamp  | Time the event was recorded            |

## Security Reports

Selecting option `4` generates a timestamped report:

```text
login_security_report_YYYYMMDD_HHMMSS.txt
```

The report contains:

* Report generation time
* Total login attempts
* Successful attempts
* Failed attempts
* Security assessment

Generated reports are excluded from GitHub using `.gitignore`.

## Security Considerations

LoginGuard is an educational security monitoring project.

It demonstrates concepts such as:

* Authentication monitoring
* Event logging
* Brute-force detection
* IP-based monitoring
* Security alerting
* Digital security reporting

The project should not be used as a replacement for a production authentication or security monitoring system.

The demonstration password is intentionally hard-coded and should never be used in a real application.

## Limitations

The current detection system uses cumulative historical login failures stored in the database.

It does not currently implement:

* Rolling time windows
* Account lockout
* CAPTCHA
* Multi-factor authentication
* Real-time network monitoring
* Centralized logging
* SIEM integration
* Automatic IP blocking
* Email or SMS alerts

## Future Improvements

Potential improvements include:

* Time-based brute-force detection
* Configurable detection thresholds
* Web dashboard
* Real-time monitoring
* Email security alerts
* Multi-factor authentication integration
* Geographic IP analysis
* Log export to JSON or CSV
* SIEM integration
* Risk scoring
* Automated incident-response workflows

## Learning Objectives

This project demonstrates practical understanding of:

* Python programming
* SQLite database management
* Authentication logging
* Security event analysis
* Brute-force detection
* IP-based security monitoring
* Security reporting
* Basic incident detection concepts

## License

This project is intended for educational and portfolio purposes.

## Author

Bradley Kimutai Kemboi Antipas

BSc Computer Security and Forensics
Kabarak University

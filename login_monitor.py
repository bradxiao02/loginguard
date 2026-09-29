import sqlite3
from datetime import datetime


DATABASE = "login_attempts.db"

MAX_FAILED_ATTEMPTS = 5
MAX_IP_FAILURES = 10
MAX_TARGETED_ACCOUNTS = 3


def initialize_database():
    connection = sqlite3.connect(DATABASE)
    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS login_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            ip_address TEXT NOT NULL,
            status TEXT NOT NULL,
            reason TEXT,
            timestamp TEXT NOT NULL
        )
    """)

    connection.commit()
    connection.close()


def record_attempt(username, ip_address, status, reason):
    connection = sqlite3.connect(DATABASE)
    cursor = connection.cursor()

    timestamp = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    cursor.execute("""
        INSERT INTO login_attempts
        (username, ip_address, status, reason, timestamp)
        VALUES (?, ?, ?, ?, ?)
    """, (
        username,
        ip_address,
        status,
        reason,
        timestamp
    ))

    connection.commit()
    connection.close()


def count_failed_for_user(username, ip_address):
    connection = sqlite3.connect(DATABASE)
    cursor = connection.cursor()

    cursor.execute("""
        SELECT COUNT(*)
        FROM login_attempts
        WHERE username = ?
        AND ip_address = ?
        AND status = 'FAILED'
    """, (username, ip_address))

    result = cursor.fetchone()[0]

    connection.close()

    return result


def count_failed_for_ip(ip_address):
    connection = sqlite3.connect(DATABASE)
    cursor = connection.cursor()

    cursor.execute("""
        SELECT COUNT(*)
        FROM login_attempts
        WHERE ip_address = ?
        AND status = 'FAILED'
    """, (ip_address,))

    result = cursor.fetchone()[0]

    connection.close()

    return result


def count_targeted_accounts(ip_address):
    connection = sqlite3.connect(DATABASE)
    cursor = connection.cursor()

    cursor.execute("""
        SELECT COUNT(DISTINCT username)
        FROM login_attempts
        WHERE ip_address = ?
        AND status = 'FAILED'
    """, (ip_address,))

    result = cursor.fetchone()[0]

    connection.close()

    return result


def analyze_activity(username, ip_address):

    user_failures = count_failed_for_user(
        username,
        ip_address
    )

    ip_failures = count_failed_for_ip(
        ip_address
    )

    targeted_accounts = count_targeted_accounts(
        ip_address
    )

    alerts = []

    if user_failures >= MAX_FAILED_ATTEMPTS:
        alerts.append(
            "Possible brute-force attack against a single account."
        )

    if ip_failures >= MAX_IP_FAILURES:
        alerts.append(
            "High number of failed attempts from the same IP address."
        )

    if targeted_accounts >= MAX_TARGETED_ACCOUNTS:
        alerts.append(
            "Multiple user accounts are being targeted from the same IP."
        )

    if alerts:

        print("\n" + "=" * 70)
        print("SECURITY ALERT")
        print("=" * 70)

        for alert in alerts:
            print(f"- {alert}")

        print(f"\nUsername failures : {user_failures}")
        print(f"IP failures       : {ip_failures}")
        print(f"Accounts targeted : {targeted_accounts}")

        print("=" * 70)

        return True

    return False


def login(username, password, ip_address):

    valid_username = "admin"
    valid_password = "Admin@123"

    if username == valid_username and password == valid_password:

        record_attempt(
            username,
            ip_address,
            "SUCCESS",
            "Valid credentials"
        )

        print("\nLOGIN SUCCESSFUL")
        print(f"User: {username}")

        return True

    record_attempt(
        username,
        ip_address,
        "FAILED",
        "Invalid credentials"
    )

    print("\nLOGIN FAILED")
    print("Invalid username or password.")

    analyze_activity(
        username,
        ip_address
    )

    return False


def display_recent_attempts():

    connection = sqlite3.connect(DATABASE)
    cursor = connection.cursor()

    cursor.execute("""
        SELECT id, username, ip_address,
               status, reason, timestamp
        FROM login_attempts
        ORDER BY id DESC
        LIMIT 15
    """)

    attempts = cursor.fetchall()

    connection.close()

    print("\n" + "=" * 80)
    print("RECENT LOGIN ATTEMPTS")
    print("=" * 80)

    if not attempts:
        print("No login attempts recorded.")
        return

    for attempt in attempts:

        print(f"""
ID          : {attempt[0]}
Username    : {attempt[1]}
IP Address  : {attempt[2]}
Status      : {attempt[3]}
Reason      : {attempt[4]}
Timestamp   : {attempt[5]}
""")

        print("-" * 80)


def display_security_summary():

    connection = sqlite3.connect(DATABASE)
    cursor = connection.cursor()

    cursor.execute("""
        SELECT COUNT(*)
        FROM login_attempts
    """)

    total = cursor.fetchone()[0]

    cursor.execute("""
        SELECT COUNT(*)
        FROM login_attempts
        WHERE status = 'SUCCESS'
    """)

    successful = cursor.fetchone()[0]

    cursor.execute("""
        SELECT COUNT(*)
        FROM login_attempts
        WHERE status = 'FAILED'
    """)

    failed = cursor.fetchone()[0]

    cursor.execute("""
        SELECT ip_address, COUNT(*) AS failures
        FROM login_attempts
        WHERE status = 'FAILED'
        GROUP BY ip_address
        ORDER BY failures DESC
        LIMIT 5
    """)

    suspicious_ips = cursor.fetchall()

    connection.close()

    print("\n" + "=" * 70)
    print("LOGIN SECURITY SUMMARY")
    print("=" * 70)

    print(f"Total Attempts : {total}")
    print(f"Successful     : {successful}")
    print(f"Failed         : {failed}")

    if failed >= MAX_FAILED_ATTEMPTS:
        print("\nOverall Status : SUSPICIOUS ACTIVITY DETECTED")
    else:
        print("\nOverall Status : NO BRUTE-FORCE ALERT")

    print("\nTOP FAILED-ATTEMPT IPs")
    print("-" * 70)

    if suspicious_ips:

        for ip, failures in suspicious_ips:
            print(
                f"{ip:<20} {failures} failed attempts"
            )

    else:
        print("No failed attempts recorded.")

    print("=" * 70)


def generate_security_report():

    connection = sqlite3.connect(DATABASE)
    cursor = connection.cursor()

    cursor.execute("""
        SELECT COUNT(*)
        FROM login_attempts
    """)

    total = cursor.fetchone()[0]

    cursor.execute("""
        SELECT COUNT(*)
        FROM login_attempts
        WHERE status = 'SUCCESS'
    """)

    successful = cursor.fetchone()[0]

    cursor.execute("""
        SELECT COUNT(*)
        FROM login_attempts
        WHERE status = 'FAILED'
    """)

    failed = cursor.fetchone()[0]

    timestamp = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    report = []

    report.append("=" * 70)
    report.append("LOGIN GUARD SECURITY REPORT")
    report.append("=" * 70)

    report.append("")
    report.append(f"Report Generated : {timestamp}")

    report.append("")
    report.append("LOGIN STATISTICS")
    report.append("-" * 70)

    report.append(f"Total Attempts : {total}")
    report.append(f"Successful     : {successful}")
    report.append(f"Failed         : {failed}")

    report.append("")
    report.append("SECURITY ASSESSMENT")
    report.append("-" * 70)

    if failed >= MAX_FAILED_ATTEMPTS:

        report.append(
            "Status: SUSPICIOUS ACTIVITY DETECTED"
        )

        report.append(
            "Repeated failed authentication attempts "
            "require investigation."
        )

    else:

        report.append(
            "Status: NO BRUTE-FORCE ALERT"
        )

    report.append("")
    report.append("=" * 70)

    filename = (
        "login_security_report_"
        + datetime.now().strftime("%Y%m%d_%H%M%S")
        + ".txt"
    )

    with open(
        filename,
        "w",
        encoding="utf-8"
    ) as file:

        file.write(
            "\n".join(report)
        )

    print(
        f"\nSecurity report saved as: {filename}"
    )


def main():

    initialize_database()

    while True:

        print("\n" + "=" * 60)
        print("LOGIN GUARD")
        print("Login Attempt Monitoring System")
        print("=" * 60)

        print("""
1. Attempt Login
2. View Recent Attempts
3. View Security Summary
4. Generate Security Report
5. Exit
""")

        choice = input(
            "Select an option: "
        ).strip()

        if choice == "1":

            username = input(
                "\nUsername: "
            ).strip()

            password = input(
                "Password: "
            ).strip()

            ip_address = input(
                "IP Address: "
            ).strip()

            login(
                username,
                password,
                ip_address
            )

        elif choice == "2":

            display_recent_attempts()

        elif choice == "3":

            display_security_summary()

        elif choice == "4":

            generate_security_report()

        elif choice == "5":

            print("\nExiting LoginGuard.")
            break

        else:

            print("\nInvalid option.")


if __name__ == "__main__":
    main()
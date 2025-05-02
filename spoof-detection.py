import re
import requests 
import hashlib
from email.parser import BytesParser 
from email.policy import default 
import logging
import time
from typing import Optional
import os
from datetime import datetime
import config

# Set up logging
logging.basicConfig(
    level=getattr(logging, config.LOG_LEVEL),
    format=config.LOG_FORMAT
)

# VirusTotal API rate limiting
VIRUSTOTAL_RATE_LIMIT = 4  # requests per minute
last_vt_request_time = 0

def wait_for_rate_limit():
    """Implement rate limiting for VirusTotal API"""
    global last_vt_request_time
    current_time = time.time()
    time_since_last_request = current_time - last_vt_request_time
    if time_since_last_request < (60 / VIRUSTOTAL_RATE_LIMIT):
        time.sleep((60 / VIRUSTOTAL_RATE_LIMIT) - time_since_last_request)
    last_vt_request_time = time.time()

def is_suspicious_attachment(filename: str) -> bool:
    """Check if attachment filename has suspicious extension"""
    if not filename:
        return False
    return any(filename.lower().endswith(ext) for ext in config.SUSPICIOUS_EXTENSIONS)

def check_email_headers(email):
    results = {
        'spf': False,
        'dmarc': False,
        'dkim': False,
        'details': []
    }
    
    # Get the headers for SPF, DMARC, and DKIM
    spf = email.get('Received-SPF', 'None').lower()
    dmarc = email.get('Authentication-Results', 'None').lower()
    dkim = email.get('DKIM-Signature', 'None').lower()

    # Check SPF result
    if "pass" in spf:
        results['spf'] = True
        results['details'].append("SPF Check: Passed")
    elif "fail" in spf:
        results['details'].append("SPF Check: Failed (Possible Spoofing)")
    else:
        results['details'].append("SPF Check: Missing (Suspicious)")

    # Check DMARC result
    if "dmarc=pass" in dmarc:
        results['dmarc'] = True
        results['details'].append("DMARC Check: Passed")
    elif "dmarc=fail" in dmarc:
        results['details'].append("DMARC Check: Failed (Possible Spoofing)")
    else:
        results['details'].append("DMARC Check: Missing (Suspicious)")

    # Check DKIM result
    if "dkim=pass" in dmarc:
        results['dkim'] = True
        results['details'].append("DKIM Check: Passed")
    elif "dkim=fail" in dmarc:
        results['details'].append("DKIM Check: Failed (Possible Spoofing)")
    elif "dkim-signature" in dkim:
        results['dkim'] = True
        results['details'].append("DKIM Check: Signature Present (Likely Passed)")
    else:
        results['details'].append("DKIM Check: Missing (Suspicious)")

    for detail in results['details']:
        logging.info(detail)

    if not all([results['spf'], results['dmarc'], results['dkim']]):
        logging.warning("Warning: This email might be fake (spoofed)!")
        return "Warning"
    return "Safe"

def check_from_return_path(email):
    # Get From and Return-Path headers
    from_header = email.get('From', '').lower()
    return_path_header = email.get('Return-Path', email.get('Reply-to', '')).lower()

    # Extract email addresses
    from_email = re.search(r'[\w\.-]+@([\w\.-]+\.\w+)', from_header)
    return_path_email = re.search(r'[\w\.-]+@([\w\.-]+\.\w+)', return_path_header)

    # Compare domains (not just full email addresses)
    if from_email and return_path_email:
        from_domain = from_email.group(1)
        return_path_domain = return_path_email.group(1)
        if from_domain == return_path_domain:
            logging.info("From and Return-Path domains match: Looks good.")
            return "Safe"
        else:
            logging.warning("From and Return-Path domains don’t match: This might be a fake email!")
            return "Warning"
    else:
        logging.warning("Couldn’t find From or Return-Path email: This is suspicious!")
        return "Warning"

def check_received_headers(email):
    # Get all Received headers
    received_headers = email.get_all('Received', [])
    if not received_headers:
        logging.warning("No Received headers found: This is suspicious!")
        return "Warning"

    # Check for suspicious patterns in the email path
    server_count = len(received_headers)
    logging.info(f"Email Path: Went through {server_count} servers.")
    
    # Look for unknown or mismatched domains
    suspicious = False
    from_domain = re.search(r'@([\w\.-]+\.\w+)', email.get('From', ''))
    from_domain = from_domain.group(1).lower() if from_domain else ""

    # Check timestamps for inconsistencies
    timestamps = []
    for header in received_headers:
        header = header.lower()
        # Look for suspicious words
        if "unknown" in header or "localhost" in header:
            suspicious = True
            logging.warning("Suspicious server in email path: Found 'unknown' or 'localhost'.")
        # Check if From domain appears in the path
        if from_domain and from_domain not in header:
            logging.info(f"From domain ({from_domain}) not found in this server. Checking further...")
        # Extract timestamp
        timestamp_match = re.search(r'\d{1,2}\s[a-z]{3}\s\d{4}\s\d{2}:\d{2}:\d{2}', header)
        if timestamp_match:
            try:
                timestamp = datetime.strptime(timestamp_match.group(), '%d %b %Y %H:%M:%S')
                timestamps.append(timestamp)
            except ValueError:
                logging.warning("Invalid timestamp in Received header: This is suspicious!")
                suspicious = True

    # Check if timestamps are in logical order (newest to oldest)
    if timestamps:
        for i in range(len(timestamps) - 1):
            if timestamps[i] < timestamps[i + 1]:
                suspicious = True
                logging.warning("Timestamps in Received headers are out of order: This might be fake!")

    if suspicious:
        logging.warning("Email path looks suspicious: Might be fake!")
        return "Warning"
    return "Safe"

def check_message_id(email):
    # Get Message-ID header
    message_id = email.get('Message-ID', '').lower()
    if not message_id:
        logging.warning("No Message-ID found: This is suspicious!")
        return "Warning"

    # Extract domain from Message-ID
    message_id_domain = re.search(r'@([\w\.-]+\.\w+)', message_id)
    from_domain = re.search(r'@([\w\.-]+\.\w+)', email.get('From', ''))

    if message_id_domain and from_domain:
        message_id_domain = message_id_domain.group(1)
        from_domain = from_domain.group(1)
        if message_id_domain == from_domain:
            logging.info("Message-ID domain matches From domain: Looks good.")
            return "Safe"
        else:
            logging.warning("Message-ID domain doesn’t match From domain: This might be fake!")
            return "Warning"
    else:
        logging.warning("Couldn’t find domain in Message-ID or From: This is suspicious!")
        return "Warning"

def extract_urls(body):
    url_regex = r'https?://\S+'
    urls = re.findall(url_regex, body)
    if urls:
        logging.info(f"Found URLs: {urls}")
    return urls

def scan_url_with_virustotal(url):
    wait_for_rate_limit()
    params = {'apikey': config.VIRUSTOTAL_API_KEY, 'resource': url}
    try:
        response = requests.get(config.VIRUSTOTAL_URL_REPORT_ENDPOINT, params=params)
        response.raise_for_status()
        result = response.json()
        logging.info(f"Checking URL: {url}")
        if result.get('positives', 0) >= config.URL_SCAN_THRESHOLD:
            logging.warning(f"URL is Dangerous: {result.get('positives')} detections!")
            return "Dangerous"
        else:
            logging.info("URL is Safe: No issues found.")
            return "Safe"
    except requests.RequestException as e:
        logging.warning(f"Couldn’t check URL: {str(e)}")
        return "Warning"

def extract_attachments(email):
    attachments = []
    for part in email.walk():
        content_disposition = part.get("Content-Disposition", "")
        if "attachment" in content_disposition:
            file_name = part.get_filename()
            
            # Check for suspicious extensions
            if is_suspicious_attachment(file_name):
                logging.warning(f"Suspicious attachment type detected: {file_name}")
                attachments.append((file_name, None, "Suspicious"))
                continue
                
            payload = part.get_payload(decode=True)
            if isinstance(payload, bytes):
                # Check file size
                if len(payload) > config.MAX_ATTACHMENT_SIZE:
                    logging.warning(f"Attachment too large: {file_name}")
                    attachments.append((file_name, None, "Too Large"))
                    continue
                    
                file_hash = hashlib.sha256(payload).hexdigest()
                attachments.append((file_name, file_hash, "Normal"))
                logging.info(f"Found Attachment: {file_name}")
            else:
                logging.warning(f"Attachment {file_name}: Can’t check this format.")
    return attachments

def scan_attachment_with_virustotal(file_hash):
    if not file_hash:
        return "Warning"
        
    wait_for_rate_limit()
    params = {'apikey': config.VIRUSTOTAL_API_KEY, 'resource': file_hash}
    try:
        response = requests.get(config.VIRUSTOTAL_FILE_REPORT_ENDPOINT, params=params)
        response.raise_for_status()
        result = response.json()
        logging.info(f"Checking Attachment (Hash: {file_hash})")
        if result.get('positives', 0) >= config.ATTACHMENT_SCAN_THRESHOLD:
            logging.warning(f"Attachment is Dangerous: {result.get('positives')} detections!")
            return "Dangerous"
        else:
            logging.info("Attachment is Safe: No issues found.")
            return "Safe"
    except requests.RequestException as e:
        logging.warning(f"Couldn’t check attachment: {str(e)}")
        return "Warning"

def calculate_risk_score(results):
    """Calculate a risk score based on the analysis results"""
    score = 0
    if results.get('Authentication Headers') == "Warning":
        score += 40  # High risk for failed authentication
    if results.get('Sender Verification') == "Warning":
        score += 30  # Medium risk for From/Return-Path mismatch
    if results.get('Email Path') == "Warning":
        score += 20  # Medium risk for suspicious path
    if results.get('Message-ID Check') == "Warning":
        score += 20  # Medium risk for Message-ID mismatch
    if results.get('URL Analysis') == "Dangerous":
        score += 30  # High risk for dangerous URLs
    elif results.get('URL Analysis') == "Warning":
        score += 10  # Low risk for URL scan issues
    if results.get('Attachment Analysis') == "Dangerous":
        score += 30  # High risk for dangerous attachments
    elif results.get('Attachment Analysis') == "Warning":
        score += 10  # Low risk for suspicious attachments
    return min(score, 100)  # Cap at 100

def generate_report(results, email):
    """Generate a detailed analysis report with risk score and recommendations"""
    report = []
    report.append("Email Safety Report")
    report.append(f"Generated at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    report.append("\nEmail Details:")
    report.append(f"From: {email.get('From', 'Unknown')}")
    report.append(f"Subject: {email.get('Subject', 'No Subject')}")
    report.append(f"Date: {email.get('Date', 'Unknown')}")
    
    report.append("\nSecurity Check Results:")
    for check, result in results.items():
        report.append(f"{check}: {result}")
    
    # Calculate and add risk score
    risk_score = calculate_risk_score(results)
    report.append(f"\nRisk Score: {risk_score}/100")
    if risk_score >= 70:
        report.append("Risk Level: High (Likely Dangerous)")
    elif risk_score >= 30:
        report.append("Risk Level: Medium (Potentially Unsafe)")
    else:
        report.append("Risk Level: Low (Likely Safe)")

    # Add recommendations
    report.append("\nWhat to Do:")
    if risk_score >= 70:
        report.append("- Do NOT click any links or open attachments!")
        report.append("- Report this email to your email provider.")
        report.append("- Delete this email immediately.")
    elif risk_score >= 30:
        report.append("- Be careful with this email.")
        report.append("- Don’t click links or open attachments unless you trust the sender.")
        report.append("- Contact the sender to confirm they sent this email.")
    else:
        report.append("- This email looks safe to use.")
        report.append("- You can open links and attachments if you trust the sender.")
    
    return "\n".join(report)

def main():
    print("Welcome to the Enhanced Email Safety Checker!")
    print("This tool will check if your email is safe or might be fake (spoofed).")
    
    # Get the email file from the user
    email_input = input("Please enter the file path of your email (like email.txt): ")
    try:
        with open(email_input, 'rb') as f:
            email = BytesParser(policy=default).parse(f)

        results = {}
        
        print("\n--- Checking Email Headers (SPF, DKIM, DMARC) ---")
        results['Authentication Headers'] = check_email_headers(email)

        print("\n--- Checking Sender (From and Return-Path) ---")
        results['Sender Verification'] = check_from_return_path(email)

        print("\n--- Checking Email Path (Received Headers) ---")
        results['Email Path'] = check_received_headers(email)

        print("\n--- Checking Message-ID ---")
        results['Message-ID Check'] = check_message_id(email)

        print("\n--- Checking URLs in the Email ---")
        body = email.get_body(preferencelist=('plain', 'html')).get_content()
        if isinstance(body, bytes):
            body = body.decode('utf-8', errors='ignore')
        urls = extract_urls(body)
        results['URL Analysis'] = "Safe"
        if urls:
            for url in urls:
                result = scan_url_with_virustotal(url)
                if result == "Dangerous":
                    results['URL Analysis'] = "Dangerous"
                    break
                elif result == "Warning" and results['URL Analysis'] != "Dangerous":
                    results['URL Analysis'] = "Warning"
        else:
            logging.info("No URLs found to scan.")

        print("\n--- Checking Attachments ---")
        attachments = extract_attachments(email)
        results['Attachment Analysis'] = "Safe"
        if attachments:
            for filename, file_hash, status in attachments:
                if status == "Suspicious":
                    results['Attachment Analysis'] = "Warning"
                    continue
                elif status == "Too Large":
                    continue
                    
                result = scan_attachment_with_virustotal(file_hash)
                if result == "Dangerous":
                    results['Attachment Analysis'] = "Dangerous"
                    break
                elif result == "Warning" and results['Attachment Analysis'] != "Dangerous":
                    results['Attachment Analysis'] = "Warning"
        else:
            logging.info("No attachments found to scan.")

        # Generate and save detailed report
        report = generate_report(results, email)
        report_filename = f"email_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        with open(report_filename, 'w') as f:
            f.write(report)
        print(f"\nDetailed report saved to: {report_filename}")

        # Final summary for the user
        print("\n--- Final Result ---")
        risk_score = calculate_risk_score(results)
        if risk_score >= 70:
            print("🚨 This email is DANGEROUS! It might be fake or harmful.")
            print("Review the detailed report for more information.")
        elif risk_score >= 30:
            print("⚠️ This email might be UNSAFE! Be careful.")
            print("Check the detailed report for specific concerns.")
        else:
            print("✅ This email looks SAFE! No significant issues found.")
            print("See the detailed report for full analysis.")

    except FileNotFoundError:
        print("❌ Error: I couldn’t find the email file. Please check the file path.")
    except Exception as e:
        print(f"❌ Error: Something went wrong ({e}). Please try again.")

if __name__ == "__main__":
    main()
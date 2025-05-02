"""Configuration settings for the email spoof detection system"""

# VirusTotal API Configuration
VIRUSTOTAL_API_KEY = 'Your_API'
VIRUSTOTAL_URL_REPORT_ENDPOINT = 'https://www.virustotal.com/vtapi/v2/url/report'
VIRUSTOTAL_FILE_REPORT_ENDPOINT = 'https://www.virustotal.com/vtapi/v2/file/report'

# Email Analysis Settings
SUSPICIOUS_KEYWORDS = [
    'unknown',
    'localhost',
    'suspicious',
    'spam',
    'phishing'
]

# Attachment Settings
SUSPICIOUS_EXTENSIONS = [
    '.exe', '.bat', '.cmd', '.scr', '.js',
    '.vbs', '.wsf', '.ps1', '.msi', '.jar'
]

MAX_ATTACHMENT_SIZE = 32 * 1024 * 1024  # 32MB

# Logging Configuration
LOG_FORMAT = '%(asctime)s - %(levelname)s - %(message)s'
LOG_LEVEL = 'INFO'

# Security Thresholds
MIN_SERVERS_IN_PATH = 2
MAX_SERVERS_IN_PATH = 15  # Suspicious if more than this
URL_SCAN_THRESHOLD = 2  # Number of positive detections to mark as dangerous
ATTACHMENT_SCAN_THRESHOLD = 3  # Number of positive detections to mark as dangerous

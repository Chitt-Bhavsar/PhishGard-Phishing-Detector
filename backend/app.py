from flask import Flask, request, jsonify
from flask_cors import CORS
import sqlite3
import os
import json
import time
import requests
import ssl
import socket
import whois
import re
import urllib.parse
import hashlib
from datetime import datetime, timedelta
from bs4 import BeautifulSoup
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
import joblib
import numpy as np
from flask_socketio import SocketIO
import threading
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)
CORS(app)  # Enable CORS for all routes
socketio = SocketIO(app, cors_allowed_origins="*")

# API Keys (in a production environment, these would be stored securely)
GOOGLE_SAFE_BROWSING_API_KEY = os.environ.get('GOOGLE_SAFE_BROWSING_API_KEY', 'your_google_api_key')
VIRUSTOTAL_API_KEY = os.environ.get('VIRUSTOTAL_API_KEY', 'your_virustotal_api_key')
PHISHTANK_API_KEY = os.environ.get('PHISHTANK_API_KEY', 'your_phishtank_api_key')

# Database setup
DB_PATH = os.path.join(os.path.dirname(__file__), 'phishing_detector.db')

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Create tables if they don't exist
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS url_scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        url TEXT NOT NULL,
        is_phishing BOOLEAN NOT NULL,
        confidence_score FLOAT NOT NULL,
        analysis_details TEXT NOT NULL,
        threat_intel_results TEXT,
        whois_data TEXT,
        ssl_info TEXT,
        content_analysis TEXT,
        scan_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')
    
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        url TEXT NOT NULL,
        risk_level TEXT NOT NULL,
        message TEXT NOT NULL,
        is_read BOOLEAN DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')
    
    conn.commit()
    conn.close()

# Initialize database on startup
init_db()

# Threat Intelligence APIs
def check_google_safe_browsing(url):
    """Check if URL is in Google Safe Browsing database."""
    try:
        api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_SAFE_BROWSING_API_KEY}"
        payload = {
            "client": {
                "clientId": "phishguard",
                "clientVersion": "1.0.0"
            },
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }
        response = requests.post(api_url, json=payload)
        result = response.json()
        
        # If matches are found, the URL is unsafe
        if "matches" in result and len(result["matches"]) > 0:
            threat_type = result["matches"][0]["threatType"]
            return {
                "source": "Google Safe Browsing",
                "is_malicious": True,
                "threat_type": threat_type,
                "details": f"URL identified as {threat_type.lower().replace('_', ' ')}"
            }
        
        return {
            "source": "Google Safe Browsing",
            "is_malicious": False,
            "details": "URL not found in Google Safe Browsing database"
        }
    except Exception as e:
        logger.error(f"Error checking Google Safe Browsing: {str(e)}")
        return {
            "source": "Google Safe Browsing",
            "is_malicious": False,
            "error": str(e),
            "details": "Error checking Google Safe Browsing"
        }

def check_virustotal(url):
    """Check URL reputation on VirusTotal."""
    try:
        # First, get the URL ID by submitting the URL for scanning
        headers = {
            "x-apikey": VIRUSTOTAL_API_KEY
        }
        scan_params = {"url": url}
        scan_response = requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data=scan_params)
        
        if scan_response.status_code != 200:
            return {
                "source": "VirusTotal",
                "is_malicious": False,
                "details": "Error submitting URL to VirusTotal"
            }
        
        # Extract the URL ID from the response
        scan_result = scan_response.json()
        url_id = scan_result.get("data", {}).get("id", "")
        
        if not url_id:
            return {
                "source": "VirusTotal",
                "is_malicious": False,
                "details": "Could not get URL ID from VirusTotal"
            }
        
        # Wait a moment for analysis to complete
        time.sleep(3)
        
        # Now get the analysis results
        analysis_response = requests.get(f"https://www.virustotal.com/api/v3/analyses/{url_id}", headers=headers)
        
        if analysis_response.status_code != 200:
            return {
                "source": "VirusTotal",
                "is_malicious": False,
                "details": "Error getting analysis results from VirusTotal"
            }
        
        analysis_result = analysis_response.json()
        stats = analysis_result.get("data", {}).get("attributes", {}).get("stats", {})
        
        malicious_count = stats.get("malicious", 0)
        suspicious_count = stats.get("suspicious", 0)
        total_engines = sum(stats.values())
        
        is_malicious = (malicious_count + suspicious_count) > 0
        
        return {
            "source": "VirusTotal",
            "is_malicious": is_malicious,
            "malicious_count": malicious_count,
            "suspicious_count": suspicious_count,
            "total_engines": total_engines,
            "details": f"{malicious_count} out of {total_engines} security vendors flagged this URL as malicious"
        }
    except Exception as e:
        logger.error(f"Error checking VirusTotal: {str(e)}")
        return {
            "source": "VirusTotal",
            "is_malicious": False,
            "error": str(e),
            "details": "Error checking VirusTotal"
        }

def check_phishtank(url):
    """Check if URL is in PhishTank database."""
    try:
        api_url = "https://checkurl.phishtank.com/checkurl/"
        payload = {
            "url": url,
            "format": "json",
            "app_key": PHISHTANK_API_KEY
        }
        response = requests.post(api_url, data=payload)
        result = response.json()
        
        if "results" in result:
            is_phishing = result["results"]["in_database"] and result["results"]["valid"]
            
            if is_phishing:
                return {
                    "source": "PhishTank",
                    "is_malicious": True,
                    "phish_id": result["results"]["phish_id"],
                    "details": "URL found in PhishTank database as a confirmed phishing site"
                }
        
        return {
            "source": "PhishTank",
            "is_malicious": False,
            "details": "URL not found in PhishTank database"
        }
    except Exception as e:
        logger.error(f"Error checking PhishTank: {str(e)}")
        return {
            "source": "PhishTank",
            "is_malicious": False,
            "error": str(e),
            "details": "Error checking PhishTank"
        }

# Advanced URL Analysis
def get_whois_data(domain):
    """Get WHOIS information for a domain."""
    try:
        w = whois.whois(domain)
        
        # Extract relevant information
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        
        expiration_date = w.expiration_date
        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0]
        
        # Calculate domain age in days
        domain_age = None
        if creation_date:
            if isinstance(creation_date, str):
                creation_date = datetime.strptime(creation_date, "%Y-%m-%d")
            domain_age = (datetime.now() - creation_date).days
        
        return {
            "registrar": w.registrar,
            "creation_date": str(creation_date) if creation_date else None,
            "expiration_date": str(expiration_date) if expiration_date else None,
            "domain_age_days": domain_age,
            "is_new_domain": domain_age < 90 if domain_age else None,
            "registrant": w.name,
            "registrant_country": w.country
        }
    except Exception as e:
        logger.error(f"Error getting WHOIS data: {str(e)}")
        return {
            "error": str(e),
            "is_new_domain": None
        }

def check_ssl_certificate(url):
    """Check SSL certificate information."""
    try:
        parsed_url = urllib.parse.urlparse(url)
        hostname = parsed_url.netloc
        
        if not hostname:
            return {
                "has_ssl": False,
                "details": "Invalid hostname"
            }
        
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                
                # Extract certificate information
                issuer = dict(x[0] for x in cert['issuer'])
                subject = dict(x[0] for x in cert['subject'])
                not_after = cert['notAfter']
                not_before = cert['notBefore']
                
                # Parse dates
                not_after_date = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                not_before_date = datetime.strptime(not_before, "%b %d %H:%M:%S %Y %Z")
                
                # Calculate certificate age and validity period
                cert_age_days = (datetime.now() - not_before_date).days
                validity_period_days = (not_after_date - not_before_date).days
                
                return {
                    "has_ssl": True,
                    "issuer": issuer.get('organizationName', issuer.get('O', 'Unknown')),
                    "subject": subject.get('commonName', subject.get('CN', 'Unknown')),
                    "valid_from": str(not_before_date),
                    "valid_until": str(not_after_date),
                    "is_expired": datetime.now() > not_after_date,
                    "is_self_signed": issuer == subject,
                    "cert_age_days": cert_age_days,
                    "validity_period_days": validity_period_days,
                    "is_short_lived": validity_period_days < 90
                }
    except Exception as e:
        logger.error(f"Error checking SSL certificate: {str(e)}")
        return {
            "has_ssl": False,
            "error": str(e),
            "details": "Could not retrieve SSL certificate information"
        }

def analyze_webpage_content(url):
    """Analyze webpage content for phishing indicators."""
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        response = requests.get(url, headers=headers, timeout=10)
        
        if response.status_code != 200:
            return {
                "error": f"Failed to fetch webpage: HTTP {response.status_code}",
                "has_login_form": None,
                "has_suspicious_scripts": None
            }
        
        # Parse HTML content
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Check for login forms
        forms = soup.find_all('form')
        login_form = False
        password_inputs = 0
        
        for form in forms:
            inputs = form.find_all('input')
            for input_field in inputs:
                if input_field.get('type') == 'password':
                    login_form = True
                    password_inputs += 1
        
        # Check for suspicious scripts
        scripts = soup.find_all('script')
        suspicious_scripts = []
        
        for script in scripts:
            script_content = script.string if script.string else ""
            
            # Check for obfuscated JavaScript
            if script_content and (
                'eval(' in script_content or 
                'document.write(' in script_content or
                'escape(' in script_content or
                'unescape(' in script_content or
                'fromCharCode(' in script_content
            ):
                suspicious_scripts.append({
                    "type": "Obfuscated JavaScript",
                    "snippet": script_content[:100] + "..." if len(script_content) > 100 else script_content
                })
        
        # Check for external domains in resources
        external_resources = []
        resource_tags = soup.find_all(['img', 'script', 'link', 'iframe'])
        
        parsed_url = urllib.parse.urlparse(url)
        base_domain = parsed_url.netloc
        
        for tag in resource_tags:
            src = tag.get('src') or tag.get('href')
            if src and src.startswith('http'):
                resource_domain = urllib.parse.urlparse(src).netloc
                if resource_domain and resource_domain != base_domain:
                    external_resources.append(resource_domain)
        
        # Check for brand names in content
        common_brands = ['paypal', 'apple', 'microsoft', 'amazon', 'google', 'facebook', 'netflix', 'bank', 'chase', 'wellsfargo', 'citibank']
        brand_mentions = []
        
        for brand in common_brands:
            if brand in response.text.lower():
                brand_mentions.append(brand)
        
        # Check for security-related keywords
        security_keywords = ['verify', 'secure', 'confirm', 'update', 'login', 'sign in', 'password', 'credit card', 'account']
        security_keyword_count = 0
        
        for keyword in security_keywords:
            if keyword in response.text.lower():
                security_keyword_count += 1
        
        return {
            "has_login_form": login_form,
            "password_input_count": password_inputs,
            "has_suspicious_scripts": len(suspicious_scripts) > 0,
            "suspicious_scripts": suspicious_scripts,
            "external_resource_count": len(set(external_resources)),
            "external_resources": list(set(external_resources))[:5],  # Limit to 5 for brevity
            "brand_mentions": brand_mentions,
            "security_keyword_count": security_keyword_count,
            "page_title": soup.title.string if soup.title else "No title",
            "content_length": len(response.text)
        }
    except Exception as e:
        logger.error(f"Error analyzing webpage content: {str(e)}")
        return {
            "error": str(e),
            "has_login_form": None,
            "has_suspicious_scripts": None
        }

def extract_advanced_features(url, whois_data=None, ssl_info=None, content_analysis=None):
    """Extract advanced features from a URL for phishing detection."""
    features = {}
    
    # Parse URL
    parsed_url = urllib.parse.urlparse(url)
    
    # Basic URL features
    features['url_length'] = len(url)
    features['domain_length'] = len(parsed_url.netloc)
    features['path_length'] = len(parsed_url.path)
    features['query_length'] = len(parsed_url.query)
    features['fragment_length'] = len(parsed_url.fragment)
    
    # Domain-specific features
    features['dots_in_domain'] = parsed_url.netloc.count('.')
    features['hyphens_in_domain'] = parsed_url.netloc.count('-')
    features['underscores_in_domain'] = parsed_url.netloc.count('_')
    features['digits_in_domain'] = sum(c.isdigit() for c in parsed_url.netloc)
    features['has_ip'] = 1 if re.search(r'\d+\.\d+\.\d+\.\d+', parsed_url.netloc) else 0
    
    # TLD features
    domain_parts = parsed_url.netloc.split('.')
    features['tld'] = domain_parts[-1] if len(domain_parts) > 1 else ""
    features['tld_length'] = len(features['tld'])
    
    # Suspicious words in URL
    suspicious_words = ['secure', 'login', 'verify', 'account', 'update', 'confirm', 'password', 'bank', 'paypal', 'ebay', 'amazon']
    features['suspicious_words_count'] = sum(1 for word in suspicious_words if word in url.lower())
    
    # Protocol features
    features['is_https'] = 1 if parsed_url.scheme == 'https' else 0
    
    # Query parameter features
    query_params = urllib.parse.parse_qs(parsed_url.query)
    features['query_params_count'] = len(query_params)
    
    # Special character features
    special_chars = ['@', '!', '#', '$', '%', '^', '&', '*', '(', ')', '+', '=', '{', '}', '[', ']', '|', '\\', ':', ';', '"', "'", '<', '>', ',', '?']
    features['special_chars_count'] = sum(url.count(char) for char in special_chars)
    
    # WHOIS features
    if whois_data and 'is_new_domain' in whois_data:
        features['is_new_domain'] = 1 if whois_data['is_new_domain'] else 0
        features['domain_age_days'] = whois_data.get('domain_age_days', 0) or 0
    else:
        features['is_new_domain'] = 0
        features['domain_age_days'] = 0
    
    # SSL features
    if ssl_info and 'has_ssl' in ssl_info:
        features['has_ssl'] = 1 if ssl_info['has_ssl'] else 0
        features['is_self_signed'] = 1 if ssl_info.get('is_self_signed', False) else 0
        features['is_expired'] = 1 if ssl_info.get('is_expired', False) else 0
        features['is_short_lived'] = 1 if ssl_info.get('is_short_lived', False) else 0
    else:
        features['has_ssl'] = 0
        features['is_self_signed'] = 0
        features['is_expired'] = 0
        features['is_short_lived'] = 0
    
    # Content analysis features
    if content_analysis:
        features['has_login_form'] = 1 if content_analysis.get('has_login_form', False) else 0
        features['has_suspicious_scripts'] = 1 if content_analysis.get('has_suspicious_scripts', False) else 0
        features['external_resource_count'] = content_analysis.get('external_resource_count', 0)
        features['security_keyword_count'] = content_analysis.get('security_keyword_count', 0)
        features['password_input_count'] = content_analysis.get('password_input_count', 0)
    else:
        features['has_login_form'] = 0
        features['has_suspicious_scripts'] = 0
        features['external_resource_count'] = 0
        features['security_keyword_count'] = 0
        features['password_input_count'] = 0
    
    return features

def analyze_url_with_ml(features):
    """Analyze URL features using machine learning to determine if it's phishing."""
    # In a real application, we would load a trained model
    # For this demo, we'll use a rule-based approach with the advanced features
    
    risk_score = 0
    analysis_details = []
    
    # URL length (phishing URLs tend to be longer)
    if features['url_length'] > 75:
        risk_score += 0.1
        analysis_details.append({
            "description": "URL is unusually long",
            "risk_level": "low"
        })
    
    # Check for IP address in domain
    if features['has_ip'] == 1:
        risk_score += 0.3
        analysis_details.append({
            "description": "URL contains an IP address instead of a domain name",
            "risk_level": "high"
        })
    
    # Check for suspicious words
    if features['suspicious_words_count'] >= 2:
        risk_score += 0.2
        analysis_details.append({
            "description": "URL contains multiple suspicious keywords often used in phishing",
            "risk_level": "medium"
        })
    
    # Check for HTTPS
    if features['is_https'] == 0:
        risk_score += 0.15
        analysis_details.append({
            "description": "Connection is not secure (HTTP instead of HTTPS)",
            "risk_level": "medium"
        })
    
    # Check domain age
    if features['is_new_domain'] == 1:
        risk_score += 0.2
        analysis_details.append({
            "description": "Domain was registered recently (less than 90 days old)",
            "risk_level": "medium"
        })
    
    # Check SSL certificate
    if features['has_ssl'] == 0:
        risk_score += 0.1
        analysis_details.append({
            "description": "Website does not use SSL encryption",
            "risk_level": "medium"
        })
    elif features['is_self_signed'] == 1:
        risk_score += 0.2
        analysis_details.append({
            "description": "Website uses a self-signed SSL certificate",
            "risk_level": "high"
        })
    elif features['is_expired'] == 1:
        risk_score += 0.25
        analysis_details.append({
            "description": "Website's SSL certificate has expired",
            "risk_level": "high"
        })
    elif features['is_short_lived'] == 1:
        risk_score += 0.1
        analysis_details.append({
            "description": "Website's SSL certificate has an unusually short validity period",
            "risk_level": "medium"
        })
    
    # Check webpage content
    if features['has_login_form'] == 1:
        if features['is_https'] == 0:
            risk_score += 0.3
            analysis_details.append({
                "description": "Login form detected on an insecure (HTTP) connection",
                "risk_level": "high"
            })
    
    if features['has_suspicious_scripts'] == 1:
        risk_score += 0.25
        analysis_details.append({
            "description": "Webpage contains potentially obfuscated or suspicious JavaScript",
            "risk_level": "high"
        })
    
    if features['external_resource_count'] > 5:
        risk_score += 0.1
        analysis_details.append({
            "description": "Webpage loads resources from multiple external domains",
            "risk_level": "medium"
        })
    
    if features['security_keyword_count'] >= 3:
        risk_score += 0.1
        analysis_details.append({
            "description": "Webpage contains multiple security-related keywords",
            "risk_level": "low"
        })
    
    # If no risks were found, add a positive detail
    if not analysis_details:
        analysis_details.append({
            "description": "No suspicious patterns detected in URL or website content",
            "risk_level": "low"
        })
    
    # Calculate confidence score (0-100)
    confidence_score = min(int(risk_score * 100), 100)
    
    # Determine if URL is likely phishing
    is_phishing = confidence_score > 50
    
    return {
        "is_phishing": is_phishing,
        "confidence_score": confidence_score,
        "analysis_details": analysis_details
    }

def create_alert(url, risk_level, message):
    """Create an alert for a high-risk URL."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute(
        "INSERT INTO alerts (url, risk_level, message) VALUES (?, ?, ?)",
        (url, risk_level, message)
    )
    
    alert_id = cursor.lastrowid
    conn.commit()
    conn.close()
    
    # Emit alert via WebSocket
    alert_data = {
        "id": alert_id,
        "url": url,
        "risk_level": risk_level,
        "message": message,
        "created_at": datetime.now().isoformat()
    }
    
    socketio.emit('new_alert', alert_data)
    
    return alert_id

# API Routes
@app.route('/api/analyze', methods=['POST'])
def analyze_url():
    data = request.json
    url = data.get('url', '')
    
    if not url:
        return jsonify({"error": "URL is required"}), 400
    
    # Start a background thread for the analysis to avoid blocking
    thread = threading.Thread(target=process_url_analysis, args=(url,))
    thread.daemon = True
    thread.start()
    
    return jsonify({
        "message": "URL analysis started",
        "url": url,
        "status": "processing"
    })

def process_url_analysis(url):
    """Process URL analysis in background and emit results via WebSocket."""
    try:
        # Parse URL to get domain
        parsed_url = urllib.parse.urlparse(url)
        domain = parsed_url.netloc
        
        # Emit status update
        socketio.emit('analysis_update', {
            "url": url,
            "status": "checking_threat_intelligence",
            "message": "Checking threat intelligence databases..."
        })
        
        # Check threat intelligence APIs
        threat_intel_results = []
        
        # Google Safe Browsing
        gsb_result = check_google_safe_browsing(url)
        threat_intel_results.append(gsb_result)
        
        # VirusTotal
        vt_result = check_virustotal(url)
        threat_intel_results.append(vt_result)
        
        # PhishTank
        pt_result = check_phishtank(url)
        threat_intel_results.append(pt_result)
        
        # Emit status update
        socketio.emit('analysis_update', {
            "url": url,
            "status": "analyzing_domain",
            "message": "Analyzing domain information..."
        })
        
        # Get WHOIS data
        whois_data = get_whois_data(domain)
        
        # Check SSL certificate
        ssl_info = check_ssl_certificate(url)
        
        # Emit status update
        socketio.emit('analysis_update', {
            "url": url,
            "status": "analyzing_content",
            "message": "Analyzing webpage content..."
        })
        
        # Analyze webpage content
        content_analysis = analyze_webpage_content(url)
        
        # Extract features
        features = extract_advanced_features(url, whois_data, ssl_info, content_analysis)
        
        # Analyze features with ML
        analysis_result = analyze_url_with_ml(features)
        
        # Add URL and additional data to result
        analysis_result['url'] = url
        analysis_result['threat_intel_results'] = threat_intel_results
        analysis_result['whois_data'] = whois_data
        analysis_result['ssl_info'] = ssl_info
        analysis_result['content_analysis'] = content_analysis
        
        # Check if any threat intelligence source flagged the URL
        threat_intel_flagged = any(result.get('is_malicious', False) for result in threat_intel_results)
        
        # If threat intelligence flagged the URL, override the ML result
        if threat_intel_flagged and not analysis_result['is_phishing']:
            analysis_result['is_phishing'] = True
            analysis_result['confidence_score'] = max(analysis_result['confidence_score'], 85)
            analysis_result['analysis_details'].append({
                "description": "URL was flagged by one or more threat intelligence sources",
                "risk_level": "high"
            })
        
        # Save scan to database
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute(
            """INSERT INTO url_scans 
               (url, is_phishing, confidence_score, analysis_details, threat_intel_results, whois_data, ssl_info, content_analysis) 
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                url, 
                analysis_result['is_phishing'], 
                analysis_result['confidence_score'], 
                json.dumps(analysis_result['analysis_details']),
                json.dumps(threat_intel_results),
                json.dumps(whois_data),
                json.dumps(ssl_info),
                json.dumps(content_analysis)
            )
        )
        conn.commit()
        conn.close()
        
        # Create alert for high-risk URLs
        if analysis_result['is_phishing'] and analysis_result['confidence_score'] >= 75:
            alert_message = f"High-risk phishing URL detected with {analysis_result['confidence_score']}% confidence"
            create_alert(url, "high", alert_message)
        
        # Emit final result
        socketio.emit('analysis_complete', analysis_result)
        
    except Exception as e:
        logger.error(f"Error in URL analysis process: {str(e)}")
        socketio.emit('analysis_error', {
            "url": url,
            "error": str(e)
        })

@app.route('/api/stats', methods=['GET'])
def get_stats():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Calculate dates
    now = datetime.now()
    seven_days_ago = now - timedelta(days=7)
    thirty_days_ago = now - timedelta(days=30)
    
    # Get stats for last 7 days
    cursor.execute(
        "SELECT COUNT(*), SUM(is_phishing) FROM url_scans WHERE scan_date >= ?",
        (seven_days_ago.strftime('%Y-%m-%d %H:%M:%S'),)
    )
    last_7_days_total, last_7_days_phishing = cursor.fetchone()
    last_7_days_total = last_7_days_total or 0
    last_7_days_phishing = last_7_days_phishing or 0
    
    # Get stats for last 30 days
    cursor.execute(
        "SELECT COUNT(*), SUM(is_phishing) FROM url_scans WHERE scan_date >= ?",
        (thirty_days_ago.strftime('%Y-%m-%d %H:%M:%S'),)
    )
    last_30_days_total, last_30_days_phishing = cursor.fetchone()
    last_30_days_total = last_30_days_total or 0
    last_30_days_phishing = last_30_days_phishing or 0
    
    # Get all-time stats
    cursor.execute("SELECT COUNT(*), SUM(is_phishing) FROM url_scans")
    all_time_total, all_time_phishing = cursor.fetchone()
    all_time_total = all_time_total or 0
    all_time_phishing = all_time_phishing or 0
    
    # Get daily stats for the last 30 days
    cursor.execute(
        """
        SELECT 
            date(scan_date) as scan_day, 
            COUNT(*) as total, 
            SUM(is_phishing) as phishing
        FROM url_scans 
        WHERE scan_date >= ?
        GROUP BY scan_day
        ORDER BY scan_day
        """,
        (thirty_days_ago.strftime('%Y-%m-%d'),)
    )
    
    daily_stats = []
    for row in cursor.fetchall():
        daily_stats.append({
            "date": row[0],
            "total": row[1],
            "phishing": row[2] or 0,
            "safe": row[1] - (row[2] or 0)
        })
    
    # Get stats by confidence score ranges
    cursor.execute(
        """
        SELECT 
            CASE 
                WHEN confidence_score BETWEEN 0 AND 25 THEN '0-25'
                WHEN confidence_score BETWEEN 26 AND 50 THEN '26-50'
                WHEN confidence_score BETWEEN 51 AND 75 THEN '51-75'
                ELSE '76-100'
            END as score_range,
            COUNT(*) as count
        FROM url_scans
        GROUP BY score_range
        """
    )
    
    confidence_score_distribution = {}
    for row in cursor.fetchall():
        confidence_score_distribution[row[0]] = row[1]
    
    # Get top phishing domains
    cursor.execute(
        """
        SELECT 
            substr(url, instr(url, '://') + 3, 
                  instr(
                      substr(url, instr(url, '://') + 3), 
                      '/'
                  ) - 1
            ) as domain,
            COUNT(*) as count
        FROM url_scans
        WHERE is_phishing = 1
        GROUP BY domain
        ORDER BY count DESC
        LIMIT 10
        """
    )
    
    top_phishing_domains = []
    for row in cursor.fetchall():
        if row[0]:  # Ensure domain is not empty
            top_phishing_domains.append({
                "domain": row[0],
                "count": row[1]
            })
    
    conn.close()
    
    return jsonify({
        "last_7_days": {
            "total": last_7_days_total,
            "phishing": last_7_days_phishing,
            "safe": last_7_days_total - last_7_days_phishing
        },
        "last_30_days": {
            "total": last_30_days_total,
            "phishing": last_30_days_phishing,
            "safe": last_30_days_total - last_30_days_phishing
        },
        "all_time": {
            "total": all_time_total,
            "phishing": all_time_phishing,
            "safe": all_time_total - all_time_phishing
        },
        "daily_stats": daily_stats,
        "confidence_score_distribution": confidence_score_distribution,
        "top_phishing_domains": top_phishing_domains
    })

@app.route('/api/recent', methods=['GET'])
def get_recent_scans():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row  # This enables column access by name
    cursor = conn.cursor()
    
    cursor.execute(
        """
        SELECT 
            url, is_phishing, confidence_score, analysis_details, 
            threat_intel_results, scan_date
        FROM url_scans 
        ORDER BY scan_date DESC 
        LIMIT 10
        """
    )
    
    rows = cursor.fetchall()
    recent_scans = []
    
    for row in rows:
        recent_scans.append({
            "url": row['url'],
            "is_phishing": bool(row['is_phishing']),
            "confidence_score": row['confidence_score'],
            "analysis_details": json.loads(row['analysis_details']),
            "threat_intel_results": json.loads(row['threat_intel_results']) if row['threat_intel_results'] else [],
            "scan_date": row['scan_date']
        })
    
    conn.close()
    
    return jsonify(recent_scans)

@app.route('/api/alerts', methods=['GET'])
def get_alerts():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    cursor.execute(
        "SELECT id, url, risk_level, message, is_read, created_at FROM alerts ORDER BY created_at DESC LIMIT 50"
    )
    
    rows = cursor.fetchall()
    alerts = []
    
    for row in rows:
        alerts.append({
            "id": row['id'],
            "url": row['url'],
            "risk_level": row['risk_level'],
            "message": row['message'],
            "is_read": bool(row['is_read']),
            "created_at": row['created_at']
        })
    
    conn.close()
    
    return jsonify(alerts)

@app.route('/api/alerts/mark-read', methods=['POST'])
def mark_alerts_read():
    data = request.json
    alert_ids = data.get('alert_ids', [])
    
    if not alert_ids:
        return jsonify({"error": "No alert IDs provided"}), 400
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Convert list of IDs to comma-separated string for SQL IN clause
    id_string = ','.join('?' for _ in alert_ids)
    
    cursor.execute(
        f"UPDATE alerts SET is_read = 1 WHERE id IN ({id_string})",
        alert_ids
    )
    
    conn.commit()
    conn.close()
    
    return jsonify({"success": True, "message": f"{cursor.rowcount} alerts marked as read"})

@app.route('/api/heatmap', methods=['GET'])
def get_heatmap_data():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Get data for the last 30 days
    thirty_days_ago = (datetime.now() - timedelta(days=30)).strftime('%Y-%m-%d')
    
    cursor.execute(
        """
        SELECT 
            date(scan_date) as day,
            COUNT(*) as total_scans
        FROM url_scans
        WHERE scan_date >= ?
        GROUP BY day
        ORDER BY day
        """,
        (thirty_days_ago,)
    )
    
    days = []
    for i in range(30):
        day = (datetime.now() - timedelta(days=29-i)).strftime('%Y-%m-%d')
        days.append(day)
    
    # Initialize data with zeros
    heatmap_data = {day: 0 for day in days}
    
    # Fill in actual data
    for row in cursor.fetchall():
        if row[0] in heatmap_data:
            heatmap_data[row[0]] = row[1]
    
    # Convert to format needed for heatmap
    result = [{"date": day, "count": count} for day, count in heatmap_data.items()]
    
    conn.close()
    
    return jsonify(result)

@socketio.on('connect')
def handle_connect():
    logger.info('Client connected')

@socketio.on('disconnect')
def handle_disconnect():
    logger.info('Client disconnected')

if __name__ == '__main__':
    socketio.run(app, debug=True, port=5000, allow_unsafe_werkzeug=True)
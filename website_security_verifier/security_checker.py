# security_checker.py
import requests
import socket
import ssl
from urllib.parse import urlparse
import whois
import datetime

class SecurityChecker:
    def __init__(self, url):
        # Ensure URL starts with http:// or https://
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        self.url = url
        self.parsed_url = urlparse(url)
        self.hostname = self.parsed_url.netloc
        self.is_https = self.parsed_url.scheme == 'https'
        self.results = {
            'is_secure': False,
            'summary': '',
            'details': []
        }
    
    def check_security(self):
        """Run all security checks and return results"""
        if not self.hostname:
            self.results['summary'] = "Invalid URL provided"
            return self.results
        
        # Check if site uses HTTPS
        self.check_https()
        
        # If HTTPS, verify certificate
        if self.is_https:
            self.check_ssl_certificate()
            self.check_security_headers()
        
        # Set overall security assessment
        self._set_security_status()
        
        return self.results
    
    def check_https(self):
        """Check if the site uses HTTPS"""
        if self.is_https:
            self.results['details'].append("✅ Site uses HTTPS")
        else:
            self.results['details'].append("❌ Site does not use HTTPS - data transmissions are not encrypted")
    
    def check_ssl_certificate(self):
        """Check SSL/TLS certificate validity"""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.hostname, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=self.hostname) as ssock:
                    cert = ssock.getpeercert()
                    
            # Extract certificate information
            if cert:
                subject = dict(x[0] for x in cert['subject'])
                issuer = dict(x[0] for x in cert['issuer'])
                
                self.results['details'].append(f"✅ Valid SSL certificate found")
                self.results['details'].append(f"📄 Certificate issued to: {subject.get('commonName', 'Unknown')}")
                self.results['details'].append(f"🔐 Certificate issued by: {issuer.get('commonName', 'Unknown')}")
                
                # Check expiration
                not_after = cert.get('notAfter')
                if not_after:
                    expiry = ssl.cert_time_to_seconds(not_after)
                    expiry_date = datetime.datetime.fromtimestamp(expiry)
                    days_remaining = (expiry_date - datetime.datetime.now()).days
                    
                    if days_remaining > 30:
                        self.results['details'].append(f"✅ Certificate valid for {days_remaining} more days")
                    elif days_remaining > 0:
                        self.results['details'].append(f"⚠️ Certificate expiring soon (in {days_remaining} days)")
                    else:
                        self.results['details'].append(f"❌ Certificate has expired")
        
        except (socket.gaierror, socket.timeout):
            self.results['details'].append("❌ Failed to establish secure connection")
        except ssl.SSLCertVerificationError:
            self.results['details'].append("❌ SSL certificate validation failed")
        except Exception as e:
            self.results['details'].append(f"❌ Error checking SSL: {str(e)}")
            
    def check_security_headers(self):
        """Check for important security headers"""
        try:
            headers_to_check = {
                'Strict-Transport-Security': 'HSTS prevents downgrade attacks',
                'Content-Security-Policy': 'CSP helps prevent XSS attacks',
                'X-Content-Type-Options': 'Prevents MIME-type sniffing',
                'X-Frame-Options': 'Prevents clickjacking attacks',
                'X-XSS-Protection': 'Helps prevent XSS attacks in older browsers'
            }
            
            response = requests.get(self.url, timeout=5)
            response_headers = response.headers
            
            self.results['details'].append("\n🔍 Security Headers Analysis:")
            found_headers = 0
            total_headers = len(headers_to_check)
            
            for header, description in headers_to_check.items():
                if header in response_headers:
                    self.results['details'].append(f"✅ {header} - {description}")
                    found_headers += 1
                else:
                    self.results['details'].append(f"❌ Missing {header} - {description}")
            
            security_score = (found_headers / total_headers) * 100
            self.results['details'].append(f"\n📊 Security Headers Score: {security_score:.1f}%")
            
        except requests.exceptions.RequestException as e:
            self.results['details'].append(f"❌ Error checking security headers: {str(e)}")
    
    def _set_security_status(self):
        """Set overall security status based on findings"""
        if not self.is_https:
            self.results['is_secure'] = False
            self.results['summary'] = "⚠️ Not Secure: This website does not use HTTPS"
        else:
            # Count critical issues (those marked with ❌)
            critical_issues = sum(1 for detail in self.results['details'] if detail.startswith('❌'))
            
            if critical_issues == 0:
                self.results['is_secure'] = True
                self.results['summary'] = "✅ Secure: This website implements good security practices"
            elif critical_issues <= 2:
                self.results['is_secure'] = True
                self.results['summary'] = "⚠️ Mostly Secure: This website has some security issues to address"
            else:
                self.results['is_secure'] = False
                self.results['summary'] = f"⚠️ Not Fully Secure: This website has {critical_issues} security issues to address"
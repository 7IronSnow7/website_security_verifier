from django.shortcuts import render
import requests
from urllib.parse import urlparse
import socket
import ssl
from datetime import datetime

def home(request):
    # Simple function to render the home page
    return render(request, 'security_check.html')

def verify_security(request):
    if request.method == 'POST':
        url = request.POST.get('url')
        if not url:
            return render(request, 'security_check.html', {'result': 'Please enter a valid URL'})
        
        # Make sure URL has a scheme
        if not urlparse(url).scheme:
            url = 'https://' + url
        
        # Initialize security details
        details = []
        is_secure = True
        security_issues = []
        
        try:
            # Basic connection check
            response = requests.get(url, timeout=10, verify=True)
            
            # --- HTTPS Verification ---
            details.append("🔍 HTTPS Implementation")
            
            parsed_url = urlparse(url)
            is_https = parsed_url.scheme == 'https'
            
            if not is_https:
                is_secure = False
                details.append("❌ Not using HTTPS: Website is using insecure HTTP protocol")
                security_issues.append("Not using HTTPS")
            else:
                details.append("✅ Using HTTPS: Website is using secure HTTPS protocol")
                
                # SSL Certificate check
                try:
                    hostname = parsed_url.netloc
                    context = ssl.create_default_context()
                    with socket.create_connection((hostname, 443)) as sock:
                        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                            cert = ssock.getpeercert()
                            
                            # Check expiration date
                            expire_date = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                            days_left = (expire_date - datetime.now()).days
                            
                            if days_left < 0:
                                is_secure = False
                                details.append(f"❌ SSL Certificate: Expired certificate")
                                security_issues.append("Expired SSL certificate")
                            elif days_left < 30:
                                details.append(f"⚠️ SSL Certificate: Valid but expires soon ({days_left} days left)")
                            else:
                                details.append(f"✅ SSL Certificate: Valid (expires in {days_left} days)")
                except Exception as e:
                    details.append(f"❌ SSL Certificate: Unable to verify certificate ({str(e)})")
                    security_issues.append("SSL certificate verification failed")
                    is_secure = False
            
            # --- Security Headers ---
            details.append("")
            details.append("🔍 Security Headers")
            
            # Check Content-Security-Policy
            csp = response.headers.get('Content-Security-Policy')
            if csp:
                details.append("✅ Content-Security-Policy: Implemented")
            else:
                details.append("❌ Content-Security-Policy: Not implemented")
                security_issues.append("Missing Content-Security-Policy header")
                is_secure = False
            
            # Check X-XSS-Protection
            xss = response.headers.get('X-XSS-Protection')
            if xss:
                details.append("✅ X-XSS-Protection: Implemented")
            else:
                details.append("❌ X-XSS-Protection: Not implemented")
                security_issues.append("Missing X-XSS-Protection header")
                is_secure = False
            
            # Check X-Frame-Options
            x_frame = response.headers.get('X-Frame-Options')
            if x_frame:
                details.append("✅ X-Frame-Options: Implemented")
            else:
                details.append("❌ X-Frame-Options: Not implemented")
                security_issues.append("Missing X-Frame-Options header")
                is_secure = False
            
            # Check Strict-Transport-Security (HSTS)
            hsts = response.headers.get('Strict-Transport-Security')
            if hsts:
                details.append("✅ HSTS: Implemented")
            else:
                details.append("❌ HSTS: Not implemented")
                security_issues.append("Missing HSTS header")
                is_secure = False
            
            # --- Cookie Security ---
            details.append("")
            details.append("🔍 Cookie Security")
            
            cookies = response.cookies
            if not cookies:
                details.append("ℹ️ No cookies found")
            else:
                secure_cookies = all(cookie.secure for cookie in cookies)
                httponly_cookies = all(cookie.has_nonstandard_attr('HttpOnly') for cookie in cookies)
                
                if secure_cookies:
                    details.append("✅ Cookies have 'Secure' flag")
                else:
                    details.append("❌ Some cookies missing 'Secure' flag")
                    security_issues.append("Insecure cookies (missing Secure flag)")
                    is_secure = False
                
                if httponly_cookies:
                    details.append("✅ Cookies have 'HttpOnly' flag")
                else:
                    details.append("❌ Some cookies missing 'HttpOnly' flag")
                    security_issues.append("Insecure cookies (missing HttpOnly flag)")
                    is_secure = False
            
            # Create result summary
            if is_secure:
                result = "Website appears to be secure. All security checks passed."
            else:
                result = f"Website has {len(security_issues)} security issues: " + ", ".join(security_issues)
            
            return render(request, 'security_check.html', {
                'result': result, 
                'details': details, 
                'is_secure': is_secure,
                'url': url
            })
                
        except requests.exceptions.SSLError:
            return render(request, 'security_check.html', {
                'result': 'SSL Certificate validation failed',
                'details': ['❌ Website has invalid SSL certificate or does not support HTTPS'],
                'is_secure': False,
                'url': url
            })
        except requests.exceptions.ConnectionError:
            return render(request, 'security_check.html', {
                'result': 'Unable to connect to the website',
                'details': ['❌ Connection failed: Website might be down or unreachable'],
                'is_secure': False,
                'url': url
            })
        except Exception as e:
            return render(request, 'security_check.html', {
                'result': f'Error while verifying: {str(e)}',
                'details': [f'❌ An error occurred during security verification: {str(e)}'],
                'is_secure': False,
                'url': url
            })
    
    return render(request, 'security_check.html')
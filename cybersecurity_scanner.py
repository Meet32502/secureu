import streamlit as st
import requests
import ssl
import socket
import subprocess
import json
import pandas as pd
from datetime import datetime, timedelta
import plotly.express as px
import plotly.graph_objects as go
from urllib.parse import urlparse
import time
import re

# Page configuration
st.set_page_config(
    page_title="CyberHygiene Scanner",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS
st.markdown("""
<style>
    .main-header {
        background: linear-gradient(90deg, #1e3c72 0%, #2a5298 100%);
        padding: 2rem;
        border-radius: 10px;
        color: white;
        text-align: center;
        margin-bottom: 2rem;
    }
    .metric-card {
        background: white;
        padding: 1rem;
        border-radius: 8px;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        border-left: 4px solid #2a5298;
    }
    .critical { border-left-color: #dc3545 !important; }
    .high { border-left-color: #fd7e14 !important; }
    .medium { border-left-color: #ffc107 !important; }
    .low { border-left-color: #28a745 !important; }
    .compliant { border-left-color: #28a745 !important; }
</style>
""", unsafe_allow_html=True)

class SecurityScanner:
    def __init__(self):
        self.results = {}
        
    def check_ssl_certificate(self, domain):
        """Check SSL certificate validity and configuration"""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    
            # Parse certificate details
            not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
            not_before = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
            days_until_expiry = (not_after - datetime.now()).days
            
            return {
                'valid': True,
                'issuer': dict(x[0] for x in cert['issuer']),
                'subject': dict(x[0] for x in cert['subject']),
                'expires': not_after.strftime('%Y-%m-%d'),
                'days_until_expiry': days_until_expiry,
                'san': cert.get('subjectAltName', [])
            }
        except Exception as e:
            return {'valid': False, 'error': str(e)}
    
    def check_security_headers(self, url):
        """Check HTTP security headers"""
        try:
            response = requests.get(url, timeout=10, allow_redirects=True)
            headers = response.headers
            
            security_headers = {
                'Strict-Transport-Security': headers.get('Strict-Transport-Security'),
                'Content-Security-Policy': headers.get('Content-Security-Policy'),
                'X-Frame-Options': headers.get('X-Frame-Options'),
                'X-Content-Type-Options': headers.get('X-Content-Type-Options'),
                'Referrer-Policy': headers.get('Referrer-Policy'),
                'Permissions-Policy': headers.get('Permissions-Policy'),
                'X-XSS-Protection': headers.get('X-XSS-Protection')
            }
            
            return {
                'status_code': response.status_code,
                'headers': security_headers,
                'server': headers.get('Server', 'Unknown'),
                'redirect_chain': len(response.history)
            }
        except Exception as e:
            return {'error': str(e)}
    
    def check_domain_security(self, domain):
        """Comprehensive domain security check"""
        results = {
            'domain': domain,
            'timestamp': datetime.now().isoformat(),
            'ssl': self.check_ssl_certificate(domain),
            'headers': self.check_security_headers(f'https://{domain}'),
        }
        
        return results
    
    def calculate_compliance_score(self, scan_results):
        """Calculate overall compliance score"""
        score = 0
        max_score = 100
        
        # SSL Certificate (30 points)
        if scan_results['ssl'].get('valid'):
            score += 20
            if scan_results['ssl'].get('days_until_expiry', 0) > 30:
                score += 10
        
        # Security Headers (70 points)
        headers = scan_results['headers'].get('headers', {})
        header_scores = {
            'Strict-Transport-Security': 15,
            'Content-Security-Policy': 15,
            'X-Frame-Options': 10,
            'X-Content-Type-Options': 10,
            'Referrer-Policy': 10,
            'X-XSS-Protection': 10
        }
        
        for header, points in header_scores.items():
            if headers.get(header):
                score += points
        
        return min(score, max_score)

def main():
    # Header
    st.markdown("""
    <div class="main-header">
        <h1>🔒 CyberHygiene Scanner</h1>
        <p>Comprehensive Security Compliance Platform for Educational Institutions</p>
    </div>
    """, unsafe_allow_html=True)
    
    # Sidebar
    st.sidebar.title("📊 Scan Configuration")
    
    # Scan type selection
    scan_type = st.sidebar.selectbox(
        "Select Scan Type",
        ["Quick Security Scan", "Comprehensive Audit", "Compliance Check", "Network Assessment"]
    )
    
    # Target configuration
    st.sidebar.subheader("Target Configuration")
    target_type = st.sidebar.radio("Target Type", ["Single Domain", "Multiple Domains", "IP Range"])
    
    if target_type == "Single Domain":
        target = st.sidebar.text_input("Domain (without https://)", placeholder="example.university.edu")
    elif target_type == "Multiple Domains":
        targets_text = st.sidebar.text_area("Domains (one per line)", placeholder="main.university.edu\nportal.university.edu\nlms.university.edu")
        target = [t.strip() for t in targets_text.split('\n') if t.strip()]
    else:
        target = st.sidebar.text_input("IP Range", placeholder="192.168.1.0/24")
    
    # Compliance frameworks
    st.sidebar.subheader("Compliance Frameworks")
    frameworks = st.sidebar.multiselect(
        "Select Frameworks",
        ["NIST Cybersecurity Framework", "FERPA", "SOC 2", "ISO 27001", "GDPR", "Custom"],
        default=["NIST Cybersecurity Framework"]
    )
    
    # Main content area
    col1, col2 = st.columns([2, 1])
    
    with col1:
        st.header("Security Assessment Dashboard")
        
        # Scan controls
        scan_col1, scan_col2, scan_col3 = st.columns(3)
        
        with scan_col1:
            start_scan = st.button("🚀 Start Scan", type="primary", use_container_width=True)
        
        with scan_col2:
            if st.button("📊 Generate Report", use_container_width=True):
                st.info("Report generation feature coming soon!")
        
        with scan_col3:
            if st.button("📥 Export Results", use_container_width=True):
                st.info("Export feature coming soon!")
        
        # Results area
        if start_scan and target:
            scanner = SecurityScanner()
            
            if target_type == "Single Domain":
                targets_to_scan = [target]
            else:
                targets_to_scan = target if isinstance(target, list) else [target]
            
            st.subheader("🔍 Scan Results")
            
            # Progress bar
            progress_bar = st.progress(0)
            status_text = st.empty()
            
            results = []
            for i, domain in enumerate(targets_to_scan[:3]):  # Limit to 3 for demo
                status_text.text(f'Scanning {domain}...')
                progress_bar.progress((i + 1) / len(targets_to_scan))
                
                try:
                    result = scanner.check_domain_security(domain)
                    results.append(result)
                    time.sleep(1)  # Simulate scan time
                except Exception as e:
                    st.error(f"Error scanning {domain}: {str(e)}")
            
            status_text.text('Scan completed!')
            
            # Display results
            if results:
                for result in results:
                    domain = result['domain']
                    score = scanner.calculate_compliance_score(result)
                    
                    # Domain header
                    st.markdown(f"### 🌐 {domain}")
                    
                    # Score and status
                    score_col1, score_col2, score_col3, score_col4 = st.columns(4)
                    
                    with score_col1:
                        st.metric("Compliance Score", f"{score}%", 
                                delta=f"{'Good' if score >= 70 else 'Needs Improvement'}")
                    
                    with score_col2:
                        ssl_status = "✅ Valid" if result['ssl'].get('valid') else "❌ Invalid"
                        st.metric("SSL Certificate", ssl_status)
                    
                    with score_col3:
                        headers_count = sum(1 for h in result['headers'].get('headers', {}).values() if h)
                        st.metric("Security Headers", f"{headers_count}/7")
                    
                    with score_col4:
                        risk_level = "Low" if score >= 80 else "Medium" if score >= 60 else "High"
                        st.metric("Risk Level", risk_level)
                    
                    # Detailed findings
                    with st.expander(f"Detailed Findings for {domain}"):
                        
                        # SSL Details
                        st.subheader("🔐 SSL Certificate Analysis")
                        if result['ssl'].get('valid'):
                            ssl_col1, ssl_col2 = st.columns(2)
                            with ssl_col1:
                                st.write("**Status:** ✅ Valid")
                                st.write(f"**Expires:** {result['ssl'].get('expires')}")
                                st.write(f"**Days until expiry:** {result['ssl'].get('days_until_expiry')}")
                            with ssl_col2:
                                st.write(f"**Issuer:** {result['ssl'].get('issuer', {}).get('organizationName', 'Unknown')}")
                                st.write(f"**Subject:** {result['ssl'].get('subject', {}).get('commonName', 'Unknown')}")
                        else:
                            st.error(f"SSL Certificate Error: {result['ssl'].get('error')}")
                        
                        # Security Headers
                        st.subheader("🛡️ Security Headers Analysis")
                        headers = result['headers'].get('headers', {})
                        
                        header_df = pd.DataFrame([
                            {"Header": "Strict-Transport-Security", "Status": "✅ Present" if headers.get('Strict-Transport-Security') else "❌ Missing", "Value": headers.get('Strict-Transport-Security', 'Not Set')},
                            {"Header": "Content-Security-Policy", "Status": "✅ Present" if headers.get('Content-Security-Policy') else "❌ Missing", "Value": headers.get('Content-Security-Policy', 'Not Set')},
                            {"Header": "X-Frame-Options", "Status": "✅ Present" if headers.get('X-Frame-Options') else "❌ Missing", "Value": headers.get('X-Frame-Options', 'Not Set')},
                            {"Header": "X-Content-Type-Options", "Status": "✅ Present" if headers.get('X-Content-Type-Options') else "❌ Missing", "Value": headers.get('X-Content-Type-Options', 'Not Set')},
                            {"Header": "Referrer-Policy", "Status": "✅ Present" if headers.get('Referrer-Policy') else "❌ Missing", "Value": headers.get('Referrer-Policy', 'Not Set')},
                            {"Header": "X-XSS-Protection", "Status": "✅ Present" if headers.get('X-XSS-Protection') else "❌ Missing", "Value": headers.get('X-XSS-Protection', 'Not Set')},
                        ])
                        
                        st.dataframe(header_df, use_container_width=True)
                    
                    st.markdown("---")
    
    with col2:
        st.header("📈 Compliance Overview")
        
        # Quick stats
        st.subheader("🎯 Scan Statistics")
        stat_col1, stat_col2 = st.columns(2)
        
        with stat_col1:
            st.metric("Domains Scanned", "0", delta="Ready to scan")
        
        with stat_col2:
            st.metric("Average Score", "0%", delta="No data yet")
        
        # Compliance frameworks info
        st.subheader("📋 Selected Frameworks")
        for framework in frameworks:
            if framework == "NIST Cybersecurity Framework":
                st.success("✅ NIST CSF - Industry standard")
            elif framework == "FERPA":
                st.info("🎓 FERPA - Educational records protection")
            elif framework == "SOC 2":
                st.warning("🏢 SOC 2 - Service organization controls")
        
        # Recent activity
        st.subheader("⏰ Recent Activity")
        st.info("No recent scans")
        
        # Security tips
        st.subheader("💡 Security Best Practices")
        with st.expander("View Recommendations"):
            st.markdown("""
            **Essential Security Headers:**
            - Strict-Transport-Security
            - Content-Security-Policy  
            - X-Frame-Options
            - X-Content-Type-Options
            
            **SSL Certificate:**
            - Valid and trusted certificate
            - Regular renewal (30+ days before expiry)
            - Strong encryption algorithms
            
            **Network Security:**
            - Regular vulnerability assessments
            - Proper firewall configuration
            - Network segmentation
            """)
    
    # Footer
    st.markdown("---")
    st.markdown("""
    <div style='text-align: center; color: #666; padding: 1rem;'>
        <p>🔒 CyberHygiene Scanner v1.0 | Built for Educational Institution Security Assessment</p>
    </div>
    """, unsafe_allow_html=True)

if __name__ == "__main__":
    main()
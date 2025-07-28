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
from io import BytesIO
import base64

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

class ReportGenerator:
    def __init__(self):
        self.report_data = {}
    
    def generate_html_report(self, scan_results, frameworks, institution_name="Institution"):
        """Generate comprehensive HTML report"""
        
        # Calculate overall statistics
        total_domains = len(scan_results)
        scanner = SecurityScanner()
        scores = [scanner.calculate_compliance_score(result) for result in scan_results]
        average_score = sum(scores) / len(scores) if scores else 0
        
        # Count issues
        ssl_issues = sum(1 for result in scan_results if not result['ssl'].get('valid'))
        header_issues = sum(1 for result in scan_results 
                          for header in result['headers'].get('headers', {}).values() 
                          if not header)
        
        # Risk categorization
        high_risk = sum(1 for score in scores if score < 60)
        medium_risk = sum(1 for score in scores if 60 <= score < 80)
        low_risk = sum(1 for score in scores if score >= 80)
        
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>CyberHygiene Security Report - {institution_name}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }}
                .header {{ background: linear-gradient(135deg, #1e3c72, #2a5298); color: white; padding: 30px; text-align: center; border-radius: 10px; margin-bottom: 30px; }}
                .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }}
                .metric-card {{ background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); text-align: center; }}
                .metric-value {{ font-size: 2em; font-weight: bold; color: #2a5298; }}
                .metric-label {{ color: #666; margin-top: 5px; }}
                .section {{ background: white; padding: 25px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); margin-bottom: 25px; }}
                .domain-result {{ border: 1px solid #ddd; border-radius: 5px; padding: 15px; margin: 10px 0; }}
                .score-good {{ color: #28a745; }}
                .score-medium {{ color: #ffc107; }}
                .score-poor {{ color: #dc3545; }}
                .issue {{ background: #fff3cd; border: 1px solid #ffeaa7; border-radius: 4px; padding: 10px; margin: 5px 0; }}
                .recommendation {{ background: #d1ecf1; border: 1px solid #bee5eb; border-radius: 4px; padding: 10px; margin: 5px 0; }}
                table {{ width: 100%; border-collapse: collapse; margin: 15px 0; }}
                th, td {{ border: 1px solid #ddd; padding: 12px; text-align: left; }}
                th {{ background: #f8f9fa; font-weight: bold; }}
                .status-pass {{ color: #28a745; font-weight: bold; }}
                .status-fail {{ color: #dc3545; font-weight: bold; }}
                .footer {{ text-align: center; color: #666; margin-top: 40px; padding: 20px; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>🔒 CyberHygiene Security Assessment Report</h1>
                <h2>{institution_name}</h2>
                <p>Generated on {datetime.now().strftime('%B %d, %Y at %I:%M %p')}</p>
            </div>
            
            <div class="summary">
                <div class="metric-card">
                    <div class="metric-value">{total_domains}</div>
                    <div class="metric-label">Domains Scanned</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value">{average_score:.0f}%</div>
                    <div class="metric-label">Average Score</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value">{ssl_issues}</div>
                    <div class="metric-label">SSL Issues</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value">{header_issues}</div>
                    <div class="metric-label">Missing Headers</div>
                </div>
            </div>
            
            <div class="section">
                <h2>📊 Executive Summary</h2>
                <p>This report provides a comprehensive security assessment of {total_domains} domain(s) belonging to {institution_name}.</p>
                
                <h3>Risk Distribution</h3>
                <ul>
                    <li><strong>High Risk:</strong> {high_risk} domains (Score < 60%)</li>
                    <li><strong>Medium Risk:</strong> {medium_risk} domains (Score 60-79%)</li>
                    <li><strong>Low Risk:</strong> {low_risk} domains (Score ≥ 80%)</li>
                </ul>
                
                <h3>Compliance Frameworks</h3>
                <ul>
        """
        
        for framework in frameworks:
            html_content += f"<li>{framework}</li>"
        
        html_content += """
                </ul>
            </div>
            
            <div class="section">
                <h2>🌐 Domain-by-Domain Analysis</h2>
        """
        
        for result in scan_results:
            domain = result['domain']
            score = scanner.calculate_compliance_score(result)
            score_class = 'score-good' if score >= 80 else 'score-medium' if score >= 60 else 'score-poor'
            
            html_content += f"""
                <div class="domain-result">
                    <h3>{domain} - <span class="{score_class}">{score:.0f}%</span></h3>
                    
                    <h4>SSL Certificate Analysis</h4>
            """
            
            if result['ssl'].get('valid'):
                days_left = result['ssl'].get('days_until_expiry', 0)
                expiry_status = 'Good' if days_left > 30 else 'Expiring Soon' if days_left > 0 else 'Expired'
                html_content += f"""
                    <p><span class="status-pass">✅ Valid Certificate</span></p>
                    <ul>
                        <li>Expires: {result['ssl'].get('expires')}</li>
                        <li>Days until expiry: {days_left} ({expiry_status})</li>
                        <li>Issuer: {result['ssl'].get('issuer', {}).get('organizationName', 'Unknown')}</li>
                    </ul>
                """
            else:
                html_content += f"""
                    <p><span class="status-fail">❌ Invalid Certificate</span></p>
                    <div class="issue">SSL Certificate Error: {result['ssl'].get('error', 'Unknown error')}</div>
                """
            
            html_content += """
                    <h4>Security Headers</h4>
                    <table>
                        <tr><th>Header</th><th>Status</th><th>Value</th></tr>
            """
            
            headers = result['headers'].get('headers', {})
            header_checks = [
                ('Strict-Transport-Security', 'HSTS'),
                ('Content-Security-Policy', 'CSP'),
                ('X-Frame-Options', 'Frame Options'),
                ('X-Content-Type-Options', 'Content Type'),
                ('Referrer-Policy', 'Referrer Policy'),
                ('X-XSS-Protection', 'XSS Protection')
            ]
            
            for header, display_name in header_checks:
                status = "✅ Present" if headers.get(header) else "❌ Missing"
                status_class = "status-pass" if headers.get(header) else "status-fail"
                value = headers.get(header, 'Not Set')[:50] + ('...' if len(str(headers.get(header, ''))) > 50 else '')
                
                html_content += f"""
                        <tr>
                            <td>{display_name}</td>
                            <td><span class="{status_class}">{status}</span></td>
                            <td>{value}</td>
                        </tr>
                """
            
            html_content += """
                    </table>
                </div>
            """
        
        html_content += f"""
            </div>
            
            <div class="section">
                <h2>🎯 Recommendations</h2>
                
                <div class="recommendation">
                    <h3>Immediate Actions Required</h3>
                    <ul>
                        <li>Fix SSL certificate issues on {ssl_issues} domain(s)</li>
                        <li>Implement missing security headers</li>
                        <li>Review and update security policies</li>
                    </ul>
                </div>
                
                <div class="recommendation">
                    <h3>Best Practices</h3>
                    <ul>
                        <li>Enable HSTS (Strict-Transport-Security) on all domains</li>
                        <li>Implement Content Security Policy (CSP)</li>
                        <li>Set up automated SSL certificate renewal</li>
                        <li>Regular security assessments (quarterly recommended)</li>
                        <li>Staff cybersecurity training programs</li>
                    </ul>
                </div>
            </div>
            
            <div class="footer">
                <p>🔒 Generated by CyberHygiene Scanner v1.0</p>
                <p>This report should be reviewed by qualified cybersecurity professionals</p>
            </div>
        </body>
        </html>
        """
        
        return html_content
    
    def create_download_link(self, html_content, filename):
        """Create downloadable HTML report"""
        b64 = base64.b64encode(html_content.encode()).decode()
        return f'<a href="data:text/html;base64,{b64}" download="{filename}">📥 Download HTML Report</a>'

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
                if 'scan_results' in st.session_state and st.session_state.scan_results:
                    # Institution name input
                    institution_name = st.text_input("Institution Name", placeholder="Your University Name")
                    if not institution_name:
                        institution_name = "Educational Institution"
                    
                    # Generate report
                    report_generator = ReportGenerator()
                    html_report = report_generator.generate_html_report(
                        st.session_state.scan_results, 
                        frameworks, 
                        institution_name
                    )
                    
                    # Create download link
                    filename = f"cybersecurity_report_{institution_name.replace(' ', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
                    download_link = report_generator.create_download_link(html_report, filename)
                    
                    st.success("Report generated successfully!")
                    st.markdown(download_link, unsafe_allow_html=True)
                    
                    # Preview section
                    with st.expander("📋 Report Preview"):
                        st.markdown("### Report Summary")
                        total_domains = len(st.session_state.scan_results)
                        scanner = SecurityScanner()
                        scores = [scanner.calculate_compliance_score(result) for result in st.session_state.scan_results]
                        avg_score = sum(scores) / len(scores) if scores else 0
                        
                        col1, col2, col3 = st.columns(3)
                        with col1:
                            st.metric("Domains Scanned", total_domains)
                        with col2:
                            st.metric("Average Score", f"{avg_score:.0f}%")
                        with col3:
                            risk_level = "Low" if avg_score >= 80 else "Medium" if avg_score >= 60 else "High"
                            st.metric("Overall Risk", risk_level)
                else:
                    st.warning("Please run a scan first to generate a report!")
        
        with scan_col3:
            if st.button("📥 Export Results", use_container_width=True):
                if 'scan_results' in st.session_state and st.session_state.scan_results:
                    # Create CSV export
                    export_data = []
                    scanner = SecurityScanner()
                    
                    for result in st.session_state.scan_results:
                        domain = result['domain']
                        score = scanner.calculate_compliance_score(result)
                        ssl_valid = result['ssl'].get('valid', False)
                        ssl_expiry = result['ssl'].get('expires', 'N/A')
                        
                        headers = result['headers'].get('headers', {})
                        header_count = sum(1 for h in headers.values() if h)
                        
                        export_data.append({
                            'Domain': domain,
                            'Compliance Score': f"{score}%",
                            'SSL Valid': 'Yes' if ssl_valid else 'No',
                            'SSL Expiry': ssl_expiry,
                            'Security Headers': f"{header_count}/7",
                            'Risk Level': 'Low' if score >= 80 else 'Medium' if score >= 60 else 'High',
                            'Scan Date': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                        })
                    
                    df = pd.DataFrame(export_data)
                    csv = df.to_csv(index=False)
                    
                    st.download_button(
                        label="📥 Download CSV Report",
                        data=csv,
                        file_name=f"cybersecurity_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                        mime="text/csv"
                    )
                else:
                    st.warning("Please run a scan first to export results!")
        
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
            
            # Store results in session state for report generation
            st.session_state.scan_results = results
            
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

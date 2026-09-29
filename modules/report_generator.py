import os
import json
from datetime import datetime


class ReportGenerator:

    def __init__(self, target, results, scan_id):
        self.target = target
        self.results = results
        self.scan_id = scan_id
        self.report_dir = os.path.join('static', 'reports')
        os.makedirs(self.report_dir, exist_ok=True)
        self.timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    def generate_json(self):
        report = {
            'report_metadata': {
                'title': 'VulnPilot Assessment Report',
                'scan_id': self.scan_id,
                'target': self.target,
                'generated_at': self.timestamp,
                'tool': 'VulnPilot Security Scanner v1.0',
                'classification': 'CONFIDENTIAL'
            },
            'executive_summary': self._executive_summary(),
            'scope': {
                'target': self.target,
                'scan_type': 'Full Automated Assessment',
                'phases': ['Reconnaissance', 'Enumeration', 'Vulnerability Scanning', 'Analysis']
            },
            'methodology': {
                'approach': 'Black-Box Testing',
                'standards': ['OWASP Top 10', 'PTES', 'NIST SP 800-115'],
                'phases': {
                    'recon': 'Web crawling, tech detection, subdomain discovery, dir fuzzing',
                    'enum': 'Port scanning, service enumeration, OS fingerprinting, banner grabbing',
                    'vuln': 'XSS, SQLi, IDOR, header analysis, SSL/TLS check, OWASP checks',
                    'analysis': 'CVSS scoring, severity classification, PoC generation, remediation'
                }
            },
            'findings': {
                'reconnaissance': {
                    'technologies': self.results.get('tech', {}),
                    'crawl': self.results.get('crawl', {}),
                    'subdomains': self.results.get('subdomains', {}),
                    'directories': self.results.get('dirs', {})
                },
                'enumeration': {
                    'ports': self.results.get('ports', {}),
                    'services': self.results.get('services', {}),
                    'os_detection': self.results.get('os', {})
                },
                'vulnerabilities': {
                    'xss': self.results.get('xss', {}),
                    'sqli': self.results.get('sqli', {}),
                    'idor': self.results.get('idor', {}),
                    'headers': self.results.get('headers', {}),
                    'ssl_tls': self.results.get('ssl', {}),
                    'api_endpoints': self.results.get('api', {}),
                    'owasp': self.results.get('owasp', {})
                },
                'analysis': self.results.get('analysis', {})
            },
            'risk_summary': self._risk_summary(),
            'remediation_recommendations': self._remediation(),
            'conclusion': self._conclusion()
        }

        path = os.path.join(self.report_dir, f'{self.scan_id}.json')
        with open(path, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        return path

    def generate_pdf(self):
        """Generate a formatted HTML-based PDF report using reportlab."""
        try:
            from reportlab.lib.pagesizes import A4
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.units import cm
            from reportlab.lib import colors
            from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer,
                                             Table, TableStyle, HRFlowable, PageBreak)
            from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY

            path = os.path.join(self.report_dir, f'{self.scan_id}.pdf')
            doc = SimpleDocTemplate(path, pagesize=A4,
                                    rightMargin=2*cm, leftMargin=2*cm,
                                    topMargin=2*cm, bottomMargin=2*cm)

            # Color palette
            dark_bg = colors.HexColor('#0d1117')
            accent = colors.HexColor('#00d4ff')
            danger = colors.HexColor('#ff4444')
            warning = colors.HexColor('#ffaa00')
            success = colors.HexColor('#00cc44')
            text_color = colors.HexColor('#333333')
            gray = colors.HexColor('#6c757d')
            light_gray = colors.HexColor('#f8f9fa')

            styles = getSampleStyleSheet()
            # Custom styles
            title_style = ParagraphStyle('Title', parent=styles['Normal'],
                fontSize=22, textColor=dark_bg, spaceAfter=8,
                fontName='Helvetica-Bold', alignment=TA_CENTER)
            h1_style = ParagraphStyle('H1', parent=styles['Normal'],
                fontSize=14, textColor=dark_bg, spaceBefore=16, spaceAfter=6,
                fontName='Helvetica-Bold', borderPad=4)
            h2_style = ParagraphStyle('H2', parent=styles['Normal'],
                fontSize=11, textColor=accent, spaceBefore=10, spaceAfter=4,
                fontName='Helvetica-Bold')
            body_style = ParagraphStyle('Body', parent=styles['Normal'],
                fontSize=9, textColor=text_color, spaceAfter=4,
                fontName='Helvetica', alignment=TA_JUSTIFY)
            small_style = ParagraphStyle('Small', parent=styles['Normal'],
                fontSize=8, textColor=gray, spaceAfter=2, fontName='Helvetica')
            mono_style = ParagraphStyle('Mono', parent=styles['Normal'],
                fontSize=8, textColor=text_color, spaceAfter=2,
                fontName='Courier', backColor=light_gray)

            content = []

            # Cover Page
            content.append(Spacer(1, 2*cm))
            content.append(HRFlowable(width='100%', thickness=3, color=dark_bg))
            content.append(Spacer(1, 0.5*cm))
            content.append(Paragraph('VULNERABILITY ASSESSMENT &', title_style))
            content.append(Paragraph('PENETRATION TESTING REPORT', title_style))
            content.append(Spacer(1, 0.5*cm))
            content.append(HRFlowable(width='100%', thickness=1, color=accent))
            content.append(Spacer(1, 1*cm))

            meta_data = [
                ['Target', self.target],
                ['Scan ID', self.scan_id[:16] + '...'],
                ['Date', self.timestamp],
                ['Classification', 'CONFIDENTIAL'],
                ['Tool', 'VulnPilot Security Scanner v1.0'],
                ['Methodology', 'OWASP Top 10 / PTES / NIST SP 800-115'],
            ]
            meta_table = Table(meta_data, colWidths=[4*cm, 12*cm])
            meta_table.setStyle(TableStyle([
                ('FONTNAME', (0,0), (-1,-1), 'Helvetica'),
                ('FONTNAME', (0,0), (0,-1), 'Helvetica-Bold'),
                ('FONTSIZE', (0,0), (-1,-1), 9),
                ('TEXTCOLOR', (0,0), (0,-1), dark_bg),
                ('TEXTCOLOR', (1,0), (1,-1), text_color),
                ('ROWBACKGROUNDS', (0,0), (-1,-1), [light_gray, colors.white]),
                ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#dee2e6')),
                ('PADDING', (0,0), (-1,-1), 6),
            ]))
            content.append(meta_table)
            content.append(PageBreak())

            # Executive Summary
            content.append(Paragraph('1. Executive Summary', h1_style))
            content.append(HRFlowable(width='100%', thickness=1, color=colors.HexColor('#dee2e6')))
            content.append(Spacer(1, 0.3*cm))
            summary = self._executive_summary()
            content.append(Paragraph(summary['overview'], body_style))

            analysis = self.results.get('analysis', {})
            sc = analysis.get('severity_counts', {})
            risk = analysis.get('overall_risk', 'Unknown')
            risk_color = danger if risk in ['Critical', 'High'] else warning if risk == 'Medium' else success

            risk_data = [
                ['Risk Level', 'Critical', 'High', 'Medium', 'Low'],
                ['Count', str(sc.get('Critical', 0)), str(sc.get('High', 0)),
                 str(sc.get('Medium', 0)), str(sc.get('Low', 0))]
            ]
            risk_table = Table(risk_data, colWidths=[4*cm, 3*cm, 3*cm, 3*cm, 3*cm])
            risk_table.setStyle(TableStyle([
                ('FONTNAME', (0,0), (-1,-1), 'Helvetica'),
                ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
                ('FONTSIZE', (0,0), (-1,-1), 9),
                ('BACKGROUND', (0,0), (-1,0), dark_bg),
                ('TEXTCOLOR', (0,0), (-1,0), colors.white),
                ('BACKGROUND', (1,1), (1,1), colors.HexColor('#ff4444') if sc.get('Critical', 0) > 0 else light_gray),
                ('BACKGROUND', (2,1), (2,1), colors.HexColor('#ff7700') if sc.get('High', 0) > 0 else light_gray),
                ('BACKGROUND', (3,1), (3,1), colors.HexColor('#ffaa00') if sc.get('Medium', 0) > 0 else light_gray),
                ('BACKGROUND', (4,1), (4,1), colors.HexColor('#00cc44') if sc.get('Low', 0) > 0 else light_gray),
                ('TEXTCOLOR', (1,1), (4,1), colors.white),
                ('ALIGN', (0,0), (-1,-1), 'CENTER'),
                ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#dee2e6')),
                ('PADDING', (0,0), (-1,-1), 8),
            ]))
            content.append(Spacer(1, 0.5*cm))
            content.append(risk_table)
            content.append(Spacer(1, 0.3*cm))
            content.append(Paragraph(f'<b>Overall Risk Rating: {risk}</b>', body_style))

            # Scope
            content.append(PageBreak())
            content.append(Paragraph('2. Scope & Methodology', h1_style))
            content.append(HRFlowable(width='100%', thickness=1, color=colors.HexColor('#dee2e6')))
            content.append(Spacer(1, 0.3*cm))
            scope_text = (f'The assessment was conducted against the target: <b>{self.target}</b>. '
                         'The scope included all web-facing assets, open ports, subdomains, APIs, '
                         'and the application layer. The methodology followed OWASP Testing Guide v4, '
                         'PTES (Penetration Testing Execution Standard), and NIST SP 800-115.')
            content.append(Paragraph(scope_text, body_style))

            phases = [
                ['Phase', 'Description', 'Tools/Techniques'],
                ['Reconnaissance', 'Technology detection, crawling, subdomain discovery, dir fuzzing',
                 'Custom scanner, HTTP analysis'],
                ['Enumeration', 'Port scanning, service enum, OS detection, banner grabbing',
                 'Socket scanning, banner analysis'],
                ['Vulnerability Scanning', 'XSS, SQLi, IDOR, header analysis, SSL, API discovery, OWASP',
                 'Payload injection, header inspection'],
                ['Analysis', 'CVSS scoring, severity classification, PoC simulation, remediation',
                 'CVSS v3.1 calculator, risk matrix'],
            ]
            phases_table = Table(phases, colWidths=[4*cm, 8*cm, 5*cm])
            phases_table.setStyle(TableStyle([
                ('FONTNAME', (0,0), (-1,-1), 'Helvetica'),
                ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
                ('FONTSIZE', (0,0), (-1,-1), 8),
                ('BACKGROUND', (0,0), (-1,0), dark_bg),
                ('TEXTCOLOR', (0,0), (-1,0), colors.white),
                ('ROWBACKGROUNDS', (0,1), (-1,-1), [light_gray, colors.white]),
                ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#dee2e6')),
                ('PADDING', (0,0), (-1,-1), 6),
                ('VALIGN', (0,0), (-1,-1), 'TOP'),
            ]))
            content.append(Spacer(1, 0.5*cm))
            content.append(phases_table)

            # Recon Findings
            content.append(PageBreak())
            content.append(Paragraph('3. Reconnaissance Findings', h1_style))
            content.append(HRFlowable(width='100%', thickness=1, color=colors.HexColor('#dee2e6')))

            tech = self.results.get('tech', {})
            content.append(Spacer(1, 0.3*cm))
            content.append(Paragraph('3.1 Technology Detection', h2_style))
            tech_data = [
                ['Component', 'Detected Value'],
                ['Server', tech.get('server', 'Unknown')],
                ['Powered By', tech.get('powered_by', 'Unknown')],
                ['CMS', tech.get('cms', 'Not detected')],
                ['Frameworks', ', '.join(tech.get('frameworks', [])) or 'None detected'],
                ['Languages', ', '.join(tech.get('languages', [])) or 'None detected'],
            ]
            tech_table = Table(tech_data, colWidths=[5*cm, 11*cm])
            tech_table.setStyle(TableStyle([
                ('FONTNAME', (0,0), (-1,-1), 'Helvetica'),
                ('FONTNAME', (0,0), (0,-1), 'Helvetica-Bold'),
                ('FONTSIZE', (0,0), (-1,-1), 9),
                ('BACKGROUND', (0,0), (-1,0), dark_bg),
                ('TEXTCOLOR', (0,0), (-1,0), colors.white),
                ('ROWBACKGROUNDS', (0,1), (-1,-1), [light_gray, colors.white]),
                ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#dee2e6')),
                ('PADDING', (0,0), (-1,-1), 6),
            ]))
            content.append(tech_table)

            crawl = self.results.get('crawl', {})
            content.append(Spacer(1, 0.5*cm))
            content.append(Paragraph('3.2 Web Crawl Results', h2_style))
            content.append(Paragraph(
                f'Pages crawled: <b>{crawl.get("pages_crawled", 0)}</b> | '
                f'Links found: <b>{len(crawl.get("links", []))}</b> | '
                f'Forms discovered: <b>{len(crawl.get("forms", []))}</b>', body_style))

            dirs = self.results.get('dirs', {})
            content.append(Spacer(1, 0.5*cm))
            content.append(Paragraph('3.3 Directory Fuzzing', h2_style))
            interesting = dirs.get('interesting', [])
            content.append(Paragraph(
                f'Total paths checked: <b>{dirs.get("total_checked", 0)}</b> | '
                f'Paths found: <b>{len(dirs.get("found", []))}</b> | '
                f'Interesting: <b>{len(interesting)}</b>', body_style))
            if interesting:
                dir_data = [['Path', 'URL', 'Status']] + [
                    [d['path'], d['url'][:40] + '...', str(d['status'])] for d in interesting[:10]
                ]
                dir_table = Table(dir_data, colWidths=[3*cm, 10*cm, 3*cm])
                dir_table.setStyle(TableStyle([
                    ('FONTNAME', (0,0), (-1,-1), 'Helvetica'),
                    ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0,0), (-1,-1), 8),
                    ('BACKGROUND', (0,0), (-1,0), dark_bg),
                    ('TEXTCOLOR', (0,0), (-1,0), colors.white),
                    ('ROWBACKGROUNDS', (0,1), (-1,-1), [light_gray, colors.white]),
                    ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#dee2e6')),
                    ('PADDING', (0,0), (-1,-1), 5),
                ]))
                content.append(Spacer(1, 0.2*cm))
                content.append(dir_table)

            # Enumeration
            content.append(PageBreak())
            content.append(Paragraph('4. Enumeration Findings', h1_style))
            content.append(HRFlowable(width='100%', thickness=1, color=colors.HexColor('#dee2e6')))
            content.append(Spacer(1, 0.3*cm))

            ports = self.results.get('ports', {})
            content.append(Paragraph('4.1 Port Scan Results', h2_style))
            content.append(Paragraph(
                f'Host: <b>{ports.get("host", "N/A")}</b> | IP: <b>{ports.get("ip", "N/A")}</b> | '
                f'Ports scanned: <b>{ports.get("total_scanned", 0)}</b> | '
                f'Open ports: <b>{len(ports.get("open", []))}</b>', body_style))

            services = self.results.get('services', {})
            if services:
                content.append(Spacer(1, 0.3*cm))
                content.append(Paragraph('4.2 Service Enumeration', h2_style))
                svc_data = [['Port', 'Service', 'Risk', 'Banner']]
                for port, info in services.items():
                    svc_data.append([
                        str(port),
                        info.get('service', 'Unknown'),
                        info.get('risk', 'Unknown'),
                        (info.get('banner', '') or '')[:40]
                    ])
                svc_table = Table(svc_data, colWidths=[2*cm, 4*cm, 3*cm, 8*cm])
                risk_colors = {'High': colors.HexColor('#ffeeee'), 'Medium': colors.HexColor('#fff8ee'), 'Low': light_gray}
                svc_style = [
                    ('FONTNAME', (0,0), (-1,-1), 'Helvetica'),
                    ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0,0), (-1,-1), 8),
                    ('BACKGROUND', (0,0), (-1,0), dark_bg),
                    ('TEXTCOLOR', (0,0), (-1,0), colors.white),
                    ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#dee2e6')),
                    ('PADDING', (0,0), (-1,-1), 5),
                ]
                for i, (port, info) in enumerate(services.items(), 1):
                    bg = risk_colors.get(info.get('risk', 'Low'), light_gray)
                    svc_style.append(('BACKGROUND', (0, i), (-1, i), bg))
                svc_table.setStyle(TableStyle(svc_style))
                content.append(svc_table)

            # Vulnerability Details
            content.append(PageBreak())
            content.append(Paragraph('5. Vulnerability Details', h1_style))
            content.append(HRFlowable(width='100%', thickness=1, color=colors.HexColor('#dee2e6')))
            content.append(Spacer(1, 0.3*cm))

            vuln_analysis = self.results.get('analysis', {}).get('vulnerabilities', [])
            sev_color = {'Critical': danger, 'High': colors.HexColor('#ff7700'),
                        'Medium': warning, 'Low': success, 'Info': gray}

            for i, vuln in enumerate(vuln_analysis[:20], 1):
                sev = vuln.get('severity', 'Info')
                color = sev_color.get(sev, gray)
                content.append(Paragraph(
                    f'<b>{i}. {vuln.get("type", vuln.get("header", "Finding"))}</b> '
                    f'<font color="{color.hexval() if hasattr(color, "hexval") else "#666666"}">'
                    f'[{sev}] CVSS: {vuln.get("cvss", "N/A")}</font>', body_style))
                if vuln.get('description'):
                    content.append(Paragraph(f'Description: {vuln["description"]}', small_style))
                if vuln.get('evidence'):
                    content.append(Paragraph(f'Evidence: {vuln["evidence"]}', small_style))
                if vuln.get('url'):
                    content.append(Paragraph(f'URL: {vuln["url"]}', small_style))
                if vuln.get('remediation'):
                    content.append(Paragraph(f'Remediation: {vuln["remediation"]}', small_style))
                content.append(Spacer(1, 0.2*cm))

            # Risk Ratings
            content.append(PageBreak())
            content.append(Paragraph('6. Risk Ratings', h1_style))
            content.append(HRFlowable(width='100%', thickness=1, color=colors.HexColor('#dee2e6')))
            content.append(Spacer(1, 0.3*cm))

            owasp_findings = self.results.get('owasp', {}).get('findings', [])
            if owasp_findings:
                owasp_data = [['OWASP Category', 'Status', 'Severity', 'CVSS']]
                for f in owasp_findings:
                    owasp_data.append([
                        f.get('category', ''),
                        f.get('status', ''),
                        f.get('severity', ''),
                        str(f.get('cvss', ''))
                    ])
                owasp_table = Table(owasp_data, colWidths=[6*cm, 5*cm, 3*cm, 2*cm])
                owasp_table.setStyle(TableStyle([
                    ('FONTNAME', (0,0), (-1,-1), 'Helvetica'),
                    ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0,0), (-1,-1), 8),
                    ('BACKGROUND', (0,0), (-1,0), dark_bg),
                    ('TEXTCOLOR', (0,0), (-1,0), colors.white),
                    ('ROWBACKGROUNDS', (0,1), (-1,-1), [light_gray, colors.white]),
                    ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#dee2e6')),
                    ('PADDING', (0,0), (-1,-1), 5),
                    ('VALIGN', (0,0), (-1,-1), 'TOP'),
                    ('WORDWRAP', (0,0), (-1,-1), True),
                ]))
                content.append(owasp_table)

            # Remediation
            content.append(PageBreak())
            content.append(Paragraph('7. Remediation Recommendations', h1_style))
            content.append(HRFlowable(width='100%', thickness=1, color=colors.HexColor('#dee2e6')))
            content.append(Spacer(1, 0.3*cm))
            for rec in self._remediation()[:10]:
                content.append(Paragraph(f'<b>{rec["finding"]}</b>', body_style))
                content.append(Paragraph(f'Priority: {rec["priority"]} | {rec["recommendation"]}', small_style))
                content.append(Spacer(1, 0.2*cm))

            # Conclusion
            content.append(PageBreak())
            content.append(Paragraph('8. Conclusion', h1_style))
            content.append(HRFlowable(width='100%', thickness=1, color=colors.HexColor('#dee2e6')))
            content.append(Spacer(1, 0.3*cm))
            content.append(Paragraph(self._conclusion(), body_style))
            content.append(Spacer(1, 1*cm))
            content.append(HRFlowable(width='100%', thickness=1, color=dark_bg))
            content.append(Spacer(1, 0.3*cm))
            content.append(Paragraph(
                f'This report was generated automatically by VulnPilot Security Scanner v1.0 on {self.timestamp}. '
                'For academic and authorized security testing use only.',
                small_style))

            doc.build(content)
            return path

        except ImportError:
            # Fallback: create a simple text-based PDF using basic method
            return self._generate_simple_pdf()

    def _generate_simple_pdf(self):
        """Fallback plain text report if reportlab is unavailable."""
        path = os.path.join(self.report_dir, f'{self.scan_id}.pdf')
        content = f"""VulnPilot Assessment Report
Target: {self.target}
Generated: {self.timestamp}
Scan ID: {self.scan_id}

This report requires reportlab to be installed for full PDF generation.
Please run: pip install reportlab

JSON report has been generated with full details.
"""
        with open(path, 'w') as f:
            f.write(content)
        return path

    def _executive_summary(self):
        analysis = self.results.get('analysis', {})
        sc = analysis.get('severity_counts', {})
        risk = analysis.get('overall_risk', 'Unknown')
        total = sum(sc.values())

        overview = (
            f"A comprehensive vulnerability assessment and penetration test was conducted against "
            f"the target '{self.target}'. The assessment identified {total} security findings, "
            f"comprising {sc.get('Critical', 0)} Critical, {sc.get('High', 0)} High, "
            f"{sc.get('Medium', 0)} Medium, and {sc.get('Low', 0)} Low severity issues. "
            f"The overall risk rating for the target is assessed as <b>{risk}</b>. "
            f"Immediate remediation of Critical and High severity findings is strongly recommended."
        )
        return {'overview': overview, 'risk': risk, 'total_findings': total, 'severity_counts': sc}

    def _risk_summary(self):
        return {
            'overall': self.results.get('analysis', {}).get('overall_risk', 'Unknown'),
            'score': self.results.get('analysis', {}).get('risk_score', 0),
            'counts': self.results.get('analysis', {}).get('severity_counts', {})
        }

    def _remediation(self):
        recs = []
        vulns = self.results.get('analysis', {}).get('vulnerabilities', [])
        for v in vulns:
            if v.get('remediation') or v.get('type'):
                recs.append({
                    'finding': v.get('type', v.get('header', 'Finding')),
                    'priority': v.get('severity', 'Low'),
                    'recommendation': v.get('remediation', 'Review and apply security best practices'),
                    'cvss': v.get('cvss', 0)
                })
        return recs

    def _conclusion(self):
        analysis = self.results.get('analysis', {})
        risk = analysis.get('overall_risk', 'Unknown')
        sc = analysis.get('severity_counts', {})
        return (
            f"The automated VulnPilot assessment of '{self.target}' has been completed. "
            f"The target demonstrates a {risk} overall security posture. "
            f"Key areas requiring immediate attention include: "
            f"{sc.get('Critical', 0)} critical vulnerabilities and {sc.get('High', 0)} high-severity issues. "
            f"It is recommended that the development and security teams prioritize remediation "
            f"of critical and high-severity findings before re-assessment. A follow-up pentest "
            f"is advised after remediation to validate that all identified vulnerabilities have been resolved. "
            f"All testing was performed in a controlled, authorized manner following ethical security research practices."
        )

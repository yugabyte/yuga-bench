"""
HTML Report Generator for YugabyteDB CIS Benchmark Tool
"""

from core.models import BenchmarkReport, ControlStatus


class HTMLReporter:
    """Generate HTML format reports"""

    @staticmethod
    def generate_report(report: BenchmarkReport, output_file: str):
        """Generate HTML report and save to file"""
        html_content = HTMLReporter._generate_html_content(report)

        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)

    @staticmethod
    def _generate_html_content(report: BenchmarkReport) -> str:
        """Generate complete HTML content"""
        return f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>YugabyteDB CIS Benchmark Report</title>
    {HTMLReporter._get_css_styles()}
</head>
<body>
    <div class="watermark">YugabyteDB</div>
    <div class="container">
        {HTMLReporter._generate_header(report)}
        {HTMLReporter._generate_summary_cards(report)}
        {HTMLReporter._generate_section_summaries(report)}
        {HTMLReporter._generate_detailed_results(report)}
    </div>
    {HTMLReporter._get_javascript()}
</body>
</html>"""

    @staticmethod
    def _get_css_styles() -> str:
        """Get CSS styles for the HTML report with YugabyteDB branding"""
        return """
    <style>
        :root {
            --yugabyte-orange: #FF6900;
            --yugabyte-dark-orange: #E55A00;
            --yugabyte-blue: #1F2F98;
            --yugabyte-light-blue: #4A90E2;
            --yugabyte-dark-blue: #0F1B5C;
            --yugabyte-black: #1A1A1A;
            --yugabyte-dark-gray: #2D2D2D;
            --yugabyte-light-gray: #F5F7FA;
            --yugabyte-border: #E1E5E9;
            --success-green: #22C55E;
            --error-red: #EF4444;
            --info-cyan: #06B6D4;
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            line-height: 1.6;
            color: var(--yugabyte-black);
            background: linear-gradient(135deg, #f8fafc 0%, #e2e8f0 100%);
            position: relative;
            min-height: 100vh;
        }

        .watermark {
            position: fixed;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%) rotate(-45deg);
            font-size: 8rem;
            font-weight: 900;
            color: rgba(31, 47, 152, 0.05);
            z-index: 0;
            pointer-events: none;
            user-select: none;
            text-transform: uppercase;
            letter-spacing: 0.1em;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            position: relative;
            z-index: 1;
        }

        .header {
            background: linear-gradient(135deg, var(--yugabyte-blue) 0%, var(--yugabyte-dark-blue) 50%, var(--yugabyte-orange) 100%);
            color: white;
            padding: 3rem 2rem;
            border-radius: 16px;
            margin-bottom: 2rem;
            box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.1), 0 10px 10px -5px rgba(0, 0, 0, 0.04);
            position: relative;
            overflow: hidden;
        }

        .header::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: url('data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><defs><pattern id="grid" width="10" height="10" patternUnits="userSpaceOnUse"><path d="M 10 0 L 0 0 0 10" fill="none" stroke="white" stroke-width="0.3" opacity="0.1"/></pattern></defs><rect width="100" height="100" fill="url(%23grid)"/></svg>');
            opacity: 0.3;
        }

        .header > * {
            position: relative;
            z-index: 2;
        }

        .header h1 {
            font-size: 2.8rem;
            margin-bottom: 1rem;
            font-weight: 800;
            text-shadow: 0 2px 4px rgba(0, 0, 0, 0.3);
        }

        .header p {
            margin: 0.5rem 0;
            opacity: 0.95;
            font-size: 1.1rem;
        }

        .summary-cards {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 1.5rem;
            margin-bottom: 2.5rem;
        }

        .summary-card {
            background: white;
            padding: 2rem 1.5rem;
            border-radius: 12px;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
            text-align: center;
            border-left: 6px solid var(--yugabyte-blue);
            transition: all 0.3s ease;
            position: relative;
            overflow: hidden;
        }

        .summary-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: linear-gradient(135deg, rgba(255, 105, 0, 0.05) 0%, transparent 50%);
        }

        .summary-card:hover {
            transform: translateY(-4px);
            box-shadow: 0 12px 25px -5px rgba(0, 0, 0, 0.15), 0 8px 10px -5px rgba(0, 0, 0, 0.1);
        }

        .summary-card.passed {
            border-left-color: var(--success-green);
            background: linear-gradient(135deg, rgba(34, 197, 94, 0.05) 0%, white 100%);
        }
        .summary-card.failed {
            border-left-color: var(--error-red);
            background: linear-gradient(135deg, rgba(239, 68, 68, 0.05) 0%, white 100%);
        }
        .summary-card.skipped {
            border-left-color: var(--yugabyte-dark-gray);
            background: linear-gradient(135deg, rgba(45, 45, 45, 0.05) 0%, white 100%);
        }

        .summary-card h3 {
            font-size: 3rem;
            margin-bottom: 0.5rem;
            font-weight: 800;
            position: relative;
        }

        .summary-card.passed h3 {
            color: var(--success-green);
            text-shadow: 0 2px 4px rgba(34, 197, 94, 0.2);
        }
        .summary-card.failed h3 {
            color: var(--error-red);
            text-shadow: 0 2px 4px rgba(239, 68, 68, 0.2);
        }
        .summary-card.skipped h3 {
            color: var(--yugabyte-dark-gray);
            text-shadow: 0 2px 4px rgba(45, 45, 45, 0.2);
        }

        .summary-card p {
            font-weight: 600;
            color: var(--yugabyte-black);
            font-size: 1.1rem;
            position: relative;
        }

        .section-summary {
            background: white;
            border-radius: 12px;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
            margin-bottom: 2rem;
            overflow: hidden;
            border: 1px solid var(--yugabyte-border);
        }

        .section-header {
            background: linear-gradient(135deg, var(--yugabyte-light-gray) 0%, #ffffff 100%);
            padding: 1.5rem;
            border-bottom: 2px solid var(--yugabyte-orange);
            cursor: pointer;
            transition: all 0.3s ease;
            position: relative;
        }

        .section-header:hover {
            background: linear-gradient(135deg, rgba(255, 105, 0, 0.1) 0%, #ffffff 100%);
            transform: translateX(4px);
        }

        .section-header h3 {
            margin: 0;
            font-size: 1.4rem;
            color: var(--yugabyte-blue);
            font-weight: 700;
        }

        .section-stats {
            display: flex;
            gap: 1rem;
            margin-top: 1rem;
            flex-wrap: wrap;
        }

        .section-stat {
            background: white;
            padding: 0.6rem 1.2rem;
            border-radius: 25px;
            font-size: 0.9rem;
            border: 2px solid var(--yugabyte-orange);
            color: var(--yugabyte-blue);
            font-weight: 600;
            box-shadow: 0 2px 4px rgba(255, 105, 0, 0.1);
        }

        .progress-bar {
            width: 100%;
            height: 10px;
            background: rgba(255, 105, 0, 0.2);
            border-radius: 6px;
            overflow: hidden;
            margin-top: 1rem;
        }

        .progress-fill {
            height: 100%;
            background: linear-gradient(90deg, var(--yugabyte-orange) 0%, var(--success-green) 100%);
            transition: width 0.5s ease;
            border-radius: 6px;
        }

        .controls-container {
            padding: 1.5rem;
            display: none;
            background: rgba(31, 47, 152, 0.02);
        }

        .controls-container.expanded {
            display: block;
        }

        .control {
            border: 1px solid var(--yugabyte-border);
            border-radius: 10px;
            margin-bottom: 1rem;
            overflow: hidden;
            transition: all 0.3s ease;
            background: white;
        }

        .control:hover {
            box-shadow: 0 8px 25px -5px rgba(0, 0, 0, 0.1);
            transform: translateY(-2px);
        }

        .control.pass {
            border-left: 5px solid var(--success-green);
            box-shadow: 0 0 0 1px rgba(34, 197, 94, 0.1);
        }
        .control.fail {
            border-left: 5px solid var(--error-red);
            box-shadow: 0 0 0 1px rgba(239, 68, 68, 0.1);
        }
        .control.skip {
            border-left: 5px solid var(--yugabyte-dark-gray);
            box-shadow: 0 0 0 1px rgba(45, 45, 45, 0.1);
        }
        .control.info {
            border-left: 5px solid var(--info-cyan);
            box-shadow: 0 0 0 1px rgba(6, 182, 212, 0.1);
        }

        .control-header {
            padding: 1.2rem 1.5rem;
            background: linear-gradient(135deg, rgba(255, 255, 255, 0.8) 0%, rgba(245, 247, 250, 0.8) 100%);
            cursor: pointer;
            display: flex;
            justify-content: space-between;
            align-items: center;
            transition: all 0.3s ease;
        }

        .control-header:hover {
            background: linear-gradient(135deg, rgba(255, 105, 0, 0.05) 0%, rgba(245, 247, 250, 0.8) 100%);
        }

        .control-body {
            padding: 1.5rem;
            background: white;
            display: none;
            border-top: 1px solid rgba(255, 105, 0, 0.1);
        }

        .control-body.expanded {
            display: block;
        }

        .status-badge {
            display: inline-block;
            padding: 0.4rem 1rem;
            border-radius: 25px;
            font-size: 0.8rem;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .status-badge.PASS {
            background: linear-gradient(135deg, var(--success-green) 0%, #16a34a 100%);
            color: white;
            box-shadow: 0 2px 4px rgba(34, 197, 94, 0.3);
        }

        .status-badge.FAIL {
            background: linear-gradient(135deg, var(--error-red) 0%, #dc2626 100%);
            color: white;
            box-shadow: 0 2px 4px rgba(239, 68, 68, 0.3);
        }

        .status-badge.SKIP {
            background: linear-gradient(135deg, var(--yugabyte-dark-gray) 0%, #404040 100%);
            color: white;
            box-shadow: 0 2px 4px rgba(45, 45, 45, 0.3);
        }

        .status-badge.INFO {
            background: linear-gradient(135deg, var(--info-cyan) 0%, #0891b2 100%);
            color: white;
            box-shadow: 0 2px 4px rgba(6, 182, 212, 0.3);
        }

        .remediation {
            background: linear-gradient(135deg, rgba(245, 158, 11, 0.1) 0%, rgba(252, 211, 77, 0.1) 100%);
            border: 2px solid rgba(245, 158, 11, 0.2);
            padding: 1.5rem;
            border-radius: 10px;
            margin-top: 1rem;
            position: relative;
        }

        .remediation::before {
            content: '⚠️';
            position: absolute;
            top: -8px;
            left: 15px;
            background: white;
            padding: 0 8px;
            font-size: 1.2rem;
        }

        .audit-cmd {
            background: linear-gradient(135deg, var(--yugabyte-black) 0%, var(--yugabyte-dark-gray) 100%);
            color: var(--yugabyte-orange);
            border: 1px solid var(--yugabyte-orange);
            padding: 1rem;
            border-radius: 8px;
            font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
            font-size: 0.9rem;
            margin: 0.5rem 0;
            overflow-x: auto;
            box-shadow: inset 0 2px 4px rgba(0, 0, 0, 0.3);
        }

        .detail-row {
            margin: 1rem 0;
            display: flex;
            flex-wrap: wrap;
            align-items: flex-start;
            gap: 0.5rem;
        }

        .detail-label {
            font-weight: 700;
            color: var(--yugabyte-blue);
            min-width: 120px;
            background: rgba(31, 47, 152, 0.1);
            padding: 0.3rem 0.8rem;
            border-radius: 6px;
            font-size: 0.9rem;
        }

        .chevron {
            transition: all 0.3s ease;
            color: var(--yugabyte-orange);
            font-weight: bold;
            font-size: 1.2rem;
        }

        .chevron.rotated {
            transform: rotate(90deg);
            color: var(--yugabyte-blue);
        }

        @media (max-width: 768px) {
            .container {
                padding: 15px;
            }

            .header {
                padding: 2rem 1.5rem;
            }

            .header h1 {
                font-size: 2.2rem;
            }

            .summary-cards {
                grid-template-columns: repeat(2, 1fr);
                gap: 1rem;
            }

            .summary-card {
                padding: 1.5rem 1rem;
            }

            .summary-card h3 {
                font-size: 2.5rem;
            }

            .section-stats {
                flex-direction: column;
                gap: 0.5rem;
            }

            .watermark {
                font-size: 4rem;
            }

            .detail-row {
                flex-direction: column;
                align-items: flex-start;
            }

            .detail-label {
                min-width: auto;
            }
        }
    </style>"""

    @staticmethod
    def _generate_header(report: BenchmarkReport) -> str:
        """Generate header section"""
        return f"""
        <div class="header">
            <h1>YugabyteDB CIS Benchmark Report</h1>
            <p><strong>Profile Level:</strong> {report.profile_level}</p>
            <p><strong>Cluster:</strong> {report.cluster_info.get('host')}:{report.cluster_info.get('port')}</p>
            <p><strong>Database:</strong> {report.cluster_info.get('database')}</p>
            <p><strong>Version:</strong> {report.cluster_info.get('version', 'Unknown')}</p>
            <p><strong>Scan Time:</strong> {report.scan_time.strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>"""

    @staticmethod
    def _generate_summary_cards(report: BenchmarkReport) -> str:
        """Generate summary cards"""
        return f"""
        <div class="summary-cards">
            <div class="summary-card">
                <h3>{report.total_checks}</h3>
                <p>Total Checks</p>
            </div>
            <div class="summary-card passed">
                <h3>{report.passed}</h3>
                <p>Passed</p>
            </div>
            <div class="summary-card failed">
                <h3>{report.failed}</h3>
                <p>Failed</p>
            </div>
            <div class="summary-card skipped">
                <h3>{report.skipped}</h3>
                <p>Skipped</p>
            </div>
        </div>"""

    @staticmethod
    def _generate_section_summaries(report: BenchmarkReport) -> str:
        """Generate section summaries"""
        sections_html = ""

        for section in report.section_summaries:
            section_results = [r for r in report.results if r.section == section.section_name]
            controls_html = ""

            for result in section_results:
                status_class = result.status.value.lower()
                controls_html += f"""
                <div class="control {status_class}">
                    <div class="control-header" onclick="toggleControl(this)">
                        <div>
                            <strong>{result.control_id}: {result.title}</strong>
                        </div>
                        <div>
                            <span class="status-badge {result.status.value}">{result.status.value}</span>
                            <span class="chevron">▶</span>
                        </div>
                    </div>
                    <div class="control-body">
                        <div class="detail-row">
                            <span class="detail-label">Message:</span>
                            <span>{result.message}</span>
                        </div>
                        <div class="detail-row">
                            <span class="detail-label">Profile Level:</span>
                            <span>{result.profile_level}</span>
                        </div>"""

                if result.expected and result.actual:
                    controls_html += f"""
                        <div class="detail-row">
                            <span class="detail-label">Expected:</span>
                            <span>{result.expected}</span>
                        </div>
                        <div class="detail-row">
                            <span class="detail-label">Actual:</span>
                            <span>{result.actual}</span>
                        </div>"""

                if result.audit_command:
                    controls_html += f"""
                        <div class="detail-row">
                            <span class="detail-label">Audit Command:</span>
                            <div class="audit-cmd">{result.audit_command}</div>
                        </div>"""

                if result.remediation:
                    controls_html += f"""
                        <div class="remediation">
                            <strong>Remediation:</strong><br>
                            {result.remediation.replace(chr(10), '<br>')}
                        </div>"""

                if result.impact:
                    controls_html += f"""
                        <div class="detail-row">
                            <span class="detail-label">Impact:</span>
                            <span>{result.impact}</span>
                        </div>"""

                controls_html += """
                    </div>
                </div>"""

            sections_html += f"""
            <div class="section-summary">
                <div class="section-header" onclick="toggleSection(this)">
                    <h3>{section.section_name} <span class="chevron">▶</span></h3>
                    <div class="section-stats">
                        <div class="section-stat">Total: {section.total_controls}</div>
                        <div class="section-stat">Passed: {section.passed}</div>
                        <div class="section-stat">Failed: {section.failed}</div>
                        <div class="section-stat">Pass Rate: {section.pass_percentage:.1f}%</div>
                    </div>
                    <div class="progress-bar">
                        <div class="progress-fill" style="width: {section.pass_percentage}%;"></div>
                    </div>
                </div>
                <div class="controls-container">
                    {controls_html}
                </div>
            </div>"""

        return sections_html

    @staticmethod
    def _generate_detailed_results(report: BenchmarkReport) -> str:
        """Generate detailed results section"""
        # This is handled within section summaries
        return ""

    @staticmethod
    def _get_javascript() -> str:
        """Get JavaScript for interactive functionality"""
        return """
    <script>
        function toggleSection(element) {
            const container = element.parentElement.querySelector('.controls-container');
            const chevron = element.querySelector('.chevron');

            container.classList.toggle('expanded');
            chevron.classList.toggle('rotated');
        }

        function toggleControl(element) {
            const body = element.nextElementSibling;
            const chevron = element.querySelector('.chevron');

            body.classList.toggle('expanded');
            chevron.classList.toggle('rotated');
        }

        // Auto-expand failed sections with animation
        document.addEventListener('DOMContentLoaded', function() {
            const failedSections = document.querySelectorAll('.section-summary');
            failedSections.forEach((section, index) => {
                const failedControls = section.querySelectorAll('.control.fail');
                if (failedControls.length > 0) {
                    setTimeout(() => {
                        const header = section.querySelector('.section-header');
                        toggleSection(header);
                    }, index * 200); // Stagger the animations
                }
            });

            // Add smooth scrolling to all internal links
            document.querySelectorAll('a[href^="#"]').forEach(anchor => {
                anchor.addEventListener('click', function (e) {
                    e.preventDefault();
                    document.querySelector(this.getAttribute('href')).scrollIntoView({
                        behavior: 'smooth'
                    });
                });
            });
        });

        // Add keyboard navigation
        document.addEventListener('keydown', function(e) {
            if (e.key === 'Escape') {
                // Close all expanded sections
                document.querySelectorAll('.controls-container.expanded').forEach(container => {
                    const header = container.previousElementSibling;
                    toggleSection(header);
                });

                document.querySelectorAll('.control-body.expanded').forEach(body => {
                    const header = body.previousElementSibling;
                    toggleControl(header);
                });
            }
        });
    </script>"""

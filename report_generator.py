"""
Report Generator Module

This module generates threat modeling and risk assessment reports in various formats.
"""

import json
import logging
import os
from typing import Dict, List, Optional

from diagram_parser import Component
from threat_analyzer import Threat
from risk_assessor import Risk

logger = logging.getLogger(__name__)

class ReportGenerator:
    """Generates threat modeling and risk assessment reports."""
    
    def __init__(self):
        """Initialize the report generator."""
        # Check for optional dependencies
        try:
            import fpdf
            self.pdf_available = True
        except ImportError:
            self.pdf_available = False
            logger.warning("fpdf not installed. PDF report generation will not be available.")
            
        try:
            import markdown
            self.markdown_available = True
        except ImportError:
            self.markdown_available = False
            logger.warning("markdown not installed. HTML report generation may have limited formatting.")
    
    def generate(self, components: List[Component], threats: List[Threat], 
                 risks: List[Risk], output_path: str, format: str = "pdf") -> str:
        """
        Generate a threat modeling and risk assessment report.
        
        Args:
            components: List of components in the architecture
            threats: List of identified threats
            risks: List of risk assessments
            output_path: Path where the report should be saved
            format: Report format ("pdf", "html", "json", or "md")
            
        Returns:
            Path to the generated report
        """
        logger.info(f"Generating {format} report at {output_path}")
        
        # Ensure the output directory exists
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        
        # Generate report in the specified format
        if format == "pdf":
            return self._generate_pdf_report(components, threats, risks, output_path)
        elif format == "html":
            return self._generate_html_report(components, threats, risks, output_path)
        elif format == "json":
            return self._generate_json_report(components, threats, risks, output_path)
        elif format == "md":
            return self._generate_markdown_report(components, threats, risks, output_path)
        else:
            logger.error(f"Unsupported report format: {format}")
            raise ValueError(f"Unsupported report format: {format}")
    
    def _generate_pdf_report(self, components: List[Component], threats: List[Threat], 
                            risks: List[Risk], output_path: str) -> str:
        """Generate a PDF report."""
        if not self.pdf_available:
            logger.warning("PDF generation not available. Falling back to Markdown.")
            md_path = self._generate_markdown_report(components, threats, risks, 
                                                   output_path.replace(".pdf", ".md"))
            logger.info(f"Generated Markdown report instead: {md_path}")
            return md_path
            
        try:
            from fpdf import FPDF
            
            # Create PDF object with UTF-8 encoding
            pdf = FPDF()
            pdf.add_page()
            
            # Title
            pdf.set_font("Arial", "B", 16)
            pdf.cell(0, 10, "Architectural Diagram Threat Model & Risk Assessment", ln=True, align="C")
            pdf.ln(10)
            
            # Executive Summary
            pdf.set_font("Arial", "B", 14)
            pdf.cell(0, 10, "Executive Summary", ln=True)
            pdf.set_font("Arial", "", 11)
            pdf.multi_cell(0, 5, f"This report presents a security analysis of the provided architectural diagram. "
                          f"A total of {len(components)} components were identified, with {len(threats)} potential "
                          f"security threats and corresponding risk assessments.")
            pdf.ln(5)
            
            # Components Section
            pdf.set_font("Arial", "B", 14)
            pdf.cell(0, 10, "Identified Components", ln=True)
            pdf.set_font("Arial", "", 11)
            
            for component in components:
                pdf.set_font("Arial", "B", 11)
                pdf.cell(0, 5, f"{component.name} ({component.component_type.value})", ln=True)
                pdf.set_font("Arial", "", 11)
                pdf.cell(0, 5, f"ID: {component.id}", ln=True)
                if component.connections:
                    pdf.cell(0, 5, f"Connections: {len(component.connections)}", ln=True)
                pdf.ln(2)
            
            pdf.ln(5)
            
            # Threats Section
            pdf.set_font("Arial", "B", 14)
            pdf.cell(0, 10, "Identified Threats", ln=True)
            
            # Group threats by severity
            severity_order = ["Critical", "High", "Medium", "Low"]
            threats_by_severity = {}
            for severity in severity_order:
                threats_by_severity[severity] = [t for t in threats if t.severity == severity]
            
            for severity in severity_order:
                if threats_by_severity[severity]:
                    pdf.set_font("Arial", "B", 12)
                    pdf.cell(0, 8, f"{severity} Severity Threats", ln=True)
                    
                    for threat in threats_by_severity[severity]:
                        pdf.set_font("Arial", "B", 11)
                        pdf.cell(0, 5, f"{threat.name} ({threat.id})", ln=True)
                        pdf.set_font("Arial", "", 11)
                        pdf.multi_cell(0, 5, f"Type: {threat.threat_type}")
                        pdf.multi_cell(0, 5, f"Description: {threat.description}")
                        
                        # Find the corresponding risk
                        risk = next((r for r in risks if r.threat_id == threat.id), None)
                        if risk:
                            pdf.multi_cell(0, 5, f"Risk: {risk.likelihood} likelihood, {risk.impact} impact (Score: {risk.risk_score})")
                        
                        # Affected components
                        affected_names = []
                        for comp_id in threat.affected_components:
                            comp = next((c for c in components if c.id == comp_id), None)
                            if comp:
                                affected_names.append(comp.name)
                        
                        if affected_names:
                            pdf.multi_cell(0, 5, f"Affected Components: {', '.join(affected_names)}")
                        
                        # Mitigations
                        if threat.mitigations:
                            pdf.set_font("Arial", "I", 11)
                            pdf.cell(0, 5, "Mitigations:", ln=True)
                            pdf.set_font("Arial", "", 11)
                            for mitigation in threat.mitigations:
                                pdf.cell(10, 5, "-", ln=0)
                                pdf.multi_cell(0, 5, mitigation)
                        
                        pdf.ln(5)
            
            # Risk Assessment Section
            pdf.add_page()
            pdf.set_font("Arial", "B", 14)
            pdf.cell(0, 10, "Risk Assessment", ln=True)
            
            # Sort risks by score (highest first)
            sorted_risks = sorted(risks, key=lambda r: r.risk_score, reverse=True)
            
            for risk in sorted_risks:
                # Find the corresponding threat
                threat = next((t for t in threats if t.id == risk.threat_id), None)
                if not threat:
                    continue
                    
                pdf.set_font("Arial", "B", 11)
                pdf.cell(0, 5, f"{threat.name} ({threat.id})", ln=True)
                pdf.set_font("Arial", "", 11)
                pdf.multi_cell(0, 5, f"Risk Score: {risk.risk_score} ({risk.likelihood} likelihood, {risk.impact} impact)")
                
                # Recommendations
                if risk.recommendations:
                    pdf.set_font("Arial", "I", 11)
                    pdf.cell(0, 5, "Recommendations:", ln=True)
                    pdf.set_font("Arial", "", 11)
                    for recommendation in risk.recommendations:
                        pdf.cell(10, 5, "-", ln=0)
                        pdf.multi_cell(0, 5, recommendation)
                
                pdf.ln(5)
            
            # Save the PDF
            pdf.output(output_path)
            logger.info(f"Generated PDF report: {output_path}")
            return output_path
            
        except Exception as e:
            logger.exception(f"Error generating PDF report: {str(e)}")
            # Fall back to markdown
            md_path = self._generate_markdown_report(components, threats, risks, 
                                                   output_path.replace(".pdf", ".md"))
            logger.info(f"Generated Markdown report instead: {md_path}")
            return md_path
    
    def _generate_html_report(self, components: List[Component], threats: List[Threat], 
                             risks: List[Risk], output_path: str) -> str:
        """Generate an HTML report."""
        try:
            # Generate markdown content
            md_content = self._generate_markdown_content(components, threats, risks)
            
            # Convert markdown to HTML
            if self.markdown_available:
                import markdown
                html_content = markdown.markdown(md_content, extensions=['tables'])
            else:
                # Simple conversion without markdown library
                html_content = md_content.replace("\n", "<br>")
                html_content = html_content.replace("# ", "<h1>").replace("\n<br>", "</h1>")
                html_content = html_content.replace("## ", "<h2>").replace("\n<br>", "</h2>")
                html_content = html_content.replace("### ", "<h3>").replace("\n<br>", "</h3>")
            
            # Add HTML structure and styling
            html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Threat Model & Risk Assessment</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            color: #333;
        }}
        h1 {{
            color: #2c3e50;
            border-bottom: 2px solid #3498db;
            padding-bottom: 10px;
        }}
        h2 {{
            color: #2c3e50;
            margin-top: 30px;
        }}
        h3 {{
            color: #3498db;
        }}
        table {{
            border-collapse: collapse;
            width: 100%;
            margin: 20px 0;
        }}
        th, td {{
            border: 1px solid #ddd;
            padding: 8px;
            text-align: left;
        }}
        th {{
            background-color: #f2f2f2;
        }}
        .severity-critical {{
            background-color: #ffdddd;
        }}
        .severity-high {{
            background-color: #ffe6cc;
        }}
        .severity-medium {{
            background-color: #fff2cc;
        }}
        .severity-low {{
            background-color: #e6f2ff;
        }}
        .risk-high {{
            background-color: #ffdddd;
        }}
        .risk-medium {{
            background-color: #fff2cc;
        }}
        .risk-low {{
            background-color: #e6f2ff;
        }}
    </style>
</head>
<body>
    {html_content}
</body>
</html>
"""
            
            # Write HTML to file
            with open(output_path, 'w') as f:
                f.write(html)
                
            logger.info(f"Generated HTML report: {output_path}")
            return output_path
            
        except Exception as e:
            logger.exception(f"Error generating HTML report: {str(e)}")
            # Fall back to markdown
            md_path = self._generate_markdown_report(components, threats, risks, 
                                                   output_path.replace(".html", ".md"))
            logger.info(f"Generated Markdown report instead: {md_path}")
            return md_path
    
    def _generate_json_report(self, components: List[Component], threats: List[Threat], 
                             risks: List[Risk], output_path: str) -> str:
        """Generate a JSON report."""
        try:
            # Create a dictionary structure for the report
            report = {
                "components": [],
                "threats": [],
                "risks": []
            }
            
            # Add components
            for component in components:
                comp_dict = {
                    "id": component.id,
                    "name": component.name,
                    "type": component.component_type.value,
                    "position": component.position,
                    "properties": component.properties,
                    "connections": component.connections
                }
                report["components"].append(comp_dict)
                
            # Add threats
            for threat in threats:
                threat_dict = {
                    "id": threat.id,
                    "name": threat.name,
                    "description": threat.description,
                    "severity": threat.severity,
                    "threat_type": threat.threat_type,
                    "affected_components": threat.affected_components,
                    "mitigations": threat.mitigations
                }
                report["threats"].append(threat_dict)
                
            # Add risks
            for risk in risks:
                risk_dict = {
                    "threat_id": risk.threat_id,
                    "likelihood": risk.likelihood,
                    "impact": risk.impact,
                    "risk_score": risk.risk_score,
                    "recommendations": risk.recommendations
                }
                report["risks"].append(risk_dict)
                
            # Write JSON to file
            with open(output_path, 'w') as f:
                json.dump(report, f, indent=2)
                
            logger.info(f"Generated JSON report: {output_path}")
            return output_path
            
        except Exception as e:
            logger.exception(f"Error generating JSON report: {str(e)}")
            # Fall back to markdown
            md_path = self._generate_markdown_report(components, threats, risks, 
                                                   output_path.replace(".json", ".md"))
            logger.info(f"Generated Markdown report instead: {md_path}")
            return md_path
    
    def _generate_markdown_report(self, components: List[Component], threats: List[Threat], 
                                 risks: List[Risk], output_path: str) -> str:
        """Generate a Markdown report."""
        try:
            # Generate markdown content
            md_content = self._generate_markdown_content(components, threats, risks)
            
            # Write markdown to file
            with open(output_path, 'w') as f:
                f.write(md_content)
                
            logger.info(f"Generated Markdown report: {output_path}")
            return output_path
            
        except Exception as e:
            logger.exception(f"Error generating Markdown report: {str(e)}")
            raise
    
    def _generate_markdown_content(self, components: List[Component], threats: List[Threat], 
                                  risks: List[Risk]) -> str:
        """Generate the markdown content for the report."""
        md = []
        
        # Title
        md.append("# Architectural Diagram Threat Model & Risk Assessment\n")
        
        # Executive Summary
        md.append("## Executive Summary\n")
        md.append(f"This report presents a security analysis of the provided architectural diagram. "
                 f"A total of {len(components)} components were identified, with {len(threats)} potential "
                 f"security threats and corresponding risk assessments.\n")
        
        # Components Section
        md.append("## Identified Components\n")
        
        for component in components:
            md.append(f"### {component.name} ({component.component_type.value})\n")
            md.append(f"- **ID**: {component.id}\n")
            
            if component.connections:
                md.append(f"- **Connections**: {len(component.connections)}\n")
                for conn in component.connections:
                    target_id = conn["target_id"]
                    target = next((c for c in components if c.id == target_id), None)
                    target_name = target.name if target else target_id
                    md.append(f"  - Connected to {target_name} ({conn.get('type', 'default')})\n")
            
            md.append("\n")
        
        # Threats Section
        md.append("## Identified Threats\n")
        
        # Group threats by severity
        severity_order = ["Critical", "High", "Medium", "Low"]
        threats_by_severity = {}
        for severity in severity_order:
            threats_by_severity[severity] = [t for t in threats if t.severity == severity]
        
        for severity in severity_order:
            if threats_by_severity[severity]:
                md.append(f"### {severity} Severity Threats\n")
                
                for threat in threats_by_severity[severity]:
                    md.append(f"#### {threat.name} ({threat.id})\n")
                    md.append(f"- **Type**: {threat.threat_type}\n")
                    md.append(f"- **Description**: {threat.description}\n")
                    
                    # Find the corresponding risk
                    risk = next((r for r in risks if r.threat_id == threat.id), None)
                    if risk:
                        md.append(f"- **Risk**: {risk.likelihood} likelihood, {risk.impact} impact (Score: {risk.risk_score})\n")
                    
                    # Affected components
                    affected_names = []
                    for comp_id in threat.affected_components:
                        comp = next((c for c in components if c.id == comp_id), None)
                        if comp:
                            affected_names.append(comp.name)
                    
                    if affected_names:
                        md.append(f"- **Affected Components**: {', '.join(affected_names)}\n")
                    
                    # Mitigations
                    if threat.mitigations:
                        md.append("- **Mitigations**:\n")
                        for mitigation in threat.mitigations:
                            md.append(f"  - {mitigation}\n")
                    
                    md.append("\n")
        
        # Risk Assessment Section
        md.append("## Risk Assessment\n")
        
        # Sort risks by score (highest first)
        sorted_risks = sorted(risks, key=lambda r: r.risk_score, reverse=True)
        
        # Risk matrix table
        md.append("### Risk Matrix\n")
        md.append("| Threat | Likelihood | Impact | Risk Score |\n")
        md.append("|--------|------------|--------|------------|\n")
        
        for risk in sorted_risks:
            # Find the corresponding threat
            threat = next((t for t in threats if t.id == risk.threat_id), None)
            if not threat:
                continue
                
            md.append(f"| {threat.name} ({threat.id}) | {risk.likelihood} | {risk.impact} | {risk.risk_score} |\n")
        
        md.append("\n")
        
        # Detailed risk assessments
        md.append("### Detailed Risk Assessments\n")
        
        for risk in sorted_risks:
            # Find the corresponding threat
            threat = next((t for t in threats if t.id == risk.threat_id), None)
            if not threat:
                continue
                
            md.append(f"#### {threat.name} ({threat.id})\n")
            md.append(f"- **Risk Score**: {risk.risk_score} ({risk.likelihood} likelihood, {risk.impact} impact)\n")
            
            # Recommendations
            if risk.recommendations:
                md.append("- **Recommendations**:\n")
                for recommendation in risk.recommendations:
                    md.append(f"  - {recommendation}\n")
            
            md.append("\n")
        
        return "\n".join(md)
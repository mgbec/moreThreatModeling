#!/usr/bin/env python3
"""
Architectural Diagram Threat Modeler

This tool ingests architectural diagrams and produces threat modeling and risk assessment
information based on the identified components and their relationships.
"""

import argparse
import logging
import os
import sys
from typing import Dict, List, Optional, Tuple

from diagram_parser import DiagramParser
from threat_analyzer import ThreatAnalyzer
from risk_assessor import RiskAssessor
from report_generator import ReportGenerator

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("arch_threat_modeler.log"),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Analyze architectural diagrams for security threats and risks"
    )
    parser.add_argument(
        "diagram_path", 
        help="Path to the architectural diagram file"
    )
    parser.add_argument(
        "--output", "-o", 
        default="threat_report.pdf",
        help="Output file path for the threat modeling report"
    )
    parser.add_argument(
        "--format", "-f", 
        choices=["pdf", "html", "json", "md"], 
        default="pdf",
        help="Output format for the report"
    )
    parser.add_argument(
        "--threat-db", 
        default="default",
        help="Path to custom threat database"
    )
    parser.add_argument(
        "--verbose", "-v", 
        action="store_true",
        help="Enable verbose output"
    )
    
    return parser.parse_args()

def main():
    """Main entry point for the application."""
    try:
        # Parse command line arguments
        args = parse_arguments()
        
        # Set logging level based on verbosity
        if args.verbose:
            logging.getLogger().setLevel(logging.DEBUG)
            
        logger.info(f"Starting analysis of diagram: {args.diagram_path}")
        
        # Validate input file exists
        if not os.path.exists(args.diagram_path):
            logger.error(f"Diagram file not found: {args.diagram_path}")
            sys.exit(1)
            
        # Parse the architectural diagram
        parser = DiagramParser()
        components = parser.parse(args.diagram_path)
        logger.info(f"Identified {len(components)} components in the diagram")
        
        # Analyze threats
        threat_analyzer = ThreatAnalyzer(threat_db_path=args.threat_db)
        threats = threat_analyzer.analyze(components)
        logger.info(f"Identified {len(threats)} potential threats")
        
        # Assess risks
        risk_assessor = RiskAssessor()
        risks = risk_assessor.assess(components, threats)
        logger.info(f"Completed risk assessment")
        
        # Generate report
        report_generator = ReportGenerator()
        report_path = report_generator.generate(
            components, 
            threats, 
            risks, 
            output_path=args.output, 
            format=args.format
        )
        
        logger.info(f"Report generated successfully: {report_path}")
        
    except Exception as e:
        logger.exception(f"Error during execution: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
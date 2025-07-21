"""
Threat Analyzer Module

This module analyzes architectural components to identify potential security threats.
"""

import json
import logging
import os
from typing import Dict, List, Optional

from diagram_parser import Component, ComponentType

logger = logging.getLogger(__name__)

class Threat:
    """Represents a security threat identified in the architecture."""
    
    def __init__(self, id: str, name: str, description: str, severity: str,
                 affected_components: List[str], threat_type: str, 
                 mitigations: List[str] = None):
        """
        Initialize a threat.
        
        Args:
            id: Unique identifier for the threat
            name: Name of the threat
            description: Description of the threat
            severity: Severity level (e.g., "High", "Medium", "Low")
            affected_components: List of component IDs affected by this threat
            threat_type: Type of threat (e.g., "Spoofing", "Tampering", etc.)
            mitigations: List of potential mitigations for this threat
        """
        self.id = id
        self.name = name
        self.description = description
        self.severity = severity
        self.affected_components = affected_components
        self.threat_type = threat_type
        self.mitigations = mitigations or []
        
    def __repr__(self) -> str:
        """String representation of the threat."""
        return f"Threat({self.id}, {self.name}, {self.severity})"

class ThreatAnalyzer:
    """Analyzes architectural components to identify potential security threats."""
    
    def __init__(self, threat_db_path: str = "default"):
        """
        Initialize the threat analyzer.
        
        Args:
            threat_db_path: Path to the threat database file or "default" to use built-in
        """
        self.threat_db = self._load_threat_database(threat_db_path)
        
    def analyze(self, components: List[Component]) -> List[Threat]:
        """
        Analyze components to identify potential security threats.
        
        Args:
            components: List of components to analyze
            
        Returns:
            List of identified threats
        """
        logger.info("Starting threat analysis")
        threats = []
        
        # Analyze individual components
        for component in components:
            component_threats = self._analyze_component(component)
            threats.extend(component_threats)
            
        # Analyze connections between components
        connection_threats = self._analyze_connections(components)
        threats.extend(connection_threats)
        
        # Analyze the overall architecture
        architecture_threats = self._analyze_architecture(components)
        threats.extend(architecture_threats)
        
        logger.info(f"Identified {len(threats)} potential threats")
        return threats
    
    def _load_threat_database(self, threat_db_path: str) -> Dict:
        """
        Load the threat database from a file or use the built-in database.
        
        Args:
            threat_db_path: Path to the threat database file or "default"
            
        Returns:
            Dictionary containing threat patterns
        """
        if threat_db_path == "default":
            # Use built-in threat database
            return self._get_default_threat_db()
        
        try:
            with open(threat_db_path, 'r') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Failed to load threat database: {str(e)}")
            logger.info("Falling back to default threat database")
            return self._get_default_threat_db()
    
    def _get_default_threat_db(self) -> Dict:
        """
        Get the default built-in threat database.
        
        Returns:
            Dictionary containing threat patterns
        """
        # This is a simplified threat database
        # In a real implementation, this would be much more comprehensive
        return {
            "component_threats": {
                ComponentType.SERVER.value: [
                    {
                        "id": "T001",
                        "name": "Unpatched Server Vulnerabilities",
                        "description": "Servers may have unpatched vulnerabilities that can be exploited",
                        "severity": "High",
                        "threat_type": "Vulnerability",
                        "mitigations": [
                            "Implement regular patching schedule",
                            "Use vulnerability scanning tools",
                            "Implement host-based intrusion detection"
                        ]
                    },
                    {
                        "id": "T002",
                        "name": "Denial of Service",
                        "description": "Servers may be vulnerable to denial of service attacks",
                        "severity": "Medium",
                        "threat_type": "Denial of Service",
                        "mitigations": [
                            "Implement rate limiting",
                            "Use DDoS protection services",
                            "Scale infrastructure to handle load"
                        ]
                    }
                ],
                ComponentType.DATABASE.value: [
                    {
                        "id": "T003",
                        "name": "SQL Injection",
                        "description": "Databases may be vulnerable to SQL injection attacks",
                        "severity": "High",
                        "threat_type": "Injection",
                        "mitigations": [
                            "Use parameterized queries",
                            "Implement input validation",
                            "Apply principle of least privilege for database users"
                        ]
                    },
                    {
                        "id": "T004",
                        "name": "Sensitive Data Exposure",
                        "description": "Databases may expose sensitive data if not properly secured",
                        "severity": "High",
                        "threat_type": "Information Disclosure",
                        "mitigations": [
                            "Encrypt sensitive data",
                            "Implement proper access controls",
                            "Use data masking for non-production environments"
                        ]
                    },
                    {
                        "id": "T005",
                        "name": "Excessive Privilege",
                        "description": "Database users may have more privileges than necessary, increasing attack surface",
                        "severity": "Medium",
                        "threat_type": "Access Control",
                        "mitigations": [
                            "Implement principle of least privilege",
                            "Regularly audit user permissions",
                            "Use role-based access control"
                        ]
                    },
                    {
                        "id": "T006",
                        "name": "Insecure Database Backup",
                        "description": "Database backups may not be properly secured, leading to data exposure",
                        "severity": "Medium",
                        "threat_type": "Information Disclosure",
                        "mitigations": [
                            "Encrypt database backups",
                            "Implement secure backup storage",
                            "Establish backup retention policies"
                        ]
                    }
                ],
                ComponentType.API_GATEWAY.value: [
                    {
                        "id": "T007",
                        "name": "API Rate Limiting Bypass",
                        "description": "Attackers may bypass rate limiting controls to perform denial of service",
                        "severity": "Medium",
                        "threat_type": "Denial of Service",
                        "mitigations": [
                            "Implement robust rate limiting algorithms",
                            "Use client identification beyond IP address",
                            "Monitor for unusual traffic patterns"
                        ]
                    },
                    {
                        "id": "T008",
                        "name": "Improper API Authentication",
                        "description": "Weak authentication mechanisms may allow unauthorized API access",
                        "severity": "High",
                        "threat_type": "Authentication",
                        "mitigations": [
                            "Use strong authentication protocols (OAuth 2.0, JWT)",
                            "Implement multi-factor authentication for sensitive operations",
                            "Regularly rotate API keys and secrets"
                        ]
                    }
                ],
                ComponentType.CONTAINER.value: [
                    {
                        "id": "T009",
                        "name": "Container Escape",
                        "description": "Attackers may escape container isolation and access the host system",
                        "severity": "Critical",
                        "threat_type": "Privilege Escalation",
                        "mitigations": [
                            "Use container security scanning tools",
                            "Apply security hardening to container configurations",
                            "Implement container runtime security monitoring"
                        ]
                    },
                    {
                        "id": "T010",
                        "name": "Insecure Container Images",
                        "description": "Container images may contain vulnerabilities or malicious code",
                        "severity": "High",
                        "threat_type": "Vulnerability",
                        "mitigations": [
                            "Use minimal base images",
                            "Scan images for vulnerabilities before deployment",
                            "Implement a secure container registry"
                        ]
                    }
                ],
                # Add more component types and their threats
            },
            "connection_threats": [
                {
                    "id": "T101",
                    "name": "Unencrypted Communication",
                    "description": "Data transmitted between components may be intercepted if not encrypted",
                    "severity": "High",
                    "threat_type": "Information Disclosure",
                    "mitigations": [
                        "Use TLS/SSL for all communications",
                        "Implement proper certificate management",
                        "Regularly audit encryption configurations"
                    ]
                },
                {
                    "id": "T102",
                    "name": "Man-in-the-Middle Attack",
                    "description": "Connections may be vulnerable to man-in-the-middle attacks",
                    "severity": "High",
                    "threat_type": "Tampering",
                    "mitigations": [
                        "Use mutual TLS authentication",
                        "Implement certificate pinning",
                        "Use secure communication protocols"
                    ]
                },
                {
                    "id": "T103",
                    "name": "Insecure API Endpoints",
                    "description": "API endpoints may not properly validate input or enforce authentication",
                    "severity": "High",
                    "threat_type": "Injection",
                    "mitigations": [
                        "Implement comprehensive input validation",
                        "Use API gateways with security controls",
                        "Apply consistent authentication across all endpoints"
                    ]
                },
                {
                    "id": "T104",
                    "name": "Insecure Service-to-Service Communication",
                    "description": "Internal service communications may lack proper authentication or encryption",
                    "severity": "Medium",
                    "threat_type": "Authentication",
                    "mitigations": [
                        "Implement service mesh for secure communication",
                        "Use mutual TLS between services",
                        "Implement service-to-service authentication"
                    ]
                },
                {
                    "id": "T105",
                    "name": "Data Validation Failures",
                    "description": "Data passed between components may not be properly validated, leading to injection or processing errors",
                    "severity": "Medium",
                    "threat_type": "Validation",
                    "mitigations": [
                        "Implement consistent data validation at all boundaries",
                        "Use schema validation for data interchange",
                        "Apply defensive programming techniques"
                    ]
                }
            ],
            "architecture_threats": [
                {
                    "id": "T201",
                    "name": "Insufficient Network Segmentation",
                    "description": "Lack of network segmentation may allow lateral movement in case of breach",
                    "severity": "Medium",
                    "threat_type": "Lateral Movement",
                    "mitigations": [
                        "Implement network segmentation",
                        "Use firewalls between segments",
                        "Apply zero trust principles"
                    ]
                },
                {
                    "id": "T202",
                    "name": "Single Point of Failure",
                    "description": "Architecture may have single points of failure affecting availability",
                    "severity": "Medium",
                    "threat_type": "Availability",
                    "mitigations": [
                        "Implement redundancy",
                        "Use load balancing",
                        "Design for fault tolerance"
                    ]
                },
                {
                    "id": "T203",
                    "name": "Inadequate Logging and Monitoring",
                    "description": "Insufficient logging and monitoring may prevent detection of security incidents",
                    "severity": "Medium",
                    "threat_type": "Detection",
                    "mitigations": [
                        "Implement centralized logging",
                        "Deploy intrusion detection systems",
                        "Establish security monitoring and alerting"
                    ]
                },
                {
                    "id": "T204",
                    "name": "Insecure Deployment Pipeline",
                    "description": "Vulnerabilities may be introduced through an insecure CI/CD pipeline",
                    "severity": "High",
                    "threat_type": "Supply Chain",
                    "mitigations": [
                        "Implement security scanning in CI/CD pipeline",
                        "Use infrastructure as code security scanning",
                        "Apply principle of least privilege to deployment processes"
                    ]
                },
                {
                    "id": "T205",
                    "name": "Inadequate Disaster Recovery",
                    "description": "Lack of disaster recovery planning may lead to extended outages",
                    "severity": "Medium",
                    "threat_type": "Availability",
                    "mitigations": [
                        "Develop and test disaster recovery plans",
                        "Implement multi-region redundancy",
                        "Establish recovery time objectives and recovery point objectives"
                    ]
                },
                {
                    "id": "T206",
                    "name": "Insufficient Access Controls",
                    "description": "Inadequate access controls across the architecture may lead to unauthorized access",
                    "severity": "High",
                    "threat_type": "Access Control",
                    "mitigations": [
                        "Implement consistent identity and access management",
                        "Apply principle of least privilege across all systems",
                        "Regularly audit access permissions"
                    ]
                }
            ]
        }
    
    def _analyze_component(self, component: Component) -> List[Threat]:
        """
        Analyze a single component for potential threats.
        
        Args:
            component: Component to analyze
            
        Returns:
            List of threats identified for this component
        """
        threats = []
        
        # Get threats for this component type from the database
        component_type = component.component_type.value
        component_threats = self.threat_db.get("component_threats", {}).get(component_type, [])
        
        # Create threat instances for each applicable threat
        for i, threat_info in enumerate(component_threats):
            threat = Threat(
                id=threat_info["id"],
                name=threat_info["name"],
                description=threat_info["description"],
                severity=threat_info["severity"],
                affected_components=[component.id],
                threat_type=threat_info["threat_type"],
                mitigations=threat_info.get("mitigations", [])
            )
            threats.append(threat)
            
        logger.debug(f"Identified {len(threats)} threats for component {component.id}")
        return threats
    
    def _analyze_connections(self, components: List[Component]) -> List[Threat]:
        """
        Analyze connections between components for potential threats.
        
        Args:
            components: List of components to analyze
            
        Returns:
            List of threats identified for connections
        """
        threats = []
        
        # Get connection threats from the database
        connection_threats = self.threat_db.get("connection_threats", [])
        
        # Find all connections
        for component in components:
            for connection in component.connections:
                target_id = connection["target_id"]
                
                # Find the target component
                target = next((c for c in components if c.id == target_id), None)
                if not target:
                    continue
                
                # Create threat instances for each applicable connection threat
                for threat_info in connection_threats:
                    # In a real implementation, you would have more sophisticated
                    # logic to determine if a threat applies to this specific connection
                    
                    threat = Threat(
                        id=f"{threat_info['id']}_{component.id}_{target_id}",
                        name=threat_info["name"],
                        description=threat_info["description"],
                        severity=threat_info["severity"],
                        affected_components=[component.id, target_id],
                        threat_type=threat_info["threat_type"],
                        mitigations=threat_info.get("mitigations", [])
                    )
                    threats.append(threat)
        
        logger.debug(f"Identified {len(threats)} threats for connections")
        return threats
    
    def _analyze_architecture(self, components: List[Component]) -> List[Threat]:
        """
        Analyze the overall architecture for potential threats.
        
        Args:
            components: List of components in the architecture
            
        Returns:
            List of threats identified for the architecture
        """
        threats = []
        
        # Get architecture threats from the database
        architecture_threats = self.threat_db.get("architecture_threats", [])
        
        # Create threat instances for each applicable architecture threat
        for threat_info in architecture_threats:
            # In a real implementation, you would have more sophisticated
            # logic to determine if a threat applies to this architecture
            
            # For now, we'll assume all architecture threats apply
            affected_components = [component.id for component in components]
            
            threat = Threat(
                id=threat_info["id"],
                name=threat_info["name"],
                description=threat_info["description"],
                severity=threat_info["severity"],
                affected_components=affected_components,
                threat_type=threat_info["threat_type"],
                mitigations=threat_info.get("mitigations", [])
            )
            threats.append(threat)
        
        logger.debug(f"Identified {len(threats)} threats for the architecture")
        return threats
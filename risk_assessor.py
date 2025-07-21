"""
Risk Assessor Module

This module assesses the risk level of identified threats based on various factors.
"""

import logging
from typing import Dict, List, Tuple

from diagram_parser import Component
from threat_analyzer import Threat

logger = logging.getLogger(__name__)

class Risk:
    """Represents a risk assessment for a threat."""
    
    def __init__(self, threat_id: str, likelihood: str, impact: str, 
                 risk_score: float, recommendations: List[str] = None):
        """
        Initialize a risk assessment.
        
        Args:
            threat_id: ID of the associated threat
            likelihood: Likelihood of the threat occurring (e.g., "High", "Medium", "Low")
            impact: Impact if the threat occurs (e.g., "High", "Medium", "Low")
            risk_score: Numerical risk score (higher is more severe)
            recommendations: List of recommended actions to mitigate the risk
        """
        self.threat_id = threat_id
        self.likelihood = likelihood
        self.impact = impact
        self.risk_score = risk_score
        self.recommendations = recommendations or []
        
    def __repr__(self) -> str:
        """String representation of the risk."""
        return f"Risk({self.threat_id}, L:{self.likelihood}, I:{self.impact}, S:{self.risk_score})"

class RiskAssessor:
    """Assesses the risk level of identified threats."""
    
    def __init__(self):
        """Initialize the risk assessor."""
        # Define risk scoring matrices
        self.likelihood_scores = {
            "High": 3,
            "Medium": 2,
            "Low": 1
        }
        
        self.impact_scores = {
            "High": 3,
            "Medium": 2,
            "Low": 1
        }
        
        self.severity_to_impact = {
            "Critical": "High",
            "High": "High",
            "Medium": "Medium",
            "Low": "Low"
        }
        
    def assess(self, components: List[Component], threats: List[Threat]) -> List[Risk]:
        """
        Assess the risk level of identified threats.
        
        Args:
            components: List of components in the architecture
            threats: List of identified threats
            
        Returns:
            List of risk assessments
        """
        logger.info("Starting risk assessment")
        risks = []
        
        for threat in threats:
            # Assess likelihood and impact
            likelihood = self._assess_likelihood(threat, components)
            impact = self._assess_impact(threat)
            
            # Calculate risk score
            risk_score = self._calculate_risk_score(likelihood, impact)
            
            # Generate recommendations
            recommendations = self._generate_recommendations(threat, risk_score)
            
            # Create risk assessment
            risk = Risk(
                threat_id=threat.id,
                likelihood=likelihood,
                impact=impact,
                risk_score=risk_score,
                recommendations=recommendations
            )
            risks.append(risk)
            
        # Sort risks by score (highest first)
        risks.sort(key=lambda r: r.risk_score, reverse=True)
        
        logger.info(f"Completed risk assessment for {len(threats)} threats")
        return risks
    
    def _assess_likelihood(self, threat: Threat, components: List[Component]) -> str:
        """
        Assess the likelihood of a threat occurring.
        
        Args:
            threat: The threat to assess
            components: List of components in the architecture
            
        Returns:
            Likelihood rating ("High", "Medium", or "Low")
        """
        # This is a simplified assessment
        # In a real implementation, this would consider many factors:
        # - Historical data on similar threats
        # - Complexity of exploitation
        # - Authentication requirements
        # - Exposure to untrusted networks
        # - etc.
        
        # For now, we'll use some simple heuristics
        
        # Default to medium likelihood
        likelihood = "Medium"
        
        # Adjust based on threat type
        if threat.threat_type in ["Injection", "Vulnerability"]:
            likelihood = "High"  # These are common attack vectors
        elif threat.threat_type in ["Physical", "Social Engineering"]:
            likelihood = "Low"   # These typically require special access
            
        # Adjust based on number of affected components
        # More affected components may mean higher likelihood of at least one being vulnerable
        if len(threat.affected_components) > 3:
            # Increase likelihood by one level (but not beyond High)
            if likelihood == "Low":
                likelihood = "Medium"
            elif likelihood == "Medium":
                likelihood = "High"
                
        logger.debug(f"Assessed likelihood for threat {threat.id}: {likelihood}")
        return likelihood
    
    def _assess_impact(self, threat: Threat) -> str:
        """
        Assess the impact if a threat occurs.
        
        Args:
            threat: The threat to assess
            
        Returns:
            Impact rating ("High", "Medium", or "Low")
        """
        # This is a simplified assessment
        # In a real implementation, this would consider many factors:
        # - Data sensitivity
        # - Business criticality of affected systems
        # - Potential financial impact
        # - Regulatory implications
        # - etc.
        
        # For now, we'll base impact primarily on the threat's severity
        impact = self.severity_to_impact.get(threat.severity, "Medium")
        
        # Adjust based on threat type
        if threat.threat_type in ["Information Disclosure", "Data Breach"]:
            # Increase impact by one level (but not beyond High)
            if impact == "Low":
                impact = "Medium"
            elif impact == "Medium":
                impact = "High"
                
        logger.debug(f"Assessed impact for threat {threat.id}: {impact}")
        return impact
    
    def _calculate_risk_score(self, likelihood: str, impact: str) -> float:
        """
        Calculate a numerical risk score based on likelihood and impact.
        
        Args:
            likelihood: Likelihood rating
            impact: Impact rating
            
        Returns:
            Numerical risk score
        """
        # Get numerical values for likelihood and impact
        likelihood_score = self.likelihood_scores.get(likelihood, 2)
        impact_score = self.impact_scores.get(impact, 2)
        
        # Calculate risk score (likelihood × impact)
        risk_score = likelihood_score * impact_score
        
        return risk_score
    
    def _generate_recommendations(self, threat: Threat, risk_score: float) -> List[str]:
        """
        Generate recommendations for mitigating the risk.
        
        Args:
            threat: The threat to generate recommendations for
            risk_score: The calculated risk score
            
        Returns:
            List of recommendations
        """
        recommendations = []
        
        # Start with the threat's mitigations
        recommendations.extend(threat.mitigations)
        
        # Add additional recommendations based on risk score
        if risk_score >= 6:  # High risk (likelihood=3, impact=2 or likelihood=2, impact=3)
            recommendations.append("Prioritize immediate remediation")
            recommendations.append("Implement compensating controls while addressing the root cause")
            recommendations.append("Consider additional monitoring for early detection")
        elif risk_score >= 4:  # Medium risk
            recommendations.append("Address within normal security improvement cycles")
            recommendations.append("Implement detection mechanisms")
        else:  # Low risk
            recommendations.append("Address as resources permit")
            recommendations.append("Document as an accepted risk if mitigation is not feasible")
            
        return recommendations
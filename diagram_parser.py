"""
Diagram Parser Module

This module is responsible for parsing architectural diagrams in various formats
and extracting components and their relationships.
"""

import logging
import os
from typing import Dict, List, Optional, Tuple
from enum import Enum

import cv2
import numpy as np

# Optional imports for different diagram formats
try:
    from PIL import Image
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False

logger = logging.getLogger(__name__)

class ComponentType(Enum):
    """Enumeration of component types that can be identified in diagrams."""
    SERVER = "server"
    DATABASE = "database"
    LOAD_BALANCER = "load_balancer"
    FIREWALL = "firewall"
    CLIENT = "client"
    API_GATEWAY = "api_gateway"
    CONTAINER = "container"
    STORAGE = "storage"
    NETWORK = "network"
    UNKNOWN = "unknown"

class Component:
    """Represents a component identified in an architectural diagram."""
    
    def __init__(self, id: str, name: str, component_type: ComponentType, 
                 position: Tuple[int, int, int, int], properties: Dict = None):
        """
        Initialize a component.
        
        Args:
            id: Unique identifier for the component
            name: Name of the component
            component_type: Type of the component
            position: Position in the diagram (x, y, width, height)
            properties: Additional properties of the component
        """
        self.id = id
        self.name = name
        self.component_type = component_type
        self.position = position
        self.properties = properties or {}
        self.connections = []  # List of connected component IDs
        
    def add_connection(self, target_id: str, connection_type: str = "default"):
        """Add a connection to another component."""
        self.connections.append({
            "target_id": target_id,
            "type": connection_type
        })
        
    def __repr__(self) -> str:
        """String representation of the component."""
        return f"Component({self.id}, {self.name}, {self.component_type})"

class DiagramParser:
    """Parser for architectural diagrams."""
    
    def __init__(self):
        """Initialize the diagram parser."""
        self.supported_formats = ['.png', '.jpg', '.jpeg', '.svg', '.drawio', '.vsdx']
        
    def parse(self, diagram_path: str) -> List[Component]:
        """
        Parse the architectural diagram and extract components.
        
        Args:
            diagram_path: Path to the diagram file
            
        Returns:
            List of identified components
        """
        file_ext = os.path.splitext(diagram_path)[1].lower()
        
        if file_ext not in self.supported_formats:
            logger.error(f"Unsupported diagram format: {file_ext}")
            raise ValueError(f"Unsupported diagram format: {file_ext}")
        
        logger.info(f"Parsing diagram: {diagram_path}")
        
        try:
            if file_ext in ['.png', '.jpg', '.jpeg']:
                return self._parse_image(diagram_path)
            elif file_ext == '.svg':
                return self._parse_svg(diagram_path)
            elif file_ext == '.drawio':
                return self._parse_drawio(diagram_path)
            elif file_ext == '.vsdx':
                return self._parse_visio(diagram_path)
        except Exception as e:
            logger.exception(f"Error parsing diagram: {str(e)}")
            raise
            
    def _parse_image(self, image_path: str) -> List[Component]:
        """
        Parse components from an image-based diagram.
        
        Uses computer vision techniques to identify common architectural components.
        """
        logger.debug(f"Parsing image diagram: {image_path}")
        
        try:
            # Read the image
            image = cv2.imread(image_path)
            if image is None:
                raise ValueError(f"Failed to load image: {image_path}")
                
            # Convert to grayscale for processing
            gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
            
            # Apply image processing to identify components
            # This is a simplified placeholder - real implementation would use
            # more sophisticated computer vision or ML techniques
            components = []
            
            # Example: Detect rectangles as potential components
            # In a real implementation, this would be much more sophisticated
            _, threshold = cv2.threshold(gray, 240, 255, cv2.THRESH_BINARY_INV)
            contours, _ = cv2.findContours(threshold, cv2.RETR_TREE, cv2.CHAIN_APPROX_SIMPLE)
            
            for i, contour in enumerate(contours):
                # Approximate the contour to a polygon
                approx = cv2.approxPolyDP(contour, 0.01 * cv2.arcLength(contour, True), True)
                
                # If it's a rectangle (4 points) and of reasonable size
                if len(approx) == 4 and cv2.contourArea(contour) > 1000:
                    x, y, w, h = cv2.boundingRect(contour)
                    
                    # Determine component type based on aspect ratio or other heuristics
                    # This is simplified - real implementation would use ML or template matching
                    component_type = ComponentType.UNKNOWN
                    if w > h * 1.5:
                        component_type = ComponentType.SERVER
                    elif h > w * 1.5:
                        component_type = ComponentType.DATABASE
                        
                    # Create component
                    component = Component(
                        id=f"comp_{i}",
                        name=f"Component {i}",
                        component_type=component_type,
                        position=(x, y, w, h)
                    )
                    components.append(component)
            
            # Detect connections between components (simplified)
            # In a real implementation, this would analyze lines between components
            self._detect_connections(components, image)
            
            logger.info(f"Identified {len(components)} components in image")
            return components
            
        except Exception as e:
            logger.exception(f"Error parsing image diagram: {str(e)}")
            raise
    
    def _parse_svg(self, svg_path: str) -> List[Component]:
        """Parse components from an SVG diagram."""
        logger.debug(f"Parsing SVG diagram: {svg_path}")
        
        try:
            # This is a placeholder - real implementation would parse SVG XML
            # to extract components and their relationships
            import xml.etree.ElementTree as ET
            
            components = []
            
            # Parse SVG XML
            tree = ET.parse(svg_path)
            root = tree.getroot()
            
            # Extract namespace if present
            ns = {'svg': root.tag.split('}')[0].strip('{')} if '}' in root.tag else {}
            
            # Find all rectangle elements (simplified)
            rect_tag = f"{{{ns['svg']}}}rect" if ns else "rect"
            for i, rect in enumerate(root.findall(f".//{rect_tag}")):
                try:
                    x = float(rect.get('x', 0))
                    y = float(rect.get('y', 0))
                    width = float(rect.get('width', 0))
                    height = float(rect.get('height', 0))
                    
                    # Try to find a label for this rectangle
                    name = f"Component {i}"
                    
                    # Create component
                    component = Component(
                        id=f"comp_{i}",
                        name=name,
                        component_type=ComponentType.UNKNOWN,
                        position=(int(x), int(y), int(width), int(height))
                    )
                    components.append(component)
                except (ValueError, TypeError) as e:
                    logger.warning(f"Skipping invalid rectangle: {e}")
            
            logger.info(f"Identified {len(components)} components in SVG")
            return components
            
        except Exception as e:
            logger.exception(f"Error parsing SVG diagram: {str(e)}")
            raise
    
    def _parse_drawio(self, drawio_path: str) -> List[Component]:
        """Parse components from a draw.io diagram."""
        logger.debug(f"Parsing draw.io diagram: {drawio_path}")
        
        try:
            # This is a placeholder - real implementation would parse the XML format
            # used by draw.io to extract components and their relationships
            import xml.etree.ElementTree as ET
            import base64
            import zlib
            
            components = []
            
            # Parse draw.io XML
            tree = ET.parse(drawio_path)
            root = tree.getroot()
            
            # Find the diagram data
            diagram = root.find(".//diagram")
            if diagram is None:
                logger.warning("No diagram found in draw.io file")
                return components
                
            # draw.io files may contain compressed data
            diagram_data = diagram.text
            if diagram_data:
                try:
                    # Try to decompress if it's compressed
                    decoded = base64.b64decode(diagram_data)
                    inflated = zlib.decompress(decoded, -15)
                    diagram_xml = ET.fromstring(inflated)
                    
                    # Process the XML to extract components
                    # This would be implementation-specific to draw.io's format
                    
                except Exception as e:
                    logger.warning(f"Could not decompress diagram data: {e}")
            
            logger.info(f"Identified {len(components)} components in draw.io diagram")
            return components
            
        except Exception as e:
            logger.exception(f"Error parsing draw.io diagram: {str(e)}")
            raise
    
    def _parse_visio(self, visio_path: str) -> List[Component]:
        """Parse components from a Visio diagram."""
        logger.debug(f"Parsing Visio diagram: {visio_path}")
        
        try:
            # This is a placeholder - real implementation would require a library
            # capable of parsing Visio's VSDX format
            logger.warning("Visio parsing is not fully implemented")
            
            # In a real implementation, you might use a library like python-pptx
            # or extract the XML from the VSDX (which is a ZIP file)
            
            components = []
            logger.info(f"Identified {len(components)} components in Visio diagram")
            return components
            
        except Exception as e:
            logger.exception(f"Error parsing Visio diagram: {str(e)}")
            raise
    
    def _detect_connections(self, components: List[Component], image: np.ndarray) -> None:
        """
        Detect connections between components in the image.
        
        This is a simplified placeholder. A real implementation would use more
        sophisticated line detection and analysis.
        """
        # Convert to grayscale if not already
        if len(image.shape) == 3:
            gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
        else:
            gray = image
            
        # Detect lines using Hough Line Transform
        edges = cv2.Canny(gray, 50, 150, apertureSize=3)
        lines = cv2.HoughLinesP(edges, 1, np.pi/180, threshold=100, minLineLength=100, maxLineGap=10)
        
        if lines is None:
            logger.debug("No lines detected in the diagram")
            return
            
        # For each line, check if it connects two components
        for line in lines:
            x1, y1, x2, y2 = line[0]
            
            # Find components at each end of the line
            comp1 = self._find_component_at_point(components, (x1, y1))
            comp2 = self._find_component_at_point(components, (x2, y2))
            
            # If line connects two different components, add the connection
            if comp1 and comp2 and comp1 != comp2:
                comp1.add_connection(comp2.id)
                
    def _find_component_at_point(self, components: List[Component], point: Tuple[int, int]) -> Optional[Component]:
        """Find a component that contains the given point."""
        x, y = point
        for component in components:
            cx, cy, cw, ch = component.position
            if cx <= x <= cx + cw and cy <= y <= cy + ch:
                return component
        return None
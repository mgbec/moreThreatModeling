# Architectural Diagram Threat Modeler

A Python-based tool for ingesting architectural diagrams and producing threat modeling and risk assessment information.

## Overview

This tool analyzes architectural diagrams to identify components and their relationships, then performs security threat modeling and risk assessment on the identified architecture. It can process various diagram formats including PNG, JPG, SVG, draw.io, and Visio files.

## Features

- Diagram parsing and component identification
- Threat analysis based on component types and relationships
- Risk assessment with likelihood and impact calculations
- Report generation in multiple formats (PDF, HTML, JSON, Markdown)
- Customizable threat database

## Installation

1. Clone this repository
2. Install the required dependencies:

```bash
pip install -r requirements.txt
```

## Usage

Basic usage:

```bash
python main.py path/to/diagram.png
```

Advanced options:

```bash
python main.py path/to/diagram.png --output report.pdf --format pdf --threat-db custom_threat_db.json --verbose
```

### Command Line Arguments

- `diagram_path`: Path to the architectural diagram file
- `--output`, `-o`: Output file path for the threat modeling report (default: threat_report.pdf)
- `--format`, `-f`: Output format for the report (choices: pdf, html, json, md; default: pdf)
- `--threat-db`: Path to custom threat database (default: built-in database)
- `--verbose`, `-v`: Enable verbose output

## Supported Diagram Formats

- PNG, JPG, JPEG: Uses computer vision techniques to identify components
- SVG: Parses SVG XML to extract components
- draw.io: Extracts components from draw.io XML format
- Visio (.vsdx): Basic support for Visio diagrams

## How It Works

1. **Diagram Parsing**: The tool analyzes the input diagram to identify components and their relationships.
2. **Threat Analysis**: Based on the identified components, the tool applies threat patterns from its database to identify potential security threats.
3. **Risk Assessment**: Each identified threat is assessed for likelihood and impact to calculate a risk score.
4. **Report Generation**: A comprehensive report is generated with details on components, threats, and risks.

## Customizing Threat Database

You can provide your own threat database as a JSON file with the following structure:

```json
{
  "component_threats": {
    "server": [
      {
        "id": "T001",
        "name": "Threat Name",
        "description": "Threat Description",
        "severity": "High",
        "threat_type": "Vulnerability",
        "mitigations": ["Mitigation 1", "Mitigation 2"]
      }
    ]
  },
  "connection_threats": [...],
  "architecture_threats": [...]
}
```

A sample custom threat database is provided in `custom_threat_db.json`.

## Adding More Threats

To add more threats to the application, you can:

1. Use a custom threat database file (recommended for production use)
2. Modify the built-in threat database in `threat_analyzer.py`

### Using a Custom Threat Database

Create a JSON file with your threat definitions and pass it to the application:

```bash
python main.py path/to/diagram.png --threat-db path/to/custom_threats.json
```

### Extending the Built-in Database

The built-in threat database in `threat_analyzer.py` can be extended by adding more entries to:

- `component_threats`: Threats specific to component types
- `connection_threats`: Threats related to connections between components
- `architecture_threats`: Threats that apply to the overall architecture

## Limitations

- Image-based diagram parsing relies on computer vision techniques which may not always correctly identify all components
- The accuracy of threat identification depends on the quality of the threat database
- Some advanced diagram features may not be properly interpreted

## License

MIT
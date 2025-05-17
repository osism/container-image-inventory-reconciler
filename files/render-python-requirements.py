#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Render Python requirements file from template and version data."""

import sys
from pathlib import Path
from typing import Any, Dict

import jinja2
import yaml


def load_versions(version_file: Path) -> Dict[str, Any]:
    """Load version information from YAML file.

    Args:
        version_file: Path to the YAML version file

    Returns:
        Dictionary containing version information

    Raises:
        FileNotFoundError: If version file doesn't exist
        yaml.YAMLError: If YAML parsing fails
    """
    try:
        with open(version_file, "rb") as fp:
            return yaml.safe_load(fp)
    except FileNotFoundError:
        print(f"Error: Version file not found: {version_file}")
        raise
    except yaml.YAMLError as e:
        print(f"Error: Failed to parse YAML file: {e}")
        raise


def create_jinja_environment(template_dir: Path) -> jinja2.Environment:
    """Create and configure Jinja2 environment.

    Args:
        template_dir: Directory containing Jinja2 templates

    Returns:
        Configured Jinja2 environment
    """
    loader = jinja2.FileSystemLoader(searchpath=str(template_dir))
    return jinja2.Environment(
        loader=loader, autoescape=False, keep_trailing_newline=True
    )


def render_requirements(
    environment: jinja2.Environment, template_name: str, context: Dict[str, Any]
) -> str:
    """Render requirements file from template.

    Args:
        environment: Jinja2 environment
        template_name: Name of the template file
        context: Context dictionary for template rendering

    Returns:
        Rendered requirements content
    """
    try:
        template = environment.get_template(template_name)
        return template.render(context)
    except jinja2.TemplateNotFound:
        print(f"Error: Template not found: {template_name}")
        raise
    except jinja2.TemplateError as e:
        print(f"Error: Template rendering failed: {e}")
        raise


def main():
    """Main function to render Python requirements file."""
    # Define paths
    version_file = Path("/release/latest/base.yml")
    template_dir = Path("/templates")
    template_name = "requirements.txt.j2"
    output_file = Path("/requirements.extra.txt")

    try:
        # Load version data
        versions = load_versions(version_file)

        # Create Jinja2 environment
        environment = create_jinja_environment(template_dir)

        # Prepare template context
        context = {"osism_projects": versions.get("osism_projects", {})}

        # Render requirements
        result = render_requirements(environment, template_name, context)

        # Write output file
        output_file.write_text(result)

    except Exception as e:
        print(f"Fatal error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()

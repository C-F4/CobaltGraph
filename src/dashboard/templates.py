"""
CobaltGraph Dashboard HTML Templates
Template rendering and generation

Responsibilities:
- Load HTML templates
- Inject dynamic data
- Template caching
- Simple templating (no heavy framework)
"""

import logging
from pathlib import Path
from typing import Dict

logger = logging.getLogger(__name__)

class TemplateEngine:
    """
    Simple template engine for dashboard

    Uses string substitution for variables
    No heavy dependencies (Jinja2, etc.)
    """

    def __init__(self, template_dir: str = "templates"):
        """
        Initialize template engine

        Args:
            template_dir: Path to templates directory
        """
        self.template_dir = Path(template_dir)
        self.cache = {}

    def load_template(self, name: str) -> str:
        """
        Load template from file

        Args:
            name: Template filename (e.g., 'dashboard.html')

        Returns:
            Template string
        """
        if name in self.cache:
            return self.cache[name]

        template_path = self.template_dir / name
        if not template_path.exists():
            logger.error(f"Template not found: {template_path}")
            return "<html><body><h1>Error: Template not found</h1></body></html>"

        with open(template_path, 'r') as f:
            template = f.read()

        self.cache[name] = template
        return template

    def render(self, template_name: str, context: Dict = None) -> str:
        """
        Render template with context

        Args:
            template_name: Template filename
            context: Dictionary of variables to substitute

        Returns:
            Rendered HTML
        """
        template = self.load_template(template_name)

        if context:
            # Simple string substitution (e.g., {{variable}})
            for key, value in context.items():
                placeholder = f'{{{{{key}}}}}'
                template = template.replace(placeholder, str(value))

        return template

    def clear_cache(self):
        """Clear template cache (for development)"""
        self.cache.clear()


# Convenience function
def render_template(name: str, **context) -> str:
    """
    Render template with context

    Args:
        name: Template filename
        **context: Template variables

    Returns:
        Rendered HTML
    """
    engine = TemplateEngine()
    return engine.render(name, context)

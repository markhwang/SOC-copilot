"""
Jinja2 template loader for all agent prompts.

All LLM prompts live in prompts/ as .jinja2 files — never hardcoded in Python.
Use render_template() from any agent to render a prompt with variables.
"""

from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, FileSystemLoader, StrictUndefined

# Resolve prompts/ relative to this file: src/utils/prompts.py → prompts/
_PROMPTS_DIR = Path(__file__).parent.parent.parent / "prompts"

_env = Environment(
    loader=FileSystemLoader(str(_PROMPTS_DIR)),
    undefined=StrictUndefined,   # raise immediately on undefined variables — no silent empty strings
    trim_blocks=True,            # strip newline after block tags
    lstrip_blocks=True,          # strip leading whitespace before block tags
)


def render_template(name: str, **kwargs: object) -> str:
    """Render a Jinja2 template from the prompts/ directory.

    Args:
        name: Template filename, e.g. "summarize_user.jinja2"
        **kwargs: Variables passed into the template.

    Returns:
        Rendered string ready to send to the LLM.

    Raises:
        jinja2.TemplateNotFound: If the template file doesn't exist.
        jinja2.UndefinedError: If the template references a variable not in kwargs.
    """
    template = _env.get_template(name)
    return template.render(**kwargs)

"""Tests for src/utils/prompts.py — Jinja2 template loading and rendering."""

import pytest
from jinja2 import TemplateNotFound, UndefinedError

from src.utils.prompts import render_template


class TestRenderTemplate:
    def test_system_prompt_renders_without_variables(self):
        result = render_template("summarize_system.jinja2")
        assert len(result) > 200
        assert "risk_score" in result
        assert "confidence_score" in result
        assert "escalation_recommended" in result

    def test_system_prompt_contains_rubric(self):
        result = render_template("summarize_system.jinja2")
        assert "9-10" in result
        assert "1-2" in result
        assert "JSON" in result

    def test_nonexistent_template_raises(self):
        with pytest.raises(TemplateNotFound):
            render_template("does_not_exist.jinja2")

    def test_undefined_variable_raises(self):
        """StrictUndefined means missing vars raise immediately, not silently."""
        with pytest.raises(UndefinedError):
            render_template("summarize_user.jinja2", alert=None, enrichment=None)

"""Tests for Pydantic schemas."""

import pytest


class TestActionGuideSchema:
    """Test ActionGuideSchema validation."""

    def test_valid_schema(self):
        from ai_security.schemas import ActionGuideSchema, HAS_PYDANTIC
        if not HAS_PYDANTIC:
            pytest.skip("Pydantic not available")
        guide = ActionGuideSchema(
            title="Test Title",
            description="Test description for the finding.",
            actions=["Action 1", "Action 2"],
        )
        assert guide.title == "Test Title"
        assert len(guide.actions) == 2

    def test_title_truncation(self):
        from ai_security.schemas import ActionGuideSchema, HAS_PYDANTIC
        if not HAS_PYDANTIC:
            pytest.skip("Pydantic not available")
        guide = ActionGuideSchema(
            title="A" * 150,
            description="Desc",
            actions=["A1", "A2"],
        )
        assert len(guide.title) <= 100

    def test_description_truncation(self):
        from ai_security.schemas import ActionGuideSchema, HAS_PYDANTIC
        if not HAS_PYDANTIC:
            pytest.skip("Pydantic not available")
        guide = ActionGuideSchema(
            title="Title",
            description="D" * 600,
            actions=["A1", "A2"],
        )
        assert len(guide.description) <= 500

    def test_too_few_actions_raises(self):
        from ai_security.schemas import ActionGuideSchema, HAS_PYDANTIC
        if not HAS_PYDANTIC:
            pytest.skip("Pydantic not available")
        with pytest.raises(Exception):
            ActionGuideSchema(
                title="Title",
                description="Desc",
                actions=["Only one"],
            )

    def test_too_many_actions_truncated(self):
        from ai_security.schemas import ActionGuideSchema, HAS_PYDANTIC
        if not HAS_PYDANTIC:
            pytest.skip("Pydantic not available")
        guide = ActionGuideSchema(
            title="Title",
            description="Desc",
            actions=["A1", "A2", "A3", "A4", "A5", "A6", "A7"],
        )
        assert len(guide.actions) <= 5


class TestLLMExplanationOutput:
    """Test LLMExplanationOutput has NO verdict/risk fields."""

    def test_no_verdict_field(self):
        from ai_security.schemas import LLMExplanationOutput
        output = LLMExplanationOutput()
        data = output.model_dump()
        assert "verdict" not in data
        assert "risk_score" not in data
        assert "risk_level" not in data

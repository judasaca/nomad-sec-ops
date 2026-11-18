"""Validate the optional CI/CD rule settings for a local target."""

from pathlib import Path
from stat import S_ISREG

import yaml
from pydantic import BaseModel, ConfigDict, Field, StrictBool, field_validator

from nomad_sec_ops.scanners.zizmor_catalog import AUDITS

CONFIG_FILENAME = "nomad-sec-ops-ci-cd.yml"
RULE_IDS = frozenset(audit.rule_id for audit in AUDITS)


class RuleSettings(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)
    disable: StrictBool


class CICDSettings(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)
    rules: dict[str, RuleSettings] = Field(default_factory=dict)

    @field_validator("rules")
    @classmethod
    def validate_rule_ids(
        cls, rules: dict[str, RuleSettings]
    ) -> dict[str, RuleSettings]:
        unknown_ids = rules.keys() - RULE_IDS
        if unknown_ids:
            names = ", ".join(repr(rule_id) for rule_id in sorted(unknown_ids))
            raise ValueError(f"Unknown rule IDs {names}.")
        return rules


def validate_ci_cd_config(path: Path) -> None:
    """Validate an optional settings file without applying rule overrides."""
    try:
        mode = path.stat().st_mode
    except FileNotFoundError:
        if path.is_symlink():
            raise
        return
    if not S_ISREG(mode):
        raise ValueError("Expected a regular file.")

    content = path.read_text(encoding="utf-8")
    try:
        data = yaml.safe_load(content)
    except (yaml.YAMLError, IndexError, KeyError, ValueError) as error:
        # PyYAML's scalar constructors can raise built-in exceptions on bad tags.
        raise ValueError(f"Invalid YAML. {error}") from error
    except RecursionError as error:
        raise ValueError("YAML is nested too deeply.") from error

    CICDSettings.model_validate(data)

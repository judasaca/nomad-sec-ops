"""Load the shipped defaults and validate repository configuration."""

from importlib.resources import files
from pathlib import Path
from stat import S_ISREG
from typing import Annotated, Literal

import yaml
from pydantic import AfterValidator, BaseModel, ConfigDict, Field, StrictBool

from nomad_sec_ops.scanners.zizmor_catalog import AUDITS

CONFIG_FILENAME = "nomad-sec-ops.yml"
RULE_IDS = frozenset(audit.rule_id for audit in AUDITS)
PINNING_RULE = "unpinned-uses"
type PinningPolicy = Literal["hash-pin", "ref-pin", "any"]


class Settings(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)


class RuleSettings(Settings):
    disable: StrictBool = False
    policies: dict[Annotated[str, Field(min_length=1)], PinningPolicy] = Field(
        default_factory=dict
    )


def _validate_rule_options(rules: dict[str, RuleSettings]) -> dict[str, RuleSettings]:
    unknown_ids = rules.keys() - RULE_IDS
    if unknown_ids:
        names = ", ".join(repr(rule_id) for rule_id in sorted(unknown_ids))
        raise ValueError(f"Unknown rule IDs {names}.")
    for rule_id, rule in rules.items():
        if rule_id != PINNING_RULE and "policies" in rule.model_fields_set:
            raise ValueError(f"Rule {rule_id!r} does not support policies.")
    return rules


class CICDSettings(Settings):
    rules: Annotated[
        dict[str, RuleSettings], AfterValidator(_validate_rule_options)
    ] = Field(default_factory=dict)

    def with_overrides(self, overrides: CICDSettings) -> CICDSettings:
        rules = self.rules.copy()
        for rule_id, override in overrides.rules.items():
            default = rules.get(rule_id, RuleSettings())
            rules[rule_id] = RuleSettings(
                disable=(
                    override.disable
                    if "disable" in override.model_fields_set
                    else default.disable
                ),
            )
            if rule_id == PINNING_RULE:
                rules[rule_id].policies = default.policies | override.policies
        return CICDSettings(rules=rules)


class RepositorySettings(Settings):
    ci_cd: CICDSettings = Field(alias="ci-cd", default_factory=CICDSettings)


def _parse_yaml(content: str) -> object:
    try:
        return yaml.safe_load(content)
    except (yaml.YAMLError, IndexError, KeyError, ValueError) as error:
        # PyYAML's scalar constructors can raise built-in exceptions on bad tags.
        raise ValueError(f"Invalid YAML. {error}") from error
    except RecursionError as error:
        raise ValueError("YAML is nested too deeply.") from error


def load_defaults() -> RepositorySettings:
    resource = files("nomad_sec_ops").joinpath(CONFIG_FILENAME)
    return RepositorySettings.model_validate(
        _parse_yaml(resource.read_text(encoding="utf-8"))
    )


def load_repository_settings(path: Path) -> RepositorySettings:
    """Load optional overrides and report unreadable entries or broken links."""
    try:
        path.lstat()
    except FileNotFoundError:
        return RepositorySettings()
    if not S_ISREG(path.stat().st_mode):
        raise ValueError("Expected a regular file.")
    return RepositorySettings.model_validate(
        _parse_yaml(path.read_text(encoding="utf-8"))
    )

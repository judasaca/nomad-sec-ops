"""Collect image declarations from a local GitLab pipeline without network I/O.

Use YAML nodes rather than constructing Python objects, retaining source marks
and allowing unrelated GitLab-specific YAML tags such as !reference.
"""

from dataclasses import dataclass
from pathlib import Path

import yaml
from yaml.nodes import MappingNode, Node, ScalarNode, SequenceNode

GLOBAL_KEYS = {
    "image",
    "services",
    "default",
    "include",
    "stages",
    "variables",
    "workflow",
    "spec",
    "before_script",
    "after_script",
    "cache",
}


@dataclass(frozen=True)
class ImageReference:
    value: str
    line: int
    column: int
    location: str


@dataclass(frozen=True)
class PipelineImages:
    references: list[ImageReference]
    limitations: list[str]


def collect_images(path: Path) -> PipelineImages:
    references: list[ImageReference] = []
    limitations: list[str] = []
    try:
        root = yaml.compose(path.read_text(encoding="utf-8"), Loader=yaml.SafeLoader)
    except yaml.YAMLError as error:
        raise ValueError(f"Invalid GitLab YAML in {path}: {error}") from error

    def mapping(node: Node, location: str) -> dict[str, Node]:
        if not isinstance(node, MappingNode) or node.tag != "tag:yaml.org,2002:map":
            raise ValueError(f"Expected a mapping at {path}: {location}.")
        result: dict[str, Node] = {}
        for key, value in node.value:
            if not isinstance(key, ScalarNode):
                raise ValueError(f"Expected a scalar key at {path}: {location}.")
            if key.value == "<<":
                limitations.append(f"{location}: YAML merge keys are not resolved")
                continue
            if key.value in result:
                raise ValueError(f"Duplicate key {key.value!r} at {path}: {location}.")
            result[key.value] = value
        return result

    def image(node: Node, location: str) -> None:
        if isinstance(node, MappingNode):
            fields = mapping(node, location)
            if "name" not in fields:
                raise ValueError(f"Missing image name at {path}: {location}.")
            node = fields["name"]
            location = f"{location}.name"
        if isinstance(node, ScalarNode) and node.tag == "tag:yaml.org,2002:str":
            assert node.start_mark is not None
            references.append(
                ImageReference(
                    node.value,
                    node.start_mark.line + 1,
                    node.start_mark.column + 1,
                    location,
                )
            )
        elif node.tag == "!reference":
            limitations.append(f"{location}: !reference is not resolved")
        else:
            raise ValueError(f"Expected an image string at {path}: {location}.")

    def container(fields: dict[str, Node], location: str) -> None:
        prefix = f"{location}." if location else ""
        if "image" in fields:
            image(fields["image"], f"{prefix}image")
        if "services" in fields:
            services = fields["services"]
            if services.tag == "!reference":
                limitations.append(f"{prefix}services: !reference is not resolved")
            elif isinstance(services, SequenceNode):
                for index, service in enumerate(services.value):
                    image(service, f"{prefix}services[{index}]")
            else:
                raise ValueError(f"Expected a services list at {path}: {location}.")

    if root is None:
        return PipelineImages([], ["pipeline is empty"])
    fields = mapping(root, "pipeline")
    if "include" in fields:
        limitations.append("include files are not resolved in this offline rule")
    container(fields, "")
    for key, node in fields.items():
        if key == "default" or key not in GLOBAL_KEYS:
            container(mapping(node, key), key)
    return PipelineImages(references, limitations)

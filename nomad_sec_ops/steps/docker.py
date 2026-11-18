"""Simulated Docker verification."""

from nomad_sec_ops.demo import DemoAnalysis


class DockerAnalysis(DemoAnalysis):
    name = "docker"
    label = "Docker"

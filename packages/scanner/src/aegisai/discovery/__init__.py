"""Project discovery: files, manifests and frameworks."""

from aegisai.discovery.files import DiscoveredFile, DiscoveryStats, discover_files
from aegisai.discovery.frameworks import Framework, FrameworkProfile
from aegisai.discovery.project import ProjectContext, build_project_context

__all__ = [
    "DiscoveredFile",
    "DiscoveryStats",
    "Framework",
    "FrameworkProfile",
    "ProjectContext",
    "build_project_context",
    "discover_files",
]

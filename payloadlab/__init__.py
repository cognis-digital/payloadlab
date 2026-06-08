"""
PAYLOADLAB — Static malicious payload analyzer — PE/ELF/LNK/macro/OneNote
Part of the Cognis Neural Suite by Cognis Digital.
https://cognis.digital · MIT License
"""
from payloadlab.core import scan, TOOL_NAME, TOOL_VERSION

__version__ = TOOL_VERSION
__author__ = "Cognis Digital"
__license__ = "MIT"
__all__ = ["scan", "TOOL_NAME", "TOOL_VERSION", "__version__"]

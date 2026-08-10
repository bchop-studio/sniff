"""sniff: local prompt-injection scanner for AI agent inputs."""

from sniff.scanner import Scanner
from sniff.scanner.models import ScanInput

__version__ = "0.1.0"
__all__ = ["ScanInput", "Scanner", "__version__"]

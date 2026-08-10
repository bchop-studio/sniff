"""sniff: local prompt-injection scanner for AI agent inputs."""

from sniff.scanner import Config, ConfigError, Scanner, load_config
from sniff.scanner.models import ScanInput

__version__ = "0.1.0"
__all__ = ["Config", "ConfigError", "ScanInput", "Scanner", "__version__", "load_config"]

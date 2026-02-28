import os
from dataclasses import dataclass, field
from dotenv import load_dotenv

load_dotenv()


@dataclass
class ModelConfig:
    primary: str = "llama-3.3-70b-versatile"
    intent: str = "llama-3.3-70b-versatile"
    classifier: str = "mixtral-8x7b-32768"


@dataclass
class EntropyThresholds:
    natural: tuple[float, float] = (0.0, 3.5)
    os_clear: tuple[float, float] = (3.5, 5.5)
    intentional_wipe: tuple[float, float] = (5.5, 7.2)
    secure_erase: tuple[float, float] = (7.2, 8.0)


@dataclass
class ISEAConfig:
    groq_api_key: str = field(default_factory=lambda: os.getenv("GROQ_API_KEY", ""))
    models: ModelConfig = field(default_factory=ModelConfig)
    entropy: EntropyThresholds = field(default_factory=EntropyThresholds)
    cluster_size: int = field(
        default_factory=lambda: int(os.getenv("CLUSTER_SIZE", "4096"))
    )
    max_clusters: int = field(
        default_factory=lambda: int(os.getenv("MAX_CLUSTERS", "0"))
    )
    report_output_dir: str = field(
        default_factory=lambda: os.getenv("REPORT_OUTPUT_DIR", "./reports")
    )

    def validate(self) -> None:
        if not self.groq_api_key:
            raise ValueError(
                "GROQ_API_KEY is not set. Copy .env.example to .env and add your key."
            )
        if self.cluster_size <= 0 or (self.cluster_size & (self.cluster_size - 1)) != 0:
            raise ValueError("CLUSTER_SIZE must be a positive power of 2.")


# Intent keywords that trigger the more powerful intent model
INTENT_KEYWORDS = [
    "intent", "intentional", "deliberate", "attacker", "attacker profile",
    "who wiped", "purpose", "why", "malicious", "cover", "coverup",
    "evidence destruction", "anti-forensic"
]

# Sensitive directory names for targeted wipe detection
SENSITIVE_DIR_PATTERNS = [
    "finance", "financial", "legal", "confidential", "private", "secret",
    "hr", "human resources", "payroll", "audit", "compliance", "executive",
    "board", "strategy", "acquisition", "merger", "lawsuit", "evidence"
]

# Global singleton
config = ISEAConfig()

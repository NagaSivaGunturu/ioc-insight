from dataclasses import dataclass, field

from models.consolidated_intel import ConsolidatedIntel


@dataclass
class IntelligenceAssessment:
    intelligence: ConsolidatedIntel
    ioc_intelligence_score: int = 0
    classification: str = "UNKNOWN"
    severity: str | None = None
    confidence: str | None = None
    summary: str | None = None
    reasons: list[str] = field(default_factory=list)
    #recommendations: list[str] = field(default_factory=list)  --> mostly not required, as we are not using this field in any of the renderers, and also not using it in the assessment.py file. So, we can remove it for now.
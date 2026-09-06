import textwrap


class AssessmentRenderer:

    WIDTH = 80
    LABEL_WIDTH = 20

    def render(self, assessment):
        self.render_header()
        print()
        self.render_ioc(assessment)
        print()
        self.render_threat_assessment(assessment)
        print()
        self.render_score(assessment)
        print()
        self.render_summary(assessment)
        print()
        self.render_evidence(assessment)
        print()
        self.render_intelligence_findings(assessment)
        print()
        self.render_intelligence_activity(assessment)
        print()
        self.render_references(assessment)

    def render_header(self):
        print("=" * self.WIDTH)
        print("IOC INTELLIGENCE ASSESSMENT".center(self.WIDTH))
        print("=" * self.WIDTH)

    def render_ioc(self, assessment):
        intelligence = assessment.intelligence
        print("IOC")
        print("-" * self.WIDTH)
        print(f"{'Value':<{self.LABEL_WIDTH}} : {intelligence.queried_ioc}")
        print(f"{'Type':<{self.LABEL_WIDTH}} : {intelligence.queried_ioc_type}")

    def render_threat_assessment(self, assessment):
        print("Threat Assessment")
        print("-" * self.WIDTH)
        classification = assessment.classification
        icon = self.get_classification_icon(classification)
        print(
            f"{'Classification':<{self.LABEL_WIDTH}} : "
            f"{icon} {classification}"
        )

    def render_score(self, assessment):
        print("IOC Intelligence Score")
        print("-" * self.WIDTH)
        score = assessment.ioc_intelligence_score
        total_blocks = 40
        filled_blocks = int(score / 100 * total_blocks)
        bar = (
            "█" * filled_blocks +
            "░" * (total_blocks - filled_blocks)
        )
        print(
            f"{'Score':<{self.LABEL_WIDTH}} : "
            f"{bar} {score}/100"
        )

    def get_classification_icon(self, classification: str) -> str:
        mapping = {
            "HIGH CONFIDENCE MALICIOUS": "🔴",
            "LIKELY MALICIOUS": "🟠",
            "SUSPICIOUS": "🟡",
            "LOW CONFIDENCE MALICIOUS": "🟢",
            "INSUFFICIENT INTELLIGENCE": "⚪",
            "UNKNOWN": "⚪"
        }
        return mapping.get(classification, "⚪")

    def render_summary(self, assessment):
        print("Intelligence Summary")
        print("-" * self.WIDTH)
        summary = assessment.summary or "No intelligence summary available."
        wrapped = textwrap.fill(
            summary,
            width=self.WIDTH
        )
        print(wrapped)

    def render_evidence(self, assessment):
        print("Evidence")
        print("-" * self.WIDTH)
        if not assessment.reasons:
            print("No supporting evidence available.")
            return
        for reason in assessment.reasons:
            print(f"✓ {reason}")

    def render_intelligence_findings(self, assessment):
        intelligence = assessment.intelligence
        print("Intelligence Findings")
        print("-" * self.WIDTH)
        self._print_list_field(
            "Threat Actors",
            intelligence.threat_actors
        )
        self._print_list_field(
            "Malware Families",
            intelligence.malware_families,
            max_items=10
        )
        self._print_list_field(
            "MITRE ATT&CK",
            intelligence.mitre_attack,
            max_items=10
        )
        self._print_list_field(
            "Tags",
            intelligence.tags,
            max_items=10
        )

    def _print_list_field(
        self,
        label: str,
        values: list[str],
        max_items: int | None = None
    ):
        if not values:
            return

        # Limit displayed items if requested

        display_values = values
        if max_items is not None and len(values) > max_items:
            remaining = len(values) - max_items
            display_values = values[:max_items]
            text = ", ".join(display_values)
            text += f" ... (+{remaining} more)"
        else:
            text = ", ".join(display_values)

        wrapped = textwrap.wrap(
            text,
            width=self.WIDTH - self.LABEL_WIDTH - 3
        )
        print(
            f"{label:<{self.LABEL_WIDTH}} : {wrapped[0]}"
        )
        for line in wrapped[1:]:
            print(
                f"{'':<{self.LABEL_WIDTH}}   {line}"
            )

    def render_intelligence_activity(self, assessment):
        intelligence = assessment.intelligence
        print("Intelligence Activity")
        print("-" * self.WIDTH)
        self._print_value_field(
            "Providers Queried",
            ", ".join(intelligence.providers)
        )
        self._print_value_field(
            "Providers Failed",
            ", ".join(intelligence.failed_providers)
        )
        self._print_value_field(
            "Community Reports",
            str(intelligence.community_reports)
        )
        self._print_value_field(
            "First Seen",
            self._format_date(intelligence.first_seen)
        )
        self._print_value_field(
            "Last Seen",
            self._format_date(intelligence.last_seen)
        )

    def _print_value_field(
        self,
        label: str,
        value: str
    ):
        if value is None or value == "":
            return
        print(
            f"{label:<{self.LABEL_WIDTH}} : {value}"
        )

    def _format_date(self, value):
        if value is None:
            return ""
        return value.strftime("%Y-%m-%d")

    def render_references(self, assessment):
        references = assessment.intelligence.references
        if not references:
            return
        print("References")
        print("-" * self.WIDTH)
        max_references = 3
        display_references = references[:max_references]
        for reference in display_references:
            print(f"• {reference}")
            print()
        remaining = len(references) - max_references
        if remaining > 0:
            print(f"... (+{remaining} more)")

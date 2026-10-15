"""Security aggregation consumes upstream components, including on a rerun."""

from collections import Counter
from pathlib import Path
import re
import unittest


class SecurityComponentTransferTests(unittest.TestCase):
    def test_download_names_match_component_uploads_and_exclude_aggregate(self) -> None:
        root = Path(__file__).resolve().parents[3]
        text = (root / ".github/workflows/security-audit-required.yml").read_text()
        chunks = re.split(r"(?m)^  ([a-z0-9-]+):\s*$", text.split("\njobs:\n", 1)[1])
        jobs = dict(zip(chunks[1::2], chunks[2::2]))

        def transfers(job: str, action: str) -> list[tuple[str, str]]:
            result = []
            for step in re.split(r"(?m)^      - ", job):
                if re.search(rf"(?m)^\s*uses:\s*actions/{action}@", step):
                    selector = re.search(r"(?m)^          (name|pattern):\s*(.+)$", step)
                    self.assertIsNotNone(selector, "artifact transfer has no selector")
                    result.append(selector.groups())
            return result

        required = jobs["required"]
        needs = re.search(r"(?m)^    needs:\n((?:      - [^\n]+\n)+)", required)
        self.assertIsNotNone(needs)
        upstream = re.findall(r"(?m)^      - ([a-z0-9-]+)$", needs.group(1))
        uploads = [item for job in upstream for item in transfers(jobs[job], "upload-artifact")]
        self.assertEqual(len(uploads), len(upstream), "each component must publish one archive")
        downloads = transfers(required, "download-artifact")
        self.assertEqual(Counter(downloads), Counter(uploads), "download exact component names; a wildcard can re-import an old aggregate")
        aggregate = transfers(required, "upload-artifact")
        self.assertTrue(aggregate)
        self.assertFalse(set(aggregate) & set(downloads), "a prior aggregate is never component input")

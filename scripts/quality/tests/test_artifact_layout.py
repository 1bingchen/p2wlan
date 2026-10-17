import importlib.util
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "scripts/quality"))
import restore_artifact_layout as layout


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


dpl = load("layout_dpl_selector", "scripts/dplpmtud/select_component_artifact.py")
nat = load("layout_nat_selector", "scripts/nat-sim/select_attempt_evidence.py")
SOURCE = "a" * 40
RUN = 424242
PATTERN = f"dplpmtud-live-component-{RUN}-*"


def artifact(attempt=1, *, name=None, artifact_id=None, **overrides):
    row = {
        "id": artifact_id or attempt,
        "name": name or f"dplpmtud-live-component-{RUN}-{attempt}",
        "workflow_run": {"id": RUN, "head_sha": SOURCE},
        "digest": "sha256:" + "b" * 64,
        "expired": False,
    }
    row.update(overrides)
    return row


class LayoutTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.download = self.root / "download"
        self.download.mkdir()
        self.output = self.root / "canonical"

    def payload(self, root=None, content=b"original evidence"):
        root = root or self.download
        root.mkdir(parents=True, exist_ok=True)
        (root / "evidence.json").write_bytes(content)

    def restore(self, rows=None, downloads=None):
        return layout.restore(rows if rows is not None else [artifact()],
                              downloads if downloads is not None else [(PATTERN, self.download)],
                              self.output, run_id=RUN, run_head_sha=SOURCE)

    def test_single_match_wraps_flat_payload_and_preserves_bytes(self):
        self.payload()
        self.restore()
        self.assertEqual((self.output / artifact()["name"] / "evidence.json").read_bytes(), b"original evidence")
        self.assertFalse(self.download.exists())

    def test_payload_name_cannot_be_mistaken_for_already_wrapped_artifact(self):
        name = artifact()["name"]
        self.payload(self.download / name)
        self.restore()
        self.assertTrue((self.output / name / name / "evidence.json").is_file())

    def test_multiple_matches_preserve_all_attempts(self):
        rows = [artifact(1), artifact(2)]
        for row in rows:
            self.payload(self.download / row["name"], str(row["id"]).encode())
        self.restore(rows)
        self.assertEqual({p.name for p in self.output.iterdir()}, {row["name"] for row in rows})
        self.assertEqual((self.output / rows[0]["name"] / "evidence.json").read_bytes(), b"1")

    def test_no_match_does_not_publish_empty_evidence(self):
        self.payload()
        with self.assertRaisesRegex(layout.LayoutError, "matches_missing"):
            self.restore([])
        self.assertFalse(self.output.exists())
        self.assertTrue(self.download.exists())

    def test_identity_digest_and_unknown_expiry_are_rejected(self):
        self.payload()
        changes = [{"workflow_run": {"id": RUN + 1, "head_sha": SOURCE}},
                   {"workflow_run": {"id": RUN, "head_sha": "c" * 40}},
                   {"digest": None}, {"expired": None}, {"id": 0}]
        for change in changes:
            with self.subTest(change=change), self.assertRaises(layout.LayoutError):
                self.restore([artifact(**change)])
            self.assertFalse(self.output.exists())

    def test_expired_attempts_are_not_downloadable_candidates(self):
        self.payload()
        rows = [artifact(1, expired=True), artifact(2)]
        self.restore(rows)
        self.assertEqual([p.name for p in self.output.iterdir()], [rows[1]["name"]])

    def test_duplicate_names_and_ids_are_rejected(self):
        self.payload()
        for rows in [[artifact(), artifact()], [artifact(1), artifact(2, artifact_id=1)]]:
            with self.assertRaisesRegex(layout.LayoutError, "duplicate"):
                self.restore(rows)
        self.assertFalse(self.output.exists())

    def test_unsafe_artifact_names_are_rejected(self):
        self.payload()
        for suffix in ["../outside", "nested/name", "nested\\name", "\ncommand"]:
            row = artifact(name=f"dplpmtud-live-component-{RUN}-{suffix}")
            with self.subTest(suffix=suffix), self.assertRaisesRegex(layout.LayoutError, "identity_invalid"):
                self.restore([row])
        self.assertFalse(self.output.exists())

    def test_missing_or_extra_named_directory_is_rejected(self):
        rows = [artifact(1), artifact(2)]
        self.payload(self.download / rows[0]["name"])
        with self.assertRaisesRegex(layout.LayoutError, "names_mismatch"):
            self.restore(rows)
        self.payload(self.download / rows[1]["name"])
        self.payload(self.download / "unrelated")
        with self.assertRaisesRegex(layout.LayoutError, "names_mismatch"):
            self.restore(rows)
        self.assertFalse(self.output.exists())

    @unittest.skipIf(os.name == "nt", "requires POSIX unprivileged symlink creation")
    def test_symlinks_in_payload_or_root_are_rejected(self):
        self.payload()
        (self.download / "link").symlink_to(self.download / "evidence.json")
        with self.assertRaisesRegex(layout.LayoutError, "link_or_special"):
            self.restore()
        alias = self.root / "alias"
        alias.symlink_to(self.download, target_is_directory=True)
        with self.assertRaisesRegex(layout.LayoutError, "root_invalid"):
            self.restore(downloads=[(PATTERN, alias)])
        self.assertFalse(self.output.exists())

    def test_empty_payload_and_capacity_are_rejected_before_moves(self):
        with self.assertRaisesRegex(layout.LayoutError, "payload_empty"):
            self.restore()
        self.payload()
        for key, value in [("MAX_BYTES", 1), ("MAX_ENTRIES", 1), ("MAX_ARTIFACTS", 0)]:
            with patch.object(layout, key, value), self.assertRaises(layout.LayoutError):
                self.restore()
            self.assertFalse(self.output.exists())

    def test_output_and_download_overlap_do_not_overwrite_evidence(self):
        self.payload()
        self.output.mkdir()
        (self.output / "keep").write_bytes(b"keep")
        with self.assertRaisesRegex(layout.LayoutError, "output_exists"):
            self.restore()
        self.assertEqual((self.output / "keep").read_bytes(), b"keep")
        self.output = self.download / "nested"
        with self.assertRaisesRegex(layout.LayoutError, "output_overlap"):
            self.restore()

    def test_all_groups_are_validated_before_any_move(self):
        self.payload()
        empty = self.root / "empty"
        empty.mkdir()
        other = artifact(name=f"nat-topology-direct-{RUN}-1", artifact_id=8)
        with self.assertRaisesRegex(layout.LayoutError, "payload_empty"):
            self.restore([artifact(), other], [(PATTERN, self.download), (f"nat-topology-direct-{RUN}-*", empty)])
        self.assertTrue((self.download / "evidence.json").is_file())
        self.assertFalse(self.output.exists())

    def test_overlapping_groups_are_rejected(self):
        self.payload()
        other = self.root / "other"
        self.payload(other)
        with self.assertRaisesRegex(layout.LayoutError, "groups_overlap"):
            self.restore(downloads=[(PATTERN, self.download), (PATTERN, other)])
        with self.assertRaisesRegex(layout.LayoutError, "roots_overlap"):
            self.restore(downloads=[(PATTERN, self.download), (PATTERN, self.download)])

    def test_move_failure_rolls_back_owned_moves(self):
        rows = [artifact(1), artifact(2)]
        for row in rows:
            self.payload(self.download / row["name"])
        rename = Path.rename
        calls = []

        def fail_second(src, dst):
            calls.append((src, dst))
            if len(calls) == 2:
                raise OSError("owned move failed")
            return rename(src, dst)

        with patch.object(Path, "rename", fail_second), self.assertRaises(OSError):
            self.restore(rows)
        self.assertFalse(self.output.exists())
        for row in rows:
            self.assertTrue((self.download / row["name"] / "evidence.json").is_file())

    def test_single_direct_and_five_relays_reach_original_six_scenario_selector(self):
        direct = artifact(name=f"nat-topology-direct-{RUN}-1")
        relays = [artifact(name=f"nat-topology-relay-{RUN}-1-{i}-of-5", artifact_id=i+1) for i in range(1, 6)]
        self.payload()
        relay_root = self.root / "relays"
        for row in relays:
            self.payload(relay_root / row["name"])
        self.restore([direct, *relays], [(f"nat-topology-direct-{RUN}-*", self.download),
                                       (f"nat-topology-relay-{RUN}-*-of-5", relay_root)])
        chosen = nat.lay_out(self.output, self.root / "selected", RUN, max_attempt=1)
        self.assertEqual(chosen, {kind: 1 for kind in nat.expected_scenarios()})
        self.assertEqual(len(chosen), 6)

    def test_flat_component_fails_original_selector_then_same_bytes_pass_after_layout(self):
        contract = {"repository": "yhan-sun/p2wlan", "component": "dplpmtud-live-dataplane"}
        workflow = "f" * 40
        component = {"schema_version": 1, **contract, "source_head_sha": SOURCE,
                     "workflow_sha": workflow, "run_id": RUN, "run_attempt": 1,
                     "contract_sha256": dpl._canonical_sha256(contract), "result": "pass"}
        component["report_digest"] = dpl._canonical_sha256(component)
        raw = json.dumps(component).encode()
        (self.download / dpl.COMPONENT_FILE).write_bytes(raw)
        options = dict(contract=contract, source_head_sha=SOURCE, workflow_sha=workflow,
                       run_id=RUN, current_attempt=1, component_result="success", attempt_jobs=lambda _: [])
        with self.assertRaisesRegex(dpl.SelectionError, "component_artifact_missing"):
            dpl.select(self.download, **options)
        self.restore()
        selected = dpl.select(self.output, **options)
        self.assertEqual(Path(selected["component"]).read_bytes(), raw)
        with self.assertRaisesRegex(dpl.SelectionError, "component_source_head_mismatch"):
            dpl.select(self.output, **dict(options, source_head_sha="c" * 40))
        with self.assertRaisesRegex(dpl.SelectionError, "component_job_not_success"):
            dpl.select(self.output, **dict(options, component_result="failure"))

    def test_dispatch_target_source_is_distinct_from_authenticated_workflow_run_head(self):
        contract = {"repository": "yhan-sun/p2wlan", "component": "dplpmtud-live-dataplane"}
        target, workflow = "c" * 40, "f" * 40
        component = {"schema_version": 1, **contract, "source_head_sha": target,
                     "workflow_sha": workflow, "run_id": RUN, "run_attempt": 1,
                     "contract_sha256": dpl._canonical_sha256(contract), "result": "pass"}
        component["report_digest"] = dpl._canonical_sha256(component)
        raw = json.dumps(component).encode()
        (self.download / dpl.COMPONENT_FILE).write_bytes(raw)
        # The inventory belongs to the workflow's actual launch head. A valid
        # target payload must not authorize an artifact from another run head.
        with self.assertRaisesRegex(layout.LayoutError, "run_source_mismatch"):
            self.restore([artifact(workflow_run={"id": RUN, "head_sha": target})])
        self.restore()
        options = dict(contract=contract, source_head_sha=target, workflow_sha=workflow,
                       run_id=RUN, current_attempt=1, component_result="success", attempt_jobs=lambda _: [])
        selected = dpl.select(self.output, **options)
        self.assertEqual(Path(selected["component"]).read_bytes(), raw)
        with self.assertRaisesRegex(dpl.SelectionError, "component_source_head_mismatch"):
            dpl.select(self.output, **dict(options, source_head_sha=SOURCE))


class InventoryTests(unittest.TestCase):
    def response(self, rows, total=None):
        return io.BytesIO(json.dumps({"total_count": len(rows) if total is None else total, "artifacts": rows}).encode())

    def test_authenticated_scoped_pagination_is_complete(self):
        rows = [artifact(i) for i in range(1, 102)]
        with patch.object(layout.urllib.request, "urlopen", side_effect=[self.response(rows[:100], 101), self.response(rows[100:], 101)]) as query:
            self.assertEqual(layout.fetch_inventory("example/project", RUN, "private-token"), rows)
        self.assertIn(f"/repos/example/project/actions/runs/{RUN}/artifacts?", query.call_args_list[0].args[0].full_url)
        self.assertTrue(query.call_args_list[1].args[0].full_url.endswith("page=2"))
        self.assertLessEqual(query.call_args_list[0].kwargs["timeout"], 15)

    def test_incomplete_changing_or_excessive_inventory_fails(self):
        cases = [[self.response([artifact()], 2)],
                 [self.response([artifact(i) for i in range(1, 101)], 101), self.response([artifact(101)], 102)],
                 [self.response([], 1001)], [io.BytesIO(b"not json")]]
        for responses in cases:
            with patch.object(layout.urllib.request, "urlopen", side_effect=responses), self.assertRaises(layout.LayoutError):
                layout.fetch_inventory("example/project", RUN, "private-token")

    def test_deadline_response_limit_and_query_failure_do_not_expose_token(self):
        with patch.object(layout.time, "monotonic", side_effect=[0, 91]), self.assertRaisesRegex(layout.LayoutError, "deadline"):
            layout.fetch_inventory("example/project", RUN, "private-token")
        with patch.object(layout, "MAX_RESPONSE", 1), patch.object(layout.urllib.request, "urlopen", return_value=self.response([])), self.assertRaisesRegex(layout.LayoutError, "response_limit"):
            layout.fetch_inventory("example/project", RUN, "private-token")
        with patch.object(layout.urllib.request, "urlopen", side_effect=OSError("private-token")), self.assertRaisesRegex(layout.LayoutError, "^artifact_query_failed$"):
            layout.fetch_inventory("example/project", RUN, "private-token")

    def test_invalid_request_identity_and_missing_token_fail_before_http(self):
        with patch.object(layout.urllib.request, "urlopen") as query:
            for repo, run, token in [("../bad", RUN, "secret"), ("example/project", 0, "secret"), ("example/project", RUN, "")]:
                with self.assertRaises(layout.LayoutError):
                    layout.fetch_inventory(repo, run, token)
            query.assert_not_called()


class WorkflowLayoutTests(unittest.TestCase):
    def test_each_pattern_group_is_isolated_then_restored_before_original_selection(self):
        cases = [("nat-topology-gate.yml", "required", ["nat-direct-downloads", "nat-relay-downloads"],
                  "nat-topology-artifacts", "scripts/nat-sim/select_attempt_evidence.py"),
                 ("dplpmtud-required.yml", "evidence_aggregate", ["dplpmtud-component-downloads"],
                  "dplpmtud-component", "scripts/dplpmtud/select_component_artifact.py")]
        for filename, job, downloads, canonical, selector in cases:
            with self.subTest(workflow=filename):
                text = (ROOT / ".github/workflows" / filename).read_text()
                block = text.split(f"\n  {job}:\n", 1)[1].split("\n  required:\n", 1)[0]
                restore_pos = block.index("python3 scripts/quality/restore_artifact_layout.py")
                self.assertLess(restore_pos, block.index(f"python3 {selector}"))
                for staging in downloads:
                    self.assertLess(block.index(f"path: ${{{{ runner.temp }}}}/{staging}\n"), restore_pos)
                    self.assertIn(f'"$RUNNER_TEMP/{staging}"', block[restore_pos:])
                self.assertEqual(block.count("merge-multiple: false"), len(downloads))
                self.assertIn(f'--output-root "$RUNNER_TEMP/{canonical}"', block)
                self.assertIn(f'--artifacts-root "$RUNNER_TEMP/{canonical}"', block)
                self.assertIn('LAYOUT_OUTCOME: ${{ steps.layout.outcome }}', block)
                self.assertIn('test "$LAYOUT_OUTCOME" = "success"', block)
                self.assertIn('GH_TOKEN: ${{ github.token }}', block)
                self.assertIn('RUN_HEAD_SHA: ${{ github.event.pull_request.head.sha || github.sha }}', block)
                self.assertIn('--run-head-sha "$RUN_HEAD_SHA"', block)
                self.assertIn('actions: read', text)


if __name__ == "__main__":
    unittest.main()

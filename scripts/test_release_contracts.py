import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_PATH = ROOT / ".github" / "workflows" / "ci.yml"
RELEASING_PATH = ROOT / "docs" / "RELEASING.md"
RELEASE_SCRIPT_PATH = ROOT / "scripts" / "publish-release.sh"
README_PATH = ROOT / "README.md"


class ReleaseContractTests(unittest.TestCase):
    def _git(self, repository: Path, *args: str) -> None:
        subprocess.run(
            ["git", *args],
            cwd=repository,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

    def _release_repository(
        self,
        root: Path,
        tag_kind: str = "annotated",
        tag_on_main: bool = True,
    ) -> tuple[Path, Path]:
        origin = root / "origin.git"
        self._git(root, "init", "--bare", "--quiet", str(origin))

        source = root / "source"
        source.mkdir()
        self._git(source, "init", "--quiet")
        self._git(source, "config", "user.name", "Release Test")
        self._git(source, "config", "user.email", "release@example.test")
        (source / "tracked.txt").write_text("release\n", encoding="utf-8")
        self._git(source, "add", "tracked.txt")
        self._git(source, "commit", "--quiet", "-m", "release")
        self._git(source, "branch", "-M", "main")
        if not tag_on_main:
            self._git(source, "switch", "--quiet", "-c", "release-source")
            (source / "tracked.txt").write_text("release branch\n", encoding="utf-8")
            self._git(source, "commit", "--quiet", "-am", "release branch")
        if tag_kind == "annotated":
            self._git(source, "tag", "-a", "v2.0.0", "-m", "ShardLure v2.0.0")
        elif tag_kind == "lightweight":
            self._git(source, "tag", "v2.0.0")
        else:
            self.fail(f"unknown tag kind: {tag_kind}")
        if not tag_on_main:
            self._git(source, "switch", "--quiet", "main")
            (source / "tracked.txt").write_text("main branch\n", encoding="utf-8")
            self._git(source, "commit", "--quiet", "-am", "main branch")

        self._git(source, "remote", "add", "origin", str(origin))
        self._git(source, "push", "--quiet", "origin", "main")
        self._git(source, "push", "--quiet", "origin", "refs/tags/v2.0.0")

        repository = root / "repository"
        self._git(
            root,
            "clone",
            "--quiet",
            "--branch",
            "main",
            str(origin),
            str(repository),
        )
        self._git(repository, "config", "user.name", "Release Test")
        self._git(repository, "config", "user.email", "release@example.test")
        release_dir = repository / "release"
        release_dir.mkdir()
        (release_dir / "shardlure-linux-amd64").write_bytes(b"binary")
        return repository, origin

    def _change_remote_tag(
        self, repository: Path, root: Path, remote_tag_state: str
    ) -> None:
        if remote_tag_state == "matching":
            return
        if remote_tag_state == "deleted":
            self._git(repository, "push", "--quiet", "origin", ":refs/tags/v2.0.0")
            return
        if remote_tag_state == "lightweight":
            self._git(
                repository,
                "push",
                "--quiet",
                "--force",
                "origin",
                "HEAD:refs/tags/v2.0.0",
            )
            return
        if remote_tag_state == "replaced":
            self._git(
                repository,
                "tag",
                "-a",
                "remote-replacement",
                "-m",
                "replacement annotation",
                "v2.0.0^{}",
            )
            self._git(
                repository,
                "push",
                "--quiet",
                "--force",
                "origin",
                "refs/tags/remote-replacement:refs/tags/v2.0.0",
            )
            return
        if remote_tag_state == "moved":
            (repository / "tracked.txt").write_text("remote move\n", encoding="utf-8")
            self._git(repository, "commit", "--quiet", "-am", "remote move")
            self._git(
                repository,
                "tag",
                "-a",
                "remote-move",
                "-m",
                "moved tag",
            )
            self._git(
                repository,
                "push",
                "--quiet",
                "--force",
                "origin",
                "refs/tags/remote-move:refs/tags/v2.0.0",
            )
            return
        if remote_tag_state == "unavailable":
            self._git(
                repository,
                "remote",
                "set-url",
                "origin",
                str(root / "missing-origin.git"),
            )
            return
        self.fail(f"unknown remote tag state: {remote_tag_state}")

    def _stub_gh(self, root: Path) -> Path:
        bin_dir = root / "bin"
        bin_dir.mkdir()
        stub = bin_dir / "gh"
        stub.write_text(
            "#!/usr/bin/env python3\n"
            "import json, os, subprocess, sys\n"
            "def delete_remote_tag():\n"
            "    subprocess.run(\n"
            "        ['git', '--git-dir', os.environ['GH_REMOTE'], 'update-ref',\n"
            "         '-d', 'refs/tags/v2.0.0'], check=True\n"
            "    )\n"
            "args = sys.argv[1:]\n"
            "with open(os.environ['GH_LOG'], 'a', encoding='utf-8') as log:\n"
            "    log.write(json.dumps(args) + '\\n')\n"
            "if args[:2] == ['release', 'view']:\n"
            "    scenario = os.environ['GH_SCENARIO']\n"
            "    with open(os.environ['GH_LOG'], encoding='utf-8') as log:\n"
            "        view_count = sum(\n"
            "            json.loads(line)[:2] == ['release', 'view'] for line in log\n"
            "        )\n"
            "    if scenario in ('missing', 'missing_remote_deleted_before_create') "
            "and view_count == 1:\n"
            "        if scenario == 'missing_remote_deleted_before_create':\n"
            "            delete_remote_tag()\n"
            "        print('release not found', file=sys.stderr)\n"
            "        raise SystemExit(1)\n"
            "    if (scenario == 'draft_remote_deleted_before_upload' and "
            "view_count == 2):\n"
            "        delete_remote_tag()\n"
            "    if scenario in (\n"
            "        'missing', 'draft', 'upload_error',\n"
            "        'draft_remote_deleted_before_upload',\n"
            "        'draft_remote_deleted_before_publish',\n"
            "    ):\n"
            "        print('true')\n"
            "        raise SystemExit(0)\n"
            "    if scenario == 'draft_then_published':\n"
            "        print('true' if view_count == 1 else 'false')\n"
            "        raise SystemExit(0)\n"
            "    if scenario == 'draft_published_after_upload':\n"
            "        print('false' if os.path.exists(os.environ['GH_STATE']) else 'true')\n"
            "        raise SystemExit(0)\n"
            "    if scenario == 'published':\n"
            "        print('false')\n"
            "        raise SystemExit(0)\n"
            "    print('failed to connect to api.github.com', file=sys.stderr)\n"
            "    raise SystemExit(1)\n"
            "if args[:2] == ['release', 'upload'] and "
            "os.environ['GH_SCENARIO'] == 'upload_error':\n"
            "    print('upload failed', file=sys.stderr)\n"
            "    raise SystemExit(1)\n"
            "if args[:2] == ['release', 'upload'] and "
            "os.environ['GH_SCENARIO'] == 'draft_remote_deleted_before_publish':\n"
            "    delete_remote_tag()\n"
            "if args[:2] == ['release', 'upload'] and "
            "os.environ['GH_SCENARIO'] == 'draft_published_after_upload':\n"
            "    with open(os.environ['GH_STATE'], 'w', encoding='utf-8') as state:\n"
            "        state.write('published\\n')\n"
            "raise SystemExit(0)\n",
            encoding="utf-8",
        )
        stub.chmod(0o755)
        return bin_dir

    def _run_release(
        self,
        scenario: str,
        tag_kind: str = "annotated",
        tag_on_main: bool = True,
        remote_tag_state: str = "matching",
    ) -> tuple[subprocess.CompletedProcess[str], list[list[str]]]:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository, origin = self._release_repository(
                root, tag_kind=tag_kind, tag_on_main=tag_on_main
            )
            self._change_remote_tag(repository, root, remote_tag_state)
            bin_dir = self._stub_gh(root)
            log_path = root / "gh.log"
            environment = os.environ.copy()
            environment.update(
                {
                    "GH_LOG": str(log_path),
                    "GH_REMOTE": str(origin),
                    "GH_SCENARIO": scenario,
                    "GH_STATE": str(root / "release-state"),
                    "GH_TOKEN": "test-token",
                    "GITHUB_REF_NAME": "v2.0.0",
                    "GITHUB_REPOSITORY": "networkshard/shardlure",
                    "PATH": str(bin_dir) + os.pathsep + environment["PATH"],
                }
            )
            result = subprocess.run(
                ["bash", str(RELEASE_SCRIPT_PATH)],
                cwd=repository,
                env=environment,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            calls = []
            if log_path.exists():
                calls = [
                    json.loads(line)
                    for line in log_path.read_text(encoding="utf-8").splitlines()
                ]
            return result, calls

    def _release_actions(self, calls: list[list[str]]) -> list[str]:
        return [call[1] for call in calls if call[:1] == ["release"]]

    def _assert_release_call_contracts(self, calls: list[list[str]]) -> None:
        for call in calls:
            if len(call) < 2 or call[0] != "release":
                continue
            action = call[1]
            if action not in {"view", "create", "upload", "edit"}:
                continue
            with self.subTest(action=action, call=call):
                self.assertIn("--repo", call)
                repo_index = call.index("--repo")
                self.assertLess(repo_index + 1, len(call))
                self.assertEqual(call[repo_index + 1], "networkshard/shardlure")
                if action in {"create", "edit"}:
                    latest_flags = [
                        argument
                        for argument in call
                        if argument == "--latest" or argument.startswith("--latest=")
                    ]
                    self.assertEqual(latest_flags, [])

    def test_workflow_delegates_release_transaction_to_script(self) -> None:
        self.assertTrue(
            RELEASE_SCRIPT_PATH.is_file(), "scripts/publish-release.sh must exist"
        )
        workflow = WORKFLOW_PATH.read_text(encoding="utf-8")
        self.assertIn("bash scripts/publish-release.sh", workflow)

    def test_ci_runs_release_contract_tests(self) -> None:
        workflow = WORKFLOW_PATH.read_text(encoding="utf-8")
        test_job = workflow[workflow.index("  test:\n") : workflow.index("  cross-build:\n")]

        self.assertIn(
            "python3 -m unittest scripts/test_release_contracts.py -v", test_job
        )

    def test_release_checkout_restores_annotated_tag_and_main_history(self) -> None:
        workflow = WORKFLOW_PATH.read_text(encoding="utf-8")
        release_job = workflow[workflow.index("  release:\n") :]
        # Slice ends at the artifact download, so anything asserted below is also
        # asserted to run BEFORE it: an unannotated tag must abort cheaply.
        checkout = release_job[
            release_job.index("      - name: Checkout\n") : release_job.index(
                "      - name: Download all artifacts\n"
            )
        ]

        # publish-release.sh needs origin/main present for its ancestry check.
        self.assertIn("fetch-depth: 0", checkout)
        self.assertIn("fetch-tags: true", checkout)

        # The load-bearing part. actions/checkout force-updates the TRIGGERING
        # tag ref to the resolved commit sha, so refs/tags/vX is a commit object
        # inside CI and publish-release.sh's annotated-tag guard rejects a
        # correctly annotated release. fetch-tags does NOT prevent it. Only an
        # explicit forced refspec for that one ref restores the tag object, so
        # assert the refspec and its verification, not just fetch-tags.
        self.assertIn("- name: Restore annotated tag object", checkout)
        self.assertIn(
            '"+refs/tags/${GITHUB_REF_NAME}:refs/tags/${GITHUB_REF_NAME}"', checkout
        )
        self.assertIn(
            'test "$(git cat-file -t "refs/tags/${GITHUB_REF_NAME}")" = tag', checkout
        )

    def test_release_job_serializes_same_tag(self) -> None:
        workflow = WORKFLOW_PATH.read_text(encoding="utf-8")
        release_job = workflow[workflow.index("  release:\n") :]

        self.assertIn(
            "group: release-${{ github.repository }}-${{ github.ref }}", release_job
        )
        self.assertIn("cancel-in-progress: false", release_job)

    def test_releasing_guide_delegates_release_creation_to_ci(self) -> None:
        self.assertTrue(RELEASING_PATH.is_file(), "docs/RELEASING.md must exist")
        guide = RELEASING_PATH.read_text(encoding="utf-8")

        self.assertIn("git tag -a v2.0.0", guide)
        self.assertIn("git push origin refs/tags/v2.0.0", guide)
        self.assertNotIn("gh release create", guide)

    def test_readme_never_uses_fixed_tmp_binary(self) -> None:
        readme = README_PATH.read_text(encoding="utf-8")
        self.assertNotIn("sudo cp /tmp/shardlure", readme)
        self.assertNotIn("BUILD_BIN", readme)

        deployment = readme[
            readme.index("## Deployment\n") : readme.index(
                "### Manual Journal Export\n"
            )
        ]
        self.assertNotIn("/tmp/shardlure", deployment)
        tokens = (
            "bash scripts/fix-go-sources.sh",
            "Run the exact `sudo install ...` command printed by "
            "`scripts/fix-go-sources.sh`",
            "sudo python3 scripts/shardlure.py finish",
        )
        offsets = [deployment.index(token) for token in tokens]
        self.assertEqual(offsets, sorted(offsets))

    def test_missing_release_creates_then_uploads_and_publishes(self) -> None:
        result, calls = self._run_release("missing")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            self._release_actions(calls),
            ["view", "create", "view", "upload", "view", "edit"],
        )
        self._assert_release_call_contracts(calls)
        self.assertIn("--verify-tag", calls[1])
        self.assertIn("--draft", calls[1])
        self.assertIn("--generate-notes", calls[1])
        self.assertIn("--clobber", calls[3])
        self.assertIn("--draft=false", calls[5])

    def test_existing_draft_uploads_without_creating(self) -> None:
        result, calls = self._run_release("draft")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            self._release_actions(calls),
            ["view", "view", "upload", "view", "edit"],
        )
        self._assert_release_call_contracts(calls)
        self.assertIn("--clobber", calls[2])
        self.assertIn("--draft=false", calls[4])

    def test_published_release_fails_without_mutation(self) -> None:
        result, calls = self._run_release("published")

        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self._release_actions(calls), ["view"])

    def test_release_view_error_fails_without_mutation(self) -> None:
        result, calls = self._run_release("error")

        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self._release_actions(calls), ["view"])

    def test_publish_does_not_force_latest(self) -> None:
        result, calls = self._run_release("draft")

        self.assertEqual(result.returncode, 0, result.stderr)
        edit_call = next(call for call in calls if call[:2] == ["release", "edit"])
        self.assertIn("--draft=false", edit_call)
        self.assertFalse(
            any(
                argument == "--latest" or argument.startswith("--latest=")
                for argument in edit_call
            )
        )

    def test_release_is_rechecked_before_asset_mutation(self) -> None:
        result, calls = self._run_release("draft_then_published")

        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self._release_actions(calls), ["view", "view"])

    def test_upload_failure_leaves_draft_unpublished(self) -> None:
        result, calls = self._run_release("upload_error")

        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self._release_actions(calls), ["view", "view", "upload"])

    def test_release_published_during_upload_is_not_edited(self) -> None:
        result, calls = self._run_release("draft_published_after_upload")

        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(
            self._release_actions(calls), ["view", "view", "upload", "view"]
        )

    def test_lightweight_tag_is_rejected_before_github_calls(self) -> None:
        result, calls = self._run_release("missing", tag_kind="lightweight")

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("annotated tag", result.stderr)
        self.assertEqual(calls, [])

    def test_tag_commit_must_be_on_origin_main(self) -> None:
        result, calls = self._run_release("missing", tag_on_main=False)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("origin/main", result.stderr)
        self.assertEqual(calls, [])

    def test_remote_annotated_tag_replacement_is_rejected_before_github(self) -> None:
        result, calls = self._run_release("draft", remote_tag_state="replaced")

        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(calls, [])

    def test_remote_annotated_tag_move_is_rejected_before_github(self) -> None:
        result, calls = self._run_release("draft", remote_tag_state="moved")

        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(calls, [])

    def test_remote_tag_deletion_is_rejected_before_github(self) -> None:
        result, calls = self._run_release("draft", remote_tag_state="deleted")

        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(calls, [])

    def test_remote_lightweight_tag_is_rejected_before_github(self) -> None:
        result, calls = self._run_release("draft", remote_tag_state="lightweight")

        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(calls, [])

    def test_remote_lookup_error_is_propagated_before_github(self) -> None:
        result, calls = self._run_release("draft", remote_tag_state="unavailable")

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("fatal:", result.stderr)
        self.assertEqual(calls, [])

    def test_remote_tag_is_revalidated_before_create(self) -> None:
        result, calls = self._run_release("missing_remote_deleted_before_create")

        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self._release_actions(calls), ["view"])

    def test_remote_tag_is_revalidated_before_upload(self) -> None:
        result, calls = self._run_release("draft_remote_deleted_before_upload")

        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self._release_actions(calls), ["view", "view"])

    def test_remote_tag_is_revalidated_before_publish(self) -> None:
        result, calls = self._run_release("draft_remote_deleted_before_publish")

        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self._release_actions(calls), ["view", "view", "upload"])


if __name__ == "__main__":
    unittest.main()

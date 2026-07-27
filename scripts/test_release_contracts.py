import json
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_PATH = ROOT / ".github" / "workflows" / "ci.yml"
RELEASING_PATH = ROOT / "docs" / "RELEASING.md"
RELEASE_SCRIPT_PATH = ROOT / "scripts" / "publish-release.sh"
INSTALLER_PATH = ROOT / "scripts" / "install.sh"
COWRIE_PIN_PATH = ROOT / "install" / "cowrie.commit"
EXAMPLE_CONFIG_PATH = ROOT / "shardlure.yaml.example"
README_PATH = ROOT / "README.md"
PRODUCT_PATH = ROOT / "PRODUCT.md"


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

    def _git_stdout(self, repository: Path, *args: str) -> str:
        return subprocess.run(
            ["git", *args],
            cwd=repository,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        ).stdout.strip()

    def _cowrie_repository(self, root: Path) -> tuple[Path, str, str]:
        repository = root / "cowrie-source"
        repository.mkdir()
        self._git(repository, "init", "--quiet")
        self._git(repository, "config", "user.name", "Installer Test")
        self._git(repository, "config", "user.email", "installer@example.test")
        tracked = repository / "tracked.txt"
        tracked.write_text("first\n", encoding="utf-8")
        self._git(repository, "add", "tracked.txt")
        self._git(repository, "commit", "--quiet", "-m", "first")
        first = self._git_stdout(repository, "rev-parse", "HEAD")
        tracked.write_text("second\n", encoding="utf-8")
        self._git(repository, "commit", "--quiet", "-am", "second")
        second = self._git_stdout(repository, "rev-parse", "HEAD")
        return repository, first, second

    def _installer_stub_environment(
        self,
        root: Path,
        *,
        curl_body: str = "",
        ambiguous_git_ref: bool = False,
        fail_git_fetch: bool = False,
        extra: dict[str, str] | None = None,
    ) -> tuple[dict[str, str], Path]:
        bin_dir = root / "installer-bin"
        bin_dir.mkdir()
        command_log = root / "installer-commands.jsonl"
        real_git = shutil.which("git")
        self.assertIsNotNone(real_git, "behavioral installer contracts require git")

        git_stub = bin_dir / "git"
        git_stub.write_text(
            "#!/usr/bin/env python3\n"
            "import json, os, sys\n"
            "from pathlib import Path\n"
            "args = sys.argv[1:]\n"
            "with open(os.environ['INSTALLER_COMMAND_LOG'], 'a', encoding='utf-8') as log:\n"
            "    log.write(json.dumps({'command': 'git', 'args': args}) + '\\n')\n"
            "if os.environ.get('STUB_GIT_AMBIGUOUS') == '1' and args[:1] == ['ls-remote']:\n"
            "    print('1111111111111111111111111111111111111111\\trefs/heads/shared')\n"
            "    print('2222222222222222222222222222222222222222\\trefs/tags/shared')\n"
            "    raise SystemExit(0)\n"
            "if os.environ.get('STUB_GIT_REPOINT_PARENT_ON_VERIFY') == '1' and 'rev-parse' in args:\n"
            "    parent_link = Path(os.environ['STUB_GIT_PARENT_LINK'])\n"
            "    parent_link.unlink()\n"
            "    parent_link.symlink_to(os.environ['STUB_GIT_REPLACEMENT_PARENT'], target_is_directory=True)\n"
            "if os.environ.get('STUB_GIT_SWAP_ON_VERIFY') == '1' and 'rev-parse' in args:\n"
            "    target = Path(os.environ['STUB_GIT_SWAP_TARGET'])\n"
            "    replacement = Path(os.environ['STUB_GIT_SWAP_SOURCE'])\n"
            "    aside = Path(os.environ['STUB_GIT_SWAP_ASIDE'])\n"
            "    if target.exists() or target.is_symlink():\n"
            "        target.rename(aside)\n"
            "    replacement.rename(target)\n"
            "if os.environ.get('STUB_GIT_FAIL_FETCH') == '1' and 'fetch' in args:\n"
            "    raise SystemExit(1)\n"
            "real_git = os.environ['REAL_GIT']\n"
            "os.execv(real_git, [real_git, *args])\n",
            encoding="utf-8",
        )
        git_stub.chmod(0o755)

        curl_stub = bin_dir / "curl"
        curl_stub.write_text(
            "#!/usr/bin/env python3\n"
            "import json, os, sys\n"
            "from pathlib import Path\n"
            "args = sys.argv[1:]\n"
            "with open(os.environ['INSTALLER_COMMAND_LOG'], 'a', encoding='utf-8') as log:\n"
            "    log.write(json.dumps({'command': 'curl', 'args': args}) + '\\n')\n"
            "try:\n"
            "    output = args[args.index('-o') + 1]\n"
            "except (ValueError, IndexError):\n"
            "    raise SystemExit(2)\n"
            "Path(output).write_text(os.environ.get('STUB_CURL_BODY', ''), encoding='utf-8')\n",
            encoding="utf-8",
        )
        curl_stub.chmod(0o755)

        id_stub = bin_dir / "id"
        id_stub.write_text(
            "#!/usr/bin/env python3\n"
            "import json, os, sys\n"
            "with open(os.environ['INSTALLER_COMMAND_LOG'], 'a', encoding='utf-8') as log:\n"
            "    log.write(json.dumps({'command': 'id', 'args': sys.argv[1:]}) + '\\n')\n"
            "raise SystemExit(97)\n",
            encoding="utf-8",
        )
        id_stub.chmod(0o755)

        environment = os.environ.copy()
        environment.update(
            {
                "INSTALLER_COMMAND_LOG": str(command_log),
                "INSTALLER_UNDER_TEST": str(INSTALLER_PATH),
                "PATH": str(bin_dir) + os.pathsep + environment["PATH"],
                "REAL_GIT": str(real_git),
                "SHARDLURE_INSTALL_SOURCE_ONLY": "1",
                "STUB_CURL_BODY": curl_body,
                "STUB_GIT_AMBIGUOUS": "1" if ambiguous_git_ref else "0",
                "STUB_GIT_FAIL_FETCH": "1" if fail_git_fetch else "0",
            }
        )
        if extra:
            environment.update(extra)
        return environment, command_log

    def _run_installer_functions(
        self,
        root: Path,
        body: str,
        **environment_options: object,
    ) -> tuple[subprocess.CompletedProcess[str], list[dict[str, object]]]:
        environment, command_log = self._installer_stub_environment(
            root, **environment_options
        )
        script = (
            'source "$INSTALLER_UNDER_TEST"\n'
            'case "$-" in *e*u*) ;; *) exit 91 ;; esac\n'
            "[[ $(set -o | awk '$1 == \"pipefail\" {print $2}') == on ]]\n"
            + body
        )
        result = subprocess.run(
            ["bash", "-c", script],
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        calls: list[dict[str, object]] = []
        if command_log.exists():
            calls = [
                json.loads(line)
                for line in command_log.read_text(encoding="utf-8").splitlines()
            ]
        return result, calls

    def _assert_data_path_initialization_wired(
        self, installer: str
    ) -> re.Match[str]:
        calls = list(
            re.finditer(r"(?m)^[ \t]*initialize_data_paths[ \t]*$", installer)
        )
        self.assertEqual(
            len(calls),
            1,
            "installer must contain exactly one executable standalone "
            "initialize_data_paths call",
        )
        call = calls[0]

        source_only = installer.index(
            'if [[ "${SHARDLURE_INSTALL_SOURCE_ONLY:-0}" == "1" ]]'
        )
        parse_start = installer.index("# -- parse CLI overrides", source_only)
        parse_end = installer.index("\ndone\n", parse_start) + len("\ndone\n")
        self.assertGreater(call.start(), source_only)
        self.assertGreater(call.start(), parse_end)

        config_marker = "# -- config ----------------------------------------------------------------\n"
        self.assertEqual(installer.count(config_marker), 1)
        config_call_start = installer.index(config_marker, parse_end) + len(
            config_marker
        )
        self.assertEqual(
            call.start(),
            config_call_start,
            "initialize_data_paths must be a top-level call immediately after "
            "the config section marker",
        )
        self.assertEqual(
            call.group(),
            "initialize_data_paths",
            "initialize_data_paths must be an unindented top-level call",
        )

        first_derivative = re.search(
            r"\$(?:\{)?(?:DATA_DIR|COWRIE_HOME|COWRIE_LOG)\b",
            installer[parse_end:],
        )
        self.assertIsNotNone(first_derivative)
        assert first_derivative is not None
        self.assertLess(call.start(), parse_end + first_derivative.start())
        return call

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

    def test_ci_fails_on_unformatted_tracked_go_files(self) -> None:
        workflow = WORKFLOW_PATH.read_text(encoding="utf-8")
        test_job = workflow[workflow.index("  test:\n") : workflow.index("  cross-build:\n")]
        step_marker = "      - name: Check Go formatting\n"
        self.assertIn(step_marker, test_job)
        step_start = test_job.index(step_marker)
        step_end = test_job.find("      - name:", step_start + 1)
        formatting_step = test_job[step_start:step_end]

        self.assertIn("git ls-files -z -- '*.go'", formatting_step)
        self.assertIn("xargs -0 -r gofmt -l", formatting_step)
        self.assertIn('if [[ -n "$unformatted" ]]', formatting_step)
        self.assertIn('printf \'%s\\n\' "$unformatted"', formatting_step)
        self.assertIn("exit 1", formatting_step)
        self.assertNotIn("gofmt -l .", formatting_step)

    def test_installer_maps_only_supported_armv7_uname_values(self) -> None:
        installer = INSTALLER_PATH.read_text(encoding="utf-8")

        for architecture in ("armv7l", "armhf"):
            with self.subTest(architecture=architecture):
                self.assertIn(
                    f"ARCH_MAP[{architecture}]=shardlure-linux-armv7", installer
                )
        self.assertNotIn("ARCH_MAP[armv7]=", installer)

        unsupported = installer[
            installer.index('if [[ -z "$BIN_NAME" ]]') : installer.index(
                'log "detected architecture:',
            )
        ]
        self.assertIn(
            "supported: x86_64, amd64, aarch64, arm64, armv7l, armhf",
            unsupported,
        )

    def test_installer_default_cowrie_checkout_uses_matching_release_pin(self) -> None:
        pin = COWRIE_PIN_PATH.read_text(encoding="utf-8")
        self.assertEqual(len(pin), 41)
        self.assertRegex(pin, r"\A[0-9a-f]{40}\n\Z")

        installer = INSTALLER_PATH.read_text(encoding="utf-8")
        self.assertIn(
            'COWRIE_PIN_URL="https://raw.githubusercontent.com/$REPO/$TAG/'
            'install/cowrie.commit"',
            installer,
        )
        self.assertIn('curl -fsSL "$COWRIE_PIN_URL"', installer)
        self.assertIn("^[0-9a-f]{40}$", installer)
        self.assertIn('wc -l < "$DL_COWRIE_PIN"', installer)
        self.assertIn('wc -c < "$DL_COWRIE_PIN"', installer)
        self.assertIn(
            'git -C "$cowrie_staging" fetch --depth 1 origin "$COWRIE_COMMIT"',
            installer,
        )
        self.assertIn(
            'git -C "$cowrie_staging" checkout --detach "$COWRIE_COMMIT"',
            installer,
        )

    def test_installer_never_uses_a_moving_default_cowrie_checkout(self) -> None:
        installer = INSTALLER_PATH.read_text(encoding="utf-8")

        for moving_default in (
            "git clone",
            "ls-remote --symref",
            "CANDIDATES",
            "CANDIDATES+=(main master)",
        ):
            with self.subTest(moving_default=moving_default):
                self.assertNotIn(moving_default, installer)

    def test_installer_override_resolves_once_to_one_immutable_commit(self) -> None:
        installer = INSTALLER_PATH.read_text(encoding="utf-8")

        self.assertIn("--cowrie-branch", installer)
        self.assertIn(
            'git ls-remote "$COWRIE_REPO" "$COWRIE_BRANCH" '
            '"${COWRIE_BRANCH}^{}"',
            installer,
        )
        self.assertIn("must resolve to exactly one commit", installer)
        self.assertIn('COWRIE_COMMIT="$COWRIE_OVERRIDE_COMMIT"', installer)
        self.assertIn(
            'COWRIE_CHECKED_OUT_COMMIT=$(git -C "$cowrie_staging" '
            'rev-parse --verify HEAD)',
            installer,
        )
        self.assertIn(
            'if [[ "$COWRIE_CHECKED_OUT_COMMIT" != "$COWRIE_COMMIT" ]]',
            installer,
        )

    def test_installer_resolves_pin_or_override_before_existing_checkout(self) -> None:
        installer = INSTALLER_PATH.read_text(encoding="utf-8")
        production = installer[installer.index("# -- cowrie installation") :]
        self.assertIn(
            '  resolve_cowrie_commit\n\n  if [[ -d "$COWRIE_HOME/.git" ]]',
            production,
        )
        for resolution_step in (
            'COWRIE_REPO="${COWRIE_REPO:-https://github.com/cowrie/cowrie.git}"',
            'COWRIE_PIN_URL="https://raw.githubusercontent.com/$REPO/$TAG/'
            'install/cowrie.commit"',
            'git ls-remote "$COWRIE_REPO" "$COWRIE_BRANCH" '
            '"${COWRIE_BRANCH}^{}"',
            'COWRIE_COMMIT="$COWRIE_OVERRIDE_COMMIT"',
        ):
            with self.subTest(resolution_step=resolution_step):
                self.assertIn(resolution_step, installer)

    def test_installer_existing_checkout_requires_exact_commit(self) -> None:
        installer = INSTALLER_PATH.read_text(encoding="utf-8")
        function_start = installer.index("validate_existing_cowrie_checkout() {")
        function_end = installer.index("\n}\n", function_start) + 2
        existing = installer[function_start:function_end]
        production = installer[installer.index("# -- cowrie installation") :]

        self.assertIn("    validate_existing_cowrie_checkout", production)
        self.assertIn(
            'COWRIE_EXISTING_COMMIT=$(git -c safe.directory="$cowrie_safe_directory" '
            '-C "$cowrie_safe_directory" '
            'rev-parse --verify HEAD 2>/dev/null)',
            existing,
        )
        self.assertIn(
            'if [[ "$COWRIE_EXISTING_COMMIT" != "$COWRIE_COMMIT" ]]', existing
        )
        self.assertIn('COWRIE_HOME="$cowrie_safe_directory"', existing)
        self.assertIn("does not match required commit", existing)
        self.assertIn("preserving existing checkout and dirty files", existing)

    def test_installer_existing_mismatch_fails_without_mutation(self) -> None:
        installer = INSTALLER_PATH.read_text(encoding="utf-8")
        function_start = installer.index("validate_existing_cowrie_checkout() {")
        function_end = installer.index("\n}\n", function_start) + 2
        existing = installer[function_start:function_end]

        self.assertIn('err "could not read Cowrie HEAD', existing)
        self.assertIn('err "existing Cowrie commit', existing)
        for mutation in (
            'git -C "$COWRIE_HOME" fetch',
            'git -C "$COWRIE_HOME" reset',
            'git -C "$COWRIE_HOME" checkout',
            'git -C "$COWRIE_HOME" clean',
            "rm -",
        ):
            with self.subTest(mutation=mutation):
                self.assertNotIn(mutation, existing)

    def test_installer_production_calls_symlink_safe_fresh_checkout_function(self) -> None:
        installer = INSTALLER_PATH.read_text(encoding="utf-8")
        production = installer[installer.index("# -- cowrie installation") :]
        function_start = installer.index("checkout_fresh_cowrie() {")
        function_end = installer.index("\n}\n", function_start) + 2
        fresh_checkout = installer[function_start:function_end]

        self.assertIn("    checkout_fresh_cowrie", production)
        self.assertIn(
            'if [[ -e "$cowrie_final_path" || -L "$cowrie_final_path" ]]',
            fresh_checkout,
        )
        self.assertIn(
            'cowrie_staging=$(mktemp -d -- '
            '"$cowrie_parent_physical/.cowrie-install.XXXXXXXXXX")',
            fresh_checkout,
        )
        self.assertIn('git -C "$cowrie_staging" init -q', fresh_checkout)
        self.assertIn(
            'mv -T --no-clobber -- "$cowrie_staging" "$cowrie_final_path"',
            fresh_checkout,
        )
        self.assertIn('COWRIE_HOME="$cowrie_final_path"', fresh_checkout)
        self.assertNotIn("COWRIE_TARGET_CREATED", fresh_checkout)
        self.assertNotIn("rm -rf", fresh_checkout)
        seam = 'if [[ "${SHARDLURE_INSTALL_SOURCE_ONLY:-0}" == "1" ]]'
        self.assertIn(seam, installer)
        self.assertLess(installer.index(seam), installer.index("# -- parse CLI overrides"))

    def test_installer_initializes_physical_data_paths_before_rendering(self) -> None:
        installer = INSTALLER_PATH.read_text(encoding="utf-8")
        self.assertIn("initialize_data_paths() {", installer)
        helper_start = installer.index("initialize_data_paths() {")
        helper_end = installer.index("\n}\n", helper_start) + 2
        helper = installer[helper_start:helper_end]
        config_start = installer.index("# -- config")
        initialization = self._assert_data_path_initialization_wired(installer)

        self.assertIn('DATA_DIR="$data_dir_physical"', helper)
        self.assertIn('COWRIE_HOME="$DATA_DIR/cowrie"', helper)
        self.assertIn(
            'COWRIE_LOG="$COWRIE_HOME/var/log/cowrie/cowrie.json"', helper
        )
        for derivative in (
            'cat > "$DATA_DIR/shardlure.yaml"',
            "cat > /etc/systemd/system/shardlure-live.service",
            "# -- cowrie installation",
        ):
            with self.subTest(derivative=derivative):
                self.assertLess(
                    initialization.start(), installer.index(derivative, config_start)
                )
        self.assertEqual(installer.count('COWRIE_HOME="$DATA_DIR/cowrie"'), 1)
        self.assertEqual(
            installer.count(
                'COWRIE_LOG="$COWRIE_HOME/var/log/cowrie/cowrie.json"'
            ),
            1,
        )

    def test_installer_data_path_wiring_rejects_commented_call(self) -> None:
        installer = INSTALLER_PATH.read_text(encoding="utf-8")
        initialization = self._assert_data_path_initialization_wired(installer)
        mutated = (
            installer[: initialization.start()]
            + "# initialize_data_paths"
            + installer[initialization.end() :]
        )

        with self.assertRaisesRegex(AssertionError, "exactly one executable"):
            self._assert_data_path_initialization_wired(mutated)

    def test_installer_data_path_wiring_rejects_unreachable_wrapped_call(
        self,
    ) -> None:
        installer = INSTALLER_PATH.read_text(encoding="utf-8")
        initialization = self._assert_data_path_initialization_wired(installer)
        mutated = (
            installer[: initialization.start()]
            + "if false; then\n  initialize_data_paths\nfi"
            + installer[initialization.end() :]
        )

        with self.assertRaisesRegex(AssertionError, "top-level call immediately"):
            self._assert_data_path_initialization_wired(mutated)

    def test_installer_function_pins_data_path_derivatives_before_parent_repoint(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            physical_data = root / "physical-data"
            physical_data.mkdir()
            swapped_data = root / "swapped-data"
            swapped_data.mkdir()
            data_link = root / "data"
            data_link.symlink_to(physical_data, target_is_directory=True)

            result, _ = self._run_installer_functions(
                root,
                """
DATA_DIR="$TEST_DATA_DIR"
initialize_data_paths
command rm -- "$TEST_DATA_DIR"
command ln -s -- "$TEST_SWAPPED_DATA_DIR" "$TEST_DATA_DIR"
mkdir -p -- "$COWRIE_HOME/var/log/cowrie"
printf 'config\n' > "$DATA_DIR/shardlure.yaml"
printf 'event\n' > "$COWRIE_LOG"
LIVE_UNIT="ExecStart=/usr/local/bin/shardlure -config $DATA_DIR/shardlure.yaml live --cowrie=$COWRIE_LOG"
printf '%s\n' "$LIVE_UNIT"
""",
                extra={
                    "TEST_DATA_DIR": str(data_link),
                    "TEST_SWAPPED_DATA_DIR": str(swapped_data),
                },
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(
                (physical_data / "shardlure.yaml").read_text(encoding="utf-8"),
                "config\n",
            )
            physical_log = physical_data / "cowrie" / "var" / "log" / "cowrie" / "cowrie.json"
            self.assertEqual(physical_log.read_text(encoding="utf-8"), "event\n")
            self.assertFalse((swapped_data / "shardlure.yaml").exists())
            self.assertFalse((swapped_data / "cowrie").exists())
            self.assertIn(f"-config {physical_data}/shardlure.yaml", result.stdout)
            self.assertIn(f"--cowrie={physical_log}", result.stdout)
            self.assertNotIn(str(data_link), result.stdout)

    def test_installer_functions_fetch_release_pin_and_detach_exact_commit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, pinned_commit, _ = self._cowrie_repository(root)
            target = root / "data" / "cowrie"
            target.parent.mkdir()
            pin_file = root / "downloaded-cowrie.commit"
            result, calls = self._run_installer_functions(
                root,
                """
REPO="example/shardlure"
TAG="v9.9.9"
COWRIE_BRANCH=""
COWRIE_REPO="$TEST_COWRIE_REPOSITORY"
DL_COWRIE_PIN="$TEST_PIN_FILE"
COWRIE_HOME="$TEST_COWRIE_HOME"
resolve_cowrie_commit
checkout_fresh_cowrie
""",
                curl_body=pinned_commit + "\n",
                extra={
                    "TEST_COWRIE_HOME": str(target),
                    "TEST_COWRIE_REPOSITORY": source.resolve().as_uri(),
                    "TEST_PIN_FILE": str(pin_file),
                },
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(self._git_stdout(target, "rev-parse", "HEAD"), pinned_commit)
            detached = subprocess.run(
                ["git", "-C", str(target), "symbolic-ref", "-q", "HEAD"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertNotEqual(detached.returncode, 0)
            self.assertFalse(any(call["command"] == "id" for call in calls), calls)
            curl_calls = [call["args"] for call in calls if call["command"] == "curl"]
            self.assertEqual(len(curl_calls), 1)
            self.assertIn(
                "https://raw.githubusercontent.com/example/shardlure/v9.9.9/"
                "install/cowrie.commit",
                curl_calls[0],
            )
            git_calls = [call["args"] for call in calls if call["command"] == "git"]
            checkout_paths = {
                call[1] for call in git_calls if call[:1] == ["-C"]
            }
            self.assertEqual(len(checkout_paths), 1, git_calls)
            staging = checkout_paths.pop()
            self.assertEqual(Path(staging).parent, target.parent.resolve())
            self.assertRegex(Path(staging).name, r"\A\.cowrie-install\.[A-Za-z0-9]{10}\Z")
            self.assertNotEqual(staging, str(target))
            self.assertIn(
                ["-C", staging, "fetch", "--depth", "1", "origin", pinned_commit],
                git_calls,
            )
            self.assertIn(
                ["-C", staging, "checkout", "--detach", pinned_commit],
                git_calls,
            )
            self.assertFalse(Path(staging).exists())

    def test_installer_function_preserves_matching_dirty_checkout(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target, _, required_commit = self._cowrie_repository(root)
            tracked = target / "tracked.txt"
            tracked.write_text("operator patch\n", encoding="utf-8")
            untracked = target / "operator-note.txt"
            untracked.write_text("keep me\n", encoding="utf-8")
            before_status = self._git_stdout(target, "status", "--porcelain")

            result, calls = self._run_installer_functions(
                root,
                """
COWRIE_HOME="$TEST_COWRIE_HOME"
COWRIE_COMMIT="$TEST_COWRIE_COMMIT"
validate_existing_cowrie_checkout
""",
                extra={
                    "TEST_COWRIE_HOME": str(target),
                    "TEST_COWRIE_COMMIT": required_commit,
                },
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("preserving existing checkout and dirty files", result.stdout)
            self.assertIn("installer-managed cowrie.cfg may still be updated", result.stdout)
            self.assertEqual(self._git_stdout(target, "rev-parse", "HEAD"), required_commit)
            self.assertEqual(self._git_stdout(target, "status", "--porcelain"), before_status)
            self.assertEqual(tracked.read_text(encoding="utf-8"), "operator patch\n")
            self.assertEqual(untracked.read_text(encoding="utf-8"), "keep me\n")
            mutating = {"fetch", "reset", "checkout", "clean"}
            for call in calls:
                if call["command"] == "git":
                    self.assertTrue(mutating.isdisjoint(call["args"]), call)

    def test_installer_function_validates_relative_checkout_with_canonical_safe_directory(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target, _, required_commit = self._cowrie_repository(root)
            relative_target = target.name

            result, calls = self._run_installer_functions(
                root,
                """
cd "$TEST_COWRIE_PARENT"
COWRIE_HOME="$TEST_COWRIE_HOME"
COWRIE_COMMIT="$TEST_COWRIE_COMMIT"
validate_existing_cowrie_checkout
""",
                extra={
                    "GIT_TEST_ASSUME_DIFFERENT_OWNER": "1",
                    "TEST_COWRIE_PARENT": str(target.parent),
                    "TEST_COWRIE_HOME": relative_target,
                    "TEST_COWRIE_COMMIT": required_commit,
                },
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            git_calls = [call["args"] for call in calls if call["command"] == "git"]
            self.assertEqual(
                git_calls,
                [
                    [
                        "-c",
                        f"safe.directory={target.resolve()}",
                        "-C",
                        str(target.resolve()),
                        "rev-parse",
                        "--verify",
                        "HEAD",
                    ]
                ],
            )

    def test_installer_function_validates_symlink_parent_with_canonical_safe_directory(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target, _, required_commit = self._cowrie_repository(root)
            linked_parent = root / "linked-parent"
            linked_parent.symlink_to(target.parent, target_is_directory=True)
            spelled_target = linked_parent / target.name

            result, calls = self._run_installer_functions(
                root,
                """
COWRIE_HOME="$TEST_COWRIE_HOME"
COWRIE_COMMIT="$TEST_COWRIE_COMMIT"
validate_existing_cowrie_checkout
""",
                extra={
                    "GIT_TEST_ASSUME_DIFFERENT_OWNER": "1",
                    "TEST_COWRIE_HOME": str(spelled_target),
                    "TEST_COWRIE_COMMIT": required_commit,
                },
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            git_calls = [call["args"] for call in calls if call["command"] == "git"]
            self.assertEqual(
                git_calls,
                [
                    [
                        "-c",
                        f"safe.directory={target.resolve()}",
                        "-C",
                        str(target.resolve()),
                        "rev-parse",
                        "--verify",
                        "HEAD",
                    ]
                ],
            )

    def test_installer_function_validates_dotdot_checkout_with_canonical_safe_directory(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository, _, required_commit = self._cowrie_repository(root)
            target = repository.rename(root / "cowrie")
            (root / "nested").mkdir()
            spelled_target = "nested/../cowrie"

            result, calls = self._run_installer_functions(
                root,
                """
cd "$TEST_COWRIE_PARENT"
COWRIE_HOME="$TEST_COWRIE_HOME"
COWRIE_COMMIT="$TEST_COWRIE_COMMIT"
validate_existing_cowrie_checkout
""",
                extra={
                    "GIT_TEST_ASSUME_DIFFERENT_OWNER": "1",
                    "TEST_COWRIE_PARENT": str(root),
                    "TEST_COWRIE_HOME": spelled_target,
                    "TEST_COWRIE_COMMIT": required_commit,
                },
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            git_calls = [call["args"] for call in calls if call["command"] == "git"]
            self.assertEqual(
                git_calls,
                [
                    [
                        "-c",
                        f"safe.directory={target.resolve()}",
                        "-C",
                        str(target.resolve()),
                        "rev-parse",
                        "--verify",
                        "HEAD",
                    ]
                ],
            )

    def test_installer_function_validates_resolved_checkout_when_parent_repoints_before_git(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original_parent = root / "original-data"
            original_parent.mkdir()
            original_repository, _, original_commit = self._cowrie_repository(
                original_parent
            )
            original_target = original_repository.rename(original_parent / "cowrie")

            replacement_parent = root / "replacement-data"
            replacement_parent.mkdir()
            replacement_repository, _, _ = self._cowrie_repository(replacement_parent)
            replacement_target = replacement_repository.rename(
                replacement_parent / "cowrie"
            )
            replacement_only = replacement_target / "replacement-only.txt"
            replacement_only.write_text("replacement\n", encoding="utf-8")
            self._git(replacement_target, "add", replacement_only.name)
            self._git(replacement_target, "commit", "--quiet", "-m", "replacement")
            required_commit = self._git_stdout(replacement_target, "rev-parse", "HEAD")
            self.assertNotEqual(original_commit, required_commit)

            parent_link = root / "data"
            parent_link.symlink_to(original_parent, target_is_directory=True)
            raw_target = parent_link / "cowrie"

            result, calls = self._run_installer_functions(
                root,
                """
COWRIE_HOME="$TEST_COWRIE_HOME"
COWRIE_COMMIT="$TEST_COWRIE_COMMIT"
validate_existing_cowrie_checkout
""",
                extra={
                    "STUB_GIT_REPOINT_PARENT_ON_VERIFY": "1",
                    "STUB_GIT_PARENT_LINK": str(parent_link),
                    "STUB_GIT_REPLACEMENT_PARENT": str(replacement_parent),
                    "TEST_COWRIE_HOME": str(raw_target),
                    "TEST_COWRIE_COMMIT": required_commit,
                },
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertIn(
                f"existing Cowrie commit {original_commit} does not match required commit "
                f"{required_commit}",
                result.stderr,
            )
            git_calls = [call["args"] for call in calls if call["command"] == "git"]
            self.assertEqual(
                git_calls,
                [
                    [
                        "-c",
                        f"safe.directory={original_target.resolve()}",
                        "-C",
                        str(original_target.resolve()),
                        "rev-parse",
                        "--verify",
                        "HEAD",
                    ]
                ],
            )

    def test_installer_function_refuses_mismatched_existing_checkout(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target, checked_out_commit, required_commit = self._cowrie_repository(root)
            self._git(target, "checkout", "--quiet", checked_out_commit)
            tracked = target / "tracked.txt"
            tracked.write_text("dirty but precious\n", encoding="utf-8")
            before_status = self._git_stdout(target, "status", "--porcelain")

            result, calls = self._run_installer_functions(
                root,
                """
COWRIE_HOME="$TEST_COWRIE_HOME"
COWRIE_COMMIT="$TEST_COWRIE_COMMIT"
validate_existing_cowrie_checkout
""",
                extra={
                    "TEST_COWRIE_HOME": str(target),
                    "TEST_COWRIE_COMMIT": required_commit,
                },
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("does not match required commit", result.stderr)
            self.assertEqual(self._git_stdout(target, "rev-parse", "HEAD"), checked_out_commit)
            self.assertEqual(self._git_stdout(target, "status", "--porcelain"), before_status)
            self.assertEqual(tracked.read_text(encoding="utf-8"), "dirty but precious\n")
            mutating = {"fetch", "reset", "checkout", "clean"}
            for call in calls:
                if call["command"] == "git":
                    self.assertTrue(mutating.isdisjoint(call["args"]), call)

    def test_installer_function_refuses_ambiguous_override(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            result, calls = self._run_installer_functions(
                root,
                """
COWRIE_REPO="https://example.invalid/cowrie.git"
COWRIE_BRANCH="shared"
DL_COWRIE_PIN="$TEST_PIN_FILE"
resolve_cowrie_commit
""",
                ambiguous_git_ref=True,
                extra={"TEST_PIN_FILE": str(root / "unused-pin")},
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("must resolve to exactly one commit", result.stderr)
            git_calls = [call["args"] for call in calls if call["command"] == "git"]
            self.assertEqual(len(git_calls), 1, calls)
            self.assertEqual(git_calls[0][0], "ls-remote")

    def test_installer_function_refuses_and_preserves_dangling_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "cowrie"
            link_destination = root / "missing-cowrie"
            target.symlink_to(link_destination)

            result, calls = self._run_installer_functions(
                root,
                """
COWRIE_HOME="$TEST_COWRIE_HOME"
COWRIE_REPO="https://example.invalid/cowrie.git"
COWRIE_COMMIT="1111111111111111111111111111111111111111"
checkout_fresh_cowrie
""",
                extra={"TEST_COWRIE_HOME": str(target)},
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("exists or is a symlink", result.stderr)
            self.assertTrue(target.is_symlink())
            self.assertEqual(os.readlink(target), str(link_destination))
            self.assertFalse(any(call["command"] == "git" for call in calls), calls)

    def test_installer_function_refuses_symlink_to_existing_checkout(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, _, required_commit = self._cowrie_repository(root)
            target = root / "cowrie-link"
            target.symlink_to(source, target_is_directory=True)

            result, calls = self._run_installer_functions(
                root,
                """
COWRIE_HOME="$TEST_COWRIE_HOME"
COWRIE_COMMIT="$TEST_COWRIE_COMMIT"
validate_existing_cowrie_checkout
""",
                extra={
                    "TEST_COWRIE_HOME": str(target),
                    "TEST_COWRIE_COMMIT": required_commit,
                },
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("must not be a symlink", result.stderr)
            self.assertTrue(target.is_symlink())
            self.assertEqual(os.readlink(target), str(source))
            self.assertFalse(any(call["command"] == "git" for call in calls), calls)

    def test_installer_function_rejects_parent_drift_after_atomic_publish(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, pinned_commit, _ = self._cowrie_repository(root)
            physical_parent = root / "physical-data"
            physical_parent.mkdir()
            swapped_parent = root / "swapped-data"
            swapped_parent.mkdir()
            swapped_target = swapped_parent / "cowrie"
            swapped_target.mkdir()
            swapped_sentinel = swapped_target / "operator-data.txt"
            swapped_sentinel.write_text("keep me\n", encoding="utf-8")
            parent_link = root / "data"
            parent_link.symlink_to(physical_parent, target_is_directory=True)
            raw_target = parent_link / "cowrie"
            physical_target = physical_parent / "cowrie"

            result, _ = self._run_installer_functions(
                root,
                """
mv() {
  command mv "$@"
  command rm -- "$TEST_COWRIE_PARENT_LINK"
  command ln -s -- "$TEST_SWAPPED_PARENT" "$TEST_COWRIE_PARENT_LINK"
}
COWRIE_HOME="$TEST_COWRIE_HOME"
COWRIE_REPO="$TEST_COWRIE_REPOSITORY"
COWRIE_COMMIT="$TEST_COWRIE_COMMIT"
checkout_fresh_cowrie
printf 'later operation\n' > "$COWRIE_HOME/later-operation.txt"
""",
                extra={
                    "TEST_COWRIE_PARENT_LINK": str(parent_link),
                    "TEST_SWAPPED_PARENT": str(swapped_parent),
                    "TEST_COWRIE_HOME": str(raw_target),
                    "TEST_COWRIE_REPOSITORY": source.resolve().as_uri(),
                    "TEST_COWRIE_COMMIT": pinned_commit,
                },
            )

            self.assertFalse((swapped_target / "later-operation.txt").exists())
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("target parent changed after publication", result.stderr)
            self.assertEqual(swapped_sentinel.read_text(encoding="utf-8"), "keep me\n")
            self.assertEqual(
                self._git_stdout(physical_target, "rev-parse", "HEAD"), pinned_commit
            )

    def test_installer_function_pins_symlink_parent_after_fresh_publish(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, pinned_commit, _ = self._cowrie_repository(root)
            physical_parent = root / "physical-data"
            physical_parent.mkdir()
            swapped_parent = root / "swapped-data"
            swapped_parent.mkdir()
            swapped_target = swapped_parent / "cowrie"
            swapped_target.mkdir()
            parent_link = root / "data"
            parent_link.symlink_to(physical_parent, target_is_directory=True)
            raw_target = parent_link / "cowrie"
            physical_target = physical_parent / "cowrie"

            result, _ = self._run_installer_functions(
                root,
                """
COWRIE_HOME="$TEST_COWRIE_HOME"
COWRIE_REPO="$TEST_COWRIE_REPOSITORY"
COWRIE_COMMIT="$TEST_COWRIE_COMMIT"
checkout_fresh_cowrie
command rm -- "$TEST_COWRIE_PARENT_LINK"
command ln -s -- "$TEST_SWAPPED_PARENT" "$TEST_COWRIE_PARENT_LINK"
printf 'later operation\n' > "$COWRIE_HOME/later-operation.txt"
""",
                extra={
                    "TEST_COWRIE_PARENT_LINK": str(parent_link),
                    "TEST_SWAPPED_PARENT": str(swapped_parent),
                    "TEST_COWRIE_HOME": str(raw_target),
                    "TEST_COWRIE_REPOSITORY": source.resolve().as_uri(),
                    "TEST_COWRIE_COMMIT": pinned_commit,
                },
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue((physical_target / "later-operation.txt").is_file())
            self.assertEqual(
                (physical_target / "later-operation.txt").read_text(encoding="utf-8"),
                "later operation\n",
            )
            self.assertFalse((swapped_target / "later-operation.txt").exists())

    def test_installer_function_pins_symlink_parent_for_existing_checkout(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            physical_parent = root / "physical-data"
            physical_parent.mkdir()
            repository, _, required_commit = self._cowrie_repository(physical_parent)
            physical_target = repository.rename(physical_parent / "cowrie")
            swapped_parent = root / "swapped-data"
            swapped_parent.mkdir()
            swapped_target = swapped_parent / "cowrie"
            swapped_target.mkdir()
            parent_link = root / "data"
            parent_link.symlink_to(physical_parent, target_is_directory=True)
            raw_target = parent_link / "cowrie"

            result, _ = self._run_installer_functions(
                root,
                """
COWRIE_HOME="$TEST_COWRIE_HOME"
COWRIE_COMMIT="$TEST_COWRIE_COMMIT"
validate_existing_cowrie_checkout
command rm -- "$TEST_COWRIE_PARENT_LINK"
command ln -s -- "$TEST_SWAPPED_PARENT" "$TEST_COWRIE_PARENT_LINK"
printf 'later validation operation\n' > "$COWRIE_HOME/post-validation.txt"
""",
                extra={
                    "GIT_TEST_ASSUME_DIFFERENT_OWNER": "1",
                    "TEST_COWRIE_PARENT_LINK": str(parent_link),
                    "TEST_SWAPPED_PARENT": str(swapped_parent),
                    "TEST_COWRIE_HOME": str(raw_target),
                    "TEST_COWRIE_COMMIT": required_commit,
                },
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue((physical_target / "post-validation.txt").is_file())
            self.assertEqual(
                (physical_target / "post-validation.txt").read_text(encoding="utf-8"),
                "later validation operation\n",
            )
            self.assertFalse((swapped_target / "post-validation.txt").exists())

    def test_installer_function_preserves_concurrent_directory_on_publish_failure(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, pinned_commit, _ = self._cowrie_repository(root)
            target = root / "data" / "cowrie"
            target.parent.mkdir()
            replacement = root / "operator-cowrie"
            replacement.mkdir()
            operator_file = replacement / "operator-data.txt"
            operator_file.write_text("keep me\n", encoding="utf-8")

            result, _ = self._run_installer_functions(
                root,
                """
COWRIE_HOME="$TEST_COWRIE_HOME"
COWRIE_REPO="$TEST_COWRIE_REPOSITORY"
COWRIE_COMMIT="$TEST_COWRIE_COMMIT"
checkout_fresh_cowrie
""",
                extra={
                    "STUB_GIT_SWAP_ON_VERIFY": "1",
                    "STUB_GIT_SWAP_TARGET": str(target),
                    "STUB_GIT_SWAP_SOURCE": str(replacement),
                    "STUB_GIT_SWAP_ASIDE": str(root / "installer-owned-aside"),
                    "TEST_COWRIE_HOME": str(target),
                    "TEST_COWRIE_REPOSITORY": source.resolve().as_uri(),
                    "TEST_COWRIE_COMMIT": pinned_commit,
                },
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertTrue(target.is_dir())
            self.assertFalse(target.is_symlink())
            self.assertEqual(
                (target / operator_file.name).read_text(encoding="utf-8"),
                "keep me\n",
            )
            self.assertIn("refusing to overwrite", result.stderr)

    def test_installer_function_preserves_concurrent_dangling_symlink_on_publish_failure(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, pinned_commit, _ = self._cowrie_repository(root)
            target = root / "data" / "cowrie"
            target.parent.mkdir()
            link_destination = root / "missing-operator-cowrie"
            replacement = root / "operator-cowrie-link"
            replacement.symlink_to(link_destination)

            result, _ = self._run_installer_functions(
                root,
                """
COWRIE_HOME="$TEST_COWRIE_HOME"
COWRIE_REPO="$TEST_COWRIE_REPOSITORY"
COWRIE_COMMIT="$TEST_COWRIE_COMMIT"
checkout_fresh_cowrie
""",
                extra={
                    "STUB_GIT_SWAP_ON_VERIFY": "1",
                    "STUB_GIT_SWAP_TARGET": str(target),
                    "STUB_GIT_SWAP_SOURCE": str(replacement),
                    "STUB_GIT_SWAP_ASIDE": str(root / "installer-owned-aside"),
                    "TEST_COWRIE_HOME": str(target),
                    "TEST_COWRIE_REPOSITORY": source.resolve().as_uri(),
                    "TEST_COWRIE_COMMIT": pinned_commit,
                },
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertTrue(target.is_symlink())
            self.assertEqual(os.readlink(target), str(link_destination))
            self.assertIn("refusing to overwrite", result.stderr)

    def test_installer_function_leaves_final_target_absent_when_staging_fetch_fails(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, pinned_commit, _ = self._cowrie_repository(root)
            target = root / "data" / "cowrie"
            target.parent.mkdir()

            result, _ = self._run_installer_functions(
                root,
                """
COWRIE_HOME="$TEST_COWRIE_HOME"
COWRIE_REPO="$TEST_COWRIE_REPOSITORY"
COWRIE_COMMIT="$TEST_COWRIE_COMMIT"
checkout_fresh_cowrie
""",
                fail_git_fetch=True,
                extra={
                    "TEST_COWRIE_HOME": str(target),
                    "TEST_COWRIE_REPOSITORY": source.resolve().as_uri(),
                    "TEST_COWRIE_COMMIT": pinned_commit,
                },
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("could not fetch and check out pinned Cowrie commit", result.stderr)
            self.assertFalse(target.exists())
            self.assertFalse(target.is_symlink())
            staging = list(target.parent.glob(".cowrie-install.*"))
            self.assertEqual(len(staging), 1, staging)
            self.assertIn(f"staging checkout left at {staging[0]}", result.stderr)

    def test_example_config_documents_cowrie_unit_and_retention_defaults(self) -> None:
        example = EXAMPLE_CONFIG_PATH.read_text(encoding="utf-8")

        cowrie = example[example.index("cowrie:\n") : example.index("\ncapture:\n")]
        self.assertIn("  unit: cowrie", cowrie)
        self.assertIn("read-only", cowrie)
        self.assertIn("dashboard uptime", cowrie)
        self.assertIn("retention_days: 90", example.splitlines())
        self.assertIn("events, enrichment cache entries, artifacts, and TTY transcripts", example)
        self.assertIn("Set to 0 to disable periodic purging", example)

    def test_docs_keep_home_coordinates_in_yaml_and_name_current_themes(self) -> None:
        readme = README_PATH.read_text(encoding="utf-8")
        product = PRODUCT_PATH.read_text(encoding="utf-8")

        self.assertNotIn("theme, home location", readme)
        self.assertNotIn("theme, home location —", readme)
        self.assertIn("Home coordinates remain in YAML", readme)
        self.assertNotIn("Dragon", product)
        for theme in ("Signal", "Meridian", "Sprite"):
            with self.subTest(theme=theme):
                self.assertIn(theme, product)

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

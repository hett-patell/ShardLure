# Installer safety and disposable Ubuntu acceptance

The release installer and Python wrapper share a standard-library-only Python
safety helper. Python 3 is required even for the release installer's no-Cowrie
mode; no additional Python packages are needed for ownership/provenance checks.
Shell rendering and source loading do not execute the helper. The actual
filesystem operations use directory/file descriptors, not recursive pathname
chown/chmod commands.

## Supported maintenance

Stop ShardLure and Cowrie deliberately and take a verified backup before a full
installer rerun. Active services, incompatible or ambiguous accounts, unproven
legacy data, changed administrative resources, symlinks/hardlinks in service
data, and nested mounts are refused. Permission traversal is limited to 200,000
entries and 64 levels. A dedicated data volume may be the root; nested mounted
volumes need separate operator review.

Existing configurations and Cowrie checkouts are preserved. Use the dedicated
patch workflow for Cowrie source changes, and review configuration changes
explicitly. A binary-only upgrade is the appropriate path for an active or
legacy installation; do not run a full installer against a collecting host.

Ownership evidence consists of the private installation record in the systemd
directory and a root-only identity stamp in the data directory. Both installers
use the same format. Administrative files have recorded identities/checksums;
customized or replaced files are not silently overwritten or removed. Pending
publication records retain the intended digest so interrupted publication can
be reviewed/retried. During maintenance the data-directory namespace is owned
by the installer; normal exceptions restore its earlier access metadata.
After an abrupt process termination, retain the record and review/retry the
same installation rather than deleting it or inventing a new ownership marker.

Uninstall preserves collection data unless --purge is explicitly selected.
Purge claims and rechecks the owned directory before descriptor-based removal;
identity conflicts retain private recovery material instead of deleting a
replacement. Service accounts and potentially shared authbind rules are kept
for manual review. Unrecognized legacy installations remain non-destructive.

The release installer downloads installer_safety.py with the selected release
and verifies it against SHA256SUMS before executing it. A release without that
asset/checksum requires its matching historical installer, not a verification
bypass.

## SSH transitions

SSH migration stages the new administrative listener alongside the existing
listeners, checks syntax and effective operator-specific Match policy, and
requires a fresh authenticated connection before retiring old listeners.
Restoration likewise stages access before finalizing the original configuration.
An existing multiplexed client connection is not a fresh verification.

Structured SSH recovery records retain original file bytes, modes/ownership,
listeners and operator context. Activation errors and failed verification roll
back the working pre-transition state; recovery records and the original backup
are not deleted on success or failure. An owned Cowrie listener may be stopped
to free the restored administrative port, and is restarted after a failed
restore once SSH rollback succeeds. Unknown recovery provenance is a refusal,
not permission to guess a configuration or delete an old backup.

## Acceptance workflow

The reusable installer-integration workflow runs in a fresh GitHub-hosted
ubuntu-24.04 VM. CI passes its own native amd64 artifact to the workflow. Release
publication depends on both cross-build and installer-integration success.
The release-download fixtures use that native artifact and matching source
helper, so a not-yet-published release is not a prerequisite.

Only the workflow's provisioning step creates the root-owned disposable-guest
marker. The harness checks its run/repository/commit identity, runner type,
Ubuntu version, architecture and real systemd before doing anything invasive.
Do not create that marker on a workstation, ARM collection VM or self-hosted
runner. Do not run ubuntu-guest.sh there, even for troubleshooting.

The guest uses throwaway accounts/keys and inert collection events, real
systemd/sshd, a retained control connection, and independent SSH clients. Cowrie
is restricted to loopback for the test. Compiler/human-prompt boundaries use
the calling run's binary and explicit fixtures; filesystem ownership, services,
SSH activation and authenticated access are real. No public intelligence is
submitted, and no captured payload is executed. Only a redacted receipt is
uploaded, never keys, databases, raw configuration or collection files.

Local tests cover installer quoting, descriptor races, provenance, activation
failure and rollback. They do not replace this real guest acceptance run. Keep
Tasks 15 and 16 open until the corresponding run is actually successful.

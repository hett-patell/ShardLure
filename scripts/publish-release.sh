#!/usr/bin/env bash
set -euo pipefail

TAG="${GITHUB_REF_NAME:?GITHUB_REF_NAME is required}"
REPOSITORY="${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is required}"
TAG_REF="refs/tags/$TAG"
MAIN_REF="refs/remotes/origin/main"

if [[ "$(git cat-file -t "$TAG_REF" 2>/dev/null || true)" != "tag" ]]; then
  echo "Refusing release: $TAG_REF must be an annotated tag." >&2
  exit 1
fi

if [[ "$(git cat-file -t "$TAG_REF^{}" 2>/dev/null || true)" != "commit" ]]; then
  echo "Refusing release: $TAG_REF must point to a commit." >&2
  exit 1
fi

if ! git show-ref --verify --quiet "$MAIN_REF"; then
  echo "Refusing release: origin/main is unavailable for ancestry verification." >&2
  exit 1
fi

tag_object="$(git rev-parse --verify "$TAG_REF")"
tag_commit="$(git rev-parse --verify "$TAG_REF^{}")"
if ! git merge-base --is-ancestor "$tag_commit" "$MAIN_REF"; then
  echo "Refusing release: $TAG_REF does not point to a commit on origin/main." >&2
  exit 1
fi

validate_remote_tag() {
  local output remote_commit remote_object status

  if output="$(git ls-remote --tags origin "$TAG_REF" "$TAG_REF^{}")"; then
    :
  else
    status=$?
    echo "Unable to verify $TAG_REF against origin." >&2
    return "$status"
  fi

  remote_object="$(awk -v ref="$TAG_REF" '$2 == ref { print $1 }' <<<"$output")"
  remote_commit="$(awk -v ref="$TAG_REF^{}" '$2 == ref { print $1 }' <<<"$output")"

  if [[ -z "$remote_object" ]]; then
    echo "Refusing release: origin does not expose $TAG_REF." >&2
    return 1
  fi
  if [[ -z "$remote_commit" ]]; then
    echo "Refusing release: origin/$TAG_REF is not an annotated commit tag." >&2
    return 1
  fi
  if [[ "$remote_object" != "$tag_object" ]]; then
    echo "Refusing release: origin/$TAG_REF does not match the event tag object." >&2
    return 1
  fi
  if [[ "$remote_commit" != "$tag_commit" ]]; then
    echo "Refusing release: origin/$TAG_REF peels to a different commit." >&2
    return 1
  fi
}

get_release_state() {
  local error_file output status
  error_file="$(mktemp)"

  if output="$(
    gh release view "$TAG" --repo "$REPOSITORY" \
      --json isDraft --jq .isDraft 2>"$error_file"
  )"; then
    rm -f "$error_file"
    case "$output" in
      true) echo "draft" ;;
      false) echo "published" ;;
      *)
        echo "Unexpected release state for $TAG: $output" >&2
        return 1
        ;;
    esac
    return
  else
    status=$?
  fi

  output="$(<"$error_file")"
  rm -f "$error_file"
  if [[ $status -eq 1 && "$output" == "release not found" ]]; then
    echo "missing"
    return
  fi

  printf '%s\n' "$output" >&2
  return "$status"
}

validate_remote_tag
release_state="$(get_release_state)"
case "$release_state" in
  missing)
    validate_remote_tag
    gh release create "$TAG" --verify-tag --draft --generate-notes --repo "$REPOSITORY"
    ;;
  draft) ;;
  published)
    echo "Refusing to mutate release $TAG because it is already published." >&2
    exit 1
    ;;
esac

release_state="$(get_release_state)"
if [[ "$release_state" != "draft" ]]; then
  echo "Refusing to upload assets because release $TAG is $release_state." >&2
  exit 1
fi

validate_remote_tag
gh release upload "$TAG" release/* --clobber --repo "$REPOSITORY"
validate_remote_tag
release_state="$(get_release_state)"
if [[ "$release_state" != "draft" ]]; then
  echo "Refusing to publish release $TAG because it is $release_state." >&2
  exit 1
fi
gh release edit "$TAG" --draft=false --repo "$REPOSITORY"

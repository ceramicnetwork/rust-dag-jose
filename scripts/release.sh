#!/bin/bash -x
# Script to perform a release.
#
# Performing a release does the following:
# * Tags the git repo with the new release version
# * Updates Cargo.toml with the new release version
# * Publishes new release to crates.io
# * Publishes new release to Github releases
#
# Assumptions:
# * git is installed
# * git-cliff is installed
# * grep is installed
# * cargo-release is installed
# * gh is installed
# * jq is installed
# * GITHUB_TOKEN is set or gh is authenticated
# * CARGO_REGISTRY_TOKEN is set or cargo is authenticated

# Fail script if any command fails
set -e

# Ensure we are in the git root
cd $(git rev-parse --show-toplevel)

# First determine the next release level
level=$(./scripts/release_level.sh)

# Perform cargo release, this will tag the repo and publish to crates.io
cargo release -vv $level -x --no-confirm

# Version determined by cargo release (without the 'v' prefix)
version=$(cargo metadata --format-version=1 --no-deps | jq -r '.packages[0].version')

# Generate release notes
release_notes=$(git cliff --latest --strip all)

# Publish Github release
gh release create "v$version" --title "v$version" --latest --notes "$release_notes"

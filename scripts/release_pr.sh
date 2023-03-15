#!/bin/bash -x
# Script to prepare a release PR
#
# Preparing a release PR does the following:
# * Deterimes the next version based on changes
# * Update Cargo.toml with new versions
# * Create PR for review
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

# Print commits since last tag
cargo release changes

# Bump crate versions
cargo release version $level \
    --verbose \
    --execute \
    --no-confirm

# Perform pre-release replacements
cargo release replace \
    --verbose \
    --execute \
    --no-confirm

# Run pre-release hooks
cargo release hook \
    --verbose \
    --execute \
    --no-confirm

# Commit the specified packages
cargo release commit \
    --verbose \
    --execute \
    --no-confirm


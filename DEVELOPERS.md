## Release Checklist

- Bump version in Cargo.toml
  - If major version was bumped, update README.md
- Update CHANGELOG.md
- Ensure the MSRV in Cargo.toml (`rust-version` key) is equal to the MSRV being
  tested (main.yml)
- Update locked dependencies: `cargo update`. Run `cargo test --all-features`
  to check if anything breaks. If that happens, see next section.
- Test if it's publishable: `cargo publish --dry-run`
- Open a PR with the version bump and changelog update, wait for review and merge
- Tag a new release in GitHub: https://github.com/ZcashFoundation/ed25519-zebra/releases/new
  - Create a tag with the version (e.g. `4.0.3`)
  - Name: e.g. `ed25519-zebra 4.0.3`
  - Paste the changelog for the version
- Publish: `cargo publish`

## If something breaks

If testing broke after running `cargo update`, first determine if it's a
test-only dependency or not. Run `cargo build --all-features`. If that works,
then it's probably a test-only dependency, and you can avoid updating that
specific dependency (leave a old version in the lockfile). Otherwise investigate
why it caused build to fail.

If the "test on nightly" test failed, then either there is some bug in the code
or some dependency update caused it to fail. Investigate and if it's the latter,
you can either downgrade in the lockfile or try to workaround it.

If the "build with no_std" test failed, then some change was introduced that
depended on the std-library. You will probably need to fix this by changing
to some no_std dependency, or gating the code so it only compiles when
`std` is enabled.

If one of the dependencies bumped its MSRV, we might require a MSRV bump too:

- Double check if the dependency is not a test-only dependency. (The MSRV
  test in CI only builds the library but does not test it, to prevent
  a test-only dependency MSRV bump from breaking it.)
- If it's not a test-only dependency, check if the main consumers of the
  library are OK with a MSRV bump. I usually ask ECC devs.
- If it's OK, bump it in Cargo.toml and main.yml.
- If not, you will need to find some workaround.

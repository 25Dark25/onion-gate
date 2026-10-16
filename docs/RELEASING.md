# Releasing

Releases are a source zip made with `git archive`, its SHA-256 and a detached
OpenPGP signature by the maintainer's key
(`A7FC EDEA D7E6 C343 7312  284A 442D A687 E0FF 73EE`). There are no prebuilt
binaries. Replace `0.1.0` with the version being released.

1. In a pull request: set `version` in `Cargo.toml`, move the `Unreleased`
   entries of `CHANGELOG.md` under the new version with the date, and merge it
   once CI is green.

2. From the merged commit on `main`, check and tag it (signed tag):

   ```bash
   git checkout main && git pull --ff-only
   cargo test --locked --offline && scripts/harness.sh check
   git tag -s v0.1.0 -m "onion-gate 0.1.0"
   git push origin v0.1.0
   ```

3. Build the archive from the tag, hash it, sign it, and check all three:

   ```bash
   git archive --format=zip --prefix=onion-gate-0.1.0/ -o onion-gate-0.1.0.zip v0.1.0
   sha256sum onion-gate-0.1.0.zip
   gpg --local-user A7FCEDEAD7E6C3437312284A442DA687E0FF73EE --armor --detach-sign onion-gate-0.1.0.zip
   gpg --verify onion-gate-0.1.0.zip.asc onion-gate-0.1.0.zip
   unzip -q onion-gate-0.1.0.zip && (cd onion-gate-0.1.0 && cargo build --release --locked --offline)
   ```

   `git archive` is deterministic for a given commit with a given git version,
   but the hash in the notes must be the one of the file actually uploaded:
   always hash and sign the same file you attach.

4. Create the release on GitHub (web interface, or `gh`), attach the zip and
   its `.asc`, and paste the notes below with the hash filled in:

   ```bash
   gh release create v0.1.0 onion-gate-0.1.0.zip onion-gate-0.1.0.zip.asc \
     --verify-tag --title "onion-gate 0.1.0" --notes-file notes.md
   ```

## Release notes template

```markdown
onion-gate 0.1.0 — <one line: what is new>. See CHANGELOG.md for the details.

**Not independently audited.** Read the README's Limitations and SECURITY.md first.

Verify before building (instructions in the README, "Download and verify a release"):

- `onion-gate-0.1.0.zip` SHA-256: `<hash>`
- Signature: `onion-gate-0.1.0.zip.asc`, key `A7FC EDEA D7E6 C343 7312  284A 442D A687 E0FF 73EE`
  (also on keys.openpgp.org and https://github.com/25Dark25.gpg)

GitHub's automatic "Source code" archives are not signed and are not this zip:
verify and build `onion-gate-0.1.0.zip`.
```

# Signing & notarization checklist (operator)

Software in this repo builds **unsigned** release layouts via `scripts/release/build_unsigned.sh`.  
The following steps require **your** certificates and portal access. Agents cannot complete them.

---

## macOS — Developer ID + notarization

1. Enroll in [Apple Developer Program](https://developer.apple.com).
2. Create **Developer ID Application** certificate in Xcode / Certificates portal.
3. Import cert + private key into the signing Mac’s Keychain.
4. Build release binaries (or unpack unsigned tarball from `build_unsigned.sh`).
5. Sign:

```bash
codesign --force --options runtime --timestamp \
  --sign "Developer ID Application: <YOUR NAME> (<TEAMID>)" \
  dist/.../bin/ash dist/.../bin/raven-node dist/.../bin/raven-swarm
codesign --verify --verbose=2 dist/.../bin/ash
```

6. Zip/app-bundle as required by `notarytool`.
7. Store credentials once, then submit. **Never pass the app-specific password
   with `--password` on the command line**: it lands in shell history, `ps`
   output and process listings (this repo's "no secrets in argv" rule). Omit it
   so `notarytool` prompts interactively and keeps it in the Keychain:

```bash
# one time on the signing Mac (prompts for the app-specific password)
xcrun notarytool store-credentials "raven-notary" \
  --apple-id "<apple-id>" --team-id "<TEAMID>"
# every release
xcrun notarytool submit <archive.zip> --keychain-profile "raven-notary" --wait
xcrun stapler staple <artifact>
```

   Alternative: App Store Connect API-key auth (`--key <AuthKey.p8> --key-id <ID>
   --issuer <issuer-uuid>`), with the key file kept out of the repo.

8. Gatekeeper check: download on a clean Mac; open without right-click bypass.
9. Optional: Developer ID Installer + productbuild for `.pkg`.

**Blocked without:** Apple ID with paid membership, certs, and a stored `notarytool` keychain profile (app-specific password) or an API key.

---

## Windows — Authenticode / MSI

1. Obtain Authenticode code-signing certificate (EV recommended for SmartScreen reputation).
2. Import into certificate store or use USB token.
3. Sign:

```powershell
signtool sign /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 /a ash.exe
signtool sign /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 /a raven-node.exe
signtool verify /pa ash.exe
```

4. Build MSI/MSIX with WiX / Advanced Installer / your pipeline (not shipped here).
5. Sign the installer package similarly.
6. Optional: Microsoft Store submission (separate Partner Center account).

**Blocked without:** org signing cert, timestamp URL access, installer project.

---

## Linux packaging (optional)

1. Build with `build_unsigned.sh` on the target distro.
2. Package deb/rpm with distro tooling; sign with your GPG key for apt/yum repos.
3. Publish to your repository — **do not** claim Raven-operated mandatory relays.

---

## After signing

- Recompute SHA256 of **signed** artifacts (they differ from unsigned sums).
- Attach signed hashes to the GitHub Release (when you choose to publish).
- Keep notarization / signtool logs offline for auditors.

---

## Raven's own release signature, next to platform signing

Platform signing and Raven's own release signature answer different
questions, and a release needs both:

| Signature | Who checks it | What it says | Made where |
|---|---|---|---|
| Developer ID + notarization (macOS), Authenticode (Windows), a GPG-signed package (Linux) | the operating system (Gatekeeper, SmartScreen) and package managers | "this program comes from that developer account" | the signing Mac or PC, with the platform's certificate |
| Raven's release signature: 2 of the 3 Raven release keys over the release manifest (RRB1), listed in the public release log (RTL1) | a Raven build (`raven update import`, `verify`, `install`), friends' Raven passing it on | "the Raven project released exactly these files for this target, and anyone can see it in the log" | the offline machine of the key ceremony ([`RELEASE_KEY_CEREMONY.md`](RELEASE_KEY_CEREMONY.md)) |
| Reproducible build: `rebuild_sha256` per file in the manifest | anyone who rebuilds the commit (`scripts/release/reproduce_check.sh`) | "these are the bytes this source commit gives, before platform signing" | any machine, independently |

**Order, every release** (details in [`RELEASE_KEY_CEREMONY.md`](RELEASE_KEY_CEREMONY.md) section 5):

1. **Reproducible build:** `scripts/release/build_reproducible.sh --out out/<target>`
   for each target. Its `SHA256SUMS` are the bytes before platform signing.
   It stops before cargo runs when a cargo configuration sits above its
   build folder (for example `/tmp/.cargo/config.toml`, which any local
   account can write): remove it, find out who put it there, and build again.
2. **Platform signing** of `out/<target>/bin/*` into a separate folder, as in
   the sections above (macOS: sign, notarize the zip; Windows: signtool;
   Linux: nothing, the shipped bytes are the build's).
3. **Manifest draft:** `scripts/release/make_bundle.sh draft --build out/<target>
   --signed <the signed folder> --key-set <key set> --out bundle/<target>`.
   The manifest lists each shipped file's SHA-256 (the platform-signed bytes)
   and its `rebuild_sha256` (the bytes before signing), so a rebuild can be
   compared even though platform signing changed the program.
4. **Raven signature:** the ceremony signs the manifests (and any security
   notice) with two release keys, lists them in the public release log and
   signs the log's tree head.
5. **Pack and check:** `make_bundle.sh pack`, then `raven-release verify` and
   `scripts/release/check_log.py`; publish the log, the `.rrb` bundles and
   their `.sha256` files.

Platform signing comes **before** the Raven signature: signing a program again
afterwards changes its bytes, and the manifest no longer matches it (a Raven
build then refuses the bundle). Notarization cannot staple a ticket to a bare
command-line program; Gatekeeper looks the ticket up online the first time a
downloaded file runs. Programs that `raven update install` writes carry no
download quarantine flag from Raven; how Gatekeeper, the firewall and the
keychain treat a new signed `raven-node` on a real Mac is still an open check.

**Status:** no Raven release key exists yet (`RELEASE_KEY_SET_V1 = None`;
owner decision OD6b-20: the Protocol owner runs the ceremony, then commits
the key set), and Raven's update gates are off, so today a release is
installed the way the install guides say, and only platform signing and the
tarball checksums apply to it. The macOS arm64 payload is 57.6 MB, close to
the 64 MiB a release bundle may hold.

Raven @VERSION@ for Linux (@ARCH@)
==================================

Raven is a private messenger with no central server. Your identity is a key
on your own computer; you and a friend add each other with a card and check
each other's 10 security words; messages are end-to-end encrypted and go
directly between your computers, or through friends, never through a
company's server.

This is a pre-release. No independent security review has happened yet.
Read https://github.com/Raven-ASHCO/raven-core before relying on it.

What is in this folder
  bin/raven             the command line and terminal app (`ash` is the same program)
  bin/raven-node        the background program that carries messages
  bin/raven-tor-helper  Tor (Arti), which raven-node starts to reach friends on other networks
  install.sh            sets Raven up for you: this user only, no root
  uninstall.sh          removes the programs and the service; your profile stays
  lib/                  the installer install.sh runs
  CHANGELOG.md          what changed in each version
  LICENSE, NOTICE       AGPL-3.0-or-later
  BUILD-INFO.txt        the source commit and the tools it was built with
  SHA256SUMS            checksums of the files in this folder

Install
  ./install.sh
  export PATH="$HOME/.local/bin:$PATH"
  raven doctor

install.sh copies the programs to ~/.local/bin, creates your profile in
~/.raven and runs raven-node as a systemd user service (raven-node.service).
Your keys go to your desktop keyring (GNOME Keyring, KWallet); on a computer
without one, raven asks for a passphrase and keeps them in an encrypted file.
Its options are at the top of install.sh. Then add a friend: `raven whoami`
shows your invite; `raven --help` starts with an example.

Check the download
  sha256sum -c raven-linux-@ARCH@-@VERSION@.tar.gz.sha256
compares the archive with the checksum file published next to it. SHA256SUMS
inside the folder only finds files damaged after unpacking: anyone who could
change the archive could change it too.

Good to know
  - Not signed. Raven updates the way you installed it: run install.sh again
    from a newer package.
  - Bluetooth nearby is not in Linux builds (macOS only).
  - Built on @BUILT_ON@: it needs a Linux with @GLIBC@
    and systemd user services.
  - Uninstall: ./uninstall.sh (run `raven erase` first to delete your profile).

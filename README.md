# servershed

Local, read-only overview of VPSes and shared-hosting accounts. TUI first (Textual), CLI later.

    python3 -m venv .venv && .venv/bin/pip install -e '.[dev]'
    .venv/bin/servershed lint                 # validate inventory.yaml
    .venv/bin/servershed probe [asset...]     # run the read-only probe, print raw facts
    .venv/bin/servershed probe --save tests/fixtures/local   # real output, git-ignored

Rule: the tool never changes a host. The probe is POSIX sh, no sudo, piped over the
system `ssh` (uses ~/.ssh/config). Assets with `kind: external` / `probe: false` are never ssh'd.

Inventory lookup: `-i PATH`, then `$SERVERSHED_INVENTORY`, then `./inventory.yaml`,
then `~/.config/servershed/inventory.yaml`.

Sensitive data stays out of git: `inventory.yaml`, `tests/fixtures/local/`, any `*.sqlite`
history and `.servershed/` cache are ignored. Start from `inventory.example.yaml`.

## License

Apache-2.0, see `LICENSE`.

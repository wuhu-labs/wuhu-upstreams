# wuhu-upstreams

Pinned upstream build recipes and prebuilt dependencies for Wuhu. Each folder is one upstream: a build script, its pin and a `PROVENANCE.md`; its workflow builds the artifacts, and a tag `<upstream>/<version>` releases them with the exact upstream source.

- [`tailcat/`](tailcat): static archives of libtailcat, the C ABI of tailscale/tailcat, for Apple platforms and x86_64 Linux.

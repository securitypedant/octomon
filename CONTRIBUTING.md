# Contributing to octomon

Thanks for your interest! Issues and pull requests are welcome.

## Development

octomon is a Rust project (edition 2024, Rust 1.88+). It currently targets
**macOS**; Linux support is planned for release 2.

```sh
cargo build            # build
cargo run              # run the dashboard
cargo run -- --check   # one-shot text snapshot (handy for issue reports)
cargo test             # unit tests
cargo fmt --all        # format
cargo clippy --all-targets -- -D warnings   # lint (CI treats warnings as errors)
```

Before opening a PR, please make sure `cargo fmt`, `cargo clippy`, and
`cargo test` are all clean — CI enforces this.

## Guidelines

- Keep the collector → shared-state → render architecture: collectors sample
  into `AppState`; the UI only reads. Don't do I/O in the render path.
- Platform-specific probes go behind `src/platform/` and stay cfg-gated so the
  tree keeps compiling for other targets.
- Match the surrounding style; prefer small, focused PRs with a clear
  description of the behaviour change.

## Reporting bugs

Use the issue templates. `octomon --check` output and your OS/version are very
helpful. For **security** issues, see [SECURITY.md](SECURITY.md) — please don't
open a public issue.

## License

By contributing, you agree that your contributions are dual-licensed under
MIT OR Apache-2.0, matching the project.

# Contributing to UBC

UBC is a protocol first and an implementation second. That shapes how
changes get made.

## The two kinds of change

**Spec changes** (`spec/`) — open an issue before writing code. The spec is
the contract every implementation depends on, so changes need discussion:
what problem it solves, why the current text can't say it, and what it
breaks. Backwards-incompatible changes bump the minor version (we're at
0.x; nothing is frozen yet, but surprises are still rude).

**Implementation changes** (`core/`, and later `cli/`, `sdks/`) — open a
pull request. The bar:

1. `cargo test` passes, and new behavior comes with new tests.
2. Unsafe code needs a comment explaining why it's safe.
3. Crypto choices are not negotiable in drive-by PRs — algorithm changes
   are spec changes (see above).

## Style

- Rust: `cargo fmt` and `cargo clippy` clean before submitting.
- Commit messages: imperative mood, say *why* when it isn't obvious.
- Small PRs beat big PRs. A 200-line PR gets a review; a 2,000-line PR
  gets a sigh.

## Code of conduct

Be the kind of collaborator you'd want reviewing your code at 1am. That's
the whole policy until we need a longer one.

## License

By contributing, you agree your work is licensed under the project's
[MIT license](LICENSE).

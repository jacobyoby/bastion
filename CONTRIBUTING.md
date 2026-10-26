# Contributing to Bastion

Bastion is an independently maintained fork of Google's Paranoid Crypto.
Contributions to this repository are reviewed by Bastion's maintainer, Jacob Durham.
The Google CLA process described in the original upstream guide does not apply
to contributions to this fork.

## What to contribute

Improvements to existing checks, new checks backed by research, bug fixes, tests,
and clearer documentation are welcome. For a substantial change, start a draft
pull request describing your approach before investing in the full implementation.
For new checks, explain the weakness detected, cite the relevant research, and
describe the expected performance on large batches of artifacts.

## Submit a pull request

1. Fork this repository and create a working branch from `dev`.
2. Keep the change focused and follow the surrounding code style. The Python
   package name remains `paranoid_crypto`.
3. Add regression tests for bug fixes and tests for new behavior. Use synthetic
   or already-public test artifacts; never include private keys from real users.
4. Update the relevant [check documentation](docs) or [examples](examples) when
   behavior or usage changes.
5. Open a pull request against `dev`. Explain the problem, your change, and how
   you verified it. Include any performance impact or limitations.

All submissions, including changes from project members, go through pull-request
review before merging.

## Run the tests

Follow the platform-specific setup in the [README](README.md#getting-started).
With the environment activated, run from the repository root:

```sh
cd paranoid_crypto
python3 -m unittest discover -b -p "*test.py"
```

Include the test command and result in your pull request. If you cannot run part
of the suite, explain what remains unverified. Documentation-only changes should
be checked in GitHub's Markdown preview for formatting and link targets.

## Responsible disclosure

If a check uncovers a vulnerability in another project or product, report it
privately to the responsible vendor or maintainers first. Coordinate disclosure
before publishing a check or test data that reveals the vulnerability.

Avoid posting undisclosed vulnerabilities, credentials, recovered private keys,
or other sensitive artifacts in public pull requests or comments. For a
vulnerability in Bastion itself, check the repository's Security tab for an
available private reporting option before sharing details publicly.

## License

Contributions should be suitable for distribution under this project's
[Apache License 2.0](LICENSE). Submit only work you have the right to contribute,
and preserve applicable copyright and attribution notices.

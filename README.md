# Bastion

**Check cryptographic keys, signatures, and pseudorandom output for known weaknesses.**

Bastion is a Python library for examining cryptographic artifacts, including those
produced by third-party software or hardware whose source you cannot inspect.
It is a fork of Google's [Paranoid](https://github.com/google/paranoid_crypto),
maintained by Jacob Durham. The Python package retains the name `paranoid_crypto`.
Bastion is independently maintained and is not affiliated with or supported by Google.

[Get started](#getting-started) · [Check documentation](docs) · [Examples](examples) · [What changed](#differences-from-upstream)

## What it checks

| Input | Purpose |
| --- | --- |
| RSA public keys | Detect known weaknesses such as shared factors, ROCA, and vulnerable key-generation patterns. |
| Elliptic-curve public keys | Check for weaknesses in EC key material. |
| ECDSA signatures | Check for weaknesses in signature generation, including nonce reuse. |
| Pseudorandom output | Run randomness tests that can reveal flaws in generators. |

Use the [check documentation](docs) to choose the checks appropriate to your data
and the [examples](examples) to see how to call them from Python. A passing check
means that check found no weakness; it does not prove that a key or generator is secure.

## Differences from upstream

- **ECDSA nonce reuse:** `CheckNonceReuse` can recover a private key from two
  signatures from the same key that reuse a nonce. See the
  [check details](docs/ecdsa_signature_tests.md#checknoncereuse).
- **More robust input handling:** empty batches, tiny or empty RSA moduli,
  out-of-range ECDSA signature values, and invalid EC points with `y = 0 (mod p)`
  are reported or skipped rather than aborting a batch.
-   **CheckWeakECPrivateKey searches only valid points**: a point off the curve
    is no longer reported as a recovered private key, and a weak key encoded
    with unreduced coordinates is still found. See
    [EC public key tests](docs/ec_public_key_tests.md#checkvalideckey).
- **Flexible import order:** `paranoid_crypto.lib.ecdsa_sig_checks` can be imported
  before `paranoid_crypto.lib.paranoid`.

## Getting started

1. Install the library using one of the options below.
2. Browse the [examples](examples) for the type of artifact you want to test.
3. Consult the [check documentation](docs) for the available checks and their behavior.

### Installation

Clone the `dev` branch to use the version described on this page:

```sh
git clone --branch dev https://github.com/jacobyoby/bastion.git
cd bastion
```

#### Debian

**NOTE**: Upstream tested the commands below on Debian 12 (bookworm). Make sure
you will be using `python3.11` or newer.

Install dependencies:

```sh
sudo apt update && sudo apt install python3 python3-full python3-pip python3-pybind11 python3-fpylll python3-gmpy2 protobuf-compiler
```

Create and activate a virtual environment:

```sh
python3 -m venv --system-site-packages ~/paranoid-venv
```

```sh
source ~/paranoid-venv/bin/activate
```

Install the Python package:

```sh
python3 -m pip install .
```

Verify the installation by running the unit tests:

```sh
cd paranoid_crypto && python3 -m unittest discover -b -p "*test.py"
```

#### macOS (Apple Silicon)

This setup uses Homebrew and [uv](https://docs.astral.sh/uv/). The
pinned `protobuf==3.20.*` runtime needs an older protoc than Homebrew ships. These
steps use the matching protoc 3.20.3, whose release has no Apple Silicon binary,
so the x86_64 binary runs under Rosetta (`softwareupdate --install-rosetta` if it
is missing).

```sh
brew install fplll
uv venv -p 3.11 .venv
curl -L -o /tmp/protoc.zip https://github.com/protocolbuffers/protobuf/releases/download/v3.20.3/protoc-3.20.3-osx-x86_64.zip
unzip -o /tmp/protoc.zip -d .venv/protoc
export CPATH=/opt/homebrew/include LIBRARY_PATH=/opt/homebrew/lib PROTOC=$PWD/.venv/protoc/bin/protoc
uv pip install -p .venv -r requirements.txt pybind11 setuptools gmpy2 cysignals fpylll
uv pip install -p .venv --no-build-isolation -e .
```

Verify the installation by running the unit tests:

```sh
cd paranoid_crypto && ../.venv/bin/python -m unittest discover -b -p "*test.py"
```

#### Docker

Alternatively, if you want to run it in a container, you can use our provided
[Dockerfile](Dockerfile) as shown below.

**NOTE**: Make sure you have [docker](https://docs.docker.com/engine/install/)
installed.

After cloning the repository, build the docker image:

```sh
docker build -t paranoid-img .
```

Create and start the container:

```sh
docker run --name paranoid-container -it paranoid-img
```

To check whether the installation was successful, run the unit tests inside the
container:

```
cd paranoid_crypto && python3 -m unittest discover -b -p "*test.py"
```

## Research background

Bastion builds on Paranoid's implementations and optimizations of published
cryptographic research, including:

-   [Arjen K. Lenstra, James P. Hughes, Maxime Augier, Joppe W. Bos, Thorsten
    Kleinjung, and Christophe Wachter. (2012). **Ron was wrong, Whit is
    right**](https://eprint.iacr.org/2012/064);

-   [Nadia Heninger, Zakir Durumeric, Eric Wustrow, and J. Alex Halderman.
    (2012). **Mining Your Ps and Qs: Detection of Widespread Weak Keys in
    Network
    Devices**](https://www.usenix.org/conference/usenixsecurity12/technical-sessions/presentation/heninger);

-   [Daniel J. Bernstein, Yun-An Chang, Chen-Mou Cheng, Li-Ping Chou, Nadia
    Heninger, Tanja Lange, and Nicko van Someren. (2013). **Factoring RSA keys
    from certified smart cards: Coppersmith in the
    wild**](https://eprint.iacr.org/2013/599);

-   [Joachim Breitner and Nadia Heninger. (2019). **Biased Nonce Sense: Lattice
    Attacks against Weak ECDSA Signatures in
    Cryptocurrencies**](https://eprint.iacr.org/2019/023);

## Historical upstream results

The following results were reported by the upstream Paranoid team in September
2022 from analysis of [Certificate Transparency](https://certificate.transparency.dev)
data. They are historical upstream findings, not measurements of this Bastion fork.
At that time, the team reported no weak EC public keys or ECDSA signatures in
their CT analysis. High- and critical-severity RSA findings are listed below.

|       **TestName**       | **Potentially Related CVEs** |    **Severity**   | **Number of Weak Artifacts** |
|:------------------------:|:----------------------------:|:-----------------:|:----------------------------:|
|   CheckOpensslDenylist   |         CVE-2008-0166        | SEVERITY_CRITICAL |             3989             |
|         CheckROCA        |        CVE-2017-15361        |   SEVERITY_HIGH   |             2875             |
|         CheckGCD         |               -              | SEVERITY_CRITICAL |             1860             |
|        CheckFermat       |        CVE-2022-26320        | SEVERITY_CRITICAL |              36              |
|  CheckContinuedFractions |               -              | SEVERITY_CRITICAL |              16              |
|     CheckBitPatterns     |               -              | SEVERITY_CRITICAL |               6              |
| CheckPermutedBitPatterns |               -              | SEVERITY_CRITICAL |               6              |
|   CheckKeypairDenylist   |        CVE-2021-41117        | SEVERITY_CRITICAL |               4              |
|      CheckPollardpm1     |               -              | SEVERITY_CRITICAL |               1              |

Some of these certificates were already expired or revoked. For the ones that
were still active (most of the CheckGCD ones), the upstream team reported them to
the Certificate Authorities to be revoked.

## Project, license, and citation

Bastion is maintained by Jacob Durham at
[jacobyoby/bastion](https://github.com/jacobyoby/bastion).

The upstream library was developed by members of the Google Security Team and is
not an officially supported Google product.
[google/paranoid_crypto](https://github.com/google/paranoid_crypto) is archived
on GitHub and no longer accepts pull requests; [CONTRIBUTING](CONTRIBUTING.md)
describes upstream's former process.

Bastion is distributed under the [Apache License 2.0](LICENSE).

To cite the upstream Paranoid work in research, use:

```bibtex
@software{Barbosa_Bleichenbacher_Paranoid_Crypto_2022,
  author = {Barbosa, Pedro and Bleichenbacher, Daniel},
  license = {Apache-2.0},
  month = {8},
  title = {{Paranoid Crypto}},
  url = {https://github.com/google/paranoid_crypto},
  year = {2022}
}
```

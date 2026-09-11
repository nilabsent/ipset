#!/usr/bin/env python3
#
# asn2cidr.py
#
# Downloads and processes RIPEstat announced-prefixes data,
# extracts and aggregates IPv4/IPv6 prefixes for one or more ASNs,
# and writes one output file per logical provider/ipset.
#
# Usage:
#   ./asn2cidr.py download
#   ./asn2cidr.py update
#
# Author: nil
# AI-assisted development: ChatGPT (OpenAI)
#

import argparse
import ipaddress
import json
import pathlib
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import urllib3
from urllib3.util import Timeout


# ----------------------------------------------------------------------
# Configuration
# ----------------------------------------------------------------------
BASE_DIR = pathlib.Path(__file__).resolve().parent

API_URL = "https://stat.ripe.net/data/announced-prefixes/data.json"
DATA_DIR = BASE_DIR / "data"
OUTPUT_DIR_V4 = BASE_DIR / "ipv4"
OUTPUT_DIR_V6 = BASE_DIR / "ipv6"
SOURCE_APP = "asn2cidr"

MAX_WORKERS = 8
CONNECT_TIMEOUT = 10
READ_TIMEOUT = 30
MAX_RETRIES = 4
RETRY_DELAY = 2

http = urllib3.PoolManager(
    num_pools=MAX_WORKERS,
    maxsize=MAX_WORKERS,
    block=True,
    retries=0,  # Retry logic is handled explicitly below.
    timeout=Timeout(connect=CONNECT_TIMEOUT, read=READ_TIMEOUT),
)


# ----------------------------------------------------------------------
# ASN / prefix configuration
# ----------------------------------------------------------------------
AS_LIST = {
    "amazon": (
        16509,
        14618,
        7224,
        21664,
        401395,
        801,
        62785,
    ),
    "cloudflare": (
        13335,
        14789,
        395747,
        400095,
        402542,
    ),
    "contabo": (
        51167,
        40021,
        141995,
    ),
    "digitalocean": (
        14061,
    ),
    "ovh": (
        16276,
    ),
    "hetzner": (
        24940,
        213230,
        212317,
    ),
    "akamai": (
        20940,
        200005,
        12222,
        24319,
        35994,
        34164,
        16625,
        31108,
        21342,
        213120,
        33905,
    ),
    "oracle": (
        31898,
        54253,
        6142,
        14544,
        20054,
    ),
    "telegram": (
        62041,
        62014,
        59930,
        44907,
        211157,
        "5.28.128.0/18",
    ),
    "meta": (
        63293,
        32934,
    ),
    "google": (
        15169,
        396982,
        36040,
        43515,
        19527,
        394089,
        395973,
        32381,
        394507,
        396178,
        33715,
        22577,
        214611,
        36384,
        16550,
        13949,
        36492,
        36411,
        36383,
        "199.36.158.0/24",
        "2620:0:890::/48",
    ),
    "sberbank": (
        35237,
        47457,
        208117,
        211631,
        43396,
        60122,
        42628,
        205158,
        44408,
        45000,
        209701,
        205161,
        42974,
    ),
    "github": (
        36459,
        "185.199.108.0/22",
        "2606:50c0:8000::/46",
    ),
    "blizzard": (
        57976,
    ),
    "reflected": (
        29789,
    ),
    "fastly": (
        54113,
    ),
    "datacamp": (
        60068,
    ),
}

def get_asns():
    """Extract unique ASNs from AS_LIST."""
    return sorted(
        {
            item
            for items in AS_LIST.values()
            for item in items
            if isinstance(item, int)
        }
    )


# ----------------------------------------------------------------------
# Core logic
# ----------------------------------------------------------------------
def fetch_asn(asn):
    """Fetch prefixes for a single ASN with retries."""
    url = f"{API_URL}?resource=AS{asn}&sourceapp={SOURCE_APP}"
    headers = {
        "Accept": "application/json",
        "User-Agent": f"{SOURCE_APP}/1.0",
    }

    retryable_statuses = {429, 500, 502, 503, 504}

    for attempt in range(1, MAX_RETRIES + 1):
        response = None

        try:
            response = http.request(
                "GET",
                url,
                headers=headers,
                preload_content=True,
            )

            if response.status != 200:
                message = f"HTTP {response.status}"

                if response.status not in retryable_statuses:
                    raise RuntimeError(message)

                raise urllib3.exceptions.HTTPError(message)

            try:
                data = json.loads(response.data)
            except (TypeError, json.JSONDecodeError) as exc:
                raise RuntimeError(f"Invalid JSON response: {exc}") from exc

            if data.get("status") != "ok":
                raise RuntimeError(
                    data.get("message", "RIPEstat returned an error")
                )

            prefixes = {
                str(ipaddress.ip_network(p["prefix"], strict=False))
                for p in data.get("data", {}).get("prefixes", [])
                if p.get("prefix")
            }

            return asn, prefixes

        except (
            urllib3.exceptions.HTTPError,
            urllib3.exceptions.TimeoutError,
            OSError,
            RuntimeError,
        ) as exc:
            exc_str = str(exc).lower()

            # DNS/network errors that make further requests pointless.
            fatal_signals = (
                "name or service not known",
                "temporary failure in name resolution",
                "network is unreachable",
                "no address associated with hostname",
            )

            is_fatal = any(signal in exc_str for signal in fatal_signals)

            if is_fatal:
                # Do not call SystemExit from a worker thread. Propagate a
                # dedicated exception to the main thread instead.
                raise RuntimeError(
                    f"FATAL network/DNS error: {exc}"
                ) from exc

            if attempt >= MAX_RETRIES:
                raise RuntimeError(
                    f"AS{asn}: failed after {attempt} attempts: {exc}"
                ) from exc

            delay = RETRY_DELAY * (2 ** (attempt - 1))
            print(
                f"AS{asn}: attempt {attempt}/{MAX_RETRIES} failed: "
                f"{exc}; retrying in {delay}s",
                file=sys.stderr,
            )
            time.sleep(delay)

        finally:
            if response is not None:
                response.release_conn()


def download():
    """Download and cache prefixes for all ASNs."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    asns = get_asns()
    print(
        f"Downloading {len(asns)} ASNs using {MAX_WORKERS} workers..."
    )

    successful = 0
    failed = []

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {
            executor.submit(fetch_asn, asn): asn
            for asn in asns
        }

        for future in as_completed(futures):
            asn = futures[future]

            try:
                _, prefixes = future.result()

                # Atomic write.
                out_file = DATA_DIR / f"AS{asn}.json"
                tmp_file = out_file.with_suffix(".json.tmp")

                with tmp_file.open("w", encoding="utf-8") as f:
                    json.dump(
                        sorted(prefixes),
                        f,
                        separators=(",", ":"),
                    )

                tmp_file.replace(out_file)

                v4 = sum(
                    1
                    for p in prefixes
                    if ipaddress.ip_network(p).version == 4
                )
                v6 = len(prefixes) - v4

                print(
                    f"AS{asn}: OK, {v4} IPv4, {v6} IPv6 prefixes"
                )
                successful += 1

            except Exception as exc:
                print(
                    f"AS{asn}: ERROR: {exc}",
                    file=sys.stderr,
                )
                failed.append(asn)

                # A fatal network/DNS error should stop the whole download.
                if str(exc).startswith("FATAL network/DNS error:"):
                    executor.shutdown(wait=False, cancel_futures=True)
                    raise SystemExit(1) from exc

    if failed:
        print(
            f"\nDownload completed with errors: "
            f"{successful}/{len(asns)} successful",
            file=sys.stderr,
        )
        print(
            "Failed ASNs:",
            ", ".join(f"AS{a}" for a in sorted(failed)),
            file=sys.stderr,
        )
        sys.exit(1)

    print(
        f"\nDownload completed successfully: "
        f"{successful}/{len(asns)} ASNs"
    )


def _load_prefixes_for_asn(asn):
    """Load cached prefixes for one ASN or raise a useful error."""
    data_file = DATA_DIR / f"AS{asn}.json"

    if not data_file.exists():
        raise FileNotFoundError(
            f"Cached data file is missing: {data_file}"
        )

    try:
        with data_file.open(encoding="utf-8") as f:
            prefixes = json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(
            f"Cannot read {data_file}: {exc}"
        ) from exc

    if not isinstance(prefixes, list):
        raise RuntimeError(
            f"Invalid cache format in {data_file}: expected a JSON list"
        )

    return prefixes


def _process_and_write(name, items):
    """Load data for one provider, aggregate and write output files."""
    v4_nets, v6_nets = set(), set()
    missing_or_invalid = []

    for item in items:
        if isinstance(item, str):
            try:
                net = ipaddress.ip_network(item, strict=False)
            except ValueError as exc:
                print(
                    f"{name}: WARNING: invalid static prefix {item!r}: {exc}",
                    file=sys.stderr,
                )
                continue

            (v4_nets if net.version == 4 else v6_nets).add(net)
            continue

        try:
            prefixes = _load_prefixes_for_asn(item)
        except (FileNotFoundError, RuntimeError) as exc:
            missing_or_invalid.append(str(exc))
            continue

        for p in prefixes:
            try:
                net = ipaddress.ip_network(p, strict=False)
                (v4_nets if net.version == 4 else v6_nets).add(net)
            except ValueError as exc:
                print(
                    f"{name}: WARNING: invalid prefix {p!r} "
                    f"in AS{item}: {exc}",
                    file=sys.stderr,
                )

    if missing_or_invalid:
        for error in missing_or_invalid:
            print(f"{name}: ERROR: {error}", file=sys.stderr)

        raise RuntimeError(
            f"{name}: one or more ASN cache files are missing or invalid"
        )

    # Write outputs.
    for out_dir, nets in (
        (OUTPUT_DIR_V4, v4_nets),
        (OUTPUT_DIR_V6, v6_nets),
    ):
        out_file = out_dir / f"{name}.txt"


        if not nets:
            if out_file.exists():
                print(
                    f"{name}: no prefixes in {out_dir.name}; "
                    f"keeping existing file"
                )
            else:
                out_file.write_text("", encoding="utf-8")
                print(
                    f"{name}: no prefixes in {out_dir.name} "
                    f"(file cleared/created)"
                )
            continue

        collapsed = list(ipaddress.collapse_addresses(nets))

        with out_file.open("w", encoding="utf-8") as f:
            for net in collapsed:
                f.write(f"{net}\n")

        print(
            f"{name} ({out_dir.name}): "
            f"{len(nets)} -> {len(collapsed)} aggregated"
        )


def update():
    """Aggregate cached prefixes and write output files."""
    if not DATA_DIR.exists():
        print(
            f"ERROR: {DATA_DIR} does not exist. "
            "Run 'download' first.",
            file=sys.stderr,
        )
        sys.exit(1)

    OUTPUT_DIR_V4.mkdir(parents=True, exist_ok=True)
    OUTPUT_DIR_V6.mkdir(parents=True, exist_ok=True)

    failed = []

    for name, items in AS_LIST.items():
        try:
            _process_and_write(name, items)
        except Exception as exc:
            print(
                f"{name}: ERROR: {exc}",
                file=sys.stderr,
            )
            failed.append(name)

    if failed:
        print(
            "\nUpdate completed with errors: "
            + ", ".join(failed),
            file=sys.stderr,
        )
        sys.exit(1)


# ----------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description=(
            "Download and aggregate RIPEstat prefixes by provider."
        )
    )
    subparsers = parser.add_subparsers(dest="command")

    subparsers.add_parser(
        "download",
        help="download prefixes from RIPEstat",
    )
    subparsers.add_parser(
        "update",
        help="aggregate cached prefixes into "
             "ipv4/*.txt and ipv6/*.txt",
    )

    args = parser.parse_args()

    try:
        if args.command == "download":
            download()
        elif args.command == "update":
            update()
        else:
            parser.print_help()
    except KeyboardInterrupt:
        print("\nInterrupted by user.", file=sys.stderr)
        sys.exit(130)


if __name__ == "__main__":
    main()

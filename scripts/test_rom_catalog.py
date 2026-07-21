#!/usr/bin/env python3
"""Run exact gcdgold round-trip checks for a CUE-described ROM collection."""

from __future__ import annotations

import argparse
import csv
from dataclasses import dataclass
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time
import tomllib
from typing import BinaryIO, Sequence, TextIO


SECTOR_SIZE = 2352
COMPARE_CHUNK_SIZE = 4 * 1024 * 1024
DEFAULT_CONFIG = Path(__file__).resolve().with_name("test_rom_catalog.toml")
FILE_PATTERN = re.compile(
    r'^\s*FILE\s+(?:"(?P<quoted>[^"]+)"|(?P<plain>[^"\s]\S*))\s+\S+(?:\s+.*)?$',
    re.IGNORECASE,
)
TRACK_PATTERN = re.compile(r"^\s*TRACK\s+\d+\s+(?P<mode>\S+)\s*$", re.IGNORECASE)


class CatalogError(ValueError):
    """The catalog configuration or failure list is invalid."""


@dataclass(frozen=True)
class Configuration:
    gcdgold: Path
    roms: Path
    output: Path


@dataclass(frozen=True)
class CommandExecution:
    returncode: int
    stdout: str
    stderr: str


@dataclass(frozen=True)
class AttemptOutcome:
    passed: bool
    reason: str


@dataclass(frozen=True)
class Discovery:
    images: tuple[Path, ...]
    errors: tuple[str, ...]


def resolve_configured_path(config_path: Path, value: str) -> Path:
    path = Path(value).expanduser()
    if not path.is_absolute():
        path = config_path.parent / path
    return path.resolve()


def load_configuration(path: Path) -> Configuration:
    config_path = path.expanduser().resolve()
    if not config_path.exists():
        raise CatalogError(f"configuration file does not exist: {config_path}")
    if not config_path.is_file():
        raise CatalogError(f"configuration path is not a regular file: {config_path}")

    try:
        with config_path.open("rb") as source:
            document = tomllib.load(source)
    except tomllib.TOMLDecodeError as error:
        raise CatalogError(f"invalid TOML in {config_path}: {error}") from error

    expected = {"gcdgold", "roms", "output"}
    actual = set(document)
    if actual != expected:
        missing = sorted(expected - actual)
        unknown = sorted(actual - expected)
        details: list[str] = []
        if missing:
            details.append(f"missing keys: {', '.join(missing)}")
        if unknown:
            details.append(f"unknown keys: {', '.join(unknown)}")
        raise CatalogError(f"invalid configuration ({'; '.join(details)})")

    values: dict[str, Path] = {}
    for key in sorted(expected):
        value = document[key]
        if not isinstance(value, str) or not value.strip():
            raise CatalogError(f"configuration key {key!r} must be a nonempty string")
        values[key] = resolve_configured_path(config_path, value)

    return Configuration(
        gcdgold=values["gcdgold"],
        roms=values["roms"],
        output=values["output"],
    )


def appended_path(path: Path, suffix: str) -> Path:
    return path.with_name(path.name + suffix)


def validate_configuration(configuration: Configuration) -> None:
    if not configuration.roms.exists():
        raise CatalogError(f"ROM directory does not exist: {configuration.roms}")
    if not configuration.roms.is_dir():
        raise CatalogError(f"ROM location is not a directory: {configuration.roms}")
    if not configuration.gcdgold.exists():
        raise CatalogError(f"gcdgold executable does not exist: {configuration.gcdgold}")
    if not configuration.gcdgold.is_file():
        raise CatalogError(
            f"gcdgold executable path is not a regular file: {configuration.gcdgold}"
        )
    if not os.access(configuration.gcdgold, os.X_OK):
        raise CatalogError(f"gcdgold path is not executable: {configuration.gcdgold}")

    configuration.output.parent.mkdir(parents=True, exist_ok=True)
    if configuration.output.is_symlink():
        raise CatalogError(f"output path must not be a symlink: {configuration.output}")
    if configuration.output.exists() and not configuration.output.is_file():
        raise CatalogError(
            f"output path is not a regular file: {configuration.output}"
        )

    for path in (
        appended_path(configuration.output, ".tmp"),
        appended_path(configuration.output, ".bak.tmp"),
    ):
        if path.is_symlink():
            raise CatalogError(f"staging path must not be a symlink: {path}")
        if path.exists() and not path.is_file():
            raise CatalogError(f"staging path is not a regular file: {path}")

    backup = appended_path(configuration.output, ".bak")
    if backup.exists() and backup.is_dir():
        raise CatalogError(f"backup path is a directory: {backup}")


def decode_cue(path: Path) -> str:
    encoded = path.read_bytes()
    try:
        return encoded.decode("utf-8-sig")
    except UnicodeDecodeError:
        return encoded.decode("cp1252")


def cue_file_path(cue: Path, value: str) -> Path:
    platform_value = value if os.sep == "\\" else value.replace("\\", os.sep)
    path = Path(platform_value)
    if not path.is_absolute():
        path = cue.parent / path
    return path.resolve()


def parse_cue(cue: Path) -> tuple[list[Path], list[str]]:
    active_file: str | None = None
    images: list[Path] = []
    errors: list[str] = []

    try:
        lines = decode_cue(cue).splitlines()
    except OSError as error:
        return [], [str(error)]

    for line_number, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped or stripped.upper().startswith("REM "):
            continue
        if stripped.upper().startswith("FILE"):
            match = FILE_PATTERN.fullmatch(line)
            if match is None:
                active_file = None
                errors.append(f"malformed FILE declaration at line {line_number}")
            else:
                active_file = match.group("quoted") or match.group("plain")
            continue
        if not stripped.upper().startswith("TRACK"):
            continue

        match = TRACK_PATTERN.fullmatch(line)
        if match is None:
            errors.append(f"malformed TRACK declaration at line {line_number}")
            continue
        mode = match.group("mode")
        if mode.upper() == "AUDIO":
            continue
        if not mode.upper().endswith("/2352"):
            errors.append(f"unsupported data track mode {mode} at line {line_number}")
            continue
        if active_file is None:
            errors.append(f"data track at line {line_number} has no preceding FILE")
            continue
        images.append(cue_file_path(cue, active_file))

    return images, errors


def discover_cues(directory: Path) -> list[Path]:
    return sorted(
        (
            path
            for path in directory.iterdir()
            if path.is_file() and path.suffix.lower() == ".cue"
        ),
        key=lambda path: (path.name.casefold(), path.name),
    )


def relative_image_path(image: Path, roms: Path) -> str:
    try:
        relative = image.relative_to(roms)
    except ValueError as error:
        raise CatalogError(f"data track path escapes the ROM directory: {image}") from error
    value = relative.as_posix()
    if "\r" in value or "\n" in value:
        raise CatalogError(f"data track path contains a newline: {value!r}")
    return value


def discover_images(roms: Path) -> Discovery:
    images: list[Path] = []
    errors: list[str] = []
    seen: set[Path] = set()

    for cue in discover_cues(roms):
        cue_images, cue_errors = parse_cue(cue)
        errors.extend(f"{cue.name}: {message}" for message in cue_errors)
        for image in cue_images:
            try:
                relative_image_path(image, roms)
            except CatalogError as error:
                errors.append(f"{cue.name}: {error}")
                continue
            if image not in seen:
                seen.add(image)
                images.append(image)

    return Discovery(images=tuple(images), errors=tuple(errors))


def load_retry_images(output: Path, roms: Path) -> tuple[Path, ...]:
    images: list[Path] = []
    seen: set[Path] = set()

    try:
        source: TextIO
        with output.open("r", encoding="utf-8", newline="") as source:
            reader = csv.reader(source)
            for row in reader:
                if len(row) != 2:
                    raise CatalogError(
                        f"invalid failure CSV record at line {reader.line_num}: "
                        "expected exactly two fields"
                    )
                path_text, reason = row
                if not path_text:
                    raise CatalogError(
                        f"invalid failure CSV record at line {reader.line_num}: "
                        "data track path is empty"
                    )
                if any(character in path_text for character in "\r\n") or any(
                    character in reason for character in "\r\n"
                ):
                    raise CatalogError(
                        f"invalid failure CSV record at line {reader.line_num}: "
                        "fields must remain on one line"
                    )

                relative = Path(path_text)
                if relative.is_absolute() or ".." in relative.parts:
                    raise CatalogError(
                        f"invalid failure CSV path at line {reader.line_num}: "
                        f"path must remain relative to the ROM directory: {path_text}"
                    )
                image = (roms / relative).resolve()
                relative_image_path(image, roms)
                if image not in seen:
                    seen.add(image)
                    images.append(image)
    except csv.Error as error:
        raise CatalogError(f"invalid failure CSV {output}: {error}") from error

    return tuple(images)


def run_command(arguments: Sequence[str]) -> CommandExecution:
    try:
        completed = subprocess.run(
            arguments,
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
    except OSError as error:
        return CommandExecution(returncode=-1, stdout="", stderr=str(error))
    return CommandExecution(
        returncode=completed.returncode,
        stdout=completed.stdout,
        stderr=completed.stderr,
    )


def normalize_message(message: str) -> str:
    return " ".join(message.replace("\t", " ").split()).strip()


def command_failure(stage: str, execution: CommandExecution) -> AttemptOutcome:
    diagnostic = normalize_message(execution.stderr)
    if not diagnostic:
        diagnostic = normalize_message(execution.stdout)
    if not diagnostic:
        diagnostic = "no diagnostic output"
    return AttemptOutcome(
        passed=False,
        reason=f"{stage}: exit {execution.returncode}: {diagnostic}",
    )


def compare_files(source: Path, rebuilt: Path) -> AttemptOutcome:
    source_size = source.stat().st_size
    rebuilt_size = rebuilt.stat().st_size
    if source_size != rebuilt_size:
        delta = rebuilt_size - source_size
        return AttemptOutcome(
            passed=False,
            reason=(
                "compare: size mismatch: "
                f"source {source_size} bytes, rebuilt {rebuilt_size} bytes, "
                f"delta {delta:+d} bytes"
            ),
        )

    offset = 0
    with source.open("rb") as expected, rebuilt.open("rb") as actual:
        while True:
            expected_chunk = expected.read(COMPARE_CHUNK_SIZE)
            actual_chunk = actual.read(COMPARE_CHUNK_SIZE)
            if expected_chunk != actual_chunk:
                difference = next(
                    index
                    for index, (expected_byte, actual_byte) in enumerate(
                        zip(expected_chunk, actual_chunk, strict=True)
                    )
                    if expected_byte != actual_byte
                )
                absolute_offset = offset + difference
                return AttemptOutcome(
                    passed=False,
                    reason=(
                        "compare: byte mismatch: "
                        f"offset {absolute_offset}, LBA {absolute_offset // SECTOR_SIZE}, "
                        f"sector offset {absolute_offset % SECTOR_SIZE}, "
                        f"source 0x{expected_chunk[difference]:02x}, "
                        f"rebuilt 0x{actual_chunk[difference]:02x}"
                    ),
                )
            if not expected_chunk:
                return AttemptOutcome(passed=True, reason="")
            offset += len(expected_chunk)


def run_round_trip(gcdgold: Path, image: Path) -> AttemptOutcome:
    if not image.exists():
        return AttemptOutcome(
            passed=False,
            reason=f"input: data track file does not exist: {image}",
        )
    if not image.is_file():
        return AttemptOutcome(
            passed=False,
            reason=f"input: data track path is not a regular file: {image}",
        )

    with tempfile.TemporaryDirectory(prefix="gcdgold-catalog-") as temporary:
        project = Path(temporary)
        manifest = project / "disc.yaml"
        data_dir = project / "assets"
        rebuilt = project / "rebuilt.bin"

        extraction = run_command(
            [
                str(gcdgold),
                "extract",
                "--image",
                str(image),
                "--manifest",
                str(manifest),
                "--data-dir",
                str(data_dir),
            ]
        )
        if extraction.returncode != 0:
            return command_failure("extract", extraction)

        building = run_command(
            [
                str(gcdgold),
                "build",
                "--manifest",
                str(manifest),
                "--image",
                str(rebuilt),
                "--data-dir",
                str(data_dir),
            ]
        )
        if building.returncode != 0:
            return command_failure("build", building)

        try:
            return compare_files(image, rebuilt)
        except OSError as error:
            return AttemptOutcome(
                passed=False,
                reason=f"compare: I/O error: {normalize_message(str(error))}",
            )


def fsync_file(output: TextIO) -> None:
    output.flush()
    os.fsync(output.fileno())


def copy_and_fsync(source: Path, destination: Path) -> None:
    input_file: BinaryIO
    output_file: BinaryIO
    with source.open("rb") as input_file, destination.open("wb") as output_file:
        shutil.copyfileobj(input_file, output_file, length=1024 * 1024)
        output_file.flush()
        os.fsync(output_file.fileno())


def fsync_directory(directory: Path) -> None:
    descriptor = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def install_results(output: Path, temporary_output: Path) -> None:
    backup = appended_path(output, ".bak")
    temporary_backup = appended_path(output, ".bak.tmp")

    if output.exists():
        copy_and_fsync(output, temporary_backup)
        os.replace(temporary_backup, backup)
        fsync_directory(output.parent)

    os.replace(temporary_output, output)
    fsync_directory(output.parent)


def pass_rate(passed: int, failed: int) -> float:
    completed = passed + failed
    if completed == 0:
        return 0.0
    return passed * 100.0 / completed


def process_catalog(configuration: Configuration) -> int:
    if configuration.output.exists():
        images = load_retry_images(configuration.output, configuration.roms)
        discovery_errors: tuple[str, ...] = ()
    else:
        discovery = discover_images(configuration.roms)
        images = discovery.images
        discovery_errors = discovery.errors

    for message in discovery_errors:
        print(f"discovery error: {message}", file=sys.stderr, flush=True)

    temporary_output = appended_path(configuration.output, ".tmp")
    passed = 0
    failed = 0

    with temporary_output.open("w", encoding="utf-8", newline="") as output:
        writer = csv.writer(output, lineterminator="\n")
        for position, image in enumerate(images, start=1):
            data_path = relative_image_path(image, configuration.roms)
            started = time.monotonic()
            outcome = run_round_trip(configuration.gcdgold, image)
            elapsed = time.monotonic() - started

            if outcome.passed:
                passed += 1
                rate = pass_rate(passed, failed)
                print(
                    f"[{position}/{len(images)}, rate: {rate:.2f}%] "
                    f"PASS {data_path} ({elapsed:.1f}s)",
                    flush=True,
                )
                continue

            failed += 1
            rate = pass_rate(passed, failed)
            writer.writerow([data_path, outcome.reason])
            fsync_file(output)
            print(
                f"[{position}/{len(images)}, rate: {rate:.2f}%] "
                f"FAIL {data_path}: "
                f"{outcome.reason} ({elapsed:.1f}s)",
                flush=True,
            )

        fsync_file(output)

    install_results(configuration.output, temporary_output)
    rate = pass_rate(passed, failed)
    print(
        "summary: "
        f"passed={passed} failed={failed} rate={rate:.2f}% "
        f"discovery_errors={len(discovery_errors)} total={len(images)}",
        flush=True,
    )
    return 1 if failed or discovery_errors else 0


def argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Test exact gcdgold round trips for CUE-described raw tracks."
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=DEFAULT_CONFIG,
        help=f"configuration file (default: {DEFAULT_CONFIG})",
    )
    return parser


def main(arguments: Sequence[str] | None = None) -> int:
    parsed = argument_parser().parse_args(arguments)
    try:
        configuration = load_configuration(parsed.config)
        validate_configuration(configuration)
        return process_catalog(configuration)
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 130
    except (CatalogError, OSError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

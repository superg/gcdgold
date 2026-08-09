#!/usr/bin/env python3
"""Run exact gcdgold round-trip checks for a CUE-described ROM collection."""

from __future__ import annotations

import argparse
import csv
from dataclasses import dataclass
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import sys
import tempfile
import time
import tomllib
from typing import BinaryIO, Sequence, TextIO


CONFIG_NAME = "test_rom_catalog.toml"
SCRIPT_CONFIG = Path(__file__).resolve().with_name(CONFIG_NAME)
FILE_PATTERN = re.compile(
    r'^\s*FILE\s+(?:"(?P<quoted>[^"]+)"|(?P<plain>[^"\s]\S*))\s+\S+(?:\s+.*)?$',
    re.IGNORECASE,
)
TRACK_PATTERN = re.compile(r"^\s*TRACK\s+\d+\s+(?P<mode>\S+)\s*$", re.IGNORECASE)


class CatalogError(ValueError):
    """The catalog configuration or passed list is invalid."""


@dataclass(frozen=True)
class Configuration:
    gcdgold: Path
    roms: Path
    failures: Path
    passed: Path
    manifests: Path | None
    extracted_projects: Path | None


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
    items: tuple[CatalogItem, ...]
    errors: tuple[str, ...]


@dataclass(frozen=True)
class CatalogItem:
    image: Path


def resolve_configured_path(config_path: Path, value: str) -> Path:
    path = Path(value).expanduser()
    if not path.is_absolute():
        path = config_path.parent / path
    return path.resolve()


def default_configuration_path() -> Path:
    cwd_config = Path.cwd() / CONFIG_NAME
    if cwd_config.exists():
        return cwd_config
    return SCRIPT_CONFIG


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

    required = {"failures", "gcdgold", "passed", "roms"}
    optional = {"extracted_projects", "manifests"}
    expected = required | optional
    actual = set(document)
    if not required.issubset(actual) or not actual.issubset(expected):
        missing = sorted(required - actual)
        unknown = sorted(actual - expected)
        details: list[str] = []
        if missing:
            details.append(f"missing keys: {', '.join(missing)}")
        if unknown:
            details.append(f"unknown keys: {', '.join(unknown)}")
        raise CatalogError(f"invalid configuration ({'; '.join(details)})")

    values: dict[str, Path] = {}
    for key in sorted(actual):
        value = document[key]
        if not isinstance(value, str) or not value.strip():
            raise CatalogError(f"configuration key {key!r} must be a nonempty string")
        values[key] = resolve_configured_path(config_path, value)

    return Configuration(
        gcdgold=values["gcdgold"],
        roms=values["roms"],
        failures=values["failures"],
        passed=values["passed"],
        manifests=values.get("manifests"),
        extracted_projects=values.get("extracted_projects"),
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

    if configuration.failures == configuration.passed:
        raise CatalogError("failures and passed paths must be distinct")
    configuration.failures.parent.mkdir(parents=True, exist_ok=True)
    configuration.passed.parent.mkdir(parents=True, exist_ok=True)
    if configuration.passed.is_symlink():
        raise CatalogError(f"passed path must not be a symlink: {configuration.passed}")
    if configuration.passed.exists() and not configuration.passed.is_file():
        raise CatalogError(
            f"passed path is not a regular file: {configuration.passed}"
        )

    if configuration.manifests is not None:
        if configuration.manifests.exists() and not configuration.manifests.is_dir():
            raise CatalogError(
                f"manifest output path is not a directory: {configuration.manifests}"
            )
        configuration.manifests.mkdir(parents=True, exist_ok=True)

    if configuration.extracted_projects is not None:
        if (
            configuration.extracted_projects.exists()
            and not configuration.extracted_projects.is_dir()
        ):
            raise CatalogError(
                "extracted project output path is not a directory: "
                f"{configuration.extracted_projects}"
            )
        configuration.extracted_projects.mkdir(parents=True, exist_ok=True)
        if not os.access(configuration.extracted_projects, os.W_OK | os.X_OK):
            raise CatalogError(
                "extracted project output directory is not writable: "
                f"{configuration.extracted_projects}"
            )


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
    selected: list[tuple[Path, int]] = []
    track_counts: dict[Path, int] = {}
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
            if active_file is not None:
                image = cue_file_path(cue, active_file)
                track_counts[image] = track_counts.get(image, 0) + 1
            errors.append(f"malformed TRACK declaration at line {line_number}")
            continue
        mode = match.group("mode")
        image = cue_file_path(cue, active_file) if active_file is not None else None
        if image is not None:
            track_counts[image] = track_counts.get(image, 0) + 1
        if mode.upper() == "AUDIO":
            continue
        if not mode.upper().endswith("/2352"):
            errors.append(f"unsupported data track mode {mode} at line {line_number}")
        elif image is None:
            errors.append(f"data track at line {line_number} has no preceding FILE")
        else:
            selected.append((image, line_number))

    images: list[Path] = []
    reported_shared: set[Path] = set()
    for image, line_number in selected:
        count = track_counts[image]
        if count > 1:
            if image not in reported_shared:
                reported_shared.add(image)
                errors.append(
                    f"data track at line {line_number} shares FILE {image.name!r} "
                    f"with {count} TRACK declarations; shared multi-track BIN "
                    "files are unsupported"
                )
            continue
        images.append(image)

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
    items: list[CatalogItem] = []
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
                items.append(CatalogItem(image=image))

    return Discovery(items=tuple(items), errors=tuple(errors))


def track_name(image: Path) -> str:
    name = image.stem
    if not name or name in {".", ".."}:
        raise CatalogError(f"data track path has no usable filename stem: {image}")
    return name


def manifest_destination(directory: Path, image: Path) -> Path:
    return directory / f"{track_name(image)}.yaml"


def project_destination(directory: Path, image: Path) -> Path:
    return directory / track_name(image)


def load_passed_images(passed: Path, roms: Path) -> set[Path]:
    if not passed.exists():
        return set()

    seen: set[Path] = set()
    try:
        source: TextIO
        with passed.open("r", encoding="utf-8", newline="") as source:
            for line_number, line in enumerate(source, start=1):
                path_text = line.rstrip("\r\n")
                if not path_text:
                    raise CatalogError(
                        f"invalid passed record at line {line_number}: "
                        "data track path is empty"
                    )
                if "\r" in path_text or "\n" in path_text:
                    raise CatalogError(
                        f"invalid passed record at line {line_number}: "
                        "path must remain on one line"
                    )
                relative = PurePosixPath(path_text)
                if relative.is_absolute() or ".." in relative.parts:
                    raise CatalogError(
                        f"invalid passed path at line {line_number}: path must remain "
                        f"relative to the ROM directory: {path_text}"
                    )
                if relative.as_posix() != path_text:
                    raise CatalogError(
                        f"invalid passed path at line {line_number}: path must use "
                        f"canonical POSIX form: {path_text}"
                    )
                image = roms.joinpath(*relative.parts).resolve()
                relative_image_path(image, roms)
                if image in seen:
                    raise CatalogError(
                        f"duplicate passed path at line {line_number}: {path_text}"
                    )
                seen.add(image)
    except UnicodeDecodeError as error:
        raise CatalogError(f"passed file is not valid UTF-8: {passed}") from error

    return seen


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


def run_round_trip(
    gcdgold: Path,
    image: Path,
    saved_manifest: Path | None = None,
    extracted_projects: Path | None = None,
) -> AttemptOutcome:
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

    with tempfile.TemporaryDirectory(
        prefix=".gcdgold-catalog-",
        dir=extracted_projects,
    ) as temporary:
        project = Path(temporary)
        manifest = project / f"{track_name(image)}.yaml"
        rebuilt = project / "rebuilt.bin"

        if extracted_projects is None:
            data_dir = project / "assets"
            retained_manifest = None
            retained_project = None
            staging_project = None
        else:
            data_dir = project / "assets"
            data_dir.mkdir()
            retained_project = project_destination(extracted_projects, image)
            retained_manifest = retained_project / f"{track_name(image)}.yaml"
            staging_project = data_dir

        try:
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

            if retained_project is not None and retained_manifest is not None:
                staged_manifest = data_dir / retained_manifest.name
                if staged_manifest.exists() or staged_manifest.is_symlink():
                    return AttemptOutcome(
                        passed=False,
                        reason=(
                            "extracted project: manifest path collides with an "
                            f"extracted asset: {retained_manifest.name}"
                        ),
                    )
                try:
                    copy_and_fsync(manifest, staged_manifest)
                    fsync_directory(data_dir)
                    install_project(data_dir, retained_project)
                except (CatalogError, OSError) as error:
                    return AttemptOutcome(
                        passed=False,
                        reason=(
                            "extracted project: I/O error: "
                            f"{normalize_message(str(error))}"
                        ),
                    )
                data_dir = retained_project
                manifest = retained_manifest
                staging_project = None

            if saved_manifest is not None:
                try:
                    install_manifest(manifest, saved_manifest)
                except (CatalogError, OSError) as error:
                    return AttemptOutcome(
                        passed=False,
                        reason=(
                            "manifest: I/O error: "
                            f"{normalize_message(str(error))}"
                        ),
                    )

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

            return AttemptOutcome(passed=True, reason="")
        finally:
            if staging_project is not None:
                shutil.rmtree(staging_project, ignore_errors=True)


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


def install_manifest(source: Path, destination: Path) -> None:
    temporary = appended_path(destination, ".tmp")
    for label, path in (("manifest", destination), ("manifest staging", temporary)):
        if path.is_symlink():
            raise CatalogError(f"{label} path must not be a symlink: {path}")
        if path.exists() and not path.is_file():
            raise CatalogError(f"{label} path is not a regular file: {path}")

    copy_and_fsync(source, temporary)
    os.replace(temporary, destination)
    fsync_directory(destination.parent)


def install_project(source: Path, destination: Path) -> None:
    backup = appended_path(destination, ".bak.tmp")
    for label, path in (("project", destination), ("project backup", backup)):
        if path.is_symlink():
            raise CatalogError(f"{label} path must not be a symlink: {path}")
    if destination.exists() and not destination.is_dir():
        raise CatalogError(f"project path is not a directory: {destination}")
    if backup.exists():
        raise CatalogError(f"project backup path already exists: {backup}")

    if not destination.exists():
        os.replace(source, destination)
        fsync_directory(destination.parent)
        return

    os.replace(destination, backup)
    fsync_directory(destination.parent)
    try:
        os.replace(source, destination)
    except BaseException:
        os.replace(backup, destination)
        fsync_directory(destination.parent)
        raise

    fsync_directory(destination.parent)
    shutil.rmtree(backup)
    fsync_directory(destination.parent)


def fsync_directory(directory: Path) -> None:
    descriptor = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def append_passed_result(passed: Path, data_path: str) -> None:
    separator = ""
    if passed.exists() and passed.stat().st_size > 0:
        with passed.open("rb") as source:
            source.seek(-1, os.SEEK_END)
            if source.read(1) != b"\n":
                separator = "\n"
    with passed.open("a", encoding="utf-8", newline="") as output:
        output.write(f"{separator}{data_path}\n")
        fsync_file(output)


def append_failure_result(failures: Path, data_path: str, reason: str) -> None:
    with failures.open("a", encoding="utf-8", newline="") as output:
        writer = csv.writer(output, quoting=csv.QUOTE_ALL, lineterminator="\n")
        writer.writerow([data_path, reason])
        fsync_file(output)


def pass_rate(passed: int, failed: int) -> float:
    completed = passed + failed
    if completed == 0:
        return 0.0
    return passed * 100.0 / completed


def process_catalog(configuration: Configuration) -> int:
    passed_images = load_passed_images(configuration.passed, configuration.roms)
    discovery = discover_images(configuration.roms)
    items = tuple(item for item in discovery.items if item.image not in passed_images)
    discovery_errors = discovery.errors
    skipped = len(discovery.items) - len(items)

    for message in discovery_errors:
        print(f"discovery error: {message}", file=sys.stderr, flush=True)

    passed = 0
    failed = 0
    for position, item in enumerate(items, start=1):
        image = item.image
        data_path = relative_image_path(image, configuration.roms)
        started = time.monotonic()
        saved_manifest = (
            manifest_destination(configuration.manifests, image)
            if configuration.manifests is not None
            else None
        )
        outcome = run_round_trip(
            configuration.gcdgold,
            image,
            saved_manifest,
            configuration.extracted_projects,
        )
        elapsed = time.monotonic() - started

        if outcome.passed:
            append_passed_result(configuration.passed, data_path)
            passed += 1
            rate = pass_rate(passed, failed)
            print(
                f"[{position}/{len(items)}, rate: {rate:.2f}%] "
                f"PASS {data_path} ({elapsed:.1f}s)",
                flush=True,
            )
            continue

        append_failure_result(configuration.failures, data_path, outcome.reason)
        failed += 1
        rate = pass_rate(passed, failed)
        print(
            f"[{position}/{len(items)}, rate: {rate:.2f}%] "
            f"FAIL {data_path}: "
            f"{outcome.reason} ({elapsed:.1f}s)",
            flush=True,
        )

    rate = pass_rate(passed, failed)
    print(
        "summary: "
        f"passed={passed} failed={failed} rate={rate:.2f}% "
        f"skipped={skipped} discovery_errors={len(discovery_errors)} "
        f"total={len(items)}",
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
        default=default_configuration_path(),
        help=(
            f"configuration file (default: ./{CONFIG_NAME} when present, "
            f"otherwise {SCRIPT_CONFIG})"
        ),
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

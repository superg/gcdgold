# gcdgold

gcdgold is a command-line tool for extracting and authoring CD-ROM data
tracks as editable projects. For every supported track, its central preservation
goal is simple: extracting and rebuilding without making changes must reproduce
the source image byte for byte.

The tool was developed from scratch to meet optical-media preservation needs.

gcdgold is under active development. It accepts only layouts it can represent
and rebuild deterministically; unsupported structures are rejected explicitly
instead of being guessed or silently copied as opaque data.

## Why gcdgold?

### Content exploration

Analyzing a data track is not always straightforward. The physical disc may be
unavailable, mounting support varies by operating system and often requires
third-party software, and ordinary PC tools do not handle every CD-ROM layout
well. XA Form 2 is a particularly awkward case: files that interleave Form 1
and Form 2 sectors generally cannot be copied correctly through a conventional
mounted filesystem.

Damage and noncompliant mastering add another layer of difficulty. Bad
directory records, malformed filesystems, and damaged sectors can make content
invisible even when its location and meaning can still be established. gcdgold
turns every supported image into an ordinary directory of files and explicit
assets plus a YAML manifest. Known recoverable damage is reported, every
decision is deterministic, and anything that cannot be represented safely is
rejected.

### Controlled image modification

An extracted project is an editable description of the complete data track.
Files can be replaced, filesystem metadata can be changed, physical layout can
be adjusted, and image-generation policies can be edited as structured YAML.
gcdgold then handles the CD image authoring details during the rebuild.

This makes it useful for translations, game hacking, other game modifications,
and retro-game development. The resulting image stays as close to its source as
the requested changes allow; with no changes, a supported image rebuilds
identically.

### Image reconstruction

It is often possible to reconstruct an image manually from known files, but
the process is painful and easily misses small mastering details. In the spirit
of the [Redumper](https://github.com/superg/redumper) skeleton concept, a
gcdgold YAML manifest acts as an exhaustive skeleton for a data track.

That skeleton also makes related images derivable from one another. For
example, some PlayStation images differ only in whether Form 2 EDC values were
calculated or zeroed; extracting one image, changing the EDC policy in YAML,
and rebuilding can reproduce the other mastered variant. Files from a sampler
disc can be combined with the manifest for a dedicated demo to reproduce that
demo image exactly. If the manifest for a missing-in-action image survives and
its files are available from other sources, gcdgold can reconstruct the image
without manual sector authoring or another image-building tool.

### Better romset compression

Potentially the most important use case is more efficient romset storage.
ROM-management and preservation workflows have historically compressed an
entire Redump-style data track with general-purpose formats such as ZIP, 7z, or
Zstandard. A raw image, however, contains a large amount of framing,
protection, filesystem, and layout data that can be derived rather than stored
verbatim.

[ECM by Neill Corlett](https://web.archive.org/web/20140227165748/http://www.neillcorlett.com/ecm/)
already demonstrates the value of removing reproducible CD-ROM EDC and ECC
before applying a general-purpose compressor. ECM works at the CD-ROM sector
layer. gcdgold goes further: it dismantles the data track into files, the system
area, demultiplexed Form 1/Form 2 content, and compact structured layout
definitions. The result avoids storing every derivable layer and presents
compressors with a highly compressible file hierarchy that remains exactly
reproducible.

Formal compression results have not yet been published. The long-term plan is
for this approach, whether delivered through a standalone executable or as a
compression library integrated into ROM managers, to become one of the most
effective ways to store optical data-track romsets.

#### Multi-disc games

Multi-disc games benefit especially from filesystem-level extraction because
their discs often share a large amount of identical content. All discs can be
extracted into one data directory while keeping a separate manifest for each
image. For example, the three Final Fantasy VII discs can share one project:

```console
gcdgold extract --image "Final Fantasy VII (USA) (Disc 1).bin" --manifest "Final Fantasy VII (USA)/Disc 1.yaml" --data-dir "Final Fantasy VII (USA)"
gcdgold extract --image "Final Fantasy VII (USA) (Disc 2).bin" --manifest "Final Fantasy VII (USA)/Disc 2.yaml" --data-dir "Final Fantasy VII (USA)"
gcdgold extract --image "Final Fantasy VII (USA) (Disc 3).bin" --manifest "Final Fantasy VII (USA)/Disc 3.yaml" --data-dir "Final Fantasy VII (USA)"
```

When a later disc extracts an asset with the same path and identical SHA-1,
gcdgold reuses the existing file. If the path is the same but the content hash
differs, gcdgold assigns a deterministic numeric suffix and updates that disc's
manifest to reference the renamed asset. Shared content is therefore stored
once, distinct content remains unambiguous, and a general-purpose compressor
can take further advantage of common data across the complete multi-disc set.

## Goal and current status

The ultimate goal is 1:1 reconstruction of every data track in the
[Redump](https://redump.info/) system library. As of August 9, 2026, the
complete Redump PlayStation romset is 100% byte-for-byte reconstructible with
gcdgold.

## Testing a ROM catalog

[`scripts/test_rom_catalog.py`](scripts/test_rom_catalog.py) automates exact
round-trip testing across a complete system romset. This is useful for anyone
who wants to measure gcdgold's current coverage for a particular console or
catalog rather than testing images one at a time.

The runner scans the configured ROM directory for CUE sheets, discovers each
isolated raw `/2352` data-track file, extracts it, rebuilds it, and requires the
result to match the source track SHA-1. It prints progress and a live pass rate,
then finishes with counts for passed, failed, skipped, and discovery-error
items. Audio tracks are ignored. A BIN shared by multiple CUE `TRACK`
declarations is reported as a discovery error because the runner does not guess
track boundaries within a shared file.

Create a TOML configuration based on
[`scripts/test_rom_catalog.toml.example`](scripts/test_rom_catalog.toml.example):

```toml
gcdgold = "target/release/gcdgold"
roms = "/path/to/psx-romset"
failures = "catalog/psx-failures.csv"
passed = "catalog/psx-passed.txt"
manifests = "catalog/psx-manifests"
# extracted_projects = "catalog/psx-extracted-projects"
```

All relative paths are resolved from the configuration file's directory. The
four required settings select the gcdgold executable, ROM directory, failure
CSV, and passed-track list. `manifests` optionally retains extracted YAML files.
`extracted_projects` optionally retains complete projects and can require
substantial storage, but it is valuable when investigating an unsupported or
incorrectly reconstructed image.

Run the catalog test with:

```console
python3 scripts/test_rom_catalog.py --config test_rom_catalog.toml
```

Each successful relative track path is appended to the passed list and skipped
on later runs, so an interrupted catalog test can resume without repeating
known passes. Failures are appended to CSV with the stage, exit status, and
diagnostic. The process exits unsuccessfully if any round trip fails or any CUE
discovery error is found. Keep the configured gcdgold executable unchanged
during a run so every result measures the same version.

## Current format support

Supported today:

- Raw 2352-byte `.bin` data tracks.
- CD-ROM Mode 1 and Mode 2 XA tracks.
- ISO 9660 and Joliet filesystems, including CD-XA directory metadata and many
  nonstandard but reproducible mastering variants.
- Structured system-area extraction and regeneration.
- Automatic Form 1/Form 2 demultiplexing and deterministic remultiplexing,
  including interleaved files and filesystemless Form 1 extents.
- Reconstruction of sector subheaders and their duplicate copies. Corner cases
  that cannot be expressed structurally can be retained exactly through bounded
  stored framing or raw-sector patches.
- Regeneration of raw sector framing, addresses, EDC, and ECC.
- Explicit physical placement of descriptors, path tables, directories, files,
  gaps, duplicate blocks, and supported vendor metadata.
- Non-owning ISO directory records for dummy or placeholder files, plus
  external CD-DA extent references for files that point to audio sectors beyond
  the authored data track.
- Initial support for ISO/HFS hybrid images with a recognized Apple HFS
  partition.
- Bounded recovery for known damaged images, including malformed directory
  data and complete raw-sector patches.
- Redump-style `0x55` sector markings for ring protections, other intentionally
  damaged protection sectors, and substitutions for noncompliant CD-R sectors,
  plus boundary raw-zero gaps, Mode 1 reserved-byte variants, and supported
  noncompliant trailing ECC.

Not currently supported:

- `.iso` data-track images stored as 2048 bytes per sector, including DVD and
  Blu-ray images.
- UDF filesystem.
- High Sierra filesystem.
- Arbitrary unknown filesystem structures, hybrid metadata, or opaque interior
  sectors that cannot yet be described structurally.

## Basic usage

Extract `disc.bin` into `disc.yaml` and its associated assets in the current
directory:

```console
gcdgold extract --image disc.bin
```

Edit the manifest or extracted files, then author a new track:

```console
gcdgold build --manifest disc.yaml --image disc.rebuilt.bin
```

The YAML schema is gcdgold-versioned. Every extracted manifest records the
exact creating version in `gcdgold.version`, and a build must use that same
gcdgold version. This keeps reconstruction behavior tied to a known schema and
implementation instead of silently interpreting a project under different
rules.

The data directory defaults to the current directory. When `--manifest` is
omitted during extraction, the manifest defaults to the input filename with a
`.yaml` extension in the current directory. A build output can also default to
the manifest filename with a `.bin` extension, but the example names it
explicitly to avoid targeting the original `disc.bin`.

Existing output files are protected by default. Pass `--overwrite` only when
you intend to replace them.

### SHA-1 metadata

Extraction writes SHA-1 hashes for the source track, system area, and extracted
assets into the YAML manifest. Every hash is optional. During a build, gcdgold
warns when an asset no longer matches its recorded hash; it also checks the
completed track when `track.sha1` is present.

For deliberate modifications, any `sha1` fields that are no longer useful can
be safely deleted. Remove `track.sha1` as well when the output is intentionally
different from the source, or the CLI will report the final track mismatch as
a failure after creating the image.

## End-to-end extraction example

Monster Rancher 2 is a compact example that includes a mixed XA stream. From a
directory containing `Monster Rancher 2 (USA).bin`, extract it into a dedicated
project directory:

```console
gcdgold extract --image "Monster Rancher 2 (USA).bin" --manifest "Monster Rancher 2 (USA)/Monster Rancher 2 (USA).yaml" --data-dir "Monster Rancher 2 (USA)"
```

The complete generated manifest is shown below with all optional `sha1` fields
removed for readability:

```yaml
gcdgold:
  version: 0.1.0
track:
  mode: 2xa
system_area:
  path: Monster Rancher 2 (USA).system
  form1_sectors: auto
iso9660:
  primary_volume:
    system_identifier: PLAYSTATION
    volume_identifier: MONSTERRANCER2
    publisher_identifier: TECMO
    application_identifier: PLAYSTATION
    creation_time: 1999-08-03T09:00:00.00+09:00
  entries:
  - path: .
    recording_time: 1999-08-03T09:00:00+09:00
    sector_subheader: data_until_final
  - path: DATA
    recording_time: 1999-08-03T09:00:00+09:00
    sector_subheader: data_until_final
  - path: SLUS_009.17
    recording_time: 1999-08-03T13:21:00+09:00
  - path: SYSTEM.CNF
    recording_time: 1999-06-17T20:54:44+09:00
    sector_subheader: iso_metadata
  - path: DATA/MF2_DATA.IMG
    recording_time: 1999-08-03T13:27:20+09:00
  - path: DATA/MF2_DATA.OBJ
    recording_time: 1999-08-03T13:27:20+09:00
  - path: DATA/MOVIE.STR
    recording_time: 1999-06-22T18:05:38+09:00
    xa:
      attributes:
      - interleaved
      file_number: 1
  layout:
  - path: SYSTEM.CNF
  - path: SLUS_009.17
  - directory: DATA
  - path: DATA/MF2_DATA.OBJ
  - path: DATA/MF2_DATA.IMG
  - path: DATA/MOVIE.STR
    xa_assets:
      form1:
        path: DATA/MOVIE.STR.F1
        framing:
          policy: runs
          runs:
          - sectors: 20635
            subheader:
              file: 1
              channel: 1
              submode:
              - data
              - realtime
          - sectors: 20
            subheader:
              file: 1
      form2:
        path: DATA/MOVIE.STR.F2
        framing:
          policy: phase
          eof: final_record
          phases:
          - phase: 15
            subheader:
              file: 1
              channel: 1
              submode:
              - audio
              - form2
              - realtime
              coding_info: 5
      interleave:
        stride: 16
        cycles: 1377
        channels:
        - file: 1
          channel: 1
          phase: 15
  - gap: 150
    kind: xa
```

The extracted project has this directory structure:

```text
Monster Rancher 2 (USA)/
├── DATA/
│   ├── MF2_DATA.IMG
│   ├── MF2_DATA.OBJ
│   ├── MOVIE.STR.F1
│   └── MOVIE.STR.F2
├── Monster Rancher 2 (USA).system
├── Monster Rancher 2 (USA).yaml
├── SLUS_009.17
└── SYSTEM.CNF
```

`MOVIE.STR` is represented by separate Form 1 and Form 2 assets rather than an
ordinary host file. The manifest records how gcdgold must remultiplex them into
the original XA stream during a build.

For all options, run:

```console
gcdgold --help
gcdgold extract --help
gcdgold build --help
```

## Author

gcdgold is created and maintained by [Hennadiy Brych](https://github.com/superg).

## Need help?

Start with the command-specific `--help` output. For a bug, unsupported disc,
or other project question, open an issue in the
[gcdgold issue tracker](https://github.com/superg/gcdgold/issues) and include
the command you ran plus the complete error or warning output. Do not upload or
attach copyrighted disc contents.

## License

gcdgold is free software licensed under the
[GNU General Public License, version 3](LICENSE).

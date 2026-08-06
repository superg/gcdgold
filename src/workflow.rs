use std::borrow::Cow;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::fs::{self, OpenOptions};
use std::io::{ErrorKind, Write};
use std::ops::Range;
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result, ensure};
use rayon::prelude::*;
use sha1::{Digest, Sha1};

use crate::iso9660;
use crate::manifest::{
    DirectorySlack, EntryReference, EntryReferenceKind, EntrySectorSubheader, FileLayoutItem,
    Form1Sectors, GCDGOLD_VERSION, GapKind, GcdgoldMetadata, IsoMetadataSubheader, Manifest,
    MetadataSubheader, MetadataVolume, PathTableSubheader, Redump0x55Run, SYSTEM_AREA_SECTORS,
    SectorPatch, SystemArea, SystemAreaFinalSubheader, SystemAreaForm1Framing,
    SystemAreaSectorKind, SystemAreaSectorRun, Track, TrackMode, VolumeTerminatorSubheader,
    XaAttributeFlag, XaExtentAssets, XaLengthEncoding, decode_sector_patch, serialize_manifest,
};
use crate::raw_cd::{
    Kind, LOGICAL_BLOCK_SIZE, MODE2_DATA_SIZE, RAW_SECTOR_SIZE, SYNC, SectorProtection,
    SectorWriter, XaSubheader, XaSubmode, finalize_sector_protection, format_msf, frame_to_msf,
    parse_image, parse_msf,
};

#[derive(Debug, Clone)]
pub struct ExtractReport {
    pub sectors: u32,
    pub sha1: String,
    pub recovery_warnings: Vec<RecoveryWarning>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryCategory {
    MissingDirectoryPrefix,
    DirectoryBufferResidue,
    MalformedSystemArea,
    FilesystemHierarchy,
    InternalRawDamage,
    TerminalRawDamage,
}

impl std::fmt::Display for RecoveryCategory {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let value = match self {
            Self::MissingDirectoryPrefix => "missing-directory-prefix",
            Self::DirectoryBufferResidue => "directory-buffer-residue",
            Self::MalformedSystemArea => "malformed-system-area",
            Self::FilesystemHierarchy => "filesystem-hierarchy",
            Self::InternalRawDamage => "internal-raw-damage",
            Self::TerminalRawDamage => "terminal-raw-damage",
        };
        formatter.write_str(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryRange {
    pub first_lba: i32,
    pub last_lba: i32,
    pub first_msf: String,
    pub last_msf: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryWarning {
    pub category: RecoveryCategory,
    pub ranges: Vec<RecoveryRange>,
    pub path: Option<String>,
    pub description: String,
}

#[derive(Debug, Clone)]
pub struct BuildReport {
    pub sectors: u32,
    pub sha1: String,
    pub sha1_mismatches: Vec<Sha1Mismatch>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Sha1Target {
    Track,
    SystemArea { path: String },
    Asset { path: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sha1Mismatch {
    pub target: Sha1Target,
    pub expected: String,
    pub actual: String,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct BuildOptions {
    pub overwrite: bool,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct ExtractOptions {
    pub overwrite: bool,
}

const FORM1_DATA_SUBHEADER: XaSubheader = XaSubheader::with_submode(XaSubmode::DATA);
const SYSTEM_END_OF_FILE_SUBHEADER: XaSubheader =
    XaSubheader::with_submode(XaSubmode::DATA.union(XaSubmode::END_OF_FILE));
const PVD_SUBHEADER: XaSubheader =
    XaSubheader::with_submode(XaSubmode::END_OF_RECORD.union(XaSubmode::DATA));
const ISO_METADATA_SUBHEADER: XaSubheader = XaSubheader::with_submode(
    XaSubmode::END_OF_RECORD
        .union(XaSubmode::DATA)
        .union(XaSubmode::END_OF_FILE),
);
const FORM2_SUBHEADER: XaSubheader = XaSubheader::with_submode(XaSubmode::FORM2);
const FORM2_PAYLOAD_SIZE: usize = 2324;
const XA_FORM1_RECORD_SIZE: usize = 8 + LOGICAL_BLOCK_SIZE;
const XA_FORM2_RECORD_SIZE: usize = 8 + FORM2_PAYLOAD_SIZE;
const XA_INDEX_RECORD_SIZE: usize = size_of::<u32>();

struct RecoveredImage<'a> {
    semantic: Cow<'a, [u8]>,
    patches: Vec<SectorPatch>,
    warnings: Vec<RecoveryWarning>,
}

fn raw_track_start_frame(raw: &[u8]) -> Result<u32> {
    ensure!(raw.len() >= RAW_SECTOR_SIZE, "raw image is empty");
    parse_msf(&format!("{:02x}:{:02x}:{:02x}", raw[12], raw[13], raw[14]))
        .context("parsing track start MSF")
}

fn detect_redump_0x55(raw: &[u8]) -> Vec<Redump0x55Run> {
    if raw.is_empty() || !raw.len().is_multiple_of(RAW_SECTOR_SIZE) {
        return Vec::new();
    }
    let track_mode = raw[15];
    if !matches!(track_mode, 1 | 2) {
        return Vec::new();
    }
    let Ok(start_frame) = raw_track_start_frame(raw) else {
        return Vec::new();
    };
    let track_start_lba = i64::from(start_frame) - 150;
    let mut runs = Vec::new();
    let mut run_start = None;
    for (index, sector) in raw.chunks_exact(RAW_SECTOR_SIZE).enumerate() {
        let expected_msf = u32::try_from(index)
            .ok()
            .and_then(|index| start_frame.checked_add(index))
            .and_then(|frame| frame_to_msf(frame).ok());
        let detected = sector[..12] == SYNC
            && sector[15] == track_mode
            && expected_msf.is_some_and(|expected| sector[12..15] == expected)
            && sector[16..].iter().all(|byte| *byte == 0x55);
        if detected {
            run_start.get_or_insert(index);
        } else if let Some(start) = run_start.take() {
            let lba = track_start_lba + i64::try_from(start).expect("sector index fits i64");
            runs.push(Redump0x55Run {
                lba: i32::try_from(lba).expect("CD LBA fits i32"),
                sectors: u32::try_from(index - start).expect("sector run fits u32"),
            });
        }
    }
    if let Some(start) = run_start {
        let sector_count = raw.len() / RAW_SECTOR_SIZE;
        let lba = track_start_lba + i64::try_from(start).expect("sector index fits i64");
        runs.push(Redump0x55Run {
            lba: i32::try_from(lba).expect("CD LBA fits i32"),
            sectors: u32::try_from(sector_count - start).expect("sector run fits u32"),
        });
    }
    runs
}

fn resolve_redump_0x55_ranges(
    track_start_frame: u32,
    sector_count: usize,
    runs: &[Redump0x55Run],
) -> Result<Vec<Range<usize>>> {
    let track_start_lba = i64::from(track_start_frame) - 150;
    runs.iter()
        .map(|run| {
            let start = i64::from(run.lba) - track_start_lba;
            ensure!(
                start >= 0,
                "Redump 0x55 run at LBA {} is before track start LBA {}",
                run.lba,
                track_start_lba
            );
            let start = usize::try_from(start)?;
            let end = start
                .checked_add(usize::try_from(run.sectors)?)
                .context("Redump 0x55 run range overflow")?;
            ensure!(
                end <= sector_count,
                "Redump 0x55 run at LBA {} extends outside the {}-sector track",
                run.lba,
                sector_count
            );
            Ok(start..end)
        })
        .collect()
}

fn validate_redump_0x55_runs(runs: &[Redump0x55Run], patches: &[SectorPatch]) -> Result<()> {
    let mut previous_end = None;
    for run in runs {
        ensure!(run.sectors > 0, "Redump 0x55 run must not be empty");
        let end = i64::from(run.lba)
            .checked_add(i64::from(run.sectors))
            .context("Redump 0x55 run LBA overflow")?;
        if let Some(previous_end) = previous_end {
            ensure!(
                i64::from(run.lba) > previous_end,
                "Redump 0x55 runs must be ordered, nonoverlapping, and nonadjacent"
            );
        }
        ensure!(
            !patches.iter().any(|patch| {
                let lba = i64::from(patch.lba);
                lba >= i64::from(run.lba) && lba < end
            }),
            "Redump 0x55 run at LBA {} overlaps a raw-sector patch",
            run.lba
        );
        previous_end = Some(end);
    }
    Ok(())
}

fn install_redump_0x55_placeholders(
    raw: &mut [u8],
    track_start_frame: u32,
    track_mode: u8,
    runs: &[Redump0x55Run],
) -> Result<()> {
    let ranges = resolve_redump_0x55_ranges(track_start_frame, raw.len() / RAW_SECTOR_SIZE, runs)?;
    let mut writer = SectorWriter::new();
    for range in ranges {
        for index in range {
            let frame = track_start_frame + u32::try_from(index)?;
            let replacement = match track_mode {
                1 => writer.mode1(frame, &[0; LOGICAL_BLOCK_SIZE])?,
                2 => writer.form1(frame, FORM1_DATA_SUBHEADER, &[0; LOGICAL_BLOCK_SIZE])?,
                _ => anyhow::bail!("unsupported track mode {track_mode}"),
            };
            let start = index * RAW_SECTOR_SIZE;
            raw[start..start + RAW_SECTOR_SIZE].copy_from_slice(&replacement);
        }
    }
    Ok(())
}

fn apply_redump_0x55(raw: &mut [u8], track_start_frame: u32, runs: &[Redump0x55Run]) -> Result<()> {
    let ranges = resolve_redump_0x55_ranges(track_start_frame, raw.len() / RAW_SECTOR_SIZE, runs)?;
    for range in ranges {
        for index in range {
            let start = index * RAW_SECTOR_SIZE;
            raw[start + 16..start + RAW_SECTOR_SIZE].fill(0x55);
        }
    }
    Ok(())
}

fn sector_bytes(raw: &[u8], index: usize) -> Result<[u8; RAW_SECTOR_SIZE]> {
    let start = index
        .checked_mul(RAW_SECTOR_SIZE)
        .context("sector offset overflow")?;
    let end = start + RAW_SECTOR_SIZE;
    ensure!(end <= raw.len(), "recovery sector {index} is outside image");
    Ok(raw[start..end].try_into().expect("validated sector length"))
}

fn install_sector(raw: &mut [u8], index: usize, sector: &[u8]) -> Result<()> {
    ensure!(
        sector.len() == RAW_SECTOR_SIZE,
        "replacement sector has invalid length"
    );
    let start = index
        .checked_mul(RAW_SECTOR_SIZE)
        .context("sector offset overflow")?;
    let end = start + RAW_SECTOR_SIZE;
    ensure!(end <= raw.len(), "recovery sector {index} is outside image");
    raw[start..end].copy_from_slice(sector);
    Ok(())
}

fn rewrite_form1_payload(
    raw: &mut [u8],
    start_frame: u32,
    index: usize,
    edit: impl FnOnce(&mut [u8; LOGICAL_BLOCK_SIZE]) -> Result<()>,
) -> Result<()> {
    let source = sector_bytes(raw, index)?;
    ensure!(
        source[15] == 2,
        "recovered Form 1 sector {index} is not Mode 2"
    );
    let subheader = XaSubheader::from(<[u8; 4]>::try_from(&source[16..20])?);
    let subheader_copy = XaSubheader::from(<[u8; 4]>::try_from(&source[20..24])?);
    ensure!(
        !subheader
            .submode
            .contains(crate::raw_cd::XaSubmodeFlag::Form2)
            && !subheader_copy
                .submode
                .contains(crate::raw_cd::XaSubmodeFlag::Form2),
        "recovered sector {index} is not Form 1"
    );
    let mut payload: [u8; LOGICAL_BLOCK_SIZE] = source[24..2072].try_into()?;
    edit(&mut payload)?;
    let replacement = SectorWriter::new().form1_with_subheaders(
        start_frame + u32::try_from(index)?,
        subheader,
        subheader_copy,
        &payload,
    )?;
    install_sector(raw, index, &replacement)
}

fn repair_missing_directory_prefix(
    payload: &mut [u8; LOGICAL_BLOCK_SIZE],
    extent: u32,
) -> Result<()> {
    ensure!(
        payload[2040..].iter().all(|byte| *byte == 0),
        "missing-prefix recovery would discard nonzero bytes"
    );
    let mut prefix = [0_u8; 8];
    prefix[0] = 48;
    prefix[2..6].copy_from_slice(&extent.to_le_bytes());
    prefix[6..8].copy_from_slice(&extent.to_be_bytes()[..2]);
    ensure!(
        payload[..2] == extent.to_be_bytes()[2..]
            && payload[40] >= 34
            && usize::from(payload[40]) <= LOGICAL_BLOCK_SIZE - 40,
        "missing-prefix directory shape does not match the approved corruption"
    );
    payload.copy_within(..2040, 8);
    payload[..8].copy_from_slice(&prefix);
    Ok(())
}

fn clear_directory_residue(payload: &mut [u8; LOGICAL_BLOCK_SIZE], valid_end: usize) -> Result<()> {
    ensure!(
        valid_end <= payload.len(),
        "directory valid boundary is outside its logical block"
    );
    ensure!(
        payload[valid_end..].iter().any(|byte| *byte != 0),
        "directory-residue recovery found no residue"
    );
    payload[valid_end..].fill(0);
    Ok(())
}

fn replace_with_form1_placeholder(
    raw: &mut [u8],
    start_frame: u32,
    index: usize,
    subheader: XaSubheader,
) -> Result<()> {
    let replacement = SectorWriter::new().form1(
        start_frame + u32::try_from(index)?,
        subheader,
        &[0; LOGICAL_BLOCK_SIZE],
    )?;
    install_sector(raw, index, &replacement)
}

fn replace_with_form2_placeholder(
    raw: &mut [u8],
    start_frame: u32,
    index: usize,
    subheader: XaSubheader,
    computed_edc: bool,
) -> Result<()> {
    let replacement = SectorWriter::new().form2(
        start_frame + u32::try_from(index)?,
        subheader,
        &[0; FORM2_PAYLOAD_SIZE],
        computed_edc,
    )?;
    install_sector(raw, index, &replacement)
}

fn rewrite_form2_payload(
    raw: &mut [u8],
    start_frame: u32,
    index: usize,
    computed_edc: bool,
) -> Result<()> {
    let source = sector_bytes(raw, index)?;
    ensure!(
        source[15] == 2,
        "recovered Form 2 sector {index} is not Mode 2"
    );
    let subheader = XaSubheader::from(<[u8; 4]>::try_from(&source[16..20])?);
    let subheader_copy = XaSubheader::from(<[u8; 4]>::try_from(&source[20..24])?);
    ensure!(
        subheader
            .submode
            .contains(crate::raw_cd::XaSubmodeFlag::Form2)
            && subheader_copy
                .submode
                .contains(crate::raw_cd::XaSubmodeFlag::Form2),
        "recovered sector {index} is not Form 2"
    );
    let replacement = SectorWriter::new().form2_with_subheaders(
        start_frame + u32::try_from(index)?,
        subheader,
        subheader_copy,
        &source[24..2348],
        computed_edc,
    )?;
    install_sector(raw, index, &replacement)
}

fn replace_with_xa_gap(raw: &mut [u8], start_frame: u32, index: usize) -> Result<()> {
    let replacement =
        SectorWriter::new().xa_gap(start_frame + u32::try_from(index)?, XaSubheader::default())?;
    install_sector(raw, index, &replacement)
}

fn nearby_form2_framing(raw: &[u8], index: usize) -> Result<(XaSubheader, bool)> {
    for distance in 1..=32 {
        for candidate in [index.checked_sub(distance), index.checked_add(distance)] {
            let Some(candidate) = candidate else {
                continue;
            };
            let Ok(bytes) = sector_bytes(raw, candidate) else {
                continue;
            };
            if bytes[..12] != crate::raw_cd::SYNC
                || bytes[15] != 2
                || bytes[16..20] != bytes[20..24]
            {
                continue;
            }
            let subheader = XaSubheader::from(<[u8; 4]>::try_from(&bytes[16..20])?);
            if !subheader
                .submode
                .contains(crate::raw_cd::XaSubmodeFlag::Form2)
            {
                continue;
            }
            let parsed = parse_image(&bytes)
                .with_context(|| format!("parsing nearby Form 2 sector {candidate}"))?
                .1
                .remove(0);
            return Ok((subheader, parsed.form2_edc_valid));
        }
    }
    anyhow::bail!("no intact nearby Form 2 framing for damaged sector {index}")
}

fn warning_ranges(start_frame: u32, indices: &BTreeSet<usize>) -> Result<Vec<RecoveryRange>> {
    let track_start_lba = i64::from(start_frame) - 150;
    let mut ranges = Vec::new();
    let mut iterator = indices.iter().copied();
    let Some(mut first) = iterator.next() else {
        return Ok(ranges);
    };
    let mut last = first;
    for index in iterator {
        if index == last + 1 {
            last = index;
            continue;
        }
        ranges.push(recovery_range(track_start_lba, first, last)?);
        first = index;
        last = index;
    }
    ranges.push(recovery_range(track_start_lba, first, last)?);
    Ok(ranges)
}

fn recovery_range(track_start_lba: i64, first: usize, last: usize) -> Result<RecoveryRange> {
    let first_lba = track_start_lba + i64::try_from(first)?;
    let last_lba = track_start_lba + i64::try_from(last)?;
    ensure!(
        first_lba >= -150 && last_lba <= i64::from(i32::MAX),
        "recovery LBA is outside supported range"
    );
    Ok(RecoveryRange {
        first_lba: i32::try_from(first_lba)?,
        last_lba: i32::try_from(last_lba)?,
        first_msf: format_msf(u32::try_from(first_lba + 150)?)?,
        last_msf: format_msf(u32::try_from(last_lba + 150)?)?,
    })
}

fn finish_recovery(
    source: &[u8],
    semantic: Vec<u8>,
    start_frame: u32,
    affected: BTreeSet<usize>,
    category: RecoveryCategory,
    path: Option<&str>,
    description: &str,
) -> Result<RecoveredImage<'static>> {
    let track_start_lba = i64::from(start_frame) - 150;
    let patches = affected
        .iter()
        .map(|index| {
            let lba = track_start_lba + i64::try_from(*index)?;
            Ok(SectorPatch {
                lba: i32::try_from(lba)?,
                hex: crate::manifest::format_sector_patch_hex(&sector_bytes(source, *index)?),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let warnings = vec![RecoveryWarning {
        category,
        ranges: warning_ranges(start_frame, &affected)?,
        path: path.map(str::to_owned),
        description: description.to_owned(),
    }];
    Ok(RecoveredImage {
        semantic: Cow::Owned(semantic),
        patches,
        warnings,
    })
}

fn no_recovery(source: &[u8]) -> RecoveredImage<'_> {
    RecoveredImage {
        semantic: Cow::Borrowed(source),
        patches: Vec::new(),
        warnings: Vec::new(),
    }
}

fn known_recovery_source(source_sha1: &str) -> bool {
    matches!(
        source_sha1,
        "aad68c8551ef04f30ea7f4c7f495fb78d0f378c5"
            | "4eca51973170275e020e8a1661a4a9110e4456a1"
            | "484e5fdec33dbe2186b0d467cb4f012dc725e86a"
            | "4d9f3ece1dc52848e29a64b8cf57c2e8ca98e8d1"
            | "ca9f57992d2af0cea3157a304a26d03cb1ebc7b6"
            | "25146a5b41f55883368c6d3de2d11b073044e205"
            | "5305263db8cc676224c35389933f9e2333c165b6"
            | "e91fe72bf2ff4a7ddef3056e75c330999df64cfb"
            | "352a3c20efd42878238dcc56a9ed1d5432ac0655"
            | "1c18a7893a71ecc5c06d84e55b8ef8a8076933fc"
            | "34477c1d770381e78e600cdcf92dab95b54c3db9"
            | "f6e02bea547536abb20dc922fd12b395588ec580"
            | "cff9183875d08ed7377ff36a4a42f1a0e2f86fe0"
            | "001392017ae58fd29c8cf9ec929a6a25f30d7a6f"
            | "5f6689009bdd930b1b1641e1a6b505e1ab95a9b8"
            | "1277d46d983b237659190938c9b41014c2c7aa2f"
            | "36510ababe9e2252fa5fc426973aa703794a77b4"
            | "3eb37f759827900432542a2c1e834fe22749e77b"
            | "53d220058ff61235f3b512d4201510777aee574a"
            | "66f0fd4b1703fa69d42c8694a68ba1965b26a538"
            | "0eade90349db8c4f9c6d0626089b02ebf577b944"
            | "ba46a36b5728d89a5aae5fe220066f90feed2200"
            | "00b595095e26108d0e07d76492a11aaf3f71ccf1"
            | "f877c53d420d571694e38d4af4e9f4ea3e5f8b7e"
            | "0ec8e3b093291ac7ce3af2bb62beda5228f09435"
            | "6bbfe335bc7be562f9f712f6a5ebfdf0e0b6d28b"
            | "b4d0f2628dc070a56f9651f22663efe07e854e6f"
    )
}

fn recover_known_corruption<'a>(source_sha1: &str, source: &'a [u8]) -> Result<RecoveredImage<'a>> {
    if !known_recovery_source(source_sha1) {
        return Ok(no_recovery(source));
    }
    let start_frame = raw_track_start_frame(source)?;
    let mut semantic = source.to_vec();
    let mut affected = BTreeSet::new();

    let missing_prefix = match source_sha1 {
        "aad68c8551ef04f30ea7f4c7f495fb78d0f378c5"
        | "4eca51973170275e020e8a1661a4a9110e4456a1"
        | "484e5fdec33dbe2186b0d467cb4f012dc725e86a"
        | "4d9f3ece1dc52848e29a64b8cf57c2e8ca98e8d1" => Some(300),
        "ca9f57992d2af0cea3157a304a26d03cb1ebc7b6" => Some(2180),
        "00b595095e26108d0e07d76492a11aaf3f71ccf1"
        | "f877c53d420d571694e38d4af4e9f4ea3e5f8b7e"
        | "0ec8e3b093291ac7ce3af2bb62beda5228f09435" => Some(14515),
        _ => None,
    };
    if let Some(index) = missing_prefix {
        rewrite_form1_payload(&mut semantic, start_frame, index, |payload| {
            repair_missing_directory_prefix(payload, u32::try_from(index)?)
        })?;
        let repaired = sector_bytes(&semantic, index)?;
        let directory_subheader = XaSubheader::from([1, 0, 0x89, 0]);
        let replacement = SectorWriter::new().form1(
            start_frame + u32::try_from(index)?,
            directory_subheader,
            &repaired[24..2072],
        )?;
        install_sector(&mut semantic, index, &replacement)?;
        affected.insert(index);
        return finish_recovery(
            source,
            semantic,
            start_frame,
            affected,
            RecoveryCategory::MissingDirectoryPrefix,
            Some("CDROM"),
            "reconstructed the uniquely implied eight-byte dot-record prefix in the semantic directory",
        );
    }

    let residue = match source_sha1 {
        "25146a5b41f55883368c6d3de2d11b073044e205"
        | "5305263db8cc676224c35389933f9e2333c165b6"
        | "f6e02bea547536abb20dc922fd12b395588ec580"
        | "b4d0f2628dc070a56f9651f22663efe07e854e6f" => Some((23, 1024, "A")),
        "0eade90349db8c4f9c6d0626089b02ebf577b944" => Some((25, 1536, "ART/TEXT")),
        _ => None,
    };
    if let Some((index, valid_end, path)) = residue {
        rewrite_form1_payload(&mut semantic, start_frame, index, |payload| {
            clear_directory_residue(payload, valid_end)
        })?;
        affected.insert(index);
        return finish_recovery(
            source,
            semantic,
            start_frame,
            affected,
            RecoveryCategory::DirectoryBufferResidue,
            Some(path),
            "stopped at the independently verified record boundary and canonicalized the non-record buffer residue",
        );
    }
    if source_sha1 == "1277d46d983b237659190938c9b41014c2c7aa2f" {
        for index in [31, 33] {
            rewrite_form1_payload(&mut semantic, start_frame, index, |payload| {
                ensure!(
                    payload.iter().any(|byte| *byte != 0),
                    "MLB directory-residue sector is already empty"
                );
                payload.fill(0);
                Ok(())
            })?;
            affected.insert(index);
        }
        return finish_recovery(
            source,
            semantic,
            start_frame,
            affected,
            RecoveryCategory::DirectoryBufferResidue,
            Some("MLB2/FE_ART/LOADING*"),
            "stopped after the valid first blocks of both loading directories and canonicalized their independently verified residue blocks",
        );
    }

    if matches!(
        source_sha1,
        "e91fe72bf2ff4a7ddef3056e75c330999df64cfb"
            | "001392017ae58fd29c8cf9ec929a6a25f30d7a6f"
            | "53d220058ff61235f3b512d4201510777aee574a"
            | "66f0fd4b1703fa69d42c8694a68ba1965b26a538"
    ) {
        let next = parse_image(&sector_bytes(source, 13)?)?.1.remove(0);
        ensure!(
            next.kind == Kind::Form2,
            "approved malformed system area is not followed by Form 2"
        );
        replace_with_form2_placeholder(
            &mut semantic,
            start_frame,
            12,
            FORM2_SUBHEADER,
            next.form2_edc_valid,
        )?;
        affected.insert(12);
        return finish_recovery(
            source,
            semantic,
            start_frame,
            affected,
            RecoveryCategory::MalformedSystemArea,
            None,
            "used a canonical empty Form 2 sector in the fixed system-area slot",
        );
    }

    if source_sha1 == "352a3c20efd42878238dcc56a9ed1d5432ac0655" {
        for index in [
            248495, 248630, 320933, 321466, 324265, 325679, 325872, 325934, 326148, 326276,
        ] {
            rewrite_form1_payload(&mut semantic, start_frame, index, |_| Ok(()))?;
            affected.insert(index);
        }
        let parsed = parse_image(&semantic)
            .context("classifying Biohazard sectors after sync/protection recovery")?
            .1;
        let valid_form2 = parsed
            .iter()
            .filter(|sector| sector.kind == Kind::Form2 && sector.form2_edc_valid)
            .count();
        let invalid_form2 = parsed
            .iter()
            .enumerate()
            .filter_map(|(index, sector)| {
                (sector.kind == Kind::Form2 && !sector.form2_edc_valid).then_some(index)
            })
            .collect::<Vec<_>>();
        ensure!(
            valid_form2 > invalid_form2.len() && !invalid_form2.is_empty(),
            "Biohazard Form 2 protection damage no longer matches the approved sparse shape"
        );
        for index in invalid_form2 {
            rewrite_form2_payload(&mut semantic, start_frame, index, true)?;
            affected.insert(index);
        }
        return finish_recovery(
            source,
            semantic,
            start_frame,
            affected,
            RecoveryCategory::InternalRawDamage,
            None,
            "retained every proven payload window and normalized the damaged framing, protection, and local Form 2 EDC convention in the semantic view",
        );
    }

    if source_sha1 == "6bbfe335bc7be562f9f712f6a5ebfdf0e0b6d28b" {
        rewrite_form1_payload(&mut semantic, start_frame, 232531, |_| Ok(()))?;
        let framing =
            XaSubheader::from(<[u8; 4]>::try_from(&sector_bytes(source, 232534)?[16..20])?);
        ensure!(
            !framing
                .submode
                .contains(crate::raw_cd::XaSubmodeFlag::Form2),
            "Tony Hawk recovery lost its proven Form 1 cadence"
        );
        replace_with_form1_placeholder(&mut semantic, start_frame, 232532, framing)?;
        let (form2, computed_edc) = nearby_form2_framing(source, 232533)?;
        replace_with_form2_placeholder(&mut semantic, start_frame, 232533, form2, computed_edc)?;
        affected.extend([232531, 232532, 232533]);
        return finish_recovery(
            source,
            semantic,
            start_frame,
            affected,
            RecoveryCategory::InternalRawDamage,
            Some("SUICIDE.STR"),
            "retained the surviving payload and used deterministic zero payloads for two cadence-proven but unrecoverable stream slots",
        );
    }

    let terminal = match source_sha1 {
        "34477c1d770381e78e600cdcf92dab95b54c3db9" => Some(&[4614][..]),
        "cff9183875d08ed7377ff36a4a42f1a0e2f86fe0" => Some(&[262259, 262260][..]),
        "5f6689009bdd930b1b1641e1a6b505e1ab95a9b8" => Some(&[80630, 80631][..]),
        "ba46a36b5728d89a5aae5fe220066f90feed2200" => Some(&[89894][..]),
        _ => None,
    };
    if let Some(indices) = terminal {
        for index in indices {
            replace_with_xa_gap(&mut semantic, start_frame, *index)?;
            affected.insert(*index);
        }
        return finish_recovery(
            source,
            semantic,
            start_frame,
            affected,
            RecoveryCategory::TerminalRawDamage,
            None,
            "placed canonical XA-gap sectors in the proven terminal gap slots",
        );
    }

    if source_sha1 == "1c18a7893a71ecc5c06d84e55b8ef8a8076933fc" {
        for (indices, parent_extent) in [(26..=41, 21_u32), (42..=54, 22), (55..=65, 23)] {
            let parent_time =
                sector_bytes(source, usize::try_from(parent_extent)?)?[24 + 18..24 + 25].to_vec();
            for index in indices {
                rewrite_form1_payload(&mut semantic, start_frame, index, |payload| {
                    let parent_offset = usize::from(payload[0]);
                    ensure!(
                        parent_offset >= 34
                            && parent_offset + 34 <= payload.len()
                            && payload[parent_offset + 32] == 1
                            && payload[parent_offset + 33] == 1
                            && u32::from_le_bytes(
                                payload[parent_offset + 2..parent_offset + 6].try_into()?
                            ) == 20,
                        "Blood Lines parent-record shape changed"
                    );
                    payload[parent_offset + 2..parent_offset + 6]
                        .copy_from_slice(&parent_extent.to_le_bytes());
                    payload[parent_offset + 6..parent_offset + 10]
                        .copy_from_slice(&parent_extent.to_be_bytes());
                    payload[parent_offset + 18..parent_offset + 25].copy_from_slice(&parent_time);
                    Ok(())
                })?;
                affected.insert(index);
            }
        }
        return finish_recovery(
            source,
            semantic,
            start_frame,
            affected,
            RecoveryCategory::FilesystemHierarchy,
            Some("DATA/*"),
            "recovered the malformed parent records from the valid DATA hierarchy and path-table evidence",
        );
    }

    if source_sha1 == "36510ababe9e2252fa5fc426973aa703794a77b4" {
        rewrite_form1_payload(&mut semantic, start_frame, 22, |payload| {
            let offset = 328;
            ensure!(
                payload[offset + 33..offset + 38] == *b"DUMMY"
                    && u32::from_le_bytes(payload[offset + 10..offset + 14].try_into()?) == 2048,
                "OverBlood DUMMY record shape changed"
            );
            payload[offset + 10..offset + 18].fill(0);
            Ok(())
        })?;
        affected.insert(22);
        return finish_recovery(
            source,
            semantic,
            start_frame,
            affected,
            RecoveryCategory::FilesystemHierarchy,
            Some("DUMMY"),
            "retained the childless path-table node as a zero-length reference and excluded its non-directory payload from hierarchy traversal",
        );
    }

    if source_sha1 == "3eb37f759827900432542a2c1e834fe22749e77b" {
        rewrite_form1_payload(&mut semantic, start_frame, 16, |payload| {
            ensure!(
                u32::from_le_bytes(payload[132..136].try_into()?) == 268
                    && u32::from_be_bytes(payload[136..140].try_into()?) == 268,
                "PoPoRoGue path-table size changed"
            );
            payload[132..136].copy_from_slice(&256_u32.to_le_bytes());
            payload[136..140].copy_from_slice(&256_u32.to_be_bytes());
            Ok(())
        })?;
        affected.insert(16);
        for index in 18..=21 {
            rewrite_form1_payload(&mut semantic, start_frame, index, |payload| {
                ensure!(
                    payload[256] == 4 && payload[264..268] == *b"MS00",
                    "PoPoRoGue phantom path-table node changed"
                );
                payload[256..268].fill(0);
                Ok(())
            })?;
            affected.insert(index);
        }
        return finish_recovery(
            source,
            semantic,
            start_frame,
            affected,
            RecoveryCategory::FilesystemHierarchy,
            Some("PCHR/MCHR/MS00"),
            "excluded the impossible path-table-only phantom node while retaining the reachable directory tree",
        );
    }

    Ok(no_recovery(source))
}

fn apply_sector_patches(
    raw: &mut [u8],
    track_start_frame: u32,
    patches: &[SectorPatch],
) -> Result<()> {
    ensure!(
        raw.len().is_multiple_of(RAW_SECTOR_SIZE),
        "canonical image size is not a multiple of 2352 bytes"
    );
    let track_start_lba = i64::from(track_start_frame) - 150;
    let sector_count = raw.len() / RAW_SECTOR_SIZE;
    let mut previous_lba = None;
    for patch in patches {
        if let Some(previous_lba) = previous_lba {
            ensure!(
                patch.lba > previous_lba,
                "patch LBAs must be strictly increasing; LBA {} follows {}",
                patch.lba,
                previous_lba
            );
        }
        previous_lba = Some(patch.lba);
        let sector_index = i64::from(patch.lba) - track_start_lba;
        ensure!(
            sector_index >= 0,
            "patch LBA {} is before track start LBA {}",
            patch.lba,
            track_start_lba
        );
        let index = usize::try_from(sector_index)?;
        ensure!(
            index < sector_count,
            "patch LBA {} is outside the {}-sector track starting at LBA {}",
            patch.lba,
            sector_count,
            track_start_lba
        );
        let replacement = decode_sector_patch(patch)?;
        let start = index * RAW_SECTOR_SIZE;
        raw[start..start + RAW_SECTOR_SIZE].copy_from_slice(&replacement);
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct XaSidecarRecord {
    subheader: XaSubheader,
    subheader_copy: XaSubheader,
    payload: [u8; FORM2_PAYLOAD_SIZE],
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum XaExtentSector {
    Form1(Box<XaForm1Sector>),
    Form2(Box<XaSidecarRecord>),
    XaGap,
}

struct XaSidecarAssets {
    form1: Vec<u8>,
    form2: Vec<u8>,
    form2_index: Vec<u8>,
    gap_index: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct XaForm1Sector {
    subheader: XaSubheader,
    subheader_copy: XaSubheader,
    payload: [u8; LOGICAL_BLOCK_SIZE],
}

fn encode_xa_form1_record(sector: &crate::raw_cd::ParsedSector) -> Result<Vec<u8>> {
    ensure!(
        sector.kind == Kind::Form1,
        "XA1 record source is not Form 1"
    );
    let mut result = Vec::with_capacity(XA_FORM1_RECORD_SIZE);
    result.extend_from_slice(&<[u8; 4]>::from(sector.subheader));
    result.extend_from_slice(&<[u8; 4]>::from(sector.subheader_copy));
    result.extend_from_slice(sector.payload());
    Ok(result)
}

fn encode_xa_form2_record(sector: &crate::raw_cd::ParsedSector) -> Result<Vec<u8>> {
    ensure!(
        sector.kind == Kind::Form2,
        "XA2 record source is not Form 2"
    );
    let mut result = Vec::with_capacity(XA_FORM2_RECORD_SIZE);
    result.extend_from_slice(&<[u8; 4]>::from(sector.subheader));
    result.extend_from_slice(&<[u8; 4]>::from(sector.subheader_copy));
    result.extend_from_slice(sector.payload());
    Ok(result)
}

fn parse_xa_form1_records(bytes: &[u8]) -> Result<Vec<XaForm1Sector>> {
    ensure!(
        bytes.len().is_multiple_of(XA_FORM1_RECORD_SIZE),
        "XA1 asset size must be a multiple of {XA_FORM1_RECORD_SIZE} bytes"
    );
    bytes
        .chunks_exact(XA_FORM1_RECORD_SIZE)
        .enumerate()
        .map(|(index, chunk)| {
            let subheader = XaSubheader::from(<[u8; 4]>::try_from(&chunk[..4])?);
            ensure!(
                !subheader
                    .submode
                    .contains(crate::raw_cd::XaSubmodeFlag::Form2),
                "XA1 record {index} is marked Form 2"
            );
            Ok(XaForm1Sector {
                subheader,
                subheader_copy: XaSubheader::from(<[u8; 4]>::try_from(&chunk[4..8])?),
                payload: chunk[8..].try_into()?,
            })
        })
        .collect()
}

fn parse_xa_form2_records(bytes: &[u8]) -> Result<Vec<XaSidecarRecord>> {
    ensure!(
        bytes.len().is_multiple_of(XA_FORM2_RECORD_SIZE),
        "XA2 asset size must be a multiple of {XA_FORM2_RECORD_SIZE} bytes"
    );
    bytes
        .chunks_exact(XA_FORM2_RECORD_SIZE)
        .enumerate()
        .map(|(index, chunk)| {
            let subheader = XaSubheader::from(<[u8; 4]>::try_from(&chunk[..4])?);
            ensure!(
                subheader
                    .submode
                    .contains(crate::raw_cd::XaSubmodeFlag::Form2),
                "XA2 record {index} is not marked Form 2"
            );
            Ok(XaSidecarRecord {
                subheader,
                subheader_copy: XaSubheader::from(<[u8; 4]>::try_from(&chunk[4..8])?),
                payload: chunk[8..].try_into()?,
            })
        })
        .collect()
}

fn encode_xa_index(indices: &[u32]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(indices.len() * XA_INDEX_RECORD_SIZE);
    for index in indices {
        bytes.extend_from_slice(&index.to_le_bytes());
    }
    bytes
}

fn parse_xa_index(bytes: &[u8]) -> Result<Vec<u32>> {
    parse_xa_positions(bytes, "XAI")
}

fn parse_xa_gap_index(bytes: &[u8]) -> Result<Vec<u32>> {
    parse_xa_positions(bytes, "XAG")
}

fn parse_xa_positions(bytes: &[u8], label: &str) -> Result<Vec<u32>> {
    ensure!(
        bytes.len().is_multiple_of(XA_INDEX_RECORD_SIZE),
        "{label} asset size must be a multiple of {XA_INDEX_RECORD_SIZE} bytes"
    );
    let indices = bytes
        .chunks_exact(XA_INDEX_RECORD_SIZE)
        .map(|chunk| Ok(u32::from_le_bytes(chunk.try_into()?)))
        .collect::<Result<Vec<_>>>()?;
    ensure!(
        indices.windows(2).all(|pair| pair[0] < pair[1]),
        "{label} sector indices must be strictly increasing"
    );
    Ok(indices)
}

fn multiplex_xa_extent(
    form1: &[u8],
    form2: &[u8],
    index: &[u8],
    gap_index: &[u8],
) -> Result<Vec<XaExtentSector>> {
    let form1 = parse_xa_form1_records(form1)?;
    let form2 = parse_xa_form2_records(form2)?;
    let indices = parse_xa_index(index)?;
    let gap_indices = parse_xa_gap_index(gap_index)?;
    ensure!(
        indices.len() == form2.len(),
        "XAI record count does not match XA2 record count"
    );
    let sector_count = form1.len() + form2.len() + gap_indices.len();
    ensure!(
        indices
            .last()
            .is_none_or(|index| usize::try_from(*index).is_ok_and(|value| value < sector_count)),
        "XAI sector index is outside the interleaved extent"
    );
    ensure!(
        gap_indices
            .last()
            .is_none_or(|index| usize::try_from(*index).is_ok_and(|value| value < sector_count)),
        "XAG sector index is outside the interleaved extent"
    );
    ensure!(
        indices
            .iter()
            .all(|index| gap_indices.binary_search(index).is_err()),
        "XAI and XAG sector indices overlap"
    );
    let mut result = Vec::with_capacity(sector_count);
    let mut form1 = form1.into_iter();
    let mut form2 = form2.into_iter();
    let mut indices = indices.into_iter().peekable();
    let mut gap_indices = gap_indices.into_iter().peekable();
    for sector_index in 0..sector_count {
        if gap_indices
            .peek()
            .is_some_and(|index| usize::try_from(*index) == Ok(sector_index))
        {
            gap_indices.next();
            result.push(XaExtentSector::XaGap);
        } else if indices
            .peek()
            .is_some_and(|index| usize::try_from(*index) == Ok(sector_index))
        {
            indices.next();
            result.push(XaExtentSector::Form2(Box::new(
                form2.next().context("XAI has too many Form 2 positions")?,
            )));
        } else {
            result.push(XaExtentSector::Form1(Box::new(
                form1
                    .next()
                    .context("XAI leaves too many Form 1 positions")?,
            )));
        }
    }
    ensure!(indices.next().is_none(), "XAI position was not consumed");
    ensure!(
        gap_indices.next().is_none(),
        "XAG position was not consumed"
    );
    ensure!(form1.next().is_none(), "XA1 record was not consumed");
    ensure!(form2.next().is_none(), "XA2 record was not consumed");
    Ok(result)
}

fn demultiplex_xa_extent(
    sectors: &[crate::raw_cd::ParsedSector],
    form2_edc: bool,
) -> Result<XaSidecarAssets> {
    let mut form1 = Vec::new();
    let mut form2 = Vec::new();
    let mut indices = Vec::new();
    let mut gap_indices = Vec::new();
    for (index, sector) in sectors.iter().enumerate() {
        match sector.kind {
            Kind::Mode1 | Kind::Mode1Gap => {
                anyhow::bail!("Mode 1 sector inside interleaved XA extent at sector {index}")
            }
            Kind::Form1 => {
                form1.extend_from_slice(&encode_xa_form1_record(sector)?);
            }
            Kind::Form2 => {
                ensure!(
                    sector_follows_form2_edc_policy(sector, form2_edc),
                    "interleaved Form 2 sector {index} does not follow track Form 2 EDC policy"
                );
                form2.extend_from_slice(&encode_xa_form2_record(sector)?);
                indices.push(u32::try_from(index)?);
            }
            Kind::XaGap => {
                ensure!(
                    sector.subheader == XaSubheader::default()
                        && sector.subheader_copy == XaSubheader::default()
                        && !sector.noncompliant_ecc,
                    "noncanonical XA gap inside interleaved extent at sector {index}"
                );
                gap_indices.push(u32::try_from(index)?);
            }
            Kind::RawZero => {
                anyhow::bail!("raw-zero sector inside interleaved XA extent at sector {index}")
            }
        }
    }
    let index = encode_xa_index(&indices);
    let gap_index = encode_xa_index(&gap_indices);
    let reconstructed = multiplex_xa_extent(&form1, &form2, &index, &gap_index)?;
    ensure!(
        reconstructed.len() == sectors.len(),
        "indexed XA assets do not reproduce the source extent length"
    );
    for (index, (source, authored)) in sectors.iter().zip(&reconstructed).enumerate() {
        match (source.kind, authored) {
            (Kind::Form1, XaExtentSector::Form1(form1)) => ensure!(
                source.subheader == form1.subheader
                    && source.subheader_copy == form1.subheader_copy
                    && source.payload() == form1.payload,
                "mixed XA Form 1 framing differs at sector {index}"
            ),
            (Kind::Form2, XaExtentSector::Form2(form2)) => ensure!(
                source.subheader == form2.subheader
                    && source.subheader_copy == form2.subheader_copy
                    && source.payload() == form2.payload,
                "mixed XA Form 2 framing differs at sector {index}"
            ),
            (Kind::XaGap, XaExtentSector::XaGap) => {}
            _ => anyhow::bail!("mixed XA sector order differs at sector {index}"),
        }
    }
    Ok(XaSidecarAssets {
        form1,
        form2,
        form2_index: index,
        gap_index,
    })
}

fn write_xa_extent_sector(
    raw: &mut Vec<u8>,
    protections: &mut Vec<SectorProtection>,
    writer: &mut SectorWriter,
    frame: u32,
    sector: &XaExtentSector,
    form2_edc: bool,
) -> Result<()> {
    match sector {
        XaExtentSector::Form1(form1) => {
            append_sector_draft(
                raw,
                protections,
                writer.form1_with_subheaders_draft(
                    frame,
                    form1.subheader,
                    form1.subheader_copy,
                    &form1.payload,
                )?,
                SectorProtection::Mode2Form1,
            );
        }
        XaExtentSector::Form2(record) => {
            append_sector_draft(
                raw,
                protections,
                writer.form2_with_subheaders_draft(
                    frame,
                    record.subheader,
                    record.subheader_copy,
                    &record.payload,
                )?,
                SectorProtection::Mode2Form2 {
                    computed_edc: form2_edc,
                },
            );
        }
        XaExtentSector::XaGap => {
            append_sector_draft(
                raw,
                protections,
                writer.xa_gap(frame, XaSubheader::default())?,
                SectorProtection::None,
            );
        }
    }
    Ok(())
}

fn append_sector_draft(
    raw: &mut Vec<u8>,
    protections: &mut Vec<SectorProtection>,
    sector: Vec<u8>,
    protection: SectorProtection,
) {
    debug_assert_eq!(sector.len(), RAW_SECTOR_SIZE);
    raw.extend_from_slice(&sector);
    protections.push(protection);
}

fn finalize_track_protection(raw: &mut [u8], protections: &[SectorProtection]) -> Result<()> {
    ensure!(
        raw.len().is_multiple_of(RAW_SECTOR_SIZE),
        "authored raw track size is not a multiple of 2352 bytes"
    );
    ensure!(
        raw.len() / RAW_SECTOR_SIZE == protections.len(),
        "authored raw sector and protection policy counts differ"
    );
    raw.par_chunks_exact_mut(RAW_SECTOR_SIZE)
        .zip(protections.par_iter().copied())
        .enumerate()
        .map(|(index, (sector, protection))| {
            finalize_sector_protection(sector, protection)
                .with_context(|| format!("finalizing protection at sector {index}"))
        })
        .collect::<Vec<_>>()
        .into_iter()
        .collect::<Result<Vec<_>>>()?;
    Ok(())
}

fn sector_follows_form2_edc_policy(sector: &crate::raw_cd::ParsedSector, computed: bool) -> bool {
    if computed {
        sector.form2_edc_valid
    } else {
        !sector.form2_edc_valid && sector.bytes[2348..2352] == [0; 4]
    }
}

fn entry_uses_xa_sidecar(entry: &crate::manifest::Entry) -> bool {
    entry
        .xa
        .as_ref()
        .is_some_and(|xa| xa.form1.is_some() || xa.length_encoding != XaLengthEncoding::Logical2048)
        || entry
            .xa
            .as_ref()
            .and_then(|xa| xa.attributes)
            .is_some_and(|attributes| {
                attributes.contains(XaAttributeFlag::Interleaved)
                    || attributes.contains(XaAttributeFlag::Mode2Form2)
            })
}

fn entry_declares_form2_xa(entry: &crate::manifest::Entry) -> bool {
    entry
        .xa
        .as_ref()
        .and_then(|xa| xa.attributes)
        .is_some_and(|attributes| {
            attributes.contains(XaAttributeFlag::Interleaved)
                || attributes.contains(XaAttributeFlag::Mode2Form2)
        })
}

fn placement_range(extent: u32, length: u32) -> Result<Range<usize>> {
    let start = usize::try_from(extent)?;
    let blocks = usize::try_from(length)?.div_ceil(LOGICAL_BLOCK_SIZE);
    Ok(start..start.checked_add(blocks).context("extent overflow")?)
}

fn detect_mode2_2336_file_lengths(
    sector_count: usize,
    parsed_iso: &mut iso9660::ParsedIso,
) -> Result<()> {
    let sector_count = u32::try_from(sector_count)?;
    let mut boundaries = parsed_iso
        .files
        .iter()
        .map(|file| file.extent)
        .chain(
            parsed_iso
                .directories
                .iter()
                .chain(&parsed_iso.supplementary_directories)
                .map(|directory| directory.extent),
        )
        .chain([sector_count])
        .collect::<Vec<_>>();
    boundaries.sort_unstable();
    boundaries.dedup();
    let entry_indices = parsed_iso
        .manifest
        .entries
        .iter()
        .enumerate()
        .map(|(index, entry)| (entry.path.clone(), index))
        .collect::<HashMap<_, _>>();

    for file in &mut parsed_iso.files {
        if file.length == 0 || !usize::try_from(file.length)?.is_multiple_of(MODE2_DATA_SIZE) {
            continue;
        }
        let physical_blocks = usize::try_from(file.length)? / MODE2_DATA_SIZE;
        let physical_blocks = u32::try_from(physical_blocks)?;
        let physical_end = file
            .extent
            .checked_add(physical_blocks)
            .context("mode2_2336 physical extent overflow")?;
        let logical_end = file
            .extent
            .checked_add(file.length.div_ceil(LOGICAL_BLOCK_SIZE as u32))
            .context("ISO file extent overflow")?;
        let Some(next_boundary) = boundaries
            .iter()
            .copied()
            .find(|boundary| *boundary > file.extent)
        else {
            continue;
        };
        if physical_end > next_boundary
            || physical_end > sector_count
            || logical_end <= next_boundary
        {
            continue;
        }

        let entry_index = *entry_indices
            .get(file.path.as_str())
            .context("parsed file has no manifest entry")?;
        let entry = &mut parsed_iso.manifest.entries[entry_index];
        entry.allocation_padding_hex = None;
        entry
            .xa
            .get_or_insert_with(crate::manifest::EntryXa::default)
            .length_encoding = XaLengthEncoding::Mode2_2336;
        file.length = physical_blocks
            .checked_mul(LOGICAL_BLOCK_SIZE as u32)
            .context("mode2_2336 logical extent length overflow")?;
    }
    Ok(())
}

fn ranges_overlap(left: &Range<usize>, right: &Range<usize>) -> bool {
    left.start < right.end && right.start < left.end
}

fn mark_entry_record_only(entry: &mut crate::manifest::Entry, extent: u32, length: u32) {
    entry.reference = Some(EntryReference {
        kind: EntryReferenceKind::RecordOnly,
        extent,
        length,
    });
    entry.allocation_padding_hex = None;
    if let Some(xa) = &mut entry.xa {
        xa.form1 = None;
        xa.form2 = None;
        xa.index = None;
        xa.gap_index = None;
        xa.logical_length = None;
        xa.length_encoding = XaLengthEncoding::default();
        xa.framing_subheader = None;
    }
}

fn detach_record_only_files(
    sector_count: usize,
    parsed_iso: &mut iso9660::ParsedIso,
) -> Result<()> {
    let entry_indices = parsed_iso
        .manifest
        .entries
        .iter()
        .enumerate()
        .map(|(index, entry)| (entry.path.clone(), index))
        .collect::<HashMap<_, _>>();
    let mut detached_paths = HashSet::new();
    for file in &parsed_iso.files {
        let range = placement_range(file.extent, file.length)?;
        let lacks_full_backing = file.extent == 0 || range.end > sector_count;
        if file.length == 0 || !lacks_full_backing {
            continue;
        }
        let entry = &mut parsed_iso.manifest.entries[entry_indices[file.path.as_str()]];
        ensure!(
            entry.reference.is_none(),
            "record-only entry already has a reference: {}",
            file.path
        );
        mark_entry_record_only(entry, file.extent, file.length);
        detached_paths.insert(file.path.clone());
    }
    parsed_iso
        .files
        .retain(|file| !detached_paths.contains(&file.path));
    Ok(())
}

fn detach_remaining_overlapping_files(parsed_iso: &mut iso9660::ParsedIso) -> Result<()> {
    let file_ranges = parsed_iso
        .files
        .iter()
        .map(|file| placement_range(file.extent, file.length))
        .collect::<Result<Vec<_>>>()?;
    let directory_ranges = parsed_iso
        .directories
        .iter()
        .chain(&parsed_iso.supplementary_directories)
        .map(|directory| placement_range(directory.extent, directory.length))
        .collect::<Result<Vec<_>>>()?;
    let detached_paths = parsed_iso
        .files
        .iter()
        .enumerate()
        .filter(|(index, _)| {
            directory_ranges
                .iter()
                .any(|directory| ranges_overlap(&file_ranges[*index], directory))
                || file_ranges.iter().enumerate().any(|(other, range)| {
                    *index != other && ranges_overlap(&file_ranges[*index], range)
                })
        })
        .map(|(_, file)| file.path.clone())
        .collect::<HashSet<_>>();
    for file in parsed_iso
        .files
        .iter()
        .filter(|file| detached_paths.contains(&file.path))
    {
        let entry = parsed_iso
            .manifest
            .entries
            .iter_mut()
            .find(|entry| entry.path == file.path)
            .context("overlapping file has no manifest entry")?;
        ensure!(
            entry.reference.is_none(),
            "overlapping entry already has a reference: {}",
            file.path
        );
        mark_entry_record_only(entry, file.extent, file.length);
    }
    parsed_iso
        .files
        .retain(|file| !detached_paths.contains(&file.path));
    Ok(())
}

fn detach_overlapping_xa_files(
    sectors: &[crate::raw_cd::ParsedSector],
    parsed_iso: &mut iso9660::ParsedIso,
) -> Result<()> {
    detach_record_only_files(sectors.len(), parsed_iso)?;
    let mut ordered = (0..parsed_iso.files.len()).collect::<Vec<_>>();
    ordered.sort_by_key(|index| parsed_iso.files[*index].extent);
    let mut components = Vec::new();
    let mut component = Vec::new();
    let mut component_end = 0;
    for index in ordered {
        let file = &parsed_iso.files[index];
        let range = placement_range(file.extent, file.length)?;
        if component.is_empty() || range.start < component_end {
            component.push(index);
            component_end = component_end.max(range.end);
        } else {
            if component.len() > 1 {
                components.push(component);
            }
            component = vec![index];
            component_end = range.end;
        }
    }
    if component.len() > 1 {
        components.push(component);
    }

    let entry_indices = parsed_iso
        .manifest
        .entries
        .iter()
        .enumerate()
        .map(|(index, entry)| (entry.path.clone(), index))
        .collect::<HashMap<_, _>>();
    let directory_ranges = parsed_iso
        .directories
        .iter()
        .chain(&parsed_iso.supplementary_directories)
        .map(|directory| placement_range(directory.extent, directory.length))
        .collect::<Result<Vec<_>>>()?;
    let root_end = parsed_iso
        .directories
        .iter()
        .chain(&parsed_iso.supplementary_directories)
        .map(|directory| placement_range(directory.extent, directory.length))
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .map(|range| range.end)
        .max()
        .unwrap_or(0);
    let mut detached_paths = HashSet::new();
    for component in components {
        let ranges = component
            .iter()
            .map(|index| {
                let file = &parsed_iso.files[*index];
                placement_range(file.extent, file.length)
            })
            .collect::<Result<Vec<_>>>()?;
        let start = ranges
            .iter()
            .map(|range| range.start)
            .min()
            .expect("overlap component is nonempty");
        let end = ranges
            .iter()
            .map(|range| range.end)
            .max()
            .expect("overlap component is nonempty");
        let entries_are_form2_xa = component.iter().all(|index| {
            let path = parsed_iso.files[*index].path.as_str();
            entry_declares_form2_xa(&parsed_iso.manifest.entries[entry_indices[path]])
        });
        let overlaps_directory = ranges.iter().any(|range| {
            directory_ranges
                .iter()
                .any(|directory| ranges_overlap(range, directory))
        });
        let physical_range_is_xa = end <= sectors.len()
            && sectors[start..end]
                .iter()
                .all(|sector| matches!(sector.kind, Kind::Form1 | Kind::Form2 | Kind::XaGap));
        if start < root_end || overlaps_directory || !entries_are_form2_xa || !physical_range_is_xa
        {
            continue;
        }
        for index in component {
            let file = &parsed_iso.files[index];
            let entry = &mut parsed_iso.manifest.entries[entry_indices[file.path.as_str()]];
            ensure!(
                entry.reference.is_none(),
                "overlapping XA entry already has a reference: {}",
                file.path
            );
            entry.reference = Some(EntryReference {
                kind: EntryReferenceKind::Layout,
                extent: file.extent,
                length: file.length,
            });
            entry.allocation_padding_hex = None;
            detached_paths.insert(file.path.clone());
        }
    }
    parsed_iso
        .files
        .retain(|file| !detached_paths.contains(&file.path));
    detach_remaining_overlapping_files(parsed_iso)
}

fn entry_file_subheader(entry: &crate::manifest::Entry, mut subheader: XaSubheader) -> XaSubheader {
    subheader.file_number = entry.xa.as_ref().map_or(0, |xa| xa.file_number);
    subheader
}

fn file_subheaders_are_representable(
    sectors: &[crate::raw_cd::ParsedSector],
    entry: &crate::manifest::Entry,
    damaged: &[bool],
) -> bool {
    let active = sectors
        .iter()
        .enumerate()
        .filter(|(index, _)| !damaged[*index])
        .map(|(_, sector)| sector)
        .collect::<Vec<_>>();
    if active.is_empty() || active.iter().any(|sector| sector.kind != Kind::Form1) {
        return active.is_empty();
    }
    let data = entry_file_subheader(entry, FORM1_DATA_SUBHEADER);
    let end_of_file = entry_file_subheader(entry, SYSTEM_END_OF_FILE_SUBHEADER);
    let metadata = entry_file_subheader(entry, ISO_METADATA_SUBHEADER);
    let matches = |index: usize, expected: XaSubheader| {
        active[index].subheader == expected && active[index].subheader_copy == expected
    };
    let all_data = (0..active.len()).all(|index| matches(index, data));
    let all_metadata = (0..active.len()).all(|index| matches(index, metadata));
    let data_then_final = |final_subheader| {
        (0..active.len() - 1).all(|index| matches(index, data))
            && matches(active.len() - 1, final_subheader)
    };
    all_data || all_metadata || data_then_final(metadata) || data_then_final(end_of_file)
}

fn prepare_xa_sidecars(
    sectors: &[crate::raw_cd::ParsedSector],
    parsed_iso: &mut iso9660::ParsedIso,
    redump_ranges: &[Range<usize>],
) -> Result<()> {
    let iso_paths = parsed_iso
        .manifest
        .entries
        .iter()
        .map(|entry| entry.path.clone())
        .collect::<HashSet<_>>();
    let mut sidecar_paths = HashSet::new();
    for file in &parsed_iso.files {
        let start = usize::try_from(file.extent)?;
        let count = usize::try_from(file.length)?.div_ceil(LOGICAL_BLOCK_SIZE);
        ensure!(
            start + count <= sectors.len(),
            "file extent is outside ISO content"
        );
        let entry_index = parsed_iso
            .manifest
            .entries
            .iter()
            .position(|entry| entry.path == file.path)
            .context("parsed file has no manifest entry")?;
        let damaged = (start..start + count)
            .map(|lba| redump_ranges.iter().any(|range| range.contains(&lba)))
            .collect::<Vec<_>>();
        let observed_mixed = sectors[start..start + count]
            .iter()
            .enumerate()
            .any(|(index, sector)| !damaged[index] && sector.kind != Kind::Form1);
        let observed_unrepresentable = !file_subheaders_are_representable(
            &sectors[start..start + count],
            &parsed_iso.manifest.entries[entry_index],
            &damaged,
        );
        if !observed_mixed
            && !observed_unrepresentable
            && !entry_uses_xa_sidecar(&parsed_iso.manifest.entries[entry_index])
        {
            continue;
        }
        let form1 = format!("{}.XA1", file.path);
        let form2 = format!("{}.XA2", file.path);
        let index = format!("{}.XAI", file.path);
        let gap_index = sectors[start..start + count]
            .iter()
            .any(|sector| sector.kind == Kind::XaGap)
            .then(|| format!("{}.XAG", file.path));
        for path in [&form1, &form2, &index].into_iter().chain(gap_index.iter()) {
            ensure!(
                !iso_paths.contains(path.as_str()),
                "XA asset path collides with ISO entry {path}"
            );
            ensure!(
                sidecar_paths.insert(path.clone()),
                "duplicate XA asset path {path}"
            );
        }
        parsed_iso.manifest.entries[entry_index].allocation_padding_hex = None;
        let xa = parsed_iso.manifest.entries[entry_index]
            .xa
            .get_or_insert_with(crate::manifest::EntryXa::default);
        xa.form1 = Some(form1);
        xa.form2 = Some(form2);
        xa.index = Some(index);
        xa.gap_index = gap_index;
        xa.logical_length = (!usize::try_from(file.length)?.is_multiple_of(LOGICAL_BLOCK_SIZE))
            .then_some(file.length);
    }
    Ok(())
}

fn detect_metadata_subheader(
    sectors: &[crate::raw_cd::ParsedSector],
    manifest: &mut crate::manifest::Iso9660,
    redump_ranges: &[Range<usize>],
) {
    if sectors[16].subheader == FORM1_DATA_SUBHEADER
        && sectors[16].subheader_copy == FORM1_DATA_SUBHEADER
    {
        manifest.metadata_subheader = MetadataSubheader::Named(IsoMetadataSubheader::Data);
    } else if sectors[16].subheader == SYSTEM_END_OF_FILE_SUBHEADER
        && sectors[16].subheader_copy == SYSTEM_END_OF_FILE_SUBHEADER
    {
        manifest.metadata_subheader = MetadataSubheader::Named(IsoMetadataSubheader::EndOfFileData);
    } else if sectors[16].subheader == ISO_METADATA_SUBHEADER
        && sectors[16].subheader_copy == ISO_METADATA_SUBHEADER
    {
        manifest.metadata_subheader = MetadataSubheader::Named(IsoMetadataSubheader::IsoMetadata);
    } else if sectors[16].subheader == PVD_SUBHEADER && sectors[16].subheader_copy == PVD_SUBHEADER
    {
        let terminator_uses_pvd_framing =
            sectors.iter().enumerate().skip(16).any(|(lba, sector)| {
                !redump_ranges.iter().any(|range| range.contains(&lba))
                    && sector.payload().starts_with(b"\xffCD001\x01")
                    && sector.subheader == PVD_SUBHEADER
                    && sector.subheader_copy == PVD_SUBHEADER
            });
        if terminator_uses_pvd_framing {
            manifest.volume_terminator_subheader = VolumeTerminatorSubheader::Pvd;
        }
    } else if sectors[16].kind == Kind::Form1 && sectors[16].subheader == sectors[16].subheader_copy
    {
        manifest.metadata_subheader = MetadataSubheader::Explicit(sectors[16].subheader);
    }
}

#[derive(Clone, Copy)]
enum SourcePlacement<'a> {
    File(&'a iso9660::ParsedFile),
    PrimaryDirectory(&'a iso9660::ParsedDirectory),
    JolietDirectory(&'a iso9660::ParsedDirectory),
}

impl<'a> SourcePlacement<'a> {
    const fn extent(self) -> u32 {
        match self {
            Self::File(file) => file.extent,
            Self::PrimaryDirectory(directory) | Self::JolietDirectory(directory) => {
                directory.extent
            }
        }
    }

    const fn length(self) -> u32 {
        match self {
            Self::File(file) => file.length,
            Self::PrimaryDirectory(directory) | Self::JolietDirectory(directory) => {
                directory.length
            }
        }
    }

    fn path(self) -> &'a str {
        match self {
            Self::File(file) => &file.path,
            Self::PrimaryDirectory(directory) | Self::JolietDirectory(directory) => &directory.path,
        }
    }

    fn manifest_item(self) -> FileLayoutItem {
        match self {
            Self::File(file) => FileLayoutItem::path(&file.path),
            Self::PrimaryDirectory(directory) => FileLayoutItem::directory(&directory.path),
            Self::JolietDirectory(directory) => {
                FileLayoutItem::volume_directory(MetadataVolume::Joliet, &directory.path)
            }
        }
    }
}

fn detect_gap_items(
    sectors: &[crate::raw_cd::ParsedSector],
    form2_edc: bool,
) -> Result<Option<Vec<FileLayoutItem>>> {
    if sectors.is_empty() {
        return Ok(None);
    }
    if sectors.iter().all(is_mode1_gap_sector) {
        return Ok(Some(vec![FileLayoutItem::mode1_gap(u32::try_from(
            sectors.len(),
        )?)]));
    }
    if sectors
        .iter()
        .any(|sector| matches!(sector.kind, Kind::Mode1 | Kind::Mode1Gap))
    {
        return Ok(None);
    }
    let mut items = Vec::new();
    let mut start = 0;
    while start < sectors.len() {
        if is_structured_form1_gap_sector(&sectors[start]) {
            let subheader = sectors[start].subheader;
            let end = (start + 1..sectors.len())
                .find(|index| {
                    !is_structured_form1_gap_sector(&sectors[*index])
                        || sectors[*index].subheader != subheader
                })
                .unwrap_or(sectors.len());
            items.push(FileLayoutItem::form1_gap(
                u32::try_from(end - start)?,
                subheader,
            ));
            start = end;
            continue;
        }
        if is_zero_form2_gap_sector(&sectors[start]) {
            let end = (start + 1..sectors.len())
                .find(|index| !is_zero_form2_gap_sector(&sectors[*index]))
                .unwrap_or(sectors.len());
            let gap_form2_edc = sectors[start].form2_edc_valid;
            ensure!(
                sectors[start..end]
                    .iter()
                    .all(|sector| sector_follows_form2_edc_policy(sector, gap_form2_edc)),
                "physical Form 2 gap uses inconsistent EDC policy"
            );
            let sectors = u32::try_from(end - start)?;
            items.push(if gap_form2_edc == form2_edc {
                FileLayoutItem::gap(sectors)
            } else {
                FileLayoutItem::form2_gap(sectors, gap_form2_edc)
            });
            start = end;
            continue;
        }
        return Ok(None);
    }
    Ok(Some(items))
}

fn is_zero_form2_gap_sector(sector: &crate::raw_cd::ParsedSector) -> bool {
    sector.kind == Kind::Form2
        && sector.subheader == FORM2_SUBHEADER
        && sector.subheader_copy == FORM2_SUBHEADER
        && sector.payload().iter().all(|byte| *byte == 0)
}

fn is_mode1_gap_sector(sector: &crate::raw_cd::ParsedSector) -> bool {
    sector.kind == Kind::Mode1Gap && sector.payload().iter().all(|byte| *byte == 0)
}

fn is_structured_form1_gap_sector(sector: &crate::raw_cd::ParsedSector) -> bool {
    sector.kind == Kind::Form1
        && sector.subheader == sector.subheader_copy
        && !sector.noncompliant_ecc
        && sector.payload().iter().all(|byte| *byte == 0)
}

struct DetectedFileLayout {
    items: Vec<FileLayoutItem>,
    assets: HashMap<String, Vec<u8>>,
    xa_extent_ranges: Vec<Range<usize>>,
}

fn append_detected_gap(
    detected: &mut DetectedFileLayout,
    sectors: &[crate::raw_cd::ParsedSector],
    start: usize,
    end: usize,
    form2_edc: bool,
    manifest_stem: &str,
) -> Result<()> {
    if let Some(items) = detect_gap_items(&sectors[start..end], form2_edc)? {
        detected.items.extend(items);
        return Ok(());
    }
    ensure!(
        sectors[start..end]
            .iter()
            .all(|sector| !matches!(sector.kind, Kind::Mode1 | Kind::Mode1Gap)),
        "unreferenced Mode 1 sectors contain nonzero data"
    );

    let ordinal = detected.xa_extent_ranges.len();
    let base = format!("{manifest_stem}.unreferenced.{ordinal:03}");
    let paths = XaExtentAssets {
        form1: format!("{base}.XA1"),
        form1_sha1: None,
        form2: format!("{base}.XA2"),
        form2_sha1: None,
        index: format!("{base}.XAI"),
        index_sha1: None,
        gap_index: sectors[start..end]
            .iter()
            .any(|sector| sector.kind == Kind::XaGap)
            .then(|| format!("{base}.XAG")),
        gap_index_sha1: None,
    };
    let assets = demultiplex_xa_extent(&sectors[start..end], form2_edc)
        .with_context(|| format!("demultiplexing unreferenced XA extent at LBA {start}"))?;
    ensure!(
        detected
            .assets
            .insert(paths.form1.clone(), assets.form1)
            .is_none(),
        "duplicate unreferenced XA1 asset path"
    );
    ensure!(
        detected
            .assets
            .insert(paths.form2.clone(), assets.form2)
            .is_none(),
        "duplicate unreferenced XA2 asset path"
    );
    ensure!(
        detected
            .assets
            .insert(paths.index.clone(), assets.form2_index)
            .is_none(),
        "duplicate unreferenced XAI asset path"
    );
    if let Some(path) = &paths.gap_index {
        ensure!(!assets.gap_index.is_empty(), "prepared XAG asset is empty");
        ensure!(
            detected
                .assets
                .insert(path.clone(), assets.gap_index)
                .is_none(),
            "duplicate unreferenced XAG asset path"
        );
    } else {
        ensure!(
            assets.gap_index.is_empty(),
            "missing unreferenced XAG asset path"
        );
    }
    detected.items.push(FileLayoutItem::xa_extent(paths));
    detected.xa_extent_ranges.push(start..end);
    Ok(())
}

fn detect_file_layout(
    sectors: &[crate::raw_cd::ParsedSector],
    files: &[iso9660::ParsedFile],
    directories: &[iso9660::ParsedDirectory],
    supplementary_directories: &[iso9660::ParsedDirectory],
    form2_edc: bool,
    manifest_stem: &str,
) -> Result<DetectedFileLayout> {
    let has_joliet = !supplementary_directories.is_empty();
    let grouped_directories = has_joliet
        && [directories, supplementary_directories]
            .into_iter()
            .all(|volume_directories| {
                let mut physical = volume_directories
                    .iter()
                    .filter(|directory| directory.length != 0);
                let Some(mut previous) = physical.next() else {
                    return false;
                };
                physical.all(|directory| {
                    let contiguous = previous
                        .extent
                        .checked_add(previous.length.div_ceil(LOGICAL_BLOCK_SIZE as u32))
                        == Some(directory.extent);
                    previous = directory;
                    contiguous
                })
            });
    let mut placements = files.iter().map(SourcePlacement::File).collect::<Vec<_>>();
    if has_joliet {
        if !grouped_directories {
            placements.extend(
                directories
                    .iter()
                    .filter(|directory| directory.length != 0)
                    .map(SourcePlacement::PrimaryDirectory)
                    .chain(
                        supplementary_directories
                            .iter()
                            .filter(|directory| directory.length != 0)
                            .map(SourcePlacement::JolietDirectory),
                    ),
            );
        }
    } else {
        placements.extend(
            directories
                .iter()
                .filter(|directory| directory.path != iso9660::ROOT_PATH && directory.length != 0)
                .map(SourcePlacement::PrimaryDirectory),
        );
    }
    placements.sort_by_key(|placement| placement.extent());
    let mut previous_end = if has_joliet && !grouped_directories {
        usize::try_from(
            placements
                .first()
                .context("interleaved directory layout is empty")?
                .extent(),
        )?
    } else {
        directories
            .iter()
            .chain(supplementary_directories)
            .filter(|directory| {
                directory.length != 0 && (has_joliet || directory.path == iso9660::ROOT_PATH)
            })
            .map(|directory| -> Result<usize> {
                Ok(usize::try_from(directory.extent)?
                    + usize::try_from(directory.length)?.div_ceil(LOGICAL_BLOCK_SIZE))
            })
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .max()
            .unwrap_or(0)
    };
    let mut detected = DetectedFileLayout {
        items: Vec::new(),
        assets: HashMap::new(),
        xa_extent_ranges: Vec::new(),
    };
    for placement in placements {
        let extent = usize::try_from(placement.extent())?;
        ensure!(
            extent >= previous_end,
            "overlapping physical placement for {}",
            placement.path()
        );
        ensure!(
            extent <= sectors.len(),
            "physical placement is outside image"
        );
        if extent > previous_end {
            append_detected_gap(
                &mut detected,
                sectors,
                previous_end,
                extent,
                form2_edc,
                manifest_stem,
            )
            .with_context(|| format!("preserving sectors before {}", placement.path()))?;
        }
        detected.items.push(placement.manifest_item());
        previous_end = extent + usize::try_from(placement.length())?.div_ceil(LOGICAL_BLOCK_SIZE);
    }
    if previous_end < sectors.len() {
        append_detected_gap(
            &mut detected,
            sectors,
            previous_end,
            sectors.len(),
            form2_edc,
            manifest_stem,
        )
        .context("preserving unreferenced sectors at the end of ISO content")?;
    }
    Ok(detected)
}

pub fn extract(
    image_path: &Path,
    manifest_path: &Path,
    data_dir: &Path,
    overwrite: bool,
) -> Result<ExtractReport> {
    extract_with_options(
        image_path,
        manifest_path,
        data_dir,
        ExtractOptions { overwrite },
    )
}

pub fn extract_with_options(
    image_path: &Path,
    manifest_path: &Path,
    data_dir: &Path,
    options: ExtractOptions,
) -> Result<ExtractReport> {
    validate_output_file(manifest_path, options.overwrite, "manifest output")?;
    let image = fs::read(image_path)
        .with_context(|| format!("reading raw image {}", image_path.display()))?;
    let source_sha1 = sha1_hex(&image);
    let redump_0x55 = detect_redump_0x55(&image);
    let mut recovery = recover_known_corruption(&source_sha1, &image)
        .context("applying approved corruption recovery")?;
    validate_redump_0x55_runs(&redump_0x55, &recovery.patches)?;
    if !redump_0x55.is_empty() {
        let start_frame = raw_track_start_frame(&image)?;
        install_redump_0x55_placeholders(
            recovery.semantic.to_mut(),
            start_frame,
            image[15],
            &redump_0x55,
        )?;
    }
    let (start_frame, sectors) = parse_image(&recovery.semantic).with_context(|| {
        if redump_0x55.is_empty() {
            "parsing recovered semantic image".to_owned()
        } else {
            "Redump 0x55 zero placeholders do not leave a parseable semantic image".to_owned()
        }
    })?;
    let redump_ranges = resolve_redump_0x55_ranges(start_frame, sectors.len(), &redump_0x55)?;
    ensure!(sectors.len() >= 23, "image is too small");
    let track_mode = match sectors[0].kind {
        Kind::Mode1 | Kind::Mode1Gap => TrackMode::Mode1,
        Kind::Form1 | Kind::Form2 | Kind::XaGap => TrackMode::Mode2Xa,
        Kind::RawZero => anyhow::bail!("raw-zero sector cannot begin a track"),
    };
    let sector_count = u32::try_from(sectors.len())?;
    let noncompliant_trailing_ecc = sectors.last().is_some_and(|sector| sector.noncompliant_ecc);
    ensure!(
        sectors[..sectors.len() - 1]
            .iter()
            .all(|sector| !sector.noncompliant_ecc),
        "noncompliant ECC is supported only on the final track sector"
    );

    let trailing_raw_zero = sectors
        .iter()
        .rev()
        .take_while(|sector| sector.kind == Kind::RawZero)
        .count();
    let trailing_gap = match track_mode {
        TrackMode::Mode1 => 0,
        TrackMode::Mode2Xa => sectors[..sectors.len() - trailing_raw_zero]
            .iter()
            .rev()
            .take_while(|sector| sector.kind == Kind::XaGap)
            .count(),
        TrackMode::Mode2 => unreachable!("raw parser does not accept non-XA Mode 2"),
    };
    ensure!(
        trailing_gap == 0 || trailing_raw_zero == 0,
        "mixed terminal framed and raw-zero gap runs are unsupported"
    );
    let trailing_physical_gap = trailing_gap + trailing_raw_zero;
    let ExtractedSystemArea {
        content: system_bytes,
        form1_count,
        form2_edc,
        sector_layout,
        final_form1_subheader,
        form1_framing,
    } = extract_system_area(&sectors[..SYSTEM_AREA_SECTORS], track_mode, &redump_ranges)?;
    let manifest_stem = manifest_stem(manifest_path)?;
    let system_name = format!("{manifest_stem}.system");
    let blocks = sectors
        .iter()
        .map(|sector| sector.logical_block().try_into())
        .collect::<Result<Vec<[u8; LOGICAL_BLOCK_SIZE]>, _>>()?;
    let mut parsed_iso = iso9660::parse(&blocks).with_context(|| {
        if redump_0x55.is_empty() {
            "parsing ISO 9660 filesystem".to_owned()
        } else {
            "Redump 0x55 zero placeholders do not leave a parseable ISO 9660 filesystem; required metadata may be damaged".to_owned()
        }
    })?;
    if source_sha1 == "1277d46d983b237659190938c9b41014c2c7aa2f" {
        for path in ["MLB2/FE_ART/LOADING", "MLB2/FE_ART/LOADING2"] {
            let entry = parsed_iso
                .manifest
                .entries
                .iter_mut()
                .find(|entry| entry.path == path)
                .with_context(|| format!("missing recovered directory {path}"))?;
            ensure!(
                entry.directory_slack.is_none(),
                "recovered directory unexpectedly has ordinary slack: {path}"
            );
            entry.directory_slack = Some(DirectorySlack {
                offset: 4095,
                hex: "00".to_owned(),
            });
        }
    }
    let content_end = sectors.len() - trailing_physical_gap;
    if track_mode == TrackMode::Mode2Xa {
        detect_metadata_subheader(
            &sectors[..content_end],
            &mut parsed_iso.manifest,
            &redump_ranges,
        );
        detect_path_table_subheader(&sectors[..content_end], &mut parsed_iso, &redump_ranges)?;
        detect_mode2_2336_file_lengths(content_end, &mut parsed_iso)?;
        detach_overlapping_xa_files(&sectors[..content_end], &mut parsed_iso)?;
        prepare_xa_sidecars(&sectors[..content_end], &mut parsed_iso, &redump_ranges)?;
        detect_entry_sector_subheaders(&sectors[..content_end], &mut parsed_iso, &redump_ranges)?;
    }
    let detected_layout = detect_file_layout(
        &sectors[..content_end],
        &parsed_iso.files,
        &parsed_iso.directories,
        &parsed_iso.supplementary_directories,
        form2_edc,
        manifest_stem,
    )?;
    if track_mode == TrackMode::Mode2Xa {
        validate_iso_subheaders_with_xa_extents(
            &sectors,
            &parsed_iso,
            trailing_physical_gap,
            &detected_layout.xa_extent_ranges,
            &redump_ranges,
        )?;
    }
    parsed_iso.manifest.layout = detected_layout.items;
    if trailing_gap > 0 {
        parsed_iso.manifest.layout.push(match track_mode {
            TrackMode::Mode1 => FileLayoutItem::mode1_gap(u32::try_from(trailing_gap)?),
            TrackMode::Mode2Xa => FileLayoutItem::xa_gap(u32::try_from(trailing_gap)?),
            TrackMode::Mode2 => unreachable!("raw parser does not accept non-XA Mode 2"),
        });
    }
    if trailing_raw_zero > 0 {
        parsed_iso
            .manifest
            .layout
            .push(FileLayoutItem::raw_zero_gap(u32::try_from(
                trailing_raw_zero,
            )?));
    }
    let mut extracted_files = detected_layout.assets;
    for file in &parsed_iso.files {
        let entry_index = parsed_iso
            .manifest
            .entries
            .iter()
            .position(|entry| entry.path == file.path)
            .context("parsed file has no manifest entry")?;
        if entry_uses_xa_sidecar(&parsed_iso.manifest.entries[entry_index]) {
            let start = usize::try_from(file.extent)?;
            let count = usize::try_from(file.length)?.div_ceil(LOGICAL_BLOCK_SIZE);
            ensure!(
                start + count <= sectors.len(),
                "interleaved extent is outside image"
            );
            let assets = demultiplex_xa_extent(&sectors[start..start + count], form2_edc)
                .with_context(|| format!("demultiplexing {}", file.path))?;
            let xa = parsed_iso.manifest.entries[entry_index]
                .xa
                .as_ref()
                .expect("checked XA metadata");
            for (path, data) in [
                (xa.form1.clone().expect("prepared XA1 path"), assets.form1),
                (xa.form2.clone().expect("prepared XA2 path"), assets.form2),
                (
                    xa.index.clone().expect("prepared XAI path"),
                    assets.form2_index,
                ),
            ] {
                ensure!(
                    extracted_files.insert(path.clone(), data).is_none(),
                    "duplicate extraction asset path {path}"
                );
            }
            if let Some(path) = &xa.gap_index {
                ensure!(!assets.gap_index.is_empty(), "prepared XAG asset is empty");
                ensure!(
                    extracted_files
                        .insert(path.clone(), assets.gap_index)
                        .is_none(),
                    "duplicate extraction asset path {path}"
                );
            } else {
                ensure!(
                    assets.gap_index.is_empty(),
                    "missing prepared XAG asset path"
                );
            }
        } else {
            let data = read_extent(&blocks, file.extent, file.length)?;
            ensure!(
                extracted_files.insert(file.path.clone(), data).is_none(),
                "duplicate extraction asset path {}",
                file.path
            );
        }
    }
    let mut manifest = Manifest {
        gcdgold: GcdgoldMetadata {
            version: GCDGOLD_VERSION.to_owned(),
        },
        track: Track {
            sha1: None,
            mode: track_mode,
            start_msf: format_msf(start_frame)?,
            form2_edc,
            noncompliant_trailing_ecc,
            redump_0x55,
            patches: recovery.patches,
        },
        system_area: SystemArea {
            path: system_name.clone(),
            sha1: None,
            form1_sectors: if system_bytes.len().div_ceil(LOGICAL_BLOCK_SIZE) == form1_count {
                Form1Sectors::Auto("auto".to_owned())
            } else {
                Form1Sectors::Count(u8::try_from(form1_count)?)
            },
            sector_layout,
            final_form1_subheader,
            form1_framing,
        },
        iso9660: parsed_iso.manifest,
    };
    ensure!(
        manifest
            .iso9660
            .entries
            .iter()
            .all(|entry| entry.path != system_name),
        "system asset path collides with an ISO entry"
    );
    ensure!(
        !extracted_files.contains_key(&system_name),
        "system asset path collides with an extraction asset"
    );
    let write_plan = plan_extraction_outputs(
        &mut manifest,
        &mut extracted_files,
        &system_bytes,
        data_dir,
        options.overwrite,
    )?;
    add_extracted_hashes(&mut manifest, &source_sha1, &system_bytes, &extracted_files)?;
    let authored_file_paths: HashSet<_> = manifest
        .iso9660
        .layout
        .iter()
        .filter_map(FileLayoutItem::as_path)
        .collect();
    let referenced_file_paths: HashSet<_> = manifest
        .iso9660
        .entries
        .iter()
        .filter(|entry| {
            entry
                .reference
                .is_some_and(|reference| reference.kind != EntryReferenceKind::Directory)
        })
        .map(|entry| entry.path.as_str())
        .collect();
    for entry in manifest
        .iso9660
        .entries
        .iter()
        .filter(|entry| entry.path != iso9660::ROOT_PATH)
    {
        if !authored_file_paths.contains(entry.path.as_str())
            && !referenced_file_paths.contains(entry.path.as_str())
        {
            let output = safe_join(data_dir, &entry.path)?;
            validate_output_ancestors(data_dir, &entry.path)?;
            validate_output_directory(&output, "extraction output")?;
        }
    }
    create_output_parent(manifest_path, "manifest output")?;
    fs::create_dir_all(data_dir)
        .with_context(|| format!("creating data directory {}", data_dir.display()))?;
    for entry in manifest
        .iso9660
        .entries
        .iter()
        .filter(|entry| entry.path != iso9660::ROOT_PATH)
    {
        if !authored_file_paths.contains(entry.path.as_str())
            && !referenced_file_paths.contains(entry.path.as_str())
        {
            let output = safe_join(data_dir, &entry.path)?;
            fs::create_dir_all(&output)
                .with_context(|| format!("creating directory {}", output.display()))?;
        }
    }
    let system_path = safe_join(data_dir, &manifest.system_area.path)?;
    if write_plan.system {
        fs::write(&system_path, &system_bytes)
            .with_context(|| format!("writing {}", system_path.display()))?;
    }
    for (path, data) in extracted_files {
        if !write_plan.assets.contains(&path) {
            continue;
        }
        let output = safe_join(data_dir, &path)?;
        if let Some(parent) = output.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&output, data).with_context(|| format!("writing {}", output.display()))?;
    }
    let yaml = serialize_manifest(&manifest)?;
    fs::write(manifest_path, yaml)
        .with_context(|| format!("writing manifest {}", manifest_path.display()))?;
    Ok(ExtractReport {
        sectors: sector_count,
        sha1: source_sha1,
        recovery_warnings: recovery.warnings,
    })
}

struct ExtractedSystemArea {
    content: Vec<u8>,
    form1_count: usize,
    form2_edc: bool,
    sector_layout: Vec<SystemAreaSectorRun>,
    final_form1_subheader: SystemAreaFinalSubheader,
    form1_framing: Vec<SystemAreaForm1Framing>,
}

fn extract_system_area(
    sectors: &[crate::raw_cd::ParsedSector],
    track_mode: TrackMode,
    redump_ranges: &[Range<usize>],
) -> Result<ExtractedSystemArea> {
    ensure!(
        sectors.len() == SYSTEM_AREA_SECTORS,
        "system area must contain sixteen sectors"
    );
    let sector_kinds = sectors
        .iter()
        .map(|sector| match sector.kind {
            Kind::Mode1 | Kind::Mode1Gap => Ok(SystemAreaSectorKind::Form1),
            Kind::Form1 => Ok(SystemAreaSectorKind::Form1),
            Kind::Form2 => Ok(SystemAreaSectorKind::Form2),
            Kind::XaGap => Ok(SystemAreaSectorKind::XaGap),
            Kind::RawZero => anyhow::bail!("raw-zero sector inside system area"),
        })
        .collect::<Result<Vec<_>>>()?;
    let form1_count = sector_kinds
        .iter()
        .filter(|kind| **kind == SystemAreaSectorKind::Form1)
        .count();
    let form2_sectors = sectors
        .iter()
        .filter(|sector| sector.kind == Kind::Form2)
        .collect::<Vec<_>>();
    ensure!(
        form2_sectors
            .iter()
            .all(|sector| sector.payload().iter().all(|byte| *byte == 0)),
        "system-area Form 2 payload is not zero"
    );
    let mut content = Vec::with_capacity(form1_count * LOGICAL_BLOCK_SIZE);
    for sector in sectors
        .iter()
        .filter(|sector| matches!(sector.kind, Kind::Mode1 | Kind::Mode1Gap | Kind::Form1))
    {
        content.extend_from_slice(sector.payload());
    }
    while content.last() == Some(&0) {
        content.pop();
    }
    let computed = form2_sectors.iter().all(|sector| sector.form2_edc_valid);
    let zeroed = form2_sectors
        .iter()
        .all(|sector| sector_follows_form2_edc_policy(sector, false));
    ensure!(computed || zeroed, "mixed Form 2 EDC policy in system area");
    let final_form1_index = sector_kinds
        .iter()
        .rposition(|kind| *kind == SystemAreaSectorKind::Form1);
    let final_form1_subheader = if let Some(index) = final_form1_index {
        let final_form1 = &sectors[index];
        if final_form1.subheader == SYSTEM_END_OF_FILE_SUBHEADER
            && final_form1.subheader_copy == SYSTEM_END_OF_FILE_SUBHEADER
        {
            SystemAreaFinalSubheader::EndOfFileData
        } else {
            SystemAreaFinalSubheader::Data
        }
    } else {
        SystemAreaFinalSubheader::Data
    };
    let mut form1_framing = Vec::new();
    if track_mode == TrackMode::Mode2Xa {
        for (index, sector) in sectors.iter().enumerate() {
            if sector.kind != Kind::Form1
                || redump_ranges.iter().any(|range| range.contains(&index))
            {
                continue;
            }
            let expected = if Some(index) == final_form1_index
                && final_form1_subheader == SystemAreaFinalSubheader::EndOfFileData
            {
                SYSTEM_END_OF_FILE_SUBHEADER
            } else {
                FORM1_DATA_SUBHEADER
            };
            if sector.subheader != expected || sector.subheader_copy != expected {
                form1_framing.push(SystemAreaForm1Framing {
                    sector: u8::try_from(index)?,
                    subheader: sector.subheader,
                    subheader_copy: sector.subheader_copy,
                });
            }
        }
    }
    ensure!(
        form2_sectors.iter().all(|sector| {
            sector.subheader == FORM2_SUBHEADER && sector.subheader_copy == FORM2_SUBHEADER
        }),
        "system-area Form 2 sectors use a nonstandard XA subheader"
    );
    ensure!(
        sectors.iter().all(|sector| {
            sector.kind != Kind::XaGap
                || (sector.subheader == XaSubheader::default()
                    && sector.subheader_copy == XaSubheader::default())
        }),
        "system-area XA gaps use a nonstandard XA subheader"
    );
    let canonical_layout = (0..SYSTEM_AREA_SECTORS)
        .map(|index| {
            if index < form1_count {
                SystemAreaSectorKind::Form1
            } else {
                SystemAreaSectorKind::Form2
            }
        })
        .collect::<Vec<_>>();
    let sector_layout = if sector_kinds == canonical_layout {
        Vec::new()
    } else {
        compress_system_area_sector_layout(&sector_kinds)
    };
    Ok(ExtractedSystemArea {
        content,
        form1_count,
        form2_edc: computed,
        sector_layout,
        final_form1_subheader,
        form1_framing,
    })
}

fn compress_system_area_sector_layout(kinds: &[SystemAreaSectorKind]) -> Vec<SystemAreaSectorRun> {
    let mut runs: Vec<SystemAreaSectorRun> = Vec::new();
    for kind in kinds {
        if let Some(run) = runs.last_mut()
            && run.kind == *kind
        {
            run.sectors += 1;
        } else {
            runs.push(SystemAreaSectorRun {
                kind: *kind,
                sectors: 1,
            });
        }
    }
    runs
}

fn expand_system_area_sector_layout(
    system_area: &SystemArea,
    form1_count: u8,
) -> Result<Vec<SystemAreaSectorKind>> {
    let kinds = if system_area.sector_layout.is_empty() {
        (0..SYSTEM_AREA_SECTORS)
            .map(|index| {
                if index < usize::from(form1_count) {
                    SystemAreaSectorKind::Form1
                } else {
                    SystemAreaSectorKind::Form2
                }
            })
            .collect::<Vec<_>>()
    } else {
        let mut kinds = Vec::new();
        for run in &system_area.sector_layout {
            ensure!(
                run.sectors > 0,
                "system-area sector layout run must not be empty"
            );
            kinds.extend(std::iter::repeat_n(run.kind, usize::from(run.sectors)));
        }
        kinds
    };
    ensure!(
        kinds.len() == SYSTEM_AREA_SECTORS,
        "system-area sector layout must describe exactly sixteen sectors"
    );
    ensure!(
        kinds
            .iter()
            .filter(|kind| **kind == SystemAreaSectorKind::Form1)
            .count()
            == usize::from(form1_count),
        "system-area sector layout Form 1 count does not match form1_sectors"
    );
    Ok(kinds)
}

fn validate_track_structure(
    manifest: &Manifest,
    system_sector_layout: &[SystemAreaSectorKind],
) -> Result<()> {
    validate_redump_0x55_runs(&manifest.track.redump_0x55, &manifest.track.patches)?;
    let mut file_gap_kinds = manifest
        .iso9660
        .layout
        .iter()
        .filter_map(FileLayoutItem::gap_kind);
    match manifest.track.mode {
        TrackMode::Mode1 => {
            ensure!(
                manifest.track.form2_edc,
                "form2_edc is not applicable to Mode 1 tracks"
            );
            ensure!(
                !manifest.track.noncompliant_trailing_ecc,
                "noncompliant_trailing_ecc is not applicable to Mode 1 tracks"
            );
            ensure!(
                system_sector_layout
                    .iter()
                    .all(|kind| *kind == SystemAreaSectorKind::Form1),
                "Mode 1 system area must contain only Mode 1 sectors"
            );
            ensure!(
                manifest.system_area.final_form1_subheader == SystemAreaFinalSubheader::Data
                    && manifest.system_area.form1_framing.is_empty(),
                "XA system-area framing is not applicable to Mode 1 tracks"
            );
            ensure!(
                manifest.iso9660.metadata_subheader
                    == MetadataSubheader::Named(IsoMetadataSubheader::Canonical)
                    && manifest.iso9660.volume_terminator_subheader
                        == VolumeTerminatorSubheader::Metadata
                    && manifest.iso9660.path_table_subheader
                        == PathTableSubheader::Named(EntrySectorSubheader::Canonical),
                "XA metadata framing is not applicable to Mode 1 tracks"
            );
            ensure!(
                manifest.iso9660.entries.iter().all(|entry| {
                    entry.sector_subheader == EntrySectorSubheader::Canonical
                        && !entry_uses_xa_sidecar(entry)
                        && entry.xa.as_ref().is_none_or(|xa| {
                            xa.form1.is_none()
                                && xa.form2.is_none()
                                && xa.index.is_none()
                                && xa.gap_index.is_none()
                                && xa.logical_length.is_none()
                                && xa.framing_subheader.is_none()
                        })
                }),
                "XA sector framing and sidecar assets are not applicable to Mode 1 tracks"
            );
            ensure!(
                manifest
                    .iso9660
                    .layout
                    .iter()
                    .all(|item| item.as_xa_extent().is_none()),
                "unreferenced XA extents are not applicable to Mode 1 tracks"
            );
            ensure!(
                file_gap_kinds.all(|kind| matches!(kind, GapKind::Mode1 | GapKind::RawZero)),
                "Mode 1 tracks may contain only Mode 1 or terminal raw-zero gaps"
            );
        }
        TrackMode::Mode2Xa => {
            ensure!(
                file_gap_kinds.all(|kind| kind != GapKind::Mode1),
                "Mode 1 gaps require a Mode 1 track"
            );
        }
        TrackMode::Mode2 => anyhow::bail!("unsupported track mode 2"),
    }
    Ok(())
}

fn path_table_subheader(setting: PathTableSubheader, block_index: u32, blocks: u32) -> XaSubheader {
    let policy = match setting {
        PathTableSubheader::Named(policy) => policy,
        PathTableSubheader::Explicit(subheader) => return subheader,
    };
    match policy {
        EntrySectorSubheader::Canonical | EntrySectorSubheader::IsoMetadata => {
            ISO_METADATA_SUBHEADER
        }
        EntrySectorSubheader::Data => FORM1_DATA_SUBHEADER,
        EntrySectorSubheader::EndOfFileData if block_index + 1 < blocks => FORM1_DATA_SUBHEADER,
        EntrySectorSubheader::EndOfFileData => SYSTEM_END_OF_FILE_SUBHEADER,
        EntrySectorSubheader::DataUntilFinal if block_index + 1 < blocks => FORM1_DATA_SUBHEADER,
        EntrySectorSubheader::DataUntilFinal => ISO_METADATA_SUBHEADER,
    }
}

fn descriptor_metadata_subheader(setting: MetadataSubheader) -> XaSubheader {
    match setting {
        MetadataSubheader::Explicit(subheader) => subheader,
        MetadataSubheader::Named(IsoMetadataSubheader::Canonical) => PVD_SUBHEADER,
        MetadataSubheader::Named(IsoMetadataSubheader::Data) => FORM1_DATA_SUBHEADER,
        MetadataSubheader::Named(IsoMetadataSubheader::EndOfFileData) => {
            SYSTEM_END_OF_FILE_SUBHEADER
        }
        MetadataSubheader::Named(IsoMetadataSubheader::IsoMetadata) => ISO_METADATA_SUBHEADER,
    }
}

fn ordinary_metadata_subheader(setting: MetadataSubheader) -> XaSubheader {
    match setting {
        MetadataSubheader::Explicit(subheader) => subheader,
        MetadataSubheader::Named(IsoMetadataSubheader::Canonical)
        | MetadataSubheader::Named(IsoMetadataSubheader::IsoMetadata) => ISO_METADATA_SUBHEADER,
        MetadataSubheader::Named(IsoMetadataSubheader::Data) => FORM1_DATA_SUBHEADER,
        MetadataSubheader::Named(IsoMetadataSubheader::EndOfFileData) => {
            SYSTEM_END_OF_FILE_SUBHEADER
        }
    }
}

fn detect_path_table_subheader(
    sectors: &[crate::raw_cd::ParsedSector],
    parsed_iso: &mut iso9660::ParsedIso,
    redump_ranges: &[Range<usize>],
) -> Result<()> {
    let Some(path_tables) = &parsed_iso.path_tables else {
        return Ok(());
    };
    for policy in [
        EntrySectorSubheader::Canonical,
        EntrySectorSubheader::Data,
        EntrySectorSubheader::EndOfFileData,
        EntrySectorSubheader::DataUntilFinal,
    ] {
        let matches = path_tables
            .extents
            .iter()
            .filter(|extent| **extent != 0)
            .all(|extent| {
                (0..path_tables.blocks).all(|block_index| {
                    let Ok(lba) = usize::try_from(*extent + block_index) else {
                        return false;
                    };
                    if redump_ranges.iter().any(|range| range.contains(&lba)) {
                        return true;
                    }
                    let Some(sector) = sectors.get(lba) else {
                        return false;
                    };
                    let expected = path_table_subheader(
                        PathTableSubheader::Named(policy),
                        block_index,
                        path_tables.blocks,
                    );
                    sector.subheader == expected && sector.subheader_copy == expected
                })
            });
        if matches {
            parsed_iso.manifest.path_table_subheader = PathTableSubheader::Named(policy);
            return Ok(());
        }
    }
    let mut custom = None;
    let matches_custom = path_tables
        .extents
        .iter()
        .filter(|extent| **extent != 0)
        .all(|extent| {
            (0..path_tables.blocks).all(|block_index| {
                let Ok(lba) = usize::try_from(*extent + block_index) else {
                    return false;
                };
                if redump_ranges.iter().any(|range| range.contains(&lba)) {
                    return true;
                }
                let Some(sector) = sectors.get(lba) else {
                    return false;
                };
                if sector.kind != Kind::Form1 || sector.subheader != sector.subheader_copy {
                    return false;
                }
                if let Some(expected) = custom {
                    sector.subheader == expected
                } else {
                    custom = Some(sector.subheader);
                    true
                }
            })
        });
    if matches_custom {
        parsed_iso.manifest.path_table_subheader =
            PathTableSubheader::Explicit(custom.expect("custom path-table match has a sector"));
        return Ok(());
    }
    anyhow::bail!("path-table sectors use an unsupported XA subheader policy")
}

fn detect_entry_sector_subheaders(
    sectors: &[crate::raw_cd::ParsedSector],
    parsed_iso: &mut iso9660::ParsedIso,
    redump_ranges: &[Range<usize>],
) -> Result<()> {
    for file in &parsed_iso.files {
        let entry = parsed_iso
            .manifest
            .entries
            .iter_mut()
            .find(|entry| entry.path == file.path)
            .context("parsed file has no manifest entry")?;
        if entry_uses_xa_sidecar(entry) {
            continue;
        }
        let blocks = usize::try_from(file.length)?.div_ceil(LOGICAL_BLOCK_SIZE);
        if blocks == 0 {
            continue;
        }
        let start = usize::try_from(file.extent)?;
        let final_lba = start + blocks - 1;
        ensure!(final_lba < sectors.len(), "file extent is outside image");
        let active = (start..=final_lba)
            .filter(|lba| !redump_ranges.iter().any(|range| range.contains(lba)))
            .collect::<Vec<_>>();
        if active.is_empty() {
            continue;
        }
        let data_subheader = entry_file_subheader(entry, FORM1_DATA_SUBHEADER);
        let end_of_file_subheader = entry_file_subheader(entry, SYSTEM_END_OF_FILE_SUBHEADER);
        let metadata_subheader = entry_file_subheader(entry, ISO_METADATA_SUBHEADER);
        if active.iter().all(|lba| {
            let sector = &sectors[*lba];
            sector.subheader == metadata_subheader && sector.subheader_copy == metadata_subheader
        }) {
            entry.sector_subheader = EntrySectorSubheader::IsoMetadata;
        } else if active.contains(&final_lba) {
            let sector = &sectors[final_lba];
            if sector.subheader == data_subheader && sector.subheader_copy == data_subheader {
                entry.sector_subheader = EntrySectorSubheader::Data;
            } else if sector.subheader == end_of_file_subheader
                && sector.subheader_copy == end_of_file_subheader
            {
                entry.sector_subheader = EntrySectorSubheader::EndOfFileData;
            }
        }
    }
    for directory in &parsed_iso.directories {
        let entry = parsed_iso
            .manifest
            .entries
            .iter_mut()
            .find(|entry| entry.path == directory.path)
            .context("parsed directory has no manifest entry")?;
        let start = usize::try_from(directory.extent)?;
        let blocks = usize::try_from(directory.length)?.div_ceil(LOGICAL_BLOCK_SIZE);
        if blocks == 0 {
            continue;
        }
        ensure!(
            start + blocks <= sectors.len(),
            "directory extent is outside image"
        );
        let active = (start..start + blocks)
            .filter(|lba| !redump_ranges.iter().any(|range| range.contains(lba)))
            .collect::<Vec<_>>();
        if active.is_empty() {
            continue;
        }
        let data_subheader = entry_file_subheader(entry, FORM1_DATA_SUBHEADER);
        let end_of_file_subheader = entry_file_subheader(entry, SYSTEM_END_OF_FILE_SUBHEADER);
        let metadata_subheader = entry_file_subheader(entry, ISO_METADATA_SUBHEADER);
        let matches = |lba: usize, expected: XaSubheader| {
            sectors[lba].subheader == expected && sectors[lba].subheader_copy == expected
        };
        let final_lba = start + blocks - 1;
        if active.iter().all(|lba| matches(*lba, data_subheader)) && active.contains(&final_lba) {
            entry.sector_subheader = EntrySectorSubheader::Data;
        } else if active.contains(&final_lba)
            && active
                .iter()
                .filter(|lba| **lba != final_lba)
                .all(|lba| matches(*lba, data_subheader))
            && matches(final_lba, end_of_file_subheader)
        {
            entry.sector_subheader = EntrySectorSubheader::EndOfFileData;
        } else if active.contains(&final_lba)
            && active
                .iter()
                .filter(|lba| **lba != final_lba)
                .all(|lba| matches(*lba, data_subheader))
            && matches(final_lba, metadata_subheader)
        {
            entry.sector_subheader = EntrySectorSubheader::DataUntilFinal;
        } else if let Some(first_lba) = active.first().copied()
            && sectors[first_lba].kind == Kind::Form1
            && sectors[first_lba].subheader == sectors[first_lba].subheader_copy
            && sectors[first_lba].subheader != metadata_subheader
        {
            let custom = sectors[first_lba].subheader;
            let prefix_matches = active
                .iter()
                .filter(|lba| **lba != final_lba)
                .all(|lba| matches(*lba, custom));
            let policy =
                if active.contains(&final_lba) && active.iter().all(|lba| matches(*lba, custom)) {
                    Some(EntrySectorSubheader::Data)
                } else if active.contains(&final_lba)
                    && prefix_matches
                    && matches(final_lba, end_of_file_subheader)
                {
                    Some(EntrySectorSubheader::EndOfFileData)
                } else if prefix_matches
                    && (active.contains(&final_lba) && matches(final_lba, metadata_subheader)
                        || !active.contains(&final_lba))
                {
                    Some(EntrySectorSubheader::DataUntilFinal)
                } else {
                    None
                };
            if let Some(policy) = policy {
                entry.sector_subheader = policy;
                entry
                    .xa
                    .get_or_insert_with(crate::manifest::EntryXa::default)
                    .framing_subheader = Some(custom);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
fn validate_iso_subheaders(
    sectors: &[crate::raw_cd::ParsedSector],
    parsed_iso: &iso9660::ParsedIso,
    trailing_gap: usize,
) -> Result<()> {
    validate_iso_subheaders_with_xa_extents(sectors, parsed_iso, trailing_gap, &[], &[])
}

fn validate_iso_subheaders_with_xa_extents(
    sectors: &[crate::raw_cd::ParsedSector],
    parsed_iso: &iso9660::ParsedIso,
    trailing_gap: usize,
    xa_extent_ranges: &[Range<usize>],
    redump_ranges: &[Range<usize>],
) -> Result<()> {
    let content_end = sectors
        .len()
        .checked_sub(trailing_gap)
        .context("trailing gap exceeds track size")?;
    let mut file_sector_info = HashMap::new();
    for file in &parsed_iso.files {
        let blocks = usize::try_from(file.length)?.div_ceil(LOGICAL_BLOCK_SIZE);
        let entry = parsed_iso
            .manifest
            .entries
            .iter()
            .find(|entry| entry.path == file.path)
            .context("parsed file has no manifest entry")?;
        let interleaved = entry_uses_xa_sidecar(entry);
        for block_index in 0..blocks {
            let lba = usize::try_from(file.extent)? + block_index;
            ensure!(lba < content_end, "file extent reaches outside ISO content");
            ensure!(
                file_sector_info
                    .insert(
                        lba,
                        (
                            block_index + 1 == blocks,
                            interleaved,
                            entry.sector_subheader,
                            entry.xa.as_ref().map_or(0, |xa| xa.file_number),
                        ),
                    )
                    .is_none(),
                "overlapping file extents at LBA {lba}"
            );
        }
    }

    let mut directory_sector_info = HashMap::new();
    for directory in &parsed_iso.directories {
        let entry = parsed_iso
            .manifest
            .entries
            .iter()
            .find(|entry| entry.path == directory.path)
            .context("parsed directory has no manifest entry")?;
        let blocks = usize::try_from(directory.length)?.div_ceil(LOGICAL_BLOCK_SIZE);
        for block_index in 0..blocks {
            let lba = usize::try_from(directory.extent)? + block_index;
            ensure!(
                lba < content_end,
                "directory extent reaches outside ISO content"
            );
            ensure!(
                directory_sector_info
                    .insert(lba, {
                        let subheader = match entry.sector_subheader {
                            EntrySectorSubheader::Data => FORM1_DATA_SUBHEADER,
                            EntrySectorSubheader::DataUntilFinal if block_index + 1 < blocks => {
                                FORM1_DATA_SUBHEADER
                            }
                            EntrySectorSubheader::EndOfFileData if block_index + 1 < blocks => {
                                FORM1_DATA_SUBHEADER
                            }
                            EntrySectorSubheader::EndOfFileData => SYSTEM_END_OF_FILE_SUBHEADER,
                            EntrySectorSubheader::Canonical
                            | EntrySectorSubheader::DataUntilFinal
                            | EntrySectorSubheader::IsoMetadata => ISO_METADATA_SUBHEADER,
                        };
                        if subheader == FORM1_DATA_SUBHEADER
                            && let Some(custom) =
                                entry.xa.as_ref().and_then(|xa| xa.framing_subheader)
                        {
                            custom
                        } else {
                            entry_file_subheader(entry, subheader)
                        }
                    })
                    .is_none(),
                "overlapping directory extents at LBA {lba}"
            );
        }
    }

    let mut path_table_sector_info = HashMap::new();
    let mut path_table_padding_sectors = HashSet::new();
    if let Some(path_tables) = &parsed_iso.path_tables {
        for extent in path_tables
            .extents
            .into_iter()
            .filter(|extent| *extent != 0)
        {
            for block_index in 0..path_tables.blocks {
                let lba = usize::try_from(extent + block_index)?;
                ensure!(
                    path_table_sector_info
                        .insert(
                            lba,
                            path_table_subheader(
                                parsed_iso.manifest.path_table_subheader,
                                block_index,
                                path_tables.blocks,
                            ),
                        )
                        .is_none(),
                    "overlapping path-table extents at LBA {lba}"
                );
            }
            let padding_end = path_tables
                .blocks
                .checked_add(parsed_iso.manifest.path_table_padding)
                .context("path-table padding overflow")?;
            for block_index in path_tables.blocks..padding_end {
                let lba = usize::try_from(extent + block_index)?;
                ensure!(
                    path_table_padding_sectors.insert(lba),
                    "overlapping path-table padding at LBA {lba}"
                );
            }
        }
    }
    let mut supplementary_metadata_sectors = HashSet::new();
    for directory in &parsed_iso.supplementary_directories {
        let blocks = directory.length.div_ceil(LOGICAL_BLOCK_SIZE as u32);
        for lba in directory.extent..directory.extent + blocks {
            ensure!(
                usize::try_from(lba).is_ok_and(|lba| lba < content_end),
                "Joliet directory extent reaches outside ISO content"
            );
            supplementary_metadata_sectors.insert(usize::try_from(lba)?);
        }
    }
    if let Some(path_tables) = &parsed_iso.supplementary_path_tables {
        for extent in path_tables
            .extents
            .into_iter()
            .filter(|extent| *extent != 0)
        {
            for lba in extent..extent + path_tables.blocks {
                ensure!(
                    usize::try_from(lba).is_ok_and(|lba| lba < content_end),
                    "Joliet path-table extent reaches outside ISO content"
                );
                supplementary_metadata_sectors.insert(usize::try_from(lba)?);
            }
        }
    }

    for (lba, sector) in sectors.iter().enumerate().take(content_end).skip(16) {
        if xa_extent_ranges.iter().any(|range| range.contains(&lba))
            || redump_ranges.iter().any(|range| range.contains(&lba))
        {
            continue;
        }
        if parsed_iso.metadata_gaps.iter().any(|gap| {
            usize::try_from(gap.start).is_ok_and(|start| {
                usize::try_from(gap.sectors)
                    .is_ok_and(|length| (start..start + length).contains(&lba))
            })
        }) {
            ensure!(
                sector.kind == Kind::XaGap
                    && sector.subheader == XaSubheader::default()
                    && sector.subheader_copy == XaSubheader::default(),
                "metadata gap at LBA {lba} is not a canonical XA gap"
            );
            continue;
        }
        if path_table_padding_sectors.contains(&lba) {
            ensure!(
                sector.kind == Kind::XaGap
                    && sector.subheader == XaSubheader::default()
                    && sector.subheader_copy == XaSubheader::default(),
                "path-table padding at LBA {lba} is not a canonical XA gap"
            );
            continue;
        }
        let is_file_sector = file_sector_info.contains_key(&lba);
        let is_directory_sector = directory_sector_info.contains_key(&lba);
        let is_path_table_sector = path_table_sector_info.contains_key(&lba);
        let context = if is_file_sector {
            "file"
        } else if is_directory_sector {
            "directory"
        } else if is_path_table_sector {
            "path-table"
        } else if supplementary_metadata_sectors.contains(&lba) {
            "Joliet metadata"
        } else {
            "metadata"
        };
        let primary_descriptor =
            (16..16 + usize::from(parsed_iso.manifest.primary_volume_copies)).contains(&lba);
        let supplementary_descriptor = sector.payload()[0] == 2
            && sector.payload()[1..6] == *b"CD001"
            && sector.payload()[6] == 1;
        let volume_descriptor = primary_descriptor || supplementary_descriptor;
        let volume_terminator = sector.payload().starts_with(b"\xffCD001\x01");
        let expected = if volume_descriptor {
            descriptor_metadata_subheader(parsed_iso.manifest.metadata_subheader)
        } else if volume_terminator
            && parsed_iso.manifest.volume_terminator_subheader == VolumeTerminatorSubheader::Pvd
        {
            PVD_SUBHEADER
        } else if let Some((is_last, interleaved, policy, file_number)) = file_sector_info.get(&lba)
        {
            if *interleaved {
                continue;
            }
            let subheader = match policy {
                EntrySectorSubheader::IsoMetadata => ISO_METADATA_SUBHEADER,
                EntrySectorSubheader::Canonical | EntrySectorSubheader::DataUntilFinal
                    if *is_last =>
                {
                    ISO_METADATA_SUBHEADER
                }
                EntrySectorSubheader::EndOfFileData if *is_last => SYSTEM_END_OF_FILE_SUBHEADER,
                EntrySectorSubheader::Canonical
                | EntrySectorSubheader::Data
                | EntrySectorSubheader::EndOfFileData
                | EntrySectorSubheader::DataUntilFinal => FORM1_DATA_SUBHEADER,
            };
            XaSubheader {
                file_number: *file_number,
                ..subheader
            }
        } else if let Some(subheader) = directory_sector_info.get(&lba) {
            *subheader
        } else if let Some(subheader) = path_table_sector_info.get(&lba) {
            *subheader
        } else {
            ordinary_metadata_subheader(parsed_iso.manifest.metadata_subheader)
        };
        if sector.kind == Kind::Form2
            && sector.subheader == FORM2_SUBHEADER
            && sector.subheader_copy == FORM2_SUBHEADER
            && sector.payload().iter().all(|byte| *byte == 0)
        {
            continue;
        }
        if !is_file_sector && !is_directory_sector && is_structured_form1_gap_sector(sector) {
            continue;
        }
        ensure!(
            sector.kind == Kind::Form1,
            "ISO sector at LBA {lba} is not Mode 2 XA Form 1"
        );
        ensure!(
            sector.subheader == expected,
            "ISO {context} sector at LBA {lba} uses XA subheader {:?}, expected {:?}",
            <[u8; 4]>::from(sector.subheader),
            <[u8; 4]>::from(expected)
        );
        ensure!(
            sector.subheader_copy == expected,
            "ISO {context} sector at LBA {lba} uses duplicated XA subheader {:?}, expected {:?}",
            <[u8; 4]>::from(sector.subheader_copy),
            <[u8; 4]>::from(expected)
        );
    }
    for (lba, sector) in sectors.iter().enumerate().skip(content_end) {
        ensure!(
            (sector.kind == Kind::XaGap
                && sector.subheader == XaSubheader::default()
                && sector.subheader_copy == XaSubheader::default())
                || (sector.kind == Kind::RawZero && sector.bytes.iter().all(|byte| *byte == 0)),
            "trailing gap sector at LBA {lba} is nonstandard"
        );
    }
    Ok(())
}

pub fn build(
    manifest_path: &Path,
    image_path: &Path,
    data_dir: &Path,
    overwrite: bool,
) -> Result<BuildReport> {
    build_with_options(
        manifest_path,
        image_path,
        data_dir,
        BuildOptions { overwrite },
    )
}

pub fn build_with_options(
    manifest_path: &Path,
    image_path: &Path,
    data_dir: &Path,
    options: BuildOptions,
) -> Result<BuildReport> {
    validate_output_file(image_path, options.overwrite, "image output")?;
    let temp_path = temporary_path(image_path)?;
    validate_output_file(&temp_path, false, "temporary output")?;
    let yaml = fs::read_to_string(manifest_path)
        .with_context(|| format!("reading manifest {}", manifest_path.display()))?;
    let manifest: Manifest = yaml_serde::from_str(&yaml).context("parsing manifest")?;
    ensure!(
        manifest.gcdgold.version == GCDGOLD_VERSION,
        "manifest gcdgold version {} does not match this gcdgold version {}",
        manifest.gcdgold.version,
        GCDGOLD_VERSION
    );
    validate_manifest_hashes(&manifest).context("validating manifest SHA-1 metadata")?;
    ensure!(
        matches!(manifest.track.mode, TrackMode::Mode1 | TrackMode::Mode2Xa),
        "unsupported track mode {}",
        manifest.track.mode
    );
    iso9660::validate(&manifest.iso9660)?;
    validate_manifest_asset_paths(&manifest)?;

    let system_path = safe_join(data_dir, &manifest.system_area.path)?;
    let system = fs::read(&system_path)
        .with_context(|| format!("reading system asset {}", system_path.display()))?;
    let mut sha1_mismatches = Vec::new();
    record_sha1_mismatch(
        &mut sha1_mismatches,
        Sha1Target::SystemArea {
            path: manifest.system_area.path.clone(),
        },
        manifest.system_area.sha1.as_deref(),
        &system,
    );
    let form1_count = manifest.system_area.form1_sectors.resolve(system.len())?;
    let system_sector_layout =
        expand_system_area_sector_layout(&manifest.system_area, form1_count)?;
    validate_track_structure(&manifest, &system_sector_layout)?;
    let mut system_framing_sectors = HashSet::new();
    for framing in &manifest.system_area.form1_framing {
        ensure!(
            system_sector_layout
                .get(usize::from(framing.sector))
                .is_some_and(|kind| *kind == SystemAreaSectorKind::Form1),
            "system-area Form 1 framing sector does not name a Form 1 sector"
        );
        ensure!(
            !framing
                .subheader
                .submode
                .contains(crate::raw_cd::XaSubmodeFlag::Form2),
            "system-area Form 1 framing cannot declare Form 2"
        );
        ensure!(
            system_framing_sectors.insert(framing.sector),
            "duplicate system-area Form 1 framing sector {}",
            framing.sector
        );
    }
    let mut file_data = HashMap::new();
    let mut file_lengths = HashMap::new();
    let mut mixed_extents = HashMap::new();
    let mut unreferenced_extents = HashMap::new();
    let entries_by_path: HashMap<_, _> = manifest
        .iso9660
        .entries
        .iter()
        .map(|entry| (entry.path.as_str(), entry))
        .collect();
    let mut secondary_paths = HashSet::new();
    for (file, source, ordinary_sha1) in manifest
        .iso9660
        .layout
        .iter()
        .filter_map(FileLayoutItem::as_path_source_with_sha1)
    {
        let entry = entries_by_path[file];
        if entry_uses_xa_sidecar(entry) {
            let xa = entry
                .xa
                .as_ref()
                .context("missing interleaved XA metadata")?;
            let form1_path = xa.form1.as_deref().context("missing XA1 asset path")?;
            let form2_path = xa.form2.as_deref().context("missing XA2 asset path")?;
            let index_path = xa.index.as_deref().context("missing XAI asset path")?;
            let mut assets = Vec::new();
            for (asset, label, expected_sha1) in [
                (form1_path, "XA1", xa.form1_sha1.as_deref()),
                (form2_path, "XA2", xa.form2_sha1.as_deref()),
                (index_path, "XAI", xa.index_sha1.as_deref()),
            ] {
                ensure!(
                    secondary_paths.insert(asset),
                    "duplicate XA secondary asset path {asset}"
                );
                ensure!(
                    asset != manifest.system_area.path,
                    "XA secondary asset path collides with the system asset: {asset}"
                );
                let host_path = safe_join(data_dir, asset)?;
                validate_input_file(&host_path, label)?;
                let data = fs::read(&host_path)
                    .with_context(|| format!("reading {label} asset {}", host_path.display()))?;
                record_sha1_mismatch(
                    &mut sha1_mismatches,
                    Sha1Target::Asset {
                        path: asset.to_owned(),
                    },
                    expected_sha1,
                    &data,
                );
                assets.push(data);
            }
            let gap_index = if let Some(asset) = xa.gap_index.as_deref() {
                ensure!(
                    secondary_paths.insert(asset),
                    "duplicate XA secondary asset path {asset}"
                );
                ensure!(
                    asset != manifest.system_area.path,
                    "XA secondary asset path collides with the system asset: {asset}"
                );
                let host_path = safe_join(data_dir, asset)?;
                validate_input_file(&host_path, "XAG")?;
                let data = fs::read(&host_path)
                    .with_context(|| format!("reading XAG asset {}", host_path.display()))?;
                record_sha1_mismatch(
                    &mut sha1_mismatches,
                    Sha1Target::Asset {
                        path: asset.to_owned(),
                    },
                    xa.gap_index_sha1.as_deref(),
                    &data,
                );
                data
            } else {
                Vec::new()
            };
            let sectors = multiplex_xa_extent(&assets[0], &assets[1], &assets[2], &gap_index)
                .with_context(|| format!("multiplexing {file}"))?;
            let logical_length = xa
                .logical_length
                .map(u64::from)
                .unwrap_or(u64::try_from(sectors.len())? * LOGICAL_BLOCK_SIZE as u64);
            ensure!(
                logical_length.div_ceil(LOGICAL_BLOCK_SIZE as u64) == u64::try_from(sectors.len())?,
                "XA logical length does not match indexed sector count for {file}"
            );
            file_lengths.insert(
                file.to_owned(),
                u64::try_from(sectors.len())? * LOGICAL_BLOCK_SIZE as u64,
            );
            mixed_extents.insert(file.to_owned(), sectors);
        } else {
            let path = safe_join(data_dir, source)?;
            let data = fs::read(&path)
                .with_context(|| format!("reading authored file {}", path.display()))?;
            record_sha1_mismatch(
                &mut sha1_mismatches,
                Sha1Target::Asset {
                    path: source.to_owned(),
                },
                ordinary_sha1,
                &data,
            );
            file_lengths.insert(file.to_owned(), u64::try_from(data.len())?);
            file_data.insert(file.to_owned(), data);
        }
    }
    for assets in manifest
        .iso9660
        .layout
        .iter()
        .filter_map(FileLayoutItem::as_xa_extent)
    {
        let mut data = Vec::new();
        for (asset, label, expected_sha1) in [
            (assets.form1.as_str(), "XA1", assets.form1_sha1.as_deref()),
            (assets.form2.as_str(), "XA2", assets.form2_sha1.as_deref()),
            (assets.index.as_str(), "XAI", assets.index_sha1.as_deref()),
        ] {
            ensure!(
                secondary_paths.insert(asset),
                "duplicate XA secondary asset path {asset}"
            );
            ensure!(
                asset != manifest.system_area.path,
                "XA secondary asset path collides with the system asset: {asset}"
            );
            let host_path = safe_join(data_dir, asset)?;
            validate_input_file(&host_path, label)?;
            let bytes = fs::read(&host_path)
                .with_context(|| format!("reading {label} asset {}", host_path.display()))?;
            record_sha1_mismatch(
                &mut sha1_mismatches,
                Sha1Target::Asset {
                    path: asset.to_owned(),
                },
                expected_sha1,
                &bytes,
            );
            data.push(bytes);
        }
        let gap_index = if let Some(asset) = assets.gap_index.as_deref() {
            ensure!(
                secondary_paths.insert(asset),
                "duplicate XA secondary asset path {asset}"
            );
            ensure!(
                asset != manifest.system_area.path,
                "XA secondary asset path collides with the system asset: {asset}"
            );
            let host_path = safe_join(data_dir, asset)?;
            validate_input_file(&host_path, "XAG")?;
            let data = fs::read(&host_path)
                .with_context(|| format!("reading XAG asset {}", host_path.display()))?;
            record_sha1_mismatch(
                &mut sha1_mismatches,
                Sha1Target::Asset {
                    path: asset.to_owned(),
                },
                assets.gap_index_sha1.as_deref(),
                &data,
            );
            data
        } else {
            Vec::new()
        };
        let sectors = multiplex_xa_extent(&data[0], &data[1], &data[2], &gap_index)
            .with_context(|| format!("multiplexing unreferenced XA extent {}", assets.index))?;
        ensure!(!sectors.is_empty(), "unreferenced XA extent is empty");
        ensure!(
            file_lengths
                .insert(
                    assets.index.clone(),
                    u64::try_from(sectors.len())? * LOGICAL_BLOCK_SIZE as u64,
                )
                .is_none(),
            "duplicate layout data key {}",
            assets.index
        );
        ensure!(
            unreferenced_extents
                .insert(assets.index.clone(), sectors)
                .is_none(),
            "duplicate unreferenced XA extent {}",
            assets.index
        );
    }
    let metadata_gap_kind = match manifest.track.mode {
        TrackMode::Mode1 => GapKind::Mode1,
        TrackMode::Mode2 | TrackMode::Mode2Xa => GapKind::Xa,
    };
    let mut layout = iso9660::layout_with_metadata_gap_kind(
        &manifest.iso9660,
        &file_lengths,
        metadata_gap_kind,
    )?;
    for placement in &layout.files {
        if mixed_extents.contains_key(&placement.path) {
            continue;
        }
        let data = &file_data[&placement.path];
        for block_index in 0..usize::try_from(placement.blocks)? {
            let source_start = block_index * LOGICAL_BLOCK_SIZE;
            let source_end = (source_start + LOGICAL_BLOCK_SIZE).min(data.len());
            if source_start < source_end {
                let target = &mut layout.blocks[usize::try_from(placement.extent)? + block_index];
                target[..source_end - source_start]
                    .copy_from_slice(&data[source_start..source_end]);
            }
        }
    }

    let start_frame = parse_msf(&manifest.track.start_msf)?;
    ensure!(
        !manifest.track.noncompliant_trailing_ecc
            || layout.trailing_gap_kind == Some(crate::manifest::GapKind::Xa),
        "noncompliant_trailing_ecc requires a final XA gap"
    );
    let mut writer = SectorWriter::new();
    let mut raw = Vec::with_capacity(usize::try_from(layout.volume_blocks)? * RAW_SECTOR_SIZE);
    let mut protections = Vec::with_capacity(usize::try_from(layout.volume_blocks)?);
    let padded_system_len = usize::from(form1_count) * LOGICAL_BLOCK_SIZE;
    let final_form1_index = system_sector_layout
        .iter()
        .rposition(|kind| *kind == SystemAreaSectorKind::Form1);
    let mut form1_data_index = 0;
    for (index, kind) in system_sector_layout.iter().copied().enumerate() {
        let frame = start_frame + u32::try_from(index)?;
        match kind {
            SystemAreaSectorKind::Form1 => {
                let mut payload = [0_u8; LOGICAL_BLOCK_SIZE];
                let start = form1_data_index * LOGICAL_BLOCK_SIZE;
                let end = (start + LOGICAL_BLOCK_SIZE).min(system.len());
                if start < end {
                    payload[..end - start].copy_from_slice(&system[start..end]);
                }
                form1_data_index += 1;
                let subheader = if Some(index) == final_form1_index
                    && manifest.system_area.final_form1_subheader
                        == SystemAreaFinalSubheader::EndOfFileData
                {
                    SYSTEM_END_OF_FILE_SUBHEADER
                } else {
                    FORM1_DATA_SUBHEADER
                };
                if manifest.track.mode == TrackMode::Mode1 {
                    append_sector_draft(
                        &mut raw,
                        &mut protections,
                        writer.mode1_draft(frame, &payload)?,
                        SectorProtection::Mode1,
                    );
                } else {
                    if let Some(framing) = manifest
                        .system_area
                        .form1_framing
                        .iter()
                        .find(|framing| usize::from(framing.sector) == index)
                    {
                        append_sector_draft(
                            &mut raw,
                            &mut protections,
                            writer.form1_with_subheaders_draft(
                                frame,
                                framing.subheader,
                                framing.subheader_copy,
                                &payload,
                            )?,
                            SectorProtection::Mode2Form1,
                        );
                    } else {
                        append_sector_draft(
                            &mut raw,
                            &mut protections,
                            writer.form1_draft(frame, subheader, &payload)?,
                            SectorProtection::Mode2Form1,
                        );
                    }
                }
            }
            SystemAreaSectorKind::Form2 => append_sector_draft(
                &mut raw,
                &mut protections,
                writer.form2_draft(frame, FORM2_SUBHEADER, &[0; 2324])?,
                SectorProtection::Mode2Form2 {
                    computed_edc: manifest.track.form2_edc,
                },
            ),
            SystemAreaSectorKind::XaGap => {
                append_sector_draft(
                    &mut raw,
                    &mut protections,
                    writer.xa_gap(frame, XaSubheader::default())?,
                    SectorProtection::None,
                );
            }
        }
    }
    ensure!(
        system.len() <= padded_system_len,
        "system padding calculation failed"
    );

    let mut file_sector_info = HashMap::new();
    for file in &layout.files {
        for block_index in 0..file.blocks {
            file_sector_info.insert(
                file.extent + block_index,
                (
                    file.path.as_str(),
                    usize::try_from(block_index)?,
                    block_index + 1 == file.blocks,
                ),
            );
        }
    }
    let mut unreferenced_sector_info = HashMap::new();
    for extent in &layout.xa_extents {
        let sectors = &unreferenced_extents[&extent.index];
        ensure!(
            sectors.len() == usize::try_from(extent.sectors)?,
            "unreferenced XA extent length changed during layout"
        );
        for block_index in 0..extent.sectors {
            ensure!(
                unreferenced_sector_info
                    .insert(
                        extent.start + block_index,
                        (extent.index.as_str(), usize::try_from(block_index)?),
                    )
                    .is_none(),
                "overlapping unreferenced XA extents"
            );
        }
    }
    for lba in 16..u32::try_from(layout.blocks.len())? {
        if layout
            .gaps
            .iter()
            .any(|gap| lba >= gap.start && lba < gap.start + gap.sectors)
        {
            let gap = layout
                .gaps
                .iter()
                .find(|gap| lba >= gap.start && lba < gap.start + gap.sectors)
                .expect("matched gap placement");
            let (sector, protection) = match gap.kind {
                crate::manifest::GapKind::Mode1 => (
                    writer.mode1_draft(start_frame + lba, &[0; LOGICAL_BLOCK_SIZE])?,
                    SectorProtection::Mode1,
                ),
                crate::manifest::GapKind::Form1 => (
                    writer.form1_draft(
                        start_frame + lba,
                        gap.subheader.expect("validated Form 1 gap subheader"),
                        &[0; LOGICAL_BLOCK_SIZE],
                    )?,
                    SectorProtection::Mode2Form1,
                ),
                crate::manifest::GapKind::Form2 => {
                    let computed_edc = gap.form2_edc.unwrap_or(manifest.track.form2_edc);
                    (
                        writer.form2_draft(
                            start_frame + lba,
                            FORM2_SUBHEADER,
                            &[0; FORM2_PAYLOAD_SIZE],
                        )?,
                        SectorProtection::Mode2Form2 { computed_edc },
                    )
                }
                crate::manifest::GapKind::Xa => {
                    if manifest.track.mode == TrackMode::Mode1 {
                        (
                            writer.mode1_draft(start_frame + lba, &[0; LOGICAL_BLOCK_SIZE])?,
                            SectorProtection::Mode1,
                        )
                    } else {
                        (
                            writer.xa_gap(start_frame + lba, XaSubheader::default())?,
                            SectorProtection::None,
                        )
                    }
                }
                crate::manifest::GapKind::RawZero => {
                    (vec![0; RAW_SECTOR_SIZE], SectorProtection::None)
                }
            };
            append_sector_draft(&mut raw, &mut protections, sector, protection);
            continue;
        }
        if let Some((path, block_index, _)) = file_sector_info.get(&lba)
            && let Some(sectors) = mixed_extents.get(*path)
        {
            write_xa_extent_sector(
                &mut raw,
                &mut protections,
                &mut writer,
                start_frame + lba,
                &sectors[*block_index],
                manifest.track.form2_edc,
            )?;
            continue;
        }
        if let Some((index, block_index)) = unreferenced_sector_info.get(&lba) {
            write_xa_extent_sector(
                &mut raw,
                &mut protections,
                &mut writer,
                start_frame + lba,
                &unreferenced_extents[*index][*block_index],
                manifest.track.form2_edc,
            )?;
            continue;
        }
        let framing_subheader = layout.framing_subheader_sectors.get(&lba).copied();
        let primary_descriptor =
            (16..16 + u32::from(manifest.iso9660.primary_volume_copies)).contains(&lba);
        let supplementary_descriptor = layout.blocks[usize::try_from(lba)?][0] == 2
            && layout.blocks[usize::try_from(lba)?][1..6] == *b"CD001"
            && layout.blocks[usize::try_from(lba)?][6] == 1;
        let volume_descriptor = primary_descriptor || supplementary_descriptor;
        let volume_terminator = layout.blocks[usize::try_from(lba)?].starts_with(b"\xffCD001\x01");
        let mut subheader = if let Some(subheader) = framing_subheader {
            subheader
        } else if volume_descriptor {
            descriptor_metadata_subheader(manifest.iso9660.metadata_subheader)
        } else if volume_terminator
            && manifest.iso9660.volume_terminator_subheader == VolumeTerminatorSubheader::Pvd
        {
            PVD_SUBHEADER
        } else if layout.data_subheader_sectors.contains(&lba) {
            FORM1_DATA_SUBHEADER
        } else if layout.end_of_file_data_subheader_sectors.contains(&lba) {
            SYSTEM_END_OF_FILE_SUBHEADER
        } else if layout.metadata_subheader_sectors.contains(&lba) {
            match manifest.iso9660.metadata_subheader {
                MetadataSubheader::Explicit(subheader) => subheader,
                MetadataSubheader::Named(_) => ISO_METADATA_SUBHEADER,
            }
        } else if let Some((_, _, is_last)) = file_sector_info.get(&lba) {
            if *is_last {
                ISO_METADATA_SUBHEADER
            } else {
                FORM1_DATA_SUBHEADER
            }
        } else {
            ordinary_metadata_subheader(manifest.iso9660.metadata_subheader)
        };
        if framing_subheader.is_none()
            && let Some(file_number) = layout.sector_file_numbers.get(&lba)
        {
            subheader.file_number = *file_number;
        }
        let block = &layout.blocks[usize::try_from(lba)?];
        if manifest.track.mode == TrackMode::Mode1 {
            append_sector_draft(
                &mut raw,
                &mut protections,
                writer.mode1_draft(start_frame + lba, block)?,
                SectorProtection::Mode1,
            );
        } else {
            append_sector_draft(
                &mut raw,
                &mut protections,
                writer.form1_draft(start_frame + lba, subheader, block)?,
                SectorProtection::Mode2Form1,
            );
        }
    }
    for lba in u32::try_from(layout.blocks.len())?..layout.volume_blocks {
        let (sector, protection) = match layout
            .trailing_gap_kind
            .context("physical track tail has no gap kind")?
        {
            crate::manifest::GapKind::Xa => {
                if manifest.track.noncompliant_trailing_ecc && lba + 1 == layout.volume_blocks {
                    (
                        writer.xa_gap(start_frame + lba, XaSubheader::default())?,
                        SectorProtection::RecordedHeaderEcc,
                    )
                } else {
                    (
                        writer.xa_gap(start_frame + lba, XaSubheader::default())?,
                        SectorProtection::None,
                    )
                }
            }
            crate::manifest::GapKind::RawZero => (vec![0; RAW_SECTOR_SIZE], SectorProtection::None),
            crate::manifest::GapKind::Mode1
            | crate::manifest::GapKind::Form1
            | crate::manifest::GapKind::Form2 => {
                unreachable!("validated terminal gap kind")
            }
        };
        append_sector_draft(&mut raw, &mut protections, sector, protection);
    }

    finalize_track_protection(&mut raw, &protections)?;

    apply_redump_0x55(&mut raw, start_frame, &manifest.track.redump_0x55)
        .context("applying structural Redump 0x55 runs")?;

    apply_sector_patches(&mut raw, start_frame, &manifest.track.patches)
        .context("applying raw-sector patches")?;

    let sha1 = sha1_hex(&raw);
    if manifest
        .track
        .sha1
        .as_deref()
        .is_some_and(|expected| !sha1.eq_ignore_ascii_case(expected))
    {
        sha1_mismatches.push(Sha1Mismatch {
            target: Sha1Target::Track,
            expected: manifest.track.sha1.clone().expect("checked track SHA-1"),
            actual: sha1.clone(),
        });
    }
    create_output_parent(image_path, "image output")?;
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp_path)
        .with_context(|| format!("creating temporary image {}", temp_path.display()))?;
    output.write_all(&raw)?;
    output.sync_all()?;
    drop(output);
    install_image(&temp_path, image_path, options.overwrite)?;
    Ok(BuildReport {
        sectors: layout.volume_blocks,
        sha1,
        sha1_mismatches,
    })
}

fn read_extent(blocks: &[[u8; LOGICAL_BLOCK_SIZE]], extent: u32, length: u32) -> Result<Vec<u8>> {
    let start = usize::try_from(extent)?;
    let count = usize::try_from(length)?.div_ceil(LOGICAL_BLOCK_SIZE);
    ensure!(
        start + count <= blocks.len(),
        "file extent is outside image"
    );
    let mut data = Vec::with_capacity(count * LOGICAL_BLOCK_SIZE);
    for block in &blocks[start..start + count] {
        data.extend_from_slice(block);
    }
    data.truncate(usize::try_from(length)?);
    Ok(data)
}

fn safe_join(base: &Path, relative: &str) -> Result<PathBuf> {
    let path = Path::new(relative);
    ensure!(!relative.is_empty(), "manifest path must not be empty");
    ensure!(
        !path.is_absolute(),
        "manifest path must be relative: {relative}"
    );
    ensure!(
        path.components()
            .all(|component| matches!(component, Component::Normal(_))),
        "manifest path contains traversal or non-normal components: {relative}"
    );
    Ok(base.join(path))
}

fn create_output_parent(path: &Path, label: &str) -> Result<()> {
    let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    else {
        return Ok(());
    };
    fs::create_dir_all(parent)
        .with_context(|| format!("creating {label} directory {}", parent.display()))
}

struct ExtractionWritePlan {
    system: bool,
    assets: HashSet<String>,
}

fn extraction_asset_paths(manifest: &Manifest) -> Result<Vec<String>> {
    let entries_by_path = manifest
        .iso9660
        .entries
        .iter()
        .map(|entry| (entry.path.as_str(), entry))
        .collect::<HashMap<_, _>>();
    let mut paths = vec![manifest.system_area.path.clone()];
    for item in &manifest.iso9660.layout {
        match item {
            FileLayoutItem::Path(file) => {
                let entry = entries_by_path
                    .get(file.path.as_str())
                    .with_context(|| format!("file layout names unknown entry {}", file.path))?;
                if entry_uses_xa_sidecar(entry) {
                    let xa = entry.xa.as_ref().context("missing indexed XA metadata")?;
                    paths.extend(
                        [
                            xa.form1.as_ref(),
                            xa.form2.as_ref(),
                            xa.index.as_ref(),
                            xa.gap_index.as_ref(),
                        ]
                        .into_iter()
                        .flatten()
                        .cloned(),
                    );
                } else {
                    paths.push(file.source.clone().unwrap_or_else(|| file.path.clone()));
                }
            }
            FileLayoutItem::XaExtent(item) => {
                let xa = &item.xa_extent;
                paths.extend([xa.form1.clone(), xa.form2.clone(), xa.index.clone()]);
                paths.extend(xa.gap_index.iter().cloned());
            }
            FileLayoutItem::Directory(_) | FileLayoutItem::Gap(_) => {}
        }
    }
    Ok(paths)
}

fn numbered_asset_family(path: &str) -> Result<(String, String, u64)> {
    let (parent, file_name) = path
        .rsplit_once('/')
        .map_or(("", path), |(parent, file_name)| (parent, file_name));
    let (stem, number) = match file_name.rsplit_once('.') {
        Some((stem, suffix))
            if !suffix.is_empty() && suffix.bytes().all(|byte| byte.is_ascii_digit()) =>
        {
            let number = suffix
                .parse::<u64>()
                .with_context(|| format!("numeric asset suffix is too large: {path}"))?
                .checked_add(1)
                .with_context(|| format!("numeric asset suffix cannot be incremented: {path}"))?;
            (stem, number)
        }
        _ => (file_name, 1),
    };
    Ok((parent.to_owned(), stem.to_owned(), number))
}

fn numbered_asset_path(parent: &str, stem: &str, number: u64) -> String {
    if parent.is_empty() {
        format!("{stem}.{number}")
    } else {
        format!("{parent}/{stem}.{number}")
    }
}

fn existing_asset_matches(path: &Path, expected_sha1: &str) -> Result<bool> {
    let bytes = fs::read(path)
        .with_context(|| format!("reading existing extraction asset {}", path.display()))?;
    Ok(sha1_hex(&bytes) == expected_sha1)
}

fn resolve_extraction_asset_path(
    nominal: &str,
    bytes: &[u8],
    data_dir: &Path,
    overwrite: bool,
    reserved: &HashSet<String>,
    selected: &mut HashSet<String>,
) -> Result<(String, bool)> {
    let nominal_output = safe_join(data_dir, nominal)?;
    validate_output_ancestors(data_dir, nominal)?;
    if overwrite {
        validate_output_file(&nominal_output, true, "extraction output")?;
        ensure!(
            selected.insert(nominal.to_owned()),
            "duplicate selected extraction asset path {nominal}"
        );
        return Ok((nominal.to_owned(), true));
    }

    let expected_sha1 = sha1_hex(bytes);
    match output_metadata(&nominal_output)? {
        None => {
            ensure!(
                selected.insert(nominal.to_owned()),
                "duplicate selected extraction asset path {nominal}"
            );
            return Ok((nominal.to_owned(), true));
        }
        Some(metadata) => {
            ensure!(
                !metadata.file_type().is_symlink(),
                "extraction output is a symlink: {}",
                nominal_output.display()
            );
            ensure!(
                metadata.is_file(),
                "extraction output is not a regular file: {}",
                nominal_output.display()
            );
            if existing_asset_matches(&nominal_output, &expected_sha1)? {
                ensure!(
                    selected.insert(nominal.to_owned()),
                    "duplicate selected extraction asset path {nominal}"
                );
                return Ok((nominal.to_owned(), false));
            }
        }
    }

    let (parent, stem, mut number) = numbered_asset_family(nominal)?;
    loop {
        let candidate = numbered_asset_path(&parent, &stem, number);
        number = number
            .checked_add(1)
            .context("numeric extraction asset suffix overflow")?;
        if reserved.contains(&candidate) || selected.contains(&candidate) {
            continue;
        }
        let output = safe_join(data_dir, &candidate)?;
        validate_output_ancestors(data_dir, &candidate)?;
        match output_metadata(&output)? {
            None => {
                ensure!(selected.insert(candidate.clone()));
                return Ok((candidate, true));
            }
            Some(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {
                if existing_asset_matches(&output, &expected_sha1)? {
                    ensure!(selected.insert(candidate.clone()));
                    return Ok((candidate, false));
                }
            }
            Some(_) => {}
        }
    }
}

fn validate_output_ancestors(base: &Path, relative: &str) -> Result<()> {
    let relative = Path::new(relative);
    let mut current = base.to_path_buf();
    let component_count = relative.components().count();
    for component in relative
        .components()
        .take(component_count.saturating_sub(1))
    {
        let Component::Normal(component) = component else {
            anyhow::bail!("manifest path contains traversal or non-normal components: {relative:?}")
        };
        current.push(component);
        match fs::symlink_metadata(&current) {
            Ok(metadata) => {
                ensure!(
                    !metadata.file_type().is_symlink(),
                    "extraction output parent is a symlink: {}",
                    current.display()
                );
                ensure!(
                    metadata.is_dir(),
                    "extraction output parent is not a directory: {}",
                    current.display()
                );
            }
            Err(error) if error.kind() == ErrorKind::NotFound => break,
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("inspecting output parent {}", current.display()));
            }
        }
    }
    Ok(())
}

fn resolve_mapped_extraction_asset(
    path: &mut String,
    assets: &mut HashMap<String, Vec<u8>>,
    data_dir: &Path,
    overwrite: bool,
    reserved: &HashSet<String>,
    selected: &mut HashSet<String>,
    writes: &mut HashSet<String>,
) -> Result<()> {
    let nominal = path.clone();
    let bytes = assets
        .remove(&nominal)
        .with_context(|| format!("missing extracted asset {nominal} during output planning"))?;
    let (resolved, write) =
        resolve_extraction_asset_path(&nominal, &bytes, data_dir, overwrite, reserved, selected)?;
    if write {
        writes.insert(resolved.clone());
    }
    *path = resolved.clone();
    ensure!(
        assets.insert(resolved.clone(), bytes).is_none(),
        "resolved extraction asset path collides with another asset: {resolved}"
    );
    Ok(())
}

fn plan_extraction_outputs(
    manifest: &mut Manifest,
    assets: &mut HashMap<String, Vec<u8>>,
    system: &[u8],
    data_dir: &Path,
    overwrite: bool,
) -> Result<ExtractionWritePlan> {
    validate_data_directory(data_dir)?;
    validate_manifest_asset_paths(manifest)?;
    let reserved = extraction_asset_paths(manifest)?
        .into_iter()
        .collect::<HashSet<_>>();
    let mut selected = HashSet::new();
    let mut writes = HashSet::new();
    let (system_path, write_system) = resolve_extraction_asset_path(
        &manifest.system_area.path,
        system,
        data_dir,
        overwrite,
        &reserved,
        &mut selected,
    )?;
    manifest.system_area.path = system_path;

    for item_index in 0..manifest.iso9660.layout.len() {
        let snapshot = manifest.iso9660.layout[item_index].clone();
        match snapshot {
            FileLayoutItem::Path(file) => {
                let entry_index = manifest
                    .iso9660
                    .entries
                    .iter()
                    .position(|entry| entry.path == file.path)
                    .with_context(|| format!("file layout names unknown entry {}", file.path))?;
                if entry_uses_xa_sidecar(&manifest.iso9660.entries[entry_index]) {
                    let xa = manifest.iso9660.entries[entry_index]
                        .xa
                        .as_mut()
                        .context("missing indexed XA metadata")?;
                    for path in [
                        &mut xa.form1,
                        &mut xa.form2,
                        &mut xa.index,
                        &mut xa.gap_index,
                    ]
                    .into_iter()
                    .flatten()
                    {
                        resolve_mapped_extraction_asset(
                            path,
                            assets,
                            data_dir,
                            overwrite,
                            &reserved,
                            &mut selected,
                            &mut writes,
                        )?;
                    }
                } else {
                    let nominal = file.source.unwrap_or_else(|| file.path.clone());
                    let mut resolved = nominal;
                    resolve_mapped_extraction_asset(
                        &mut resolved,
                        assets,
                        data_dir,
                        overwrite,
                        &reserved,
                        &mut selected,
                        &mut writes,
                    )?;
                    let FileLayoutItem::Path(item) = &mut manifest.iso9660.layout[item_index]
                    else {
                        unreachable!("snapshot preserves file layout kind")
                    };
                    item.source = (resolved != item.path).then_some(resolved);
                }
            }
            FileLayoutItem::XaExtent(_) => {
                let FileLayoutItem::XaExtent(item) = &mut manifest.iso9660.layout[item_index]
                else {
                    unreachable!("snapshot preserves file layout kind")
                };
                let xa = &mut item.xa_extent;
                for path in [&mut xa.form1, &mut xa.form2, &mut xa.index] {
                    resolve_mapped_extraction_asset(
                        path,
                        assets,
                        data_dir,
                        overwrite,
                        &reserved,
                        &mut selected,
                        &mut writes,
                    )?;
                }
                if let Some(path) = &mut xa.gap_index {
                    resolve_mapped_extraction_asset(
                        path,
                        assets,
                        data_dir,
                        overwrite,
                        &reserved,
                        &mut selected,
                        &mut writes,
                    )?;
                }
            }
            FileLayoutItem::Directory(_) | FileLayoutItem::Gap(_) => {}
        }
    }
    validate_manifest_asset_paths(manifest)?;
    ensure!(
        selected.len() == assets.len() + 1,
        "extraction output planning did not resolve every asset"
    );
    Ok(ExtractionWritePlan {
        system: write_system,
        assets: writes,
    })
}

fn validate_data_directory(path: &Path) -> Result<()> {
    let Some(metadata) = output_metadata(path)? else {
        return Ok(());
    };
    ensure!(
        !metadata.file_type().is_symlink(),
        "data directory is a symlink: {}",
        path.display()
    );
    ensure!(
        metadata.is_dir(),
        "data directory is not a directory: {}",
        path.display()
    );
    Ok(())
}

fn validate_output_file(path: &Path, overwrite: bool, label: &str) -> Result<()> {
    let Some(metadata) = output_metadata(path)? else {
        return Ok(());
    };
    ensure!(overwrite, "{label} already exists: {}", path.display());
    ensure!(
        !metadata.file_type().is_symlink(),
        "{label} is a symlink: {}",
        path.display()
    );
    ensure!(
        metadata.is_file(),
        "{label} is not a regular file: {}",
        path.display()
    );
    Ok(())
}

fn validate_input_file(path: &Path, label: &str) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspecting {label} {}", path.display()))?;
    ensure!(
        !metadata.file_type().is_symlink(),
        "{label} is a symlink: {}",
        path.display()
    );
    ensure!(
        metadata.is_file(),
        "{label} is not a regular file: {}",
        path.display()
    );
    Ok(())
}

fn validate_output_directory(path: &Path, label: &str) -> Result<()> {
    let Some(metadata) = output_metadata(path)? else {
        return Ok(());
    };
    ensure!(
        !metadata.file_type().is_symlink(),
        "{label} is a symlink: {}",
        path.display()
    );
    ensure!(
        metadata.is_dir(),
        "{label} is not a directory: {}",
        path.display()
    );
    Ok(())
}

fn output_metadata(path: &Path) -> Result<Option<fs::Metadata>> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => Ok(Some(metadata)),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| format!("inspecting output {}", path.display())),
    }
}

fn manifest_stem(path: &Path) -> Result<&str> {
    path.file_stem()
        .and_then(|value| value.to_str())
        .context("manifest path has no UTF-8 file stem")
}

fn temporary_path(path: &Path) -> Result<PathBuf> {
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .context("image path has no UTF-8 file name")?;
    Ok(path.with_file_name(format!(".{file_name}.gcdgold.tmp")))
}

fn install_image(temp_path: &Path, image_path: &Path, _overwrite: bool) -> Result<()> {
    #[cfg(windows)]
    if _overwrite {
        match fs::remove_file(image_path) {
            Ok(()) => {}
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("replacing image {}", image_path.display()));
            }
        }
    }
    fs::rename(temp_path, image_path)
        .with_context(|| format!("installing image {}", image_path.display()))
}

fn sha1_hex(bytes: &[u8]) -> String {
    hex::encode(Sha1::digest(bytes))
}

fn validate_sha1_value(value: &str, label: &str) -> Result<()> {
    ensure!(
        value.len() == 40 && value.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "{label} must be a 40-character hexadecimal SHA-1"
    );
    Ok(())
}

fn validate_optional_sha1(value: Option<&str>, label: &str) -> Result<()> {
    if let Some(value) = value {
        validate_sha1_value(value, label)?;
    }
    Ok(())
}

fn validate_xa_asset_hashes(xa: &crate::manifest::EntryXa, owner: &str) -> Result<()> {
    for (path, sha1, label) in [
        (xa.form1.as_deref(), xa.form1_sha1.as_deref(), "form1_sha1"),
        (xa.form2.as_deref(), xa.form2_sha1.as_deref(), "form2_sha1"),
        (xa.index.as_deref(), xa.index_sha1.as_deref(), "index_sha1"),
        (
            xa.gap_index.as_deref(),
            xa.gap_index_sha1.as_deref(),
            "gap_index_sha1",
        ),
    ] {
        ensure!(
            sha1.is_none() || path.is_some(),
            "{owner} {label} requires its corresponding asset path"
        );
        validate_optional_sha1(sha1, &format!("{owner} {label}"))?;
    }
    Ok(())
}

fn validate_manifest_hashes(manifest: &Manifest) -> Result<()> {
    validate_optional_sha1(manifest.track.sha1.as_deref(), "track sha1")?;
    validate_optional_sha1(manifest.system_area.sha1.as_deref(), "system-area sha1")?;
    let entries_by_path = manifest
        .iso9660
        .entries
        .iter()
        .map(|entry| (entry.path.as_str(), entry))
        .collect::<HashMap<_, _>>();
    for item in &manifest.iso9660.layout {
        match item {
            FileLayoutItem::Path(file) => {
                validate_optional_sha1(file.sha1.as_deref(), &format!("asset {} sha1", file.path))?;
                if entries_by_path
                    .get(file.path.as_str())
                    .is_some_and(|entry| entry_uses_xa_sidecar(entry))
                {
                    ensure!(
                        file.source.is_none(),
                        "indexed XA file {} cannot declare an ordinary-file source",
                        file.path
                    );
                    ensure!(
                        file.sha1.is_none(),
                        "indexed XA file {} cannot declare an ordinary-file sha1",
                        file.path
                    );
                }
            }
            FileLayoutItem::XaExtent(item) => {
                let assets = &item.xa_extent;
                for (path, sha1, label) in [
                    (
                        Some(assets.form1.as_str()),
                        assets.form1_sha1.as_deref(),
                        "form1_sha1",
                    ),
                    (
                        Some(assets.form2.as_str()),
                        assets.form2_sha1.as_deref(),
                        "form2_sha1",
                    ),
                    (
                        Some(assets.index.as_str()),
                        assets.index_sha1.as_deref(),
                        "index_sha1",
                    ),
                    (
                        assets.gap_index.as_deref(),
                        assets.gap_index_sha1.as_deref(),
                        "gap_index_sha1",
                    ),
                ] {
                    ensure!(
                        sha1.is_none() || path.is_some(),
                        "unreferenced XA {label} requires its corresponding asset path"
                    );
                    validate_optional_sha1(sha1, &format!("unreferenced XA {label}"))?;
                }
            }
            FileLayoutItem::Directory(_) | FileLayoutItem::Gap(_) => {}
        }
    }
    for entry in &manifest.iso9660.entries {
        if let Some(xa) = &entry.xa {
            validate_xa_asset_hashes(xa, &format!("entry {}", entry.path))?;
        }
        if let Some(xa) = &entry.directory_self_xa {
            validate_xa_asset_hashes(xa, &format!("entry {} directory_self_xa", entry.path))?;
        }
    }
    for volume in &manifest.iso9660.supplementary_volumes {
        for entry in &volume.entries {
            if let Some(xa) = &entry.xa {
                validate_xa_asset_hashes(xa, &format!("Joliet entry {}", entry.path))?;
            }
            if let Some(xa) = &entry.directory_self_xa {
                validate_xa_asset_hashes(
                    xa,
                    &format!("Joliet entry {} directory_self_xa", entry.path),
                )?;
            }
        }
    }
    Ok(())
}

fn validate_manifest_asset_paths(manifest: &Manifest) -> Result<()> {
    let entries_by_path = manifest
        .iso9660
        .entries
        .iter()
        .map(|entry| (entry.path.as_str(), entry))
        .collect::<HashMap<_, _>>();
    let mut paths = HashSet::new();
    let mut register = |path: &str, owner: &str| -> Result<()> {
        safe_join(Path::new("."), path)
            .with_context(|| format!("validating authored asset path for {owner}"))?;
        ensure!(
            paths.insert(path.to_owned()),
            "duplicate authored asset path {path}"
        );
        Ok(())
    };
    register(&manifest.system_area.path, "system area")?;
    for item in &manifest.iso9660.layout {
        match item {
            FileLayoutItem::Path(file) => {
                let entry = entries_by_path
                    .get(file.path.as_str())
                    .with_context(|| format!("file layout names unknown entry {}", file.path))?;
                if entry_uses_xa_sidecar(entry) {
                    let xa = entry.xa.as_ref().context("missing indexed XA metadata")?;
                    for (path, label) in [
                        (xa.form1.as_deref(), "XA1"),
                        (xa.form2.as_deref(), "XA2"),
                        (xa.index.as_deref(), "XAI"),
                        (xa.gap_index.as_deref(), "XAG"),
                    ] {
                        if let Some(path) = path {
                            register(path, &format!("{} {label}", file.path))?;
                        }
                    }
                } else {
                    register(
                        file.source.as_deref().unwrap_or(&file.path),
                        &format!("ordinary file {}", file.path),
                    )?;
                }
            }
            FileLayoutItem::XaExtent(item) => {
                let xa = &item.xa_extent;
                for (path, label) in [
                    (Some(xa.form1.as_str()), "XA1"),
                    (Some(xa.form2.as_str()), "XA2"),
                    (Some(xa.index.as_str()), "XAI"),
                    (xa.gap_index.as_deref(), "XAG"),
                ] {
                    if let Some(path) = path {
                        register(path, &format!("unreferenced {label}"))?;
                    }
                }
            }
            FileLayoutItem::Directory(_) | FileLayoutItem::Gap(_) => {}
        }
    }
    Ok(())
}

fn record_sha1_mismatch(
    mismatches: &mut Vec<Sha1Mismatch>,
    target: Sha1Target,
    expected: Option<&str>,
    bytes: &[u8],
) {
    let Some(expected) = expected else {
        return;
    };
    let actual = sha1_hex(bytes);
    if !actual.eq_ignore_ascii_case(expected) {
        mismatches.push(Sha1Mismatch {
            target,
            expected: expected.to_owned(),
            actual,
        });
    }
}

fn set_extracted_asset_sha1(
    path: &str,
    destination: &mut Option<String>,
    assets: &HashMap<String, Vec<u8>>,
    hashed_paths: &mut HashSet<String>,
) -> Result<()> {
    let bytes = assets
        .get(path)
        .with_context(|| format!("missing extracted asset {path} while hashing"))?;
    *destination = Some(sha1_hex(bytes));
    ensure!(
        hashed_paths.insert(path.to_owned()),
        "duplicate extracted asset hash path {path}"
    );
    Ok(())
}

fn add_extracted_hashes(
    manifest: &mut Manifest,
    source_sha1: &str,
    system: &[u8],
    assets: &HashMap<String, Vec<u8>>,
) -> Result<()> {
    manifest.track.sha1 = Some(source_sha1.to_owned());
    manifest.system_area.sha1 = Some(sha1_hex(system));
    let indexed_paths = manifest
        .iso9660
        .entries
        .iter()
        .filter(|entry| entry_uses_xa_sidecar(entry))
        .map(|entry| entry.path.clone())
        .collect::<HashSet<_>>();
    let mut hashed_paths = HashSet::new();
    for item in &mut manifest.iso9660.layout {
        match item {
            FileLayoutItem::Path(file) if !indexed_paths.contains(&file.path) => {
                let path = file.source.as_deref().unwrap_or(&file.path);
                set_extracted_asset_sha1(path, &mut file.sha1, assets, &mut hashed_paths)?;
            }
            FileLayoutItem::XaExtent(item) => {
                let xa = &mut item.xa_extent;
                set_extracted_asset_sha1(&xa.form1, &mut xa.form1_sha1, assets, &mut hashed_paths)?;
                set_extracted_asset_sha1(&xa.form2, &mut xa.form2_sha1, assets, &mut hashed_paths)?;
                set_extracted_asset_sha1(&xa.index, &mut xa.index_sha1, assets, &mut hashed_paths)?;
                if let Some(path) = xa.gap_index.as_deref() {
                    set_extracted_asset_sha1(
                        path,
                        &mut xa.gap_index_sha1,
                        assets,
                        &mut hashed_paths,
                    )?;
                }
            }
            FileLayoutItem::Path(_) | FileLayoutItem::Directory(_) | FileLayoutItem::Gap(_) => {}
        }
    }
    for entry in &mut manifest.iso9660.entries {
        let Some(xa) = entry.xa.as_mut().filter(|xa| xa.form1.is_some()) else {
            continue;
        };
        for (path, destination) in [
            (xa.form1.as_deref(), &mut xa.form1_sha1),
            (xa.form2.as_deref(), &mut xa.form2_sha1),
            (xa.index.as_deref(), &mut xa.index_sha1),
            (xa.gap_index.as_deref(), &mut xa.gap_index_sha1),
        ] {
            if let Some(path) = path {
                set_extracted_asset_sha1(path, destination, assets, &mut hashed_paths)?;
            }
        }
    }
    ensure!(
        hashed_paths.len() == assets.len() && assets.keys().all(|path| hashed_paths.contains(path)),
        "not every extracted host asset received a SHA-1"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::{Entry, SectorPatch, format_sector_patch_hex};

    fn test_manifest() -> Manifest {
        yaml_serde::from_str(&format!(
            "gcdgold:\n\
             \x20 version: {GCDGOLD_VERSION}\n\
             track:\n\
             \x20 mode: 2xa\n\
             system_area:\n\
             \x20 path: sample.system\n\
             \x20 form1_sectors: auto\n\
             iso9660:\n\
             \x20 primary_volume: {{}}\n\
             \x20 entries:\n\
             \x20 - path: .\n\
             \x20   recording_time: 1998-03-19T11:58:36+09:00\n\
             \x20 - path: FILE.BIN\n\
             \x20   recording_time: 1998-03-19T11:58:36+09:00\n\
             \x20 layout:\n\
             \x20 - path: FILE.BIN\n"
        ))
        .unwrap()
    }

    #[test]
    fn parallel_bulk_protection_matches_synchronous_sector_writing() {
        let mut writer = SectorWriter::new();
        let form1_subheader: XaSubheader = [1, 2, 0x08, 4].into();
        let form2_subheader: XaSubheader = [5, 6, 0x20, 7].into();
        let expected = [
            writer.mode1(150, &[0x11; LOGICAL_BLOCK_SIZE]).unwrap(),
            writer
                .form1(151, form1_subheader, &[0x22; LOGICAL_BLOCK_SIZE])
                .unwrap(),
            writer
                .form2(152, form2_subheader, &[0x33; FORM2_PAYLOAD_SIZE], true)
                .unwrap(),
            writer
                .form2(153, form2_subheader, &[0x44; FORM2_PAYLOAD_SIZE], false)
                .unwrap(),
            writer.xa_gap(154, XaSubheader::default()).unwrap(),
            vec![0; RAW_SECTOR_SIZE],
            writer
                .xa_gap_with_recorded_header_ecc(156, XaSubheader::default())
                .unwrap(),
        ]
        .concat();

        let drafts = [
            (
                writer
                    .mode1_draft(150, &[0x11; LOGICAL_BLOCK_SIZE])
                    .unwrap(),
                SectorProtection::Mode1,
            ),
            (
                writer
                    .form1_draft(151, form1_subheader, &[0x22; LOGICAL_BLOCK_SIZE])
                    .unwrap(),
                SectorProtection::Mode2Form1,
            ),
            (
                writer
                    .form2_draft(152, form2_subheader, &[0x33; FORM2_PAYLOAD_SIZE])
                    .unwrap(),
                SectorProtection::Mode2Form2 { computed_edc: true },
            ),
            (
                writer
                    .form2_draft(153, form2_subheader, &[0x44; FORM2_PAYLOAD_SIZE])
                    .unwrap(),
                SectorProtection::Mode2Form2 {
                    computed_edc: false,
                },
            ),
            (
                writer.xa_gap(154, XaSubheader::default()).unwrap(),
                SectorProtection::None,
            ),
            (vec![0; RAW_SECTOR_SIZE], SectorProtection::None),
            (
                writer.xa_gap(156, XaSubheader::default()).unwrap(),
                SectorProtection::RecordedHeaderEcc,
            ),
        ];
        let mut raw = Vec::new();
        let mut protections = Vec::new();
        for (sector, protection) in drafts {
            append_sector_draft(&mut raw, &mut protections, sector, protection);
        }
        finalize_track_protection(&mut raw, &protections).unwrap();
        assert_eq!(raw, expected);

        assert_eq!(
            finalize_track_protection(&mut raw, &protections[..protections.len() - 1])
                .unwrap_err()
                .to_string(),
            "authored raw sector and protection policy counts differ"
        );
    }

    #[test]
    fn mode1_track_accepts_only_mode1_physical_framing() {
        let mut manifest = test_manifest();
        manifest.track.mode = TrackMode::Mode1;
        manifest.iso9660.layout.push(FileLayoutItem::mode1_gap(150));
        let system_layout = vec![SystemAreaSectorKind::Form1; SYSTEM_AREA_SECTORS];

        validate_track_structure(&manifest, &system_layout).unwrap();

        manifest.iso9660.metadata_subheader = MetadataSubheader::Explicit(XaSubheader::default());
        assert!(validate_track_structure(&manifest, &system_layout).is_err());
        manifest.iso9660.metadata_subheader = MetadataSubheader::default();

        manifest.iso9660.layout.pop();
        manifest.iso9660.layout.push(FileLayoutItem::gap(150));
        assert_eq!(
            validate_track_structure(&manifest, &system_layout)
                .unwrap_err()
                .to_string(),
            "Mode 1 tracks may contain only Mode 1 or terminal raw-zero gaps"
        );
    }

    fn parsed_iso() -> iso9660::ParsedIso {
        iso9660::ParsedIso {
            manifest: test_manifest().iso9660,
            files: vec![iso9660::ParsedFile {
                path: "FILE.BIN".to_owned(),
                extent: 17,
                length: LOGICAL_BLOCK_SIZE as u32,
            }],
            directories: Vec::new(),
            path_tables: None,
            supplementary_directories: Vec::new(),
            supplementary_path_tables: None,
            metadata_gaps: Vec::new(),
        }
    }

    fn parsed_form1_sequence(subheaders: &[XaSubheader]) -> Vec<crate::raw_cd::ParsedSector> {
        let mut writer = SectorWriter::new();
        let mut raw = Vec::with_capacity(subheaders.len() * RAW_SECTOR_SIZE);
        for (lba, subheader) in subheaders.iter().copied().enumerate() {
            raw.extend_from_slice(
                &writer
                    .form1(
                        150 + u32::try_from(lba).unwrap(),
                        subheader,
                        &[u8::try_from(lba).unwrap(); LOGICAL_BLOCK_SIZE],
                    )
                    .unwrap(),
            );
        }
        parse_image(&raw).unwrap().1
    }

    fn canonical_patch_target() -> Vec<u8> {
        let mut writer = SectorWriter::new();
        let mut raw = Vec::new();
        for index in 0..20 {
            let mut payload = [0_u8; LOGICAL_BLOCK_SIZE];
            payload[0] = index as u8;
            raw.extend_from_slice(
                &writer
                    .form1(150 + index, FORM1_DATA_SUBHEADER, &payload)
                    .unwrap(),
            );
        }
        raw
    }

    fn redump_test_image(mode: TrackMode) -> Vec<u8> {
        let mut writer = SectorWriter::new();
        let mut raw = Vec::new();
        for index in 0..4 {
            let sector = match mode {
                TrackMode::Mode1 => writer
                    .mode1(150 + index, &[index as u8; LOGICAL_BLOCK_SIZE])
                    .unwrap(),
                TrackMode::Mode2Xa => writer
                    .form1(
                        150 + index,
                        FORM1_DATA_SUBHEADER,
                        &[index as u8; LOGICAL_BLOCK_SIZE],
                    )
                    .unwrap(),
                TrackMode::Mode2 => unreachable!(),
            };
            raw.extend_from_slice(&sector);
        }
        for index in 1..3 {
            raw[index * RAW_SECTOR_SIZE + 16..(index + 1) * RAW_SECTOR_SIZE].fill(0x55);
        }
        raw
    }

    #[test]
    fn redump_0x55_detection_is_exact_for_mode1_and_mode2() {
        for mode in [TrackMode::Mode1, TrackMode::Mode2Xa] {
            let raw = redump_test_image(mode);
            assert_eq!(
                detect_redump_0x55(&raw),
                vec![Redump0x55Run { lba: 1, sectors: 2 }]
            );
        }
    }

    #[test]
    fn redump_0x55_near_matches_are_not_detected() {
        let exact = redump_test_image(TrackMode::Mode1);
        for (offset, value) in [
            (RAW_SECTOR_SIZE, 1),
            (RAW_SECTOR_SIZE + 12, 0x99),
            (RAW_SECTOR_SIZE + 15, 2),
            (RAW_SECTOR_SIZE + 100, 0x54),
        ] {
            let mut raw = exact.clone();
            raw[offset] = value;
            assert_eq!(
                detect_redump_0x55(&raw),
                vec![Redump0x55Run { lba: 2, sectors: 1 }]
            );
        }
    }

    #[test]
    fn redump_0x55_placeholders_and_generation_preserve_sector_headers() {
        for (mode, raw_mode, expected_kind) in [
            (TrackMode::Mode1, 1, Kind::Mode1Gap),
            (TrackMode::Mode2Xa, 2, Kind::Form1),
        ] {
            let mut raw = redump_test_image(mode);
            let header = raw[RAW_SECTOR_SIZE..RAW_SECTOR_SIZE + 16].to_vec();
            let runs = detect_redump_0x55(&raw);
            install_redump_0x55_placeholders(&mut raw, 150, raw_mode, &runs).unwrap();
            let sectors = parse_image(&raw).unwrap().1;
            assert_eq!(sectors[1].kind, expected_kind);
            assert_eq!(sectors[1].logical_block(), &[0; LOGICAL_BLOCK_SIZE]);
            if mode == TrackMode::Mode2Xa {
                assert_eq!(sectors[1].subheader, FORM1_DATA_SUBHEADER);
            }

            apply_redump_0x55(&mut raw, 150, &runs).unwrap();
            assert_eq!(&raw[RAW_SECTOR_SIZE..RAW_SECTOR_SIZE + 16], &header);
            assert!(
                raw[RAW_SECTOR_SIZE + 16..2 * RAW_SECTOR_SIZE]
                    .iter()
                    .all(|byte| *byte == 0x55)
            );
        }
    }

    #[test]
    fn redump_0x55_runs_are_strictly_validated() {
        let valid = [Redump0x55Run {
            lba: -74,
            sectors: 1,
        }];
        validate_redump_0x55_runs(&valid, &[]).unwrap();
        let ranges = resolve_redump_0x55_ranges(75, 2, &valid).unwrap();
        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges[0], 1..2);

        for invalid in [
            vec![Redump0x55Run { lba: 0, sectors: 0 }],
            vec![
                Redump0x55Run { lba: 2, sectors: 1 },
                Redump0x55Run { lba: 1, sectors: 1 },
            ],
            vec![
                Redump0x55Run { lba: 1, sectors: 2 },
                Redump0x55Run { lba: 2, sectors: 1 },
            ],
            vec![
                Redump0x55Run { lba: 1, sectors: 1 },
                Redump0x55Run { lba: 2, sectors: 1 },
            ],
        ] {
            assert!(validate_redump_0x55_runs(&invalid, &[]).is_err());
        }

        let patch = SectorPatch {
            lba: -74,
            hex: format_sector_patch_hex(&[0; RAW_SECTOR_SIZE]),
        };
        assert!(validate_redump_0x55_runs(&valid, &[patch]).is_err());
        assert!(
            resolve_redump_0x55_ranges(
                150,
                2,
                &[Redump0x55Run {
                    lba: -1,
                    sectors: 1
                }]
            )
            .is_err()
        );
        assert!(
            resolve_redump_0x55_ranges(150, 2, &[Redump0x55Run { lba: 2, sectors: 1 }]).is_err()
        );
    }

    #[test]
    fn raw_sector_patches_replace_complete_sectors_without_reprotecting() {
        let mut raw = canonical_patch_target();
        let replacement = [0xa5; RAW_SECTOR_SIZE];
        let patches = [SectorPatch {
            lba: 1,
            hex: format_sector_patch_hex(&replacement),
        }];

        apply_sector_patches(&mut raw, 150, &patches).unwrap();

        assert_eq!(&raw[RAW_SECTOR_SIZE..2 * RAW_SECTOR_SIZE], &replacement);
        assert!(parse_image(&raw[RAW_SECTOR_SIZE..2 * RAW_SECTOR_SIZE]).is_err());
    }

    #[test]
    fn patch_lbas_are_absolute_signed_ordered_and_bounded() {
        let replacement = [0x3c; RAW_SECTOR_SIZE];
        let patch = SectorPatch {
            lba: -74,
            hex: format_sector_patch_hex(&replacement),
        };
        let mut raw = canonical_patch_target()[..2 * RAW_SECTOR_SIZE].to_vec();
        apply_sector_patches(&mut raw, 75, &[patch]).unwrap();
        assert_eq!(&raw[RAW_SECTOR_SIZE..], &replacement);

        for patches in [
            vec![
                SectorPatch {
                    lba: -74,
                    hex: format_sector_patch_hex(&replacement),
                },
                SectorPatch {
                    lba: -74,
                    hex: format_sector_patch_hex(&replacement),
                },
            ],
            vec![
                SectorPatch {
                    lba: -74,
                    hex: format_sector_patch_hex(&replacement),
                },
                SectorPatch {
                    lba: -75,
                    hex: format_sector_patch_hex(&replacement),
                },
            ],
            vec![SectorPatch {
                lba: -76,
                hex: format_sector_patch_hex(&replacement),
            }],
            vec![SectorPatch {
                lba: 0,
                hex: format_sector_patch_hex(&replacement),
            }],
        ] {
            let mut raw = canonical_patch_target()[..2 * RAW_SECTOR_SIZE].to_vec();
            assert!(apply_sector_patches(&mut raw, 75, &patches).is_err());
        }
    }

    #[test]
    fn recovery_ranges_group_adjacent_absolute_lbas_and_render_msf() {
        let indices = BTreeSet::from([0, 1, 3]);
        let ranges = warning_ranges(150, &indices).unwrap();
        assert_eq!(
            ranges,
            vec![
                RecoveryRange {
                    first_lba: 0,
                    last_lba: 1,
                    first_msf: "00:02:00".to_owned(),
                    last_msf: "00:02:01".to_owned(),
                },
                RecoveryRange {
                    first_lba: 3,
                    last_lba: 3,
                    first_msf: "00:02:03".to_owned(),
                    last_msf: "00:02:03".to_owned(),
                },
            ]
        );
    }

    #[test]
    fn damaged_slots_recover_payload_or_use_deterministic_form_placeholders() {
        let mut writer = SectorWriter::new();
        let payload = [0x7b; LOGICAL_BLOCK_SIZE];
        let mut damaged = writer.form1(150, FORM1_DATA_SUBHEADER, &payload).unwrap();
        damaged[5] ^= 0x40;
        rewrite_form1_payload(&mut damaged, 150, 0, |_| Ok(())).unwrap();
        let recovered = parse_image(&damaged).unwrap().1.remove(0);
        assert_eq!(recovered.kind, Kind::Form1);
        assert_eq!(recovered.payload(), payload);

        let mut placeholders = vec![0xa5; 2 * RAW_SECTOR_SIZE];
        replace_with_form1_placeholder(&mut placeholders, 150, 0, FORM1_DATA_SUBHEADER).unwrap();
        replace_with_form2_placeholder(&mut placeholders, 150, 1, FORM2_SUBHEADER, true).unwrap();
        let parsed = parse_image(&placeholders).unwrap().1;
        assert_eq!(parsed[0].kind, Kind::Form1);
        assert_eq!(parsed[1].kind, Kind::Form2);
        assert!(
            parsed
                .iter()
                .all(|sector| sector.payload().iter().all(|byte| *byte == 0))
        );
    }

    #[test]
    fn bounded_directory_repairs_reject_loss_and_preserve_valid_prefixes() {
        let extent = 300_u32;
        let mut missing = [0_u8; LOGICAL_BLOCK_SIZE];
        missing[..2].copy_from_slice(&extent.to_be_bytes()[2..]);
        missing[40] = 48;
        missing[41..48].copy_from_slice(b"parent!");
        let original = missing;
        repair_missing_directory_prefix(&mut missing, extent).unwrap();
        assert_eq!(missing[0], 48);
        assert_eq!(&missing[2..6], &extent.to_le_bytes());
        assert_eq!(&missing[8..48], &original[..40]);
        assert_eq!(&missing[48..56], &original[40..48]);

        let mut lossy = original;
        lossy[2047] = 1;
        assert!(repair_missing_directory_prefix(&mut lossy, extent).is_err());

        let mut residue = [0_u8; LOGICAL_BLOCK_SIZE];
        residue[..16].fill(0x11);
        residue[1024..].fill(0xa5);
        clear_directory_residue(&mut residue, 1024).unwrap();
        assert!(residue[..16].iter().all(|byte| *byte == 0x11));
        assert!(residue[1024..].iter().all(|byte| *byte == 0));
        assert!(clear_directory_residue(&mut residue, 1024).is_err());
    }

    #[test]
    fn healthy_and_unknown_images_do_not_gain_automatic_patches() {
        let healthy = canonical_patch_target();
        let recovered = recover_known_corruption(&sha1_hex(&healthy), &healthy).unwrap();
        assert_eq!(recovered.semantic, healthy);
        assert!(recovered.patches.is_empty());
        assert!(recovered.warnings.is_empty());

        let mut unknown = canonical_patch_target();
        unknown[0] ^= 1;
        let recovered = recover_known_corruption(&sha1_hex(&unknown), &unknown).unwrap();
        assert!(recovered.patches.is_empty());
        assert!(parse_image(&recovered.semantic).is_err());
    }

    #[test]
    fn terminal_recovery_creates_an_existing_canonical_gap_slot() {
        let mut raw = vec![0x5a; RAW_SECTOR_SIZE];
        replace_with_xa_gap(&mut raw, 150, 0).unwrap();
        let parsed = parse_image(&raw).unwrap().1;
        assert_eq!(parsed[0].kind, Kind::XaGap);
        assert_eq!(raw.len(), RAW_SECTOR_SIZE);
    }

    #[test]
    fn system_area_variants_are_parsed_from_memory() {
        let mut writer = SectorWriter::new();
        let mut raw = Vec::new();
        let mut first = [0_u8; LOGICAL_BLOCK_SIZE];
        first[0] = 7;
        for index in 0..12 {
            let data = if index == 0 {
                &first
            } else {
                &[0; LOGICAL_BLOCK_SIZE]
            };
            raw.extend_from_slice(
                &writer
                    .form1(150 + index, FORM1_DATA_SUBHEADER, data)
                    .unwrap(),
            );
        }
        for index in 12..16 {
            raw.extend_from_slice(
                &writer
                    .form2(150 + index, FORM2_SUBHEADER, &[0; FORM2_PAYLOAD_SIZE], true)
                    .unwrap(),
            );
        }

        let mut sectors = parse_image(&raw).unwrap().1;
        let extracted = extract_system_area(&sectors, TrackMode::Mode2Xa, &[]).unwrap();
        assert_eq!(extracted.content, vec![7]);
        assert_eq!(extracted.form1_count, 12);
        assert!(extracted.form2_edc);
        assert_eq!(
            extracted.final_form1_subheader,
            SystemAreaFinalSubheader::Data
        );
        assert!(extracted.form1_framing.is_empty());

        sectors[11].subheader = SYSTEM_END_OF_FILE_SUBHEADER;
        sectors[11].subheader_copy = SYSTEM_END_OF_FILE_SUBHEADER;
        assert_eq!(
            extract_system_area(&sectors, TrackMode::Mode2Xa, &[])
                .unwrap()
                .final_form1_subheader,
            SystemAreaFinalSubheader::EndOfFileData
        );

        let custom = SystemAreaForm1Framing {
            sector: 11,
            subheader: XaSubheader::from([0, 10, 0, 0]),
            subheader_copy: XaSubheader::default(),
        };
        sectors[11].subheader = custom.subheader;
        sectors[11].subheader_copy = custom.subheader_copy;
        assert_eq!(
            extract_system_area(&sectors, TrackMode::Mode2Xa, &[])
                .unwrap()
                .form1_framing,
            vec![custom]
        );

        sectors[9].subheader_copy.coding_info = 33;
        assert_eq!(
            extract_system_area(&sectors, TrackMode::Mode2Xa, &[])
                .unwrap()
                .form1_framing
                .iter()
                .map(|framing| framing.sector)
                .collect::<Vec<_>>(),
            vec![9, 11]
        );
    }

    #[test]
    fn xa_gap_wrapped_system_area_is_parsed_from_memory() {
        let mut writer = SectorWriter::new();
        let mut raw = Vec::new();
        for index in 0..4 {
            raw.extend_from_slice(&writer.xa_gap(150 + index, XaSubheader::default()).unwrap());
        }
        for index in 4..12 {
            let mut payload = [0_u8; LOGICAL_BLOCK_SIZE];
            if index == 4 {
                payload[0] = 7;
            }
            raw.extend_from_slice(
                &writer
                    .form1(150 + index, FORM1_DATA_SUBHEADER, &payload)
                    .unwrap(),
            );
        }
        for index in 12..16 {
            raw.extend_from_slice(&writer.xa_gap(150 + index, XaSubheader::default()).unwrap());
        }

        let sectors = parse_image(&raw).unwrap().1;
        let extracted = extract_system_area(&sectors, TrackMode::Mode2Xa, &[]).unwrap();

        assert_eq!(extracted.content, vec![7]);
        assert_eq!(extracted.form1_count, 8);
        assert_eq!(
            extracted.sector_layout,
            vec![
                SystemAreaSectorRun {
                    kind: SystemAreaSectorKind::XaGap,
                    sectors: 4,
                },
                SystemAreaSectorRun {
                    kind: SystemAreaSectorKind::Form1,
                    sectors: 8,
                },
                SystemAreaSectorRun {
                    kind: SystemAreaSectorKind::XaGap,
                    sectors: 4,
                },
            ]
        );
    }

    #[test]
    fn standard_xa_subheaders_have_expected_raw_bytes() {
        assert_eq!(<[u8; 4]>::from(FORM1_DATA_SUBHEADER), [0, 0, 8, 0]);
        assert_eq!(<[u8; 4]>::from(PVD_SUBHEADER), [0, 0, 9, 0]);
        assert_eq!(<[u8; 4]>::from(ISO_METADATA_SUBHEADER), [0, 0, 137, 0]);
        assert_eq!(<[u8; 4]>::from(FORM2_SUBHEADER), [0, 0, 32, 0]);
    }

    fn parsed_xa_sector(form2: bool, marker: u8) -> crate::raw_cd::ParsedSector {
        let primary = if form2 {
            XaSubheader::from([marker, marker.wrapping_add(1), 0x24, marker.wrapping_add(2)])
        } else {
            XaSubheader::from([marker, marker.wrapping_add(1), 0x48, marker.wrapping_add(2)])
        };
        let copy = XaSubheader::from([
            marker.wrapping_add(3),
            marker.wrapping_add(4),
            marker.wrapping_add(5),
            marker.wrapping_add(6),
        ]);
        let mut writer = SectorWriter::new();
        let raw = if form2 {
            writer
                .form2_with_subheaders(150, primary, copy, &[marker; FORM2_PAYLOAD_SIZE], true)
                .unwrap()
        } else {
            writer
                .form1_with_subheaders(150, primary, copy, &[marker; LOGICAL_BLOCK_SIZE])
                .unwrap()
        };
        parse_image(&raw).unwrap().1.remove(0)
    }

    fn parsed_xa_gap_sector() -> crate::raw_cd::ParsedSector {
        let mut writer = SectorWriter::new();
        let raw = writer.xa_gap(150, XaSubheader::default()).unwrap();
        parse_image(&raw).unwrap().1.remove(0)
    }

    #[test]
    fn xa_sidecars_preserve_framing_payloads_and_order() {
        let layouts = [
            vec![false, true, false, true],
            vec![false, true, true, false],
            vec![true, false, false],
            vec![true, false, true, true, false, true, false],
        ];
        for layout in layouts {
            let sectors = layout
                .iter()
                .enumerate()
                .map(|(index, form2)| parsed_xa_sector(*form2, u8::try_from(index + 1).unwrap()))
                .collect::<Vec<_>>();
            let assets = demultiplex_xa_extent(&sectors, true).unwrap();
            let expected_indices = layout
                .iter()
                .enumerate()
                .filter_map(|(index, form2)| form2.then_some(u32::try_from(index).unwrap()))
                .collect::<Vec<_>>();
            assert_eq!(
                parse_xa_index(&assets.form2_index).unwrap(),
                expected_indices
            );
            assert!(assets.gap_index.is_empty());

            let reconstructed = multiplex_xa_extent(
                &assets.form1,
                &assets.form2,
                &assets.form2_index,
                &assets.gap_index,
            )
            .unwrap();
            for (expected, actual) in sectors.iter().zip(reconstructed) {
                match actual {
                    XaExtentSector::Form1(actual) => {
                        assert_eq!(expected.kind, Kind::Form1);
                        assert_eq!(actual.subheader, expected.subheader);
                        assert_eq!(actual.subheader_copy, expected.subheader_copy);
                        assert_eq!(actual.payload, expected.payload());
                    }
                    XaExtentSector::Form2(actual) => {
                        assert_eq!(expected.kind, Kind::Form2);
                        assert_eq!(actual.subheader, expected.subheader);
                        assert_eq!(actual.subheader_copy, expected.subheader_copy);
                        assert_eq!(actual.payload, expected.payload());
                    }
                    XaExtentSector::XaGap => panic!("unexpected XA gap"),
                }
            }
        }
    }

    #[test]
    fn redump_0x55_placeholder_keeps_an_indexed_xa_position() {
        let mut writer = SectorWriter::new();
        let mut damaged = Vec::new();
        for index in 0..3 {
            damaged.extend_from_slice(
                &writer
                    .form2(
                        150 + index,
                        FORM2_SUBHEADER,
                        &[index as u8; FORM2_PAYLOAD_SIZE],
                        true,
                    )
                    .unwrap(),
            );
        }
        damaged[RAW_SECTOR_SIZE + 16..2 * RAW_SECTOR_SIZE].fill(0x55);
        let runs = detect_redump_0x55(&damaged);
        let mut semantic = damaged.clone();
        install_redump_0x55_placeholders(&mut semantic, 150, 2, &runs).unwrap();
        let sectors = parse_image(&semantic).unwrap().1;
        let assets = demultiplex_xa_extent(&sectors, true).unwrap();

        assert_eq!(parse_xa_index(&assets.form2_index).unwrap(), vec![0, 2]);
        assert_eq!(assets.form1.len(), XA_FORM1_RECORD_SIZE);
        assert!(assets.form1[8..].iter().all(|byte| *byte == 0));
        assert_eq!(
            multiplex_xa_extent(
                &assets.form1,
                &assets.form2,
                &assets.form2_index,
                &assets.gap_index,
            )
            .unwrap()
            .len(),
            3
        );

        apply_redump_0x55(&mut semantic, 150, &runs).unwrap();
        assert_eq!(semantic, damaged);
    }

    #[test]
    fn xa_sidecars_preserve_structured_gap_positions() {
        let sectors = vec![
            parsed_xa_sector(false, 1),
            parsed_xa_gap_sector(),
            parsed_xa_sector(true, 2),
        ];

        let assets = demultiplex_xa_extent(&sectors, true).unwrap();
        assert_eq!(parse_xa_gap_index(&assets.gap_index).unwrap(), vec![1]);
        assert_eq!(
            multiplex_xa_extent(
                &assets.form1,
                &assets.form2,
                &assets.form2_index,
                &assets.gap_index,
            )
            .unwrap(),
            vec![
                XaExtentSector::Form1(Box::new(XaForm1Sector {
                    subheader: sectors[0].subheader,
                    subheader_copy: sectors[0].subheader_copy,
                    payload: sectors[0].payload().try_into().unwrap(),
                })),
                XaExtentSector::XaGap,
                XaExtentSector::Form2(Box::new(XaSidecarRecord {
                    subheader: sectors[2].subheader,
                    subheader_copy: sectors[2].subheader_copy,
                    payload: sectors[2].payload().try_into().unwrap(),
                })),
            ]
        );
    }

    #[test]
    fn explicit_xa_assets_can_describe_an_extent_with_omitted_attributes() {
        let mut entry = test_manifest().iso9660.entries.remove(1);
        entry.xa = Some(crate::manifest::EntryXa {
            attributes: Some(crate::manifest::XaAttributes::from_bits(0)),
            form1: Some("FILE.BIN.XA1".to_owned()),
            form2: Some("FILE.BIN.XA2".to_owned()),
            index: Some("FILE.BIN.XAI".to_owned()),
            ..crate::manifest::EntryXa::default()
        });

        assert!(entry_uses_xa_sidecar(&entry));
    }

    #[test]
    fn mixed_xa_sidecars_are_inferred_from_observed_sector_kinds() {
        let mut sectors = parsed_form1_sequence(&[FORM1_DATA_SUBHEADER; 18]);
        sectors[17] = parsed_xa_sector(true, 1);
        let mut parsed = parsed_iso();

        prepare_xa_sidecars(&sectors, &mut parsed, &[]).unwrap();

        let xa = parsed.manifest.entries[1].xa.as_ref().unwrap();
        assert_eq!(xa.form1.as_deref(), Some("FILE.BIN.XA1"));
        assert_eq!(xa.form2.as_deref(), Some("FILE.BIN.XA2"));
        assert_eq!(xa.index.as_deref(), Some("FILE.BIN.XAI"));
        assert_eq!(xa.gap_index, None);
    }

    #[test]
    fn xa_sidecars_are_inferred_for_unrepresentable_file_subheaders() {
        let mut sectors = parsed_form1_sequence(&[FORM1_DATA_SUBHEADER; 18]);
        sectors[17].subheader_copy.submode =
            sectors[17].subheader_copy.submode.union(XaSubmode::AUDIO);
        let mut parsed = parsed_iso();
        parsed.files[0].length = 1;

        prepare_xa_sidecars(&sectors, &mut parsed, &[]).unwrap();

        let xa = parsed.manifest.entries[1].xa.as_ref().unwrap();
        assert_eq!(xa.form1.as_deref(), Some("FILE.BIN.XA1"));
        assert_eq!(xa.form2.as_deref(), Some("FILE.BIN.XA2"));
        assert_eq!(xa.index.as_deref(), Some("FILE.BIN.XAI"));
        assert_eq!(xa.logical_length, Some(1));
    }

    #[test]
    fn mode2_2336_length_inference_keeps_adjacent_files_physically_separate() {
        let sectors = parsed_form1_sequence(&[FORM1_DATA_SUBHEADER; 4]);
        let mut parsed = parsed_iso();
        parsed.files[0].extent = 1;
        parsed.files[0].length = 2 * MODE2_DATA_SIZE as u32;
        parsed.manifest.entries.push(Entry {
            path: "NEXT.BIN".to_owned(),
            recording_time: "1998-03-19T11:58:36+09:00".to_owned(),
            hidden: false,
            associated: false,
            reference: None,
            xa_system_use: None,
            directory_slack: None,
            allocation_padding_hex: None,
            directory_self_xa: None,
            sector_subheader: EntrySectorSubheader::Canonical,
            xa: None,
        });
        parsed.files.push(iso9660::ParsedFile {
            path: "NEXT.BIN".to_owned(),
            extent: 3,
            length: LOGICAL_BLOCK_SIZE as u32,
        });
        parsed.directories.push(iso9660::ParsedDirectory {
            path: iso9660::ROOT_PATH.to_owned(),
            extent: 0,
            length: LOGICAL_BLOCK_SIZE as u32,
        });

        detect_mode2_2336_file_lengths(sectors.len(), &mut parsed).unwrap();
        detach_overlapping_xa_files(&sectors, &mut parsed).unwrap();
        prepare_xa_sidecars(&sectors, &mut parsed, &[]).unwrap();

        assert_eq!(
            parsed
                .files
                .iter()
                .map(|file| (file.path.as_str(), file.length))
                .collect::<Vec<_>>(),
            vec![
                ("FILE.BIN", 2 * LOGICAL_BLOCK_SIZE as u32),
                ("NEXT.BIN", LOGICAL_BLOCK_SIZE as u32),
            ]
        );
        let xa = parsed.manifest.entries[1].xa.as_ref().unwrap();
        assert_eq!(xa.length_encoding, XaLengthEncoding::Mode2_2336);
        assert_eq!(xa.form1.as_deref(), Some("FILE.BIN.XA1"));
        assert_eq!(xa.form2.as_deref(), Some("FILE.BIN.XA2"));
        assert_eq!(xa.index.as_deref(), Some("FILE.BIN.XAI"));
        assert_eq!(xa.logical_length, None);
    }

    #[test]
    fn indexed_xa_assets_reject_malformed_records_and_positions() {
        assert!(parse_xa_form1_records(&[0; XA_FORM1_RECORD_SIZE - 1]).is_err());
        assert!(parse_xa_form2_records(&[0; XA_FORM2_RECORD_SIZE - 1]).is_err());
        assert!(parse_xa_index(&[0; 3]).is_err());
        assert!(parse_xa_index(&encode_xa_index(&[1, 1])).is_err());
        assert!(parse_xa_index(&encode_xa_index(&[2, 1])).is_err());

        let form1 = encode_xa_form1_record(&parsed_xa_sector(false, 1)).unwrap();
        let form2 = encode_xa_form2_record(&parsed_xa_sector(true, 2)).unwrap();
        assert!(multiplex_xa_extent(&form1, &form2, &encode_xa_index(&[]), &[]).is_err());
        assert!(multiplex_xa_extent(&form1, &form2, &encode_xa_index(&[2]), &[]).is_err());

        let mut wrong_form1 = form1;
        wrong_form1[2] |= XaSubmode::FORM2.bits();
        assert!(parse_xa_form1_records(&wrong_form1).is_err());
        let mut wrong_form2 = form2;
        wrong_form2[2] &= !XaSubmode::FORM2.bits();
        assert!(parse_xa_form2_records(&wrong_form2).is_err());
    }

    #[test]
    fn file_layout_preserves_terminal_form2_gaps_in_memory() {
        let mut writer = SectorWriter::new();
        let mut raw = writer
            .form1(150, FORM1_DATA_SUBHEADER, &[0x5a; LOGICAL_BLOCK_SIZE])
            .unwrap()
            .to_vec();
        for frame in 151..154 {
            raw.extend_from_slice(
                &writer
                    .form2(frame, FORM2_SUBHEADER, &[0; FORM2_PAYLOAD_SIZE], true)
                    .unwrap(),
            );
        }
        let sectors = parse_image(&raw).unwrap().1;
        let files = vec![iso9660::ParsedFile {
            path: "FILE.BIN".to_owned(),
            extent: 0,
            length: LOGICAL_BLOCK_SIZE as u32,
        }];

        assert_eq!(
            detect_file_layout(&sectors, &files, &[], &[], true, "test")
                .unwrap()
                .items,
            vec![FileLayoutItem::path("FILE.BIN"), FileLayoutItem::gap(3)]
        );
    }

    #[test]
    fn form2_gap_can_override_the_track_edc_policy() {
        let mut writer = SectorWriter::new();
        let mut raw = writer
            .form1(150, FORM1_DATA_SUBHEADER, &[0x5a; LOGICAL_BLOCK_SIZE])
            .unwrap();
        raw.extend_from_slice(
            &writer
                .form2(151, FORM2_SUBHEADER, &[0; FORM2_PAYLOAD_SIZE], false)
                .unwrap(),
        );
        let sectors = parse_image(&raw).unwrap().1;
        let files = vec![iso9660::ParsedFile {
            path: "FILE.BIN".to_owned(),
            extent: 0,
            length: LOGICAL_BLOCK_SIZE as u32,
        }];

        assert_eq!(
            detect_file_layout(&sectors, &files, &[], &[], true, "test")
                .unwrap()
                .items,
            vec![
                FileLayoutItem::path("FILE.BIN"),
                FileLayoutItem::form2_gap(1, false),
            ]
        );
    }

    #[test]
    fn file_layout_interleaves_primary_and_joliet_directories() {
        let sectors = parsed_form1_sequence(&[FORM1_DATA_SUBHEADER; 5]);
        let files = vec![iso9660::ParsedFile {
            path: "FILE.BIN".to_owned(),
            extent: 4,
            length: LOGICAL_BLOCK_SIZE as u32,
        }];
        let primary = vec![
            iso9660::ParsedDirectory {
                path: iso9660::ROOT_PATH.to_owned(),
                extent: 0,
                length: LOGICAL_BLOCK_SIZE as u32,
            },
            iso9660::ParsedDirectory {
                path: "DATA".to_owned(),
                extent: 2,
                length: LOGICAL_BLOCK_SIZE as u32,
            },
        ];
        let joliet = vec![
            iso9660::ParsedDirectory {
                path: iso9660::ROOT_PATH.to_owned(),
                extent: 1,
                length: LOGICAL_BLOCK_SIZE as u32,
            },
            iso9660::ParsedDirectory {
                path: "DATA".to_owned(),
                extent: 3,
                length: LOGICAL_BLOCK_SIZE as u32,
            },
        ];

        assert_eq!(
            detect_file_layout(&sectors, &files, &primary, &joliet, true, "test")
                .unwrap()
                .items,
            vec![
                FileLayoutItem::directory(iso9660::ROOT_PATH),
                FileLayoutItem::volume_directory(MetadataVolume::Joliet, iso9660::ROOT_PATH),
                FileLayoutItem::directory("DATA"),
                FileLayoutItem::volume_directory(MetadataVolume::Joliet, "DATA"),
                FileLayoutItem::path("FILE.BIN"),
            ]
        );
    }

    #[test]
    fn file_layout_ignores_zero_length_directory_references() {
        let sectors = parsed_form1_sequence(&[FORM1_DATA_SUBHEADER]);
        let directories = vec![
            iso9660::ParsedDirectory {
                path: iso9660::ROOT_PATH.to_owned(),
                extent: 0,
                length: LOGICAL_BLOCK_SIZE as u32,
            },
            iso9660::ParsedDirectory {
                path: "OLD".to_owned(),
                extent: 0,
                length: 0,
            },
        ];

        assert!(
            detect_file_layout(&sectors, &[], &directories, &[], true, "test")
                .unwrap()
                .items
                .is_empty()
        );
    }

    #[test]
    fn zero_length_directory_reference_has_no_sector_subheader_policy() {
        let sectors = parsed_form1_sequence(&[FORM1_DATA_SUBHEADER]);
        let mut parsed = parsed_iso();
        parsed.files.clear();
        parsed.manifest.layout.clear();
        parsed.manifest.entries.truncate(1);
        let mut reference = parsed.manifest.entries[0].clone();
        reference.path = "OLD".to_owned();
        reference.reference = Some(EntryReference {
            kind: EntryReferenceKind::Directory,
            extent: 0,
            length: 0,
        });
        parsed.manifest.entries.push(reference);
        parsed.directories = vec![
            iso9660::ParsedDirectory {
                path: iso9660::ROOT_PATH.to_owned(),
                extent: 0,
                length: LOGICAL_BLOCK_SIZE as u32,
            },
            iso9660::ParsedDirectory {
                path: "OLD".to_owned(),
                extent: 0,
                length: 0,
            },
        ];

        detect_entry_sector_subheaders(&sectors, &mut parsed, &[]).unwrap();

        assert_eq!(
            parsed.manifest.entries[1].sector_subheader,
            EntrySectorSubheader::Canonical
        );
    }

    #[test]
    fn file_layout_detects_zero_form1_separator_in_memory() {
        let separator = XaSubheader {
            file_number: 1,
            submode: XaSubmode::END_OF_FILE,
            ..XaSubheader::default()
        };
        let mut sectors =
            parsed_form1_sequence(&[FORM1_DATA_SUBHEADER, separator, FORM1_DATA_SUBHEADER]);
        let mut writer = SectorWriter::new();
        sectors[1] = parse_image(
            &writer
                .form1(151, separator, &[0; LOGICAL_BLOCK_SIZE])
                .unwrap(),
        )
        .unwrap()
        .1
        .remove(0);
        let files = vec![
            iso9660::ParsedFile {
                path: "A.BIN".to_owned(),
                extent: 0,
                length: LOGICAL_BLOCK_SIZE as u32,
            },
            iso9660::ParsedFile {
                path: "B.BIN".to_owned(),
                extent: 2,
                length: LOGICAL_BLOCK_SIZE as u32,
            },
        ];

        assert_eq!(
            detect_file_layout(&sectors, &files, &[], &[], true, "test")
                .unwrap()
                .items,
            vec![
                FileLayoutItem::path("A.BIN"),
                FileLayoutItem::form1_gap(1, separator),
                FileLayoutItem::path("B.BIN"),
            ]
        );
    }

    #[test]
    fn file_layout_detects_unreferenced_framed_xa_extent_in_memory() {
        let sectors = parsed_form1_sequence(&[
            FORM1_DATA_SUBHEADER,
            FORM1_DATA_SUBHEADER,
            FORM1_DATA_SUBHEADER,
        ]);
        let files = vec![
            iso9660::ParsedFile {
                path: "A.BIN".to_owned(),
                extent: 0,
                length: LOGICAL_BLOCK_SIZE as u32,
            },
            iso9660::ParsedFile {
                path: "B.BIN".to_owned(),
                extent: 2,
                length: LOGICAL_BLOCK_SIZE as u32,
            },
        ];

        let layout = detect_file_layout(&sectors, &files, &[], &[], true, "test").unwrap();
        assert!(layout.items[1].as_xa_extent().is_some());
    }

    #[test]
    fn overlapping_xa_files_become_layout_references_for_form2_and_mixed_unions() {
        for mixed in [false, true] {
            let sectors = (0..6)
                .map(|marker| parsed_xa_sector(!mixed || marker % 2 == 0, marker))
                .collect::<Vec<_>>();
            let mut parsed = parsed_iso();
            parsed.manifest.entries[1].xa = Some(crate::manifest::EntryXa {
                attributes: Some(crate::manifest::XaAttributes::INTERLEAVED),
                ..crate::manifest::EntryXa::default()
            });
            parsed.manifest.entries.push(Entry {
                path: "B.XA".to_owned(),
                recording_time: "1998-03-19T11:58:36+09:00".to_owned(),
                hidden: false,
                associated: false,
                reference: None,
                xa_system_use: None,
                directory_slack: None,
                allocation_padding_hex: None,
                directory_self_xa: None,
                sector_subheader: EntrySectorSubheader::Canonical,
                xa: Some(crate::manifest::EntryXa {
                    attributes: Some(crate::manifest::XaAttributes::INTERLEAVED),
                    ..crate::manifest::EntryXa::default()
                }),
            });
            parsed.manifest.entries.push(Entry {
                path: "NEXT.BIN".to_owned(),
                recording_time: "1998-03-19T11:58:36+09:00".to_owned(),
                hidden: false,
                associated: false,
                reference: None,
                xa_system_use: None,
                directory_slack: None,
                allocation_padding_hex: None,
                directory_self_xa: None,
                sector_subheader: EntrySectorSubheader::Canonical,
                xa: None,
            });
            parsed.files = vec![
                iso9660::ParsedFile {
                    path: "FILE.BIN".to_owned(),
                    extent: 1,
                    length: 4 * LOGICAL_BLOCK_SIZE as u32,
                },
                iso9660::ParsedFile {
                    path: "B.XA".to_owned(),
                    extent: 2,
                    length: 3 * LOGICAL_BLOCK_SIZE as u32,
                },
                iso9660::ParsedFile {
                    path: "NEXT.BIN".to_owned(),
                    extent: 5,
                    length: LOGICAL_BLOCK_SIZE as u32,
                },
            ];
            parsed.directories = vec![iso9660::ParsedDirectory {
                path: iso9660::ROOT_PATH.to_owned(),
                extent: 0,
                length: LOGICAL_BLOCK_SIZE as u32,
            }];

            detach_overlapping_xa_files(&sectors, &mut parsed).unwrap();

            assert_eq!(
                parsed
                    .files
                    .iter()
                    .map(|file| file.path.as_str())
                    .collect::<Vec<_>>(),
                vec!["NEXT.BIN"]
            );
            assert_eq!(
                parsed.manifest.entries[1].reference,
                Some(EntryReference {
                    kind: EntryReferenceKind::Layout,
                    extent: 1,
                    length: 4 * LOGICAL_BLOCK_SIZE as u32,
                })
            );
            assert_eq!(
                parsed.manifest.entries[2].reference,
                Some(EntryReference {
                    kind: EntryReferenceKind::Layout,
                    extent: 2,
                    length: 3 * LOGICAL_BLOCK_SIZE as u32,
                })
            );
            let layout = detect_file_layout(
                &sectors,
                &parsed.files,
                &parsed.directories,
                &[],
                true,
                "test",
            )
            .unwrap();
            assert!(layout.items[0].as_xa_extent().is_some());
            assert_eq!(layout.items[1], FileLayoutItem::path("NEXT.BIN"));
        }
    }

    #[test]
    fn files_without_local_sectors_become_fixed_references() {
        let sectors = parsed_form1_sequence(&[FORM1_DATA_SUBHEADER; 18]);
        let mut parsed = parsed_iso();
        parsed.files[0].extent = 0;
        parsed.manifest.entries[1].allocation_padding_hex = Some("aa".to_owned());
        parsed.manifest.entries.push(Entry {
            path: "OUTSIDE.BIN".to_owned(),
            recording_time: "1998-03-19T11:58:36+09:00".to_owned(),
            hidden: false,
            associated: false,
            reference: None,
            xa_system_use: None,
            directory_slack: None,
            allocation_padding_hex: None,
            directory_self_xa: None,
            sector_subheader: EntrySectorSubheader::Canonical,
            xa: None,
        });
        parsed.files.push(iso9660::ParsedFile {
            path: "OUTSIDE.BIN".to_owned(),
            extent: 100,
            length: LOGICAL_BLOCK_SIZE as u32,
        });
        parsed.manifest.entries.push(Entry {
            path: "PARTIAL.BIN".to_owned(),
            recording_time: "1998-03-19T11:58:36+09:00".to_owned(),
            hidden: false,
            associated: false,
            reference: None,
            xa_system_use: None,
            directory_slack: None,
            allocation_padding_hex: None,
            directory_self_xa: None,
            sector_subheader: EntrySectorSubheader::Canonical,
            xa: None,
        });
        parsed.files.push(iso9660::ParsedFile {
            path: "PARTIAL.BIN".to_owned(),
            extent: 17,
            length: 2 * LOGICAL_BLOCK_SIZE as u32,
        });

        detach_overlapping_xa_files(&sectors, &mut parsed).unwrap();

        assert!(parsed.files.is_empty());
        assert_eq!(parsed.manifest.entries[1].reference.unwrap().extent, 0);
        assert_eq!(parsed.manifest.entries[2].reference.unwrap().extent, 100);
        assert_eq!(parsed.manifest.entries[3].reference.unwrap().extent, 17);
        assert!(
            parsed.manifest.entries[1..4]
                .iter()
                .all(|entry| { entry.reference.unwrap().kind == EntryReferenceKind::RecordOnly })
        );
        assert!(parsed.manifest.entries[1].allocation_padding_hex.is_none());

        parsed.manifest.layout.clear();
        assert!(iso9660::layout(&parsed.manifest, &HashMap::new()).is_ok());
    }

    #[test]
    fn record_only_form2_xa_file_retains_only_directory_record_xa_fields() {
        let sectors = parsed_form1_sequence(&[FORM1_DATA_SUBHEADER; 18]);
        let mut parsed = parsed_iso();
        parsed.files[0].extent = 100;
        let attributes = crate::manifest::XaAttributes::from_bits(
            crate::manifest::XaAttributes::MODE2_FORM1.bits()
                | crate::manifest::XaAttributes::MODE2_FORM2.bits(),
        );
        parsed.manifest.entries[1].xa = Some(crate::manifest::EntryXa {
            attributes: Some(attributes),
            length_encoding: XaLengthEncoding::Mode2_2336,
            ..crate::manifest::EntryXa::default()
        });

        detach_overlapping_xa_files(&sectors, &mut parsed).unwrap();

        let entry = &parsed.manifest.entries[1];
        assert_eq!(
            entry.reference.unwrap().kind,
            EntryReferenceKind::RecordOnly
        );
        let xa = entry.xa.as_ref().unwrap();
        assert_eq!(xa.attributes, Some(attributes));
        assert_eq!(xa.length_encoding, XaLengthEncoding::Logical2048);
        assert!(xa.form1.is_none());
        assert!(xa.form2.is_none());
        assert!(xa.index.is_none());
        parsed.manifest.layout.clear();
        iso9660::layout(&parsed.manifest, &HashMap::new()).unwrap();
    }

    #[test]
    fn overlapping_ordinary_files_become_record_only_references() {
        let sectors = parsed_form1_sequence(&[FORM1_DATA_SUBHEADER; 8]);
        let mut parsed = parsed_iso();
        parsed.files[0].extent = 1;
        parsed.files[0].length = 4 * LOGICAL_BLOCK_SIZE as u32;
        parsed.manifest.entries.push(Entry {
            path: "SECOND.BIN".to_owned(),
            recording_time: "1998-03-19T11:58:36+09:00".to_owned(),
            hidden: false,
            associated: false,
            reference: None,
            xa_system_use: None,
            directory_slack: None,
            allocation_padding_hex: None,
            directory_self_xa: None,
            sector_subheader: EntrySectorSubheader::Canonical,
            xa: None,
        });
        parsed.files.push(iso9660::ParsedFile {
            path: "SECOND.BIN".to_owned(),
            extent: 3,
            length: 2 * LOGICAL_BLOCK_SIZE as u32,
        });

        detach_overlapping_xa_files(&sectors, &mut parsed).unwrap();

        assert!(parsed.files.is_empty());
        assert_eq!(
            parsed.manifest.entries[1].reference.unwrap().kind,
            EntryReferenceKind::RecordOnly
        );
        assert_eq!(
            parsed.manifest.entries[2].reference.unwrap().kind,
            EntryReferenceKind::RecordOnly
        );
        assert_eq!(parsed.manifest.entries[1].reference.unwrap().extent, 1);
        assert_eq!(parsed.manifest.entries[2].reference.unwrap().extent, 3);
        let detected = detect_file_layout(
            &sectors,
            &parsed.files,
            &parsed.directories,
            &[],
            true,
            "test",
        )
        .unwrap();
        assert_eq!(detected.items.len(), 1);
        assert!(detected.items[0].as_xa_extent().is_some());
    }

    #[test]
    fn file_layout_preserves_zero_form1_gap_with_metadata_subheader() {
        let separator = ISO_METADATA_SUBHEADER;
        let mut sectors =
            parsed_form1_sequence(&[FORM1_DATA_SUBHEADER, separator, FORM1_DATA_SUBHEADER]);
        let mut writer = SectorWriter::new();
        sectors[1] = parse_image(
            &writer
                .form1(151, separator, &[0; LOGICAL_BLOCK_SIZE])
                .unwrap(),
        )
        .unwrap()
        .1
        .remove(0);
        let files = vec![
            iso9660::ParsedFile {
                path: "A.BIN".to_owned(),
                extent: 0,
                length: LOGICAL_BLOCK_SIZE as u32,
            },
            iso9660::ParsedFile {
                path: "B.BIN".to_owned(),
                extent: 2,
                length: LOGICAL_BLOCK_SIZE as u32,
            },
        ];

        assert_eq!(
            detect_file_layout(&sectors, &files, &[], &[], true, "test")
                .unwrap()
                .items,
            vec![
                FileLayoutItem::path("A.BIN"),
                FileLayoutItem::form1_gap(1, separator),
                FileLayoutItem::path("B.BIN"),
            ]
        );
    }

    #[test]
    fn file_layout_splits_mixed_zero_gap_runs() {
        let mut writer = SectorWriter::new();
        let mut raw = Vec::new();
        raw.extend_from_slice(
            &writer
                .form1(150, FORM1_DATA_SUBHEADER, &[1; LOGICAL_BLOCK_SIZE])
                .unwrap(),
        );
        raw.extend_from_slice(
            &writer
                .form1(151, ISO_METADATA_SUBHEADER, &[0; LOGICAL_BLOCK_SIZE])
                .unwrap(),
        );
        for frame in [152, 153] {
            raw.extend_from_slice(
                &writer
                    .form2(frame, FORM2_SUBHEADER, &[0; 2324], true)
                    .unwrap(),
            );
        }
        raw.extend_from_slice(
            &writer
                .form1(154, FORM1_DATA_SUBHEADER, &[2; LOGICAL_BLOCK_SIZE])
                .unwrap(),
        );
        let sectors = parse_image(&raw).unwrap().1;
        let files = vec![
            iso9660::ParsedFile {
                path: "A.BIN".to_owned(),
                extent: 0,
                length: LOGICAL_BLOCK_SIZE as u32,
            },
            iso9660::ParsedFile {
                path: "B.BIN".to_owned(),
                extent: 4,
                length: LOGICAL_BLOCK_SIZE as u32,
            },
        ];

        assert_eq!(
            detect_file_layout(&sectors, &files, &[], &[], true, "test")
                .unwrap()
                .items,
            vec![
                FileLayoutItem::path("A.BIN"),
                FileLayoutItem::form1_gap(1, ISO_METADATA_SUBHEADER),
                FileLayoutItem::gap(2),
                FileLayoutItem::path("B.BIN"),
            ]
        );
    }

    #[test]
    fn iso_validation_accepts_structured_form1_gap_between_files() {
        let separator = XaSubheader {
            file_number: 1,
            submode: XaSubmode::END_OF_FILE,
            ..XaSubheader::default()
        };
        let mut subheaders = vec![FORM1_DATA_SUBHEADER; 20];
        subheaders[16] = PVD_SUBHEADER;
        subheaders[17] = ISO_METADATA_SUBHEADER;
        subheaders[18] = separator;
        subheaders[19] = ISO_METADATA_SUBHEADER;
        let mut sectors = parsed_form1_sequence(&subheaders);
        let mut writer = SectorWriter::new();
        sectors[18] = parse_image(
            &writer
                .form1(168, separator, &[0; LOGICAL_BLOCK_SIZE])
                .unwrap(),
        )
        .unwrap()
        .1
        .remove(0);
        let mut parsed = parsed_iso();
        parsed.manifest.entries.push(crate::manifest::Entry {
            path: "SECOND.BIN".to_owned(),
            recording_time: "1998-03-19T11:58:36+09:00".to_owned(),
            hidden: false,
            associated: false,
            reference: None,
            xa_system_use: None,
            directory_slack: None,
            allocation_padding_hex: None,
            directory_self_xa: None,
            sector_subheader: EntrySectorSubheader::Canonical,
            xa: None,
        });
        parsed.files.push(iso9660::ParsedFile {
            path: "SECOND.BIN".to_owned(),
            extent: 19,
            length: LOGICAL_BLOCK_SIZE as u32,
        });

        validate_iso_subheaders(&sectors, &parsed, 0).unwrap();
    }

    #[test]
    fn iso_subheader_validation_reports_primary_and_duplicate_mismatches() {
        let mut subheaders = vec![FORM1_DATA_SUBHEADER; 18];
        subheaders[16] = PVD_SUBHEADER;
        subheaders[17] = ISO_METADATA_SUBHEADER;
        let mut sectors = parsed_form1_sequence(&subheaders);
        let parsed = parsed_iso();

        sectors[16].subheader = FORM1_DATA_SUBHEADER;
        assert_eq!(
            validate_iso_subheaders(&sectors, &parsed, 0)
                .unwrap_err()
                .to_string(),
            "ISO metadata sector at LBA 16 uses XA subheader [0, 0, 8, 0], expected [0, 0, 9, 0]"
        );

        sectors = parsed_form1_sequence(&subheaders);
        sectors[16].subheader_copy = XaSubheader::from([0, 0x7e, 9, 0]);
        assert_eq!(
            validate_iso_subheaders(&sectors, &parsed, 0)
                .unwrap_err()
                .to_string(),
            "ISO metadata sector at LBA 16 uses duplicated XA subheader [0, 126, 9, 0], expected [0, 0, 9, 0]"
        );
    }

    #[test]
    fn joliet_descriptor_uses_pvd_framing_but_terminator_uses_metadata_framing() {
        let mut subheaders = vec![FORM1_DATA_SUBHEADER; 19];
        subheaders[16] = PVD_SUBHEADER;
        subheaders[17] = PVD_SUBHEADER;
        subheaders[18] = ISO_METADATA_SUBHEADER;
        let mut sectors = parsed_form1_sequence(&subheaders);
        sectors[16].bytes[24..31].copy_from_slice(b"\x01CD001\x01");
        sectors[17].bytes[24..31].copy_from_slice(b"\x02CD001\x01");
        sectors[18].bytes[24..31].copy_from_slice(b"\xffCD001\x01");
        let mut parsed = parsed_iso();
        parsed.files.clear();
        parsed.manifest.entries.truncate(1);
        parsed.manifest.layout.clear();

        validate_iso_subheaders(&sectors, &parsed, 0).unwrap();
    }

    #[test]
    fn pvd_framed_volume_terminator_selects_scoped_framing() {
        let mut sectors = parsed_form1_sequence(&[PVD_SUBHEADER; 19]);
        sectors[16].bytes[24..31].copy_from_slice(b"\x01CD001\x01");
        sectors[17].bytes[24..31].copy_from_slice(b"\x02CD001\x01");
        sectors[18].bytes[24..31].copy_from_slice(b"\xffCD001\x01");
        let mut parsed = parsed_iso();

        detect_metadata_subheader(&sectors, &mut parsed.manifest, &[]);

        assert_eq!(
            parsed.manifest.volume_terminator_subheader,
            VolumeTerminatorSubheader::Pvd
        );
    }

    #[test]
    fn pvd_iso_metadata_subheader_is_supported_in_memory() {
        let mut subheaders = vec![FORM1_DATA_SUBHEADER; 18];
        subheaders[16] = ISO_METADATA_SUBHEADER;
        subheaders[17] = ISO_METADATA_SUBHEADER;
        let sectors = parsed_form1_sequence(&subheaders);
        let mut parsed = parsed_iso();
        parsed.manifest.metadata_subheader =
            MetadataSubheader::Named(IsoMetadataSubheader::IsoMetadata);

        validate_iso_subheaders(&sectors, &parsed, 0).unwrap();
    }

    #[test]
    fn pvd_end_of_file_data_subheader_is_supported_in_memory() {
        let mut subheaders = vec![FORM1_DATA_SUBHEADER; 18];
        subheaders[16] = SYSTEM_END_OF_FILE_SUBHEADER;
        subheaders[17] = SYSTEM_END_OF_FILE_SUBHEADER;
        let sectors = parsed_form1_sequence(&subheaders);
        let mut parsed = parsed_iso();
        parsed.manifest.metadata_subheader =
            MetadataSubheader::Named(IsoMetadataSubheader::EndOfFileData);
        parsed.manifest.entries.truncate(1);
        parsed.manifest.layout.clear();
        parsed.files.clear();

        validate_iso_subheaders(&sectors, &parsed, 0).unwrap();
    }

    #[test]
    fn custom_iso_metadata_subheader_is_supported_in_memory() {
        let custom = XaSubheader::default();
        let mut subheaders = vec![FORM1_DATA_SUBHEADER; 18];
        subheaders[16] = custom;
        subheaders[17] = custom;
        let sectors = parsed_form1_sequence(&subheaders);
        let mut parsed = parsed_iso();
        parsed.manifest.metadata_subheader = MetadataSubheader::Explicit(custom);
        parsed.manifest.entries.truncate(1);
        parsed.manifest.layout.clear();
        parsed.files.clear();

        validate_iso_subheaders(&sectors, &parsed, 0).unwrap();
    }

    #[test]
    fn repeated_pvds_retain_the_pvd_subheader() {
        let mut subheaders = vec![ISO_METADATA_SUBHEADER; 20];
        subheaders[..16].fill(FORM1_DATA_SUBHEADER);
        subheaders[16..19].fill(PVD_SUBHEADER);
        let sectors = parsed_form1_sequence(&subheaders);
        let mut parsed = parsed_iso();
        parsed.manifest.primary_volume_copies = 3;
        parsed.manifest.entries.truncate(1);
        parsed.manifest.layout.clear();
        parsed.files.clear();

        validate_iso_subheaders(&sectors, &parsed, 0).unwrap();
    }

    #[test]
    fn pvd_metadata_policy_can_mix_all_metadata_and_canonical_files() {
        let mut subheaders = vec![FORM1_DATA_SUBHEADER; 21];
        subheaders[16] = ISO_METADATA_SUBHEADER;
        subheaders[17] = ISO_METADATA_SUBHEADER;
        subheaders[18] = ISO_METADATA_SUBHEADER;
        subheaders[19] = FORM1_DATA_SUBHEADER;
        subheaders[20] = ISO_METADATA_SUBHEADER;
        let sectors = parsed_form1_sequence(&subheaders);
        let mut parsed = parsed_iso();
        parsed.manifest.metadata_subheader =
            MetadataSubheader::Named(IsoMetadataSubheader::IsoMetadata);
        parsed.files[0].length = (2 * LOGICAL_BLOCK_SIZE) as u32;
        parsed.manifest.entries.push(crate::manifest::Entry {
            path: "SECOND.BIN".to_owned(),
            recording_time: "1998-03-19T11:58:36+09:00".to_owned(),
            hidden: false,
            associated: false,
            reference: None,
            xa_system_use: None,
            directory_slack: None,
            allocation_padding_hex: None,
            directory_self_xa: None,
            sector_subheader: EntrySectorSubheader::Canonical,
            xa: None,
        });
        parsed.files.push(iso9660::ParsedFile {
            path: "SECOND.BIN".to_owned(),
            extent: 19,
            length: (2 * LOGICAL_BLOCK_SIZE) as u32,
        });

        detect_entry_sector_subheaders(&sectors, &mut parsed, &[]).unwrap();
        assert_eq!(
            parsed.manifest.entries[1].sector_subheader,
            EntrySectorSubheader::IsoMetadata
        );
        assert_eq!(
            parsed.manifest.entries[2].sector_subheader,
            EntrySectorSubheader::Canonical
        );
        validate_iso_subheaders(&sectors, &parsed, 0).unwrap();
    }

    #[test]
    fn entry_and_directory_subheader_policies_are_detected_in_memory() {
        let mut file_subheaders = vec![FORM1_DATA_SUBHEADER; 18];
        file_subheaders[16] = PVD_SUBHEADER;
        let file_sectors = parsed_form1_sequence(&file_subheaders);
        let mut file_iso = parsed_iso();
        detect_entry_sector_subheaders(&file_sectors, &mut file_iso, &[]).unwrap();
        assert_eq!(
            file_iso.manifest.entries[1].sector_subheader,
            EntrySectorSubheader::Data
        );
        validate_iso_subheaders(&file_sectors, &file_iso, 0).unwrap();

        let mut directory_subheaders = vec![FORM1_DATA_SUBHEADER; 19];
        directory_subheaders[16] = PVD_SUBHEADER;
        directory_subheaders[18] = ISO_METADATA_SUBHEADER;
        let directory_sectors = parsed_form1_sequence(&directory_subheaders);
        let mut directory_iso = parsed_iso();
        directory_iso.files.clear();
        directory_iso
            .manifest
            .entries
            .retain(|entry| entry.path == iso9660::ROOT_PATH);
        directory_iso.manifest.entries.push(Entry {
            path: "DIR".to_owned(),
            recording_time: "1998-03-19T11:58:36+09:00".to_owned(),
            hidden: false,
            associated: false,
            reference: None,
            xa_system_use: None,
            directory_slack: None,
            allocation_padding_hex: None,
            directory_self_xa: None,
            sector_subheader: EntrySectorSubheader::Canonical,
            xa: None,
        });
        directory_iso.directories.push(iso9660::ParsedDirectory {
            path: "DIR".to_owned(),
            extent: 17,
            length: (2 * LOGICAL_BLOCK_SIZE) as u32,
        });

        detect_entry_sector_subheaders(&directory_sectors, &mut directory_iso, &[]).unwrap();
        assert_eq!(
            directory_iso.manifest.entries[1].sector_subheader,
            EntrySectorSubheader::DataUntilFinal
        );
        validate_iso_subheaders(&directory_sectors, &directory_iso, 0).unwrap();
    }

    #[test]
    fn directory_end_of_file_data_subheader_is_detected_in_memory() {
        let mut subheaders = vec![FORM1_DATA_SUBHEADER; 18];
        subheaders[16] = PVD_SUBHEADER;
        subheaders[17] = SYSTEM_END_OF_FILE_SUBHEADER;
        let sectors = parsed_form1_sequence(&subheaders);
        let mut parsed = parsed_iso();
        parsed.files.clear();
        parsed
            .manifest
            .entries
            .retain(|entry| entry.path == iso9660::ROOT_PATH);
        parsed.manifest.entries.push(Entry {
            path: "DIR".to_owned(),
            recording_time: "1998-03-19T11:58:36+09:00".to_owned(),
            hidden: false,
            associated: false,
            reference: None,
            xa_system_use: None,
            directory_slack: None,
            allocation_padding_hex: None,
            directory_self_xa: None,
            sector_subheader: EntrySectorSubheader::Canonical,
            xa: None,
        });
        parsed.directories.push(iso9660::ParsedDirectory {
            path: "DIR".to_owned(),
            extent: 17,
            length: LOGICAL_BLOCK_SIZE as u32,
        });

        detect_entry_sector_subheaders(&sectors, &mut parsed, &[]).unwrap();

        assert_eq!(
            parsed.manifest.entries[1].sector_subheader,
            EntrySectorSubheader::EndOfFileData
        );
        validate_iso_subheaders(&sectors, &parsed, 0).unwrap();
    }

    #[test]
    fn uniform_custom_directory_subheader_is_detected_in_memory() {
        let custom = XaSubheader::with_submode(XaSubmode::DATA.union(XaSubmode::VIDEO));
        let mut subheaders = vec![FORM1_DATA_SUBHEADER; 19];
        subheaders[16] = PVD_SUBHEADER;
        subheaders[17] = custom;
        subheaders[18] = ISO_METADATA_SUBHEADER;
        let sectors = parsed_form1_sequence(&subheaders);
        let mut parsed = parsed_iso();
        parsed.files.clear();
        parsed
            .manifest
            .entries
            .retain(|entry| entry.path == iso9660::ROOT_PATH);
        parsed.manifest.entries.push(Entry {
            path: "DIR".to_owned(),
            recording_time: "1998-03-19T11:58:36+09:00".to_owned(),
            hidden: false,
            associated: false,
            reference: None,
            xa_system_use: None,
            directory_slack: None,
            allocation_padding_hex: None,
            directory_self_xa: None,
            sector_subheader: EntrySectorSubheader::Canonical,
            xa: None,
        });
        parsed.directories.push(iso9660::ParsedDirectory {
            path: "DIR".to_owned(),
            extent: 17,
            length: (2 * LOGICAL_BLOCK_SIZE) as u32,
        });

        let redump_ranges = std::iter::once(18..19).collect::<Vec<_>>();
        detect_entry_sector_subheaders(&sectors, &mut parsed, &redump_ranges).unwrap();

        assert_eq!(
            parsed.manifest.entries[1]
                .xa
                .as_ref()
                .and_then(|xa| xa.framing_subheader),
            Some(custom)
        );
        assert_eq!(
            parsed.manifest.entries[1].sector_subheader,
            EntrySectorSubheader::DataUntilFinal
        );
        validate_iso_subheaders_with_xa_extents(&sectors, &parsed, 0, &[], &redump_ranges).unwrap();
    }

    #[test]
    fn path_table_data_until_final_policy_is_detected_in_memory() {
        let mut subheaders = vec![ISO_METADATA_SUBHEADER; 26];
        subheaders[..16].fill(FORM1_DATA_SUBHEADER);
        subheaders[16] = PVD_SUBHEADER;
        for lba in [18, 20, 22, 24] {
            subheaders[lba] = FORM1_DATA_SUBHEADER;
        }
        let sectors = parsed_form1_sequence(&subheaders);
        let mut parsed = parsed_iso();
        parsed.path_tables = Some(iso9660::ParsedPathTables {
            extents: [18, 20, 22, 24],
            blocks: 2,
        });

        detect_path_table_subheader(&sectors, &mut parsed, &[]).unwrap();

        assert_eq!(
            parsed.manifest.path_table_subheader,
            PathTableSubheader::Named(EntrySectorSubheader::DataUntilFinal)
        );
        validate_iso_subheaders(&sectors, &parsed, 0).unwrap();
    }

    #[test]
    fn path_table_end_of_file_data_policy_is_detected_in_memory() {
        let mut subheaders = vec![ISO_METADATA_SUBHEADER; 26];
        subheaders[..16].fill(FORM1_DATA_SUBHEADER);
        subheaders[16] = PVD_SUBHEADER;
        for lba in [18, 20, 22, 24] {
            subheaders[lba] = FORM1_DATA_SUBHEADER;
            subheaders[lba + 1] = SYSTEM_END_OF_FILE_SUBHEADER;
        }
        let sectors = parsed_form1_sequence(&subheaders);
        let mut parsed = parsed_iso();
        parsed.path_tables = Some(iso9660::ParsedPathTables {
            extents: [18, 20, 22, 24],
            blocks: 2,
        });

        detect_path_table_subheader(&sectors, &mut parsed, &[]).unwrap();

        assert_eq!(
            parsed.manifest.path_table_subheader,
            PathTableSubheader::Named(EntrySectorSubheader::EndOfFileData)
        );
        validate_iso_subheaders(&sectors, &parsed, 0).unwrap();
    }

    #[test]
    fn custom_path_table_form1_subheader_is_detected_in_memory() {
        let custom = XaSubheader::default();
        let mut subheaders = vec![ISO_METADATA_SUBHEADER; 32];
        subheaders[..16].fill(FORM1_DATA_SUBHEADER);
        subheaders[16] = PVD_SUBHEADER;
        for lba in [18, 19, 22, 23, 26, 27, 30, 31] {
            subheaders[lba] = custom;
        }
        let sectors = parsed_form1_sequence(&subheaders);
        let mut parsed = parsed_iso();
        parsed.path_tables = Some(iso9660::ParsedPathTables {
            extents: [18, 22, 26, 30],
            blocks: 2,
        });

        detect_path_table_subheader(&sectors, &mut parsed, &[]).unwrap();

        assert_eq!(
            parsed.manifest.path_table_subheader,
            PathTableSubheader::Explicit(custom)
        );
        validate_iso_subheaders(&sectors, &parsed, 0).unwrap();
    }

    #[test]
    fn path_table_xa_gap_padding_is_validated_in_memory() {
        let mut subheaders = vec![ISO_METADATA_SUBHEADER; 23];
        subheaders[..16].fill(FORM1_DATA_SUBHEADER);
        subheaders[16] = PVD_SUBHEADER;
        let mut sectors = parsed_form1_sequence(&subheaders);
        sectors[19] = parsed_xa_gap_sector();
        sectors[21] = parsed_xa_gap_sector();
        let mut parsed = parsed_iso();
        parsed.manifest.entries.truncate(1);
        parsed.manifest.layout.clear();
        parsed.manifest.path_table_copies = crate::manifest::PathTableCopies::Single;
        parsed.manifest.path_table_padding = 1;
        parsed.files.clear();
        parsed.path_tables = Some(iso9660::ParsedPathTables {
            extents: [18, 0, 20, 0],
            blocks: 1,
        });

        validate_iso_subheaders(&sectors, &parsed, 0).unwrap();
    }

    #[test]
    fn absent_optional_path_tables_are_not_treated_as_lba_zero() {
        let mut subheaders = vec![ISO_METADATA_SUBHEADER; 20];
        subheaders[..16].fill(FORM1_DATA_SUBHEADER);
        subheaders[16] = PVD_SUBHEADER;
        let sectors = parsed_form1_sequence(&subheaders);
        let mut parsed = parsed_iso();
        parsed.path_tables = Some(iso9660::ParsedPathTables {
            extents: [18, 0, 19, 0],
            blocks: 1,
        });

        detect_path_table_subheader(&sectors, &mut parsed, &[]).unwrap();
        validate_iso_subheaders(&sectors, &parsed, 0).unwrap();
    }

    #[test]
    fn file_end_of_file_data_subheader_is_detected_in_memory() {
        let mut subheaders = vec![FORM1_DATA_SUBHEADER; 18];
        subheaders[16] = PVD_SUBHEADER;
        subheaders[17] = SYSTEM_END_OF_FILE_SUBHEADER;
        let sectors = parsed_form1_sequence(&subheaders);
        let mut parsed = parsed_iso();

        detect_entry_sector_subheaders(&sectors, &mut parsed, &[]).unwrap();
        assert_eq!(
            parsed.manifest.entries[1].sector_subheader,
            EntrySectorSubheader::EndOfFileData
        );
        validate_iso_subheaders(&sectors, &parsed, 0).unwrap();
    }

    #[test]
    fn entry_xa_file_number_drives_iso_sector_subheaders() {
        let mut subheaders = vec![FORM1_DATA_SUBHEADER; 18];
        subheaders[16] = PVD_SUBHEADER;
        subheaders[17] = XaSubheader {
            file_number: 1,
            ..ISO_METADATA_SUBHEADER
        };
        let sectors = parsed_form1_sequence(&subheaders);
        let mut parsed = parsed_iso();
        parsed.manifest.entries[1].xa = Some(crate::manifest::EntryXa {
            file_number: 1,
            ..crate::manifest::EntryXa::default()
        });

        detect_entry_sector_subheaders(&sectors, &mut parsed, &[]).unwrap();
        validate_iso_subheaders(&sectors, &parsed, 0).unwrap();
    }

    #[test]
    fn manifests_are_compact_and_include_required_version_and_track_mode() {
        let mut manifest = test_manifest();
        manifest.iso9660.entries[1].xa_system_use = Some(false);
        let compact = serialize_manifest(&manifest).unwrap();
        assert!(compact.starts_with(&format!("gcdgold:\n  version: {GCDGOLD_VERSION}\n")));
        assert!(compact.contains("track:\n  mode: 2xa\n"));
        assert!(!compact.contains("sha1"));
        assert!(!compact.contains("source:"));
        assert!(!compact.contains("start_msf:"));
        assert!(!compact.contains("form2_edc:"));
        assert!(!compact.contains("noncompliant_trailing_ecc:"));
        assert!(!compact.contains("metadata_subheader:"));
        assert!(!compact.contains("sector_subheader:"));
        assert!(compact.contains("xa_system_use: false"));
        assert!(compact.contains("  layout:\n"));
        assert!(!compact.contains("  files:\n"));
        assert!(yaml_serde::from_str::<Manifest>(&compact).is_ok());
        let missing_gcdgold =
            compact.replacen(&format!("gcdgold:\n  version: {GCDGOLD_VERSION}\n"), "", 1);
        assert!(yaml_serde::from_str::<Manifest>(&missing_gcdgold).is_err());
        let missing_version = compact.replacen(&format!("  version: {GCDGOLD_VERSION}\n"), "", 1);
        assert!(yaml_serde::from_str::<Manifest>(&missing_version).is_err());
        let numeric_version = compact.replacen(
            &format!("  version: {GCDGOLD_VERSION}\n"),
            "  version: 1\n",
            1,
        );
        assert!(yaml_serde::from_str::<Manifest>(&numeric_version).is_err());
        let unknown_metadata = compact.replacen(
            &format!("  version: {GCDGOLD_VERSION}\n"),
            &format!("  version: {GCDGOLD_VERSION}\n  schema: 1\n"),
            1,
        );
        assert!(yaml_serde::from_str::<Manifest>(&unknown_metadata).is_err());
        let missing_track = compact.replacen("track:\n  mode: 2xa\n", "", 1);
        assert!(yaml_serde::from_str::<Manifest>(&missing_track).is_err());

        let mut sourced = manifest;
        let FileLayoutItem::Path(file) = &mut sourced.iso9660.layout[0] else {
            panic!("expected ordinary file")
        };
        file.source = Some("FILE.BIN.1".to_owned());
        assert!(
            serialize_manifest(&sourced)
                .unwrap()
                .contains("source: FILE.BIN.1")
        );
    }

    #[test]
    fn removed_files_layout_key_is_rejected() {
        let yaml = serialize_manifest(&test_manifest()).unwrap();
        let legacy = yaml.replacen("  layout:\n", "  files:\n", 1);
        let error = yaml_serde::from_str::<Manifest>(&legacy)
            .unwrap_err()
            .to_string();

        assert!(error.contains("unknown field"));
        assert!(error.contains("files"));

        for removed in [
            "  metadata_framing_subheader: {}\n",
            "  path_table_framing_subheader: {}\n",
        ] {
            let legacy = yaml.replacen("  entries:\n", &format!("{removed}  entries:\n"), 1);
            assert!(yaml_serde::from_str::<Manifest>(&legacy).is_err());
        }
    }

    #[test]
    fn manifest_sha1_validation_accepts_uppercase_and_rejects_invalid_placement() {
        let uppercase = "0123456789ABCDEF0123456789ABCDEF01234567";
        let mut manifest = test_manifest();
        manifest.track.sha1 = Some(uppercase.to_owned());
        manifest.system_area.sha1 = Some(uppercase.to_owned());
        if let FileLayoutItem::Path(file) = &mut manifest.iso9660.layout[0] {
            file.sha1 = Some(uppercase.to_owned());
        }
        validate_manifest_hashes(&manifest).unwrap();

        manifest.track.sha1 = Some("not-a-sha1".to_owned());
        assert!(validate_manifest_hashes(&manifest).is_err());
        manifest.track.sha1 = Some(uppercase.to_owned());
        manifest.iso9660.entries[1].xa = Some(crate::manifest::EntryXa {
            form1: Some("FILE.BIN.XA1".to_owned()),
            form2: Some("FILE.BIN.XA2".to_owned()),
            index: Some("FILE.BIN.XAI".to_owned()),
            ..crate::manifest::EntryXa::default()
        });
        assert_eq!(
            validate_manifest_hashes(&manifest).unwrap_err().to_string(),
            "indexed XA file FILE.BIN cannot declare an ordinary-file sha1"
        );

        if let FileLayoutItem::Path(file) = &mut manifest.iso9660.layout[0] {
            file.sha1 = None;
        }
        manifest.iso9660.entries[1].xa = None;
        manifest
            .iso9660
            .layout
            .push(FileLayoutItem::xa_extent(XaExtentAssets {
                form1: "EXTRA.XA1".to_owned(),
                form1_sha1: None,
                form2: "EXTRA.XA2".to_owned(),
                form2_sha1: None,
                index: "EXTRA.XAI".to_owned(),
                index_sha1: None,
                gap_index: None,
                gap_index_sha1: Some(uppercase.to_owned()),
            }));
        assert!(validate_manifest_hashes(&manifest).is_err());
    }

    #[test]
    fn extracted_hashes_cover_ordinary_indexed_and_unreferenced_assets() {
        let mut manifest = test_manifest();
        let mut ordinary = manifest.iso9660.entries[1].clone();
        ordinary.path = "ORDINARY.BIN".to_owned();
        manifest.iso9660.entries.push(ordinary);
        manifest
            .iso9660
            .layout
            .push(FileLayoutItem::path("ORDINARY.BIN"));
        manifest.iso9660.entries[1].xa = Some(crate::manifest::EntryXa {
            form1: Some("FILE.BIN.XA1".to_owned()),
            form2: Some("FILE.BIN.XA2".to_owned()),
            index: Some("FILE.BIN.XAI".to_owned()),
            gap_index: Some("FILE.BIN.XAG".to_owned()),
            ..crate::manifest::EntryXa::default()
        });
        manifest
            .iso9660
            .layout
            .push(FileLayoutItem::xa_extent(XaExtentAssets {
                form1: "EXTRA.XA1".to_owned(),
                form1_sha1: None,
                form2: "EXTRA.XA2".to_owned(),
                form2_sha1: None,
                index: "EXTRA.XAI".to_owned(),
                index_sha1: None,
                gap_index: Some("EXTRA.XAG".to_owned()),
                gap_index_sha1: None,
            }));
        let assets = [
            ("ORDINARY.BIN", vec![1]),
            ("FILE.BIN.XA1", Vec::new()),
            ("FILE.BIN.XA2", vec![2]),
            ("FILE.BIN.XAI", vec![3]),
            ("FILE.BIN.XAG", vec![4]),
            ("EXTRA.XA1", vec![5]),
            ("EXTRA.XA2", vec![6]),
            ("EXTRA.XAI", vec![7]),
            ("EXTRA.XAG", vec![8]),
        ]
        .into_iter()
        .map(|(path, bytes)| (path.to_owned(), bytes))
        .collect::<HashMap<_, _>>();

        let track_sha1 = sha1_hex(b"track");
        add_extracted_hashes(&mut manifest, &track_sha1, b"system", &assets).unwrap();

        let system_sha1 = sha1_hex(b"system");
        assert_eq!(manifest.track.sha1.as_deref(), Some(track_sha1.as_str()));
        assert_eq!(
            manifest.system_area.sha1.as_deref(),
            Some(system_sha1.as_str())
        );
        let xa = manifest.iso9660.entries[1].xa.as_ref().unwrap();
        assert_eq!(
            xa.form1_sha1.as_deref(),
            Some("da39a3ee5e6b4b0d3255bfef95601890afd80709")
        );
        assert!(xa.form2_sha1.is_some());
        assert!(xa.index_sha1.is_some());
        assert!(xa.gap_index_sha1.is_some());
        if let FileLayoutItem::Path(file) = &manifest.iso9660.layout[1] {
            let expected = sha1_hex(&[1]);
            assert_eq!(file.sha1.as_deref(), Some(expected.as_str()));
        } else {
            panic!("ordinary asset is not a path item");
        }
        if let FileLayoutItem::XaExtent(item) = &manifest.iso9660.layout[2] {
            assert!(item.xa_extent.form1_sha1.is_some());
            assert!(item.xa_extent.form2_sha1.is_some());
            assert!(item.xa_extent.index_sha1.is_some());
            assert!(item.xa_extent.gap_index_sha1.is_some());
        } else {
            panic!("unreferenced asset is not an XA extent");
        }
        let yaml = serialize_manifest(&manifest).unwrap();
        assert!(yaml.contains(&format!("sha1: {track_sha1}")));
        assert!(yaml.contains("form1_sha1: da39a3ee5e6b4b0d3255bfef95601890afd80709"));
        let reparsed: Manifest = yaml_serde::from_str(&yaml).unwrap();
        assert_eq!(reparsed.track.sha1, manifest.track.sha1);
    }

    #[test]
    fn indexed_xa_asset_hash_mismatches_are_reported_in_asset_order() {
        let project = tempfile::tempdir().unwrap();
        let data_dir = project.path().join("assets");
        fs::create_dir(&data_dir).unwrap();
        fs::write(
            data_dir.join("sample.system"),
            vec![0_u8; SYSTEM_AREA_SECTORS * LOGICAL_BLOCK_SIZE],
        )
        .unwrap();
        let sectors = vec![
            parsed_xa_sector(false, 1),
            parsed_xa_sector(true, 2),
            parsed_xa_gap_sector(),
            parsed_xa_sector(false, 3),
        ];
        let assets = demultiplex_xa_extent(&sectors, true).unwrap();
        for (path, bytes) in [
            ("FILE.XA1", &assets.form1),
            ("FILE.XA2", &assets.form2),
            ("FILE.XAI", &assets.form2_index),
            ("FILE.XAG", &assets.gap_index),
        ] {
            fs::write(data_dir.join(path), bytes).unwrap();
        }
        let mut manifest = test_manifest();
        manifest.system_area.sha1 =
            Some(sha1_hex(&fs::read(data_dir.join("sample.system")).unwrap()));
        manifest.iso9660.entries[1].xa = Some(crate::manifest::EntryXa {
            attributes: Some(crate::manifest::XaAttributes::from_bits(
                crate::manifest::XaAttributes::MODE2_FORM1.bits()
                    | crate::manifest::XaAttributes::INTERLEAVED.bits(),
            )),
            form1: Some("FILE.XA1".to_owned()),
            form1_sha1: Some(sha1_hex(&assets.form1)),
            form2: Some("FILE.XA2".to_owned()),
            form2_sha1: Some(sha1_hex(&assets.form2)),
            index: Some("FILE.XAI".to_owned()),
            index_sha1: Some(sha1_hex(&assets.form2_index)),
            gap_index: Some("FILE.XAG".to_owned()),
            gap_index_sha1: Some(sha1_hex(&assets.gap_index)),
            ..crate::manifest::EntryXa::default()
        });
        let manifest_path = project.path().join("disc.yaml");
        fs::write(&manifest_path, serialize_manifest(&manifest).unwrap()).unwrap();
        let unchanged = build(
            &manifest_path,
            &project.path().join("unchanged.bin"),
            &data_dir,
            false,
        )
        .unwrap();
        assert!(unchanged.sha1_mismatches.is_empty());

        let mut warning_only_manifest = manifest.clone();
        warning_only_manifest.system_area.sha1 = Some("0".repeat(40));
        warning_only_manifest.iso9660.entries[1]
            .xa
            .as_mut()
            .unwrap()
            .form1_sha1 = Some("1".repeat(40));
        let warning_only_manifest_path = project.path().join("warning-only.yaml");
        fs::write(
            &warning_only_manifest_path,
            serialize_manifest(&warning_only_manifest).unwrap(),
        )
        .unwrap();
        let warning_only = build(
            &warning_only_manifest_path,
            &project.path().join("warning-only.bin"),
            &data_dir,
            false,
        )
        .unwrap();
        assert_eq!(warning_only.sha1_mismatches.len(), 2);
        assert!(
            warning_only
                .sha1_mismatches
                .iter()
                .all(|mismatch| mismatch.target != Sha1Target::Track)
        );

        let mut no_track_hash_manifest = manifest.clone();
        no_track_hash_manifest.track.sha1 = None;
        let no_track_hash_manifest_path = project.path().join("no-track-hash.yaml");
        fs::write(
            &no_track_hash_manifest_path,
            serialize_manifest(&no_track_hash_manifest).unwrap(),
        )
        .unwrap();
        let no_track_hash = build(
            &no_track_hash_manifest_path,
            &project.path().join("no-track-hash.bin"),
            &data_dir,
            false,
        )
        .unwrap();
        assert!(no_track_hash.sha1_mismatches.is_empty());

        let mut wrong_track_hash_manifest = manifest.clone();
        wrong_track_hash_manifest.track.sha1 = Some("f".repeat(40));
        let wrong_track_hash_manifest_path = project.path().join("wrong-track-hash.yaml");
        fs::write(
            &wrong_track_hash_manifest_path,
            serialize_manifest(&wrong_track_hash_manifest).unwrap(),
        )
        .unwrap();
        let wrong_track_image = project.path().join("wrong-track-hash.bin");
        let wrong_track_hash = build(
            &wrong_track_hash_manifest_path,
            &wrong_track_image,
            &data_dir,
            false,
        )
        .unwrap();
        assert!(wrong_track_image.is_file());
        assert_eq!(wrong_track_hash.sha1_mismatches.len(), 1);
        assert_eq!(
            wrong_track_hash.sha1_mismatches[0].target,
            Sha1Target::Track
        );

        let mut form1 = assets.form1.clone();
        form1[8] ^= 1;
        fs::write(data_dir.join("FILE.XA1"), form1).unwrap();
        let mut form2 = assets.form2.clone();
        form2[8] ^= 1;
        fs::write(data_dir.join("FILE.XA2"), form2).unwrap();
        fs::write(data_dir.join("FILE.XAI"), encode_xa_index(&[0])).unwrap();
        fs::write(data_dir.join("FILE.XAG"), encode_xa_index(&[3])).unwrap();

        let changed = build(
            &manifest_path,
            &project.path().join("changed.bin"),
            &data_dir,
            false,
        )
        .unwrap();
        assert_eq!(
            changed
                .sha1_mismatches
                .iter()
                .map(|mismatch| match &mismatch.target {
                    Sha1Target::Asset { path } => path.as_str(),
                    Sha1Target::Track | Sha1Target::SystemArea { .. } => "unexpected",
                })
                .collect::<Vec<_>>(),
            ["FILE.XA1", "FILE.XA2", "FILE.XAI", "FILE.XAG"]
        );
    }

    fn build_redump_integration_fixture(project: &Path) -> (Vec<u8>, u32) {
        let data_dir = project.join("source");
        fs::create_dir(&data_dir).unwrap();
        fs::write(
            data_dir.join("sample.system"),
            vec![0_u8; SYSTEM_AREA_SECTORS * LOGICAL_BLOCK_SIZE],
        )
        .unwrap();
        fs::write(
            data_dir.join("FILE.BIN"),
            vec![0xa5_u8; 2 * LOGICAL_BLOCK_SIZE],
        )
        .unwrap();
        let mut manifest = test_manifest();
        manifest.iso9660.layout.insert(0, FileLayoutItem::gap(3));
        manifest.iso9660.layout.push(FileLayoutItem::xa_gap(4));
        let manifest_path = project.join("source.yaml");
        fs::write(&manifest_path, serialize_manifest(&manifest).unwrap()).unwrap();
        let image_path = project.join("source.bin");
        build(&manifest_path, &image_path, &data_dir, false).unwrap();
        let raw = fs::read(image_path).unwrap();
        let blocks = parse_image(&raw)
            .unwrap()
            .1
            .iter()
            .map(|sector| sector.logical_block().try_into().unwrap())
            .collect::<Vec<[u8; LOGICAL_BLOCK_SIZE]>>();
        let parsed = iso9660::parse(&blocks).unwrap();
        (raw, parsed.files[0].extent)
    }

    #[test]
    fn build_rejects_a_different_gcdgold_version_before_creating_the_image() {
        let project = tempfile::tempdir().unwrap();
        let _ = build_redump_integration_fixture(project.path());
        let source_image = project.path().join("source.bin");
        let data_dir = project.path().join("extracted");
        let manifest_path = project.path().join("extracted.yaml");
        extract_with_options(
            &source_image,
            &manifest_path,
            &data_dir,
            ExtractOptions { overwrite: false },
        )
        .unwrap();

        let mut manifest: Manifest =
            yaml_serde::from_str(&fs::read_to_string(&manifest_path).unwrap()).unwrap();
        assert_eq!(manifest.gcdgold.version, GCDGOLD_VERSION);
        manifest.gcdgold.version = "different-version".to_owned();
        fs::write(&manifest_path, serialize_manifest(&manifest).unwrap()).unwrap();

        let image_path = project.path().join("mismatched.bin");
        let error = build(&manifest_path, &image_path, &data_dir, false)
            .unwrap_err()
            .to_string();
        assert_eq!(
            error,
            format!(
                "manifest gcdgold version different-version does not match this gcdgold version {GCDGOLD_VERSION}"
            )
        );
        assert!(!image_path.exists());
    }

    #[test]
    fn extracted_hashes_are_always_emitted_and_warn_without_blocking_build() {
        let project = tempfile::tempdir().unwrap();
        let (raw, _) = build_redump_integration_fixture(project.path());
        let source_image = project.path().join("source.bin");

        let plain_manifest_path = project.path().join("plain.yaml");
        extract_with_options(
            &source_image,
            &plain_manifest_path,
            &project.path().join("plain-assets"),
            ExtractOptions { overwrite: false },
        )
        .unwrap();
        let plain: Manifest =
            yaml_serde::from_str(&fs::read_to_string(plain_manifest_path).unwrap()).unwrap();
        assert_eq!(plain.gcdgold.version, GCDGOLD_VERSION);
        assert_eq!(plain.track.sha1, Some(sha1_hex(&raw)));
        assert!(plain.system_area.sha1.is_some());
        assert!(
            plain
                .iso9660
                .layout
                .iter()
                .filter_map(FileLayoutItem::as_path_source_with_sha1)
                .all(|(_, _, sha1)| sha1.is_some())
        );

        let data_dir = project.path().join("hashed-assets");
        let manifest_path = project.path().join("hashed.yaml");
        extract_with_options(
            &source_image,
            &manifest_path,
            &data_dir,
            ExtractOptions { overwrite: false },
        )
        .unwrap();
        let manifest: Manifest =
            yaml_serde::from_str(&fs::read_to_string(&manifest_path).unwrap()).unwrap();
        assert_eq!(manifest.track.sha1, Some(sha1_hex(&raw)));
        let system = fs::read(data_dir.join(&manifest.system_area.path)).unwrap();
        assert_eq!(manifest.system_area.sha1, Some(sha1_hex(&system)));
        let file_sha1 = manifest
            .iso9660
            .layout
            .iter()
            .filter_map(FileLayoutItem::as_path_source_with_sha1)
            .find(|(path, _, _)| *path == "FILE.BIN")
            .and_then(|(_, _, sha1)| sha1)
            .unwrap();
        assert_eq!(
            file_sha1,
            sha1_hex(&fs::read(data_dir.join("FILE.BIN")).unwrap())
        );

        let unchanged = build(
            &manifest_path,
            &project.path().join("unchanged.bin"),
            &data_dir,
            false,
        )
        .unwrap();
        assert!(unchanged.sha1_mismatches.is_empty());

        let mut patched_manifest = manifest.clone();
        let patch_index = raw.len() / RAW_SECTOR_SIZE - 1;
        let replacement = [0x3c; RAW_SECTOR_SIZE];
        patched_manifest.track.patches.push(SectorPatch {
            lba: i32::try_from(patch_index).unwrap(),
            hex: format_sector_patch_hex(&replacement),
        });
        let mut patched_raw = raw.clone();
        patched_raw[patch_index * RAW_SECTOR_SIZE..].copy_from_slice(&replacement);
        patched_manifest.track.sha1 = Some(sha1_hex(&patched_raw));
        let patched_manifest_path = project.path().join("patched.yaml");
        fs::write(
            &patched_manifest_path,
            serialize_manifest(&patched_manifest).unwrap(),
        )
        .unwrap();
        let patched = build(
            &patched_manifest_path,
            &project.path().join("patched.bin"),
            &data_dir,
            false,
        )
        .unwrap();
        assert!(patched.sha1_mismatches.is_empty());
        fs::write(data_dir.join(&manifest.system_area.path), [1]).unwrap();
        let mut file = fs::read(data_dir.join("FILE.BIN")).unwrap();
        file[0] ^= 0xff;
        fs::write(data_dir.join("FILE.BIN"), file).unwrap();
        let changed_image = project.path().join("changed.bin");
        let changed = build(&manifest_path, &changed_image, &data_dir, false).unwrap();
        assert!(changed_image.is_file());
        assert_eq!(changed.sha1_mismatches.len(), 3);
        assert!(matches!(
            &changed.sha1_mismatches[0].target,
            Sha1Target::SystemArea { path } if path == &manifest.system_area.path
        ));
        assert_eq!(
            changed.sha1_mismatches[1].target,
            Sha1Target::Asset {
                path: "FILE.BIN".to_owned()
            }
        );
        assert_eq!(changed.sha1_mismatches[2].target, Sha1Target::Track);
    }

    #[test]
    fn redump_0x55_runs_preserve_system_unreferenced_file_and_terminal_allocations() {
        let project = tempfile::tempdir().unwrap();
        let (mut raw, file_extent) = build_redump_integration_fixture(project.path());
        let last = raw.len() / RAW_SECTOR_SIZE - 1;
        let file_extent = usize::try_from(file_extent).unwrap();
        let damaged = [0_usize, file_extent - 2, file_extent, last];
        for index in damaged {
            raw[index * RAW_SECTOR_SIZE + 16..(index + 1) * RAW_SECTOR_SIZE].fill(0x55);
        }
        let image_path = project.path().join("damaged.bin");
        fs::write(&image_path, &raw).unwrap();
        let manifest_path = project.path().join("damaged.yaml");
        let report = extract_with_options(
            &image_path,
            &manifest_path,
            &project.path().join("extracted"),
            ExtractOptions { overwrite: false },
        )
        .unwrap();
        assert!(report.recovery_warnings.is_empty());
        let manifest: Manifest =
            yaml_serde::from_str(&fs::read_to_string(manifest_path).unwrap()).unwrap();
        assert_eq!(
            manifest.track.redump_0x55,
            damaged
                .into_iter()
                .map(|lba| Redump0x55Run {
                    lba: i32::try_from(lba).unwrap(),
                    sectors: 1,
                })
                .collect::<Vec<_>>()
        );
        assert!(manifest.track.patches.is_empty());
        assert_eq!(
            manifest.track.sha1.as_deref(),
            Some(sha1_hex(&raw).as_str())
        );
    }

    #[test]
    fn redump_0x55_damage_to_required_iso_metadata_is_targeted() {
        let project = tempfile::tempdir().unwrap();
        let (mut raw, _) = build_redump_integration_fixture(project.path());
        raw[16 * RAW_SECTOR_SIZE + 16..17 * RAW_SECTOR_SIZE].fill(0x55);
        let image_path = project.path().join("metadata-damaged.bin");
        fs::write(&image_path, raw).unwrap();
        let error = extract_with_options(
            &image_path,
            &project.path().join("metadata-damaged.yaml"),
            &project.path().join("extracted"),
            ExtractOptions { overwrite: false },
        )
        .unwrap_err();
        assert!(
            format!("{error:#}").contains(
                "Redump 0x55 zero placeholders do not leave a parseable ISO 9660 filesystem; required metadata may be damaged"
            )
        );
    }

    #[test]
    fn extent_reads_are_bounded_and_trimmed_in_memory() {
        let mut blocks = [[0_u8; LOGICAL_BLOCK_SIZE]; 2];
        blocks[0][0] = 0x11;
        blocks[1][0] = 0x22;

        let data = read_extent(&blocks, 0, (LOGICAL_BLOCK_SIZE + 1) as u32).unwrap();
        assert_eq!(data.len(), LOGICAL_BLOCK_SIZE + 1);
        assert_eq!(data[0], 0x11);
        assert_eq!(data[LOGICAL_BLOCK_SIZE], 0x22);
        assert!(read_extent(&blocks, 2, 1).is_err());
    }

    #[test]
    fn path_and_output_preflight_helpers_are_independent_of_images() {
        assert!(safe_join(Path::new("root"), "../escape").is_err());
        assert_eq!(
            safe_join(Path::new("root"), "DIR/FILE.BIN").unwrap(),
            Path::new("root/DIR/FILE.BIN")
        );
        assert_eq!(manifest_stem(Path::new("disc.yaml")).unwrap(), "disc");
        assert_eq!(
            temporary_path(Path::new("/tmp/output")).unwrap(),
            Path::new("/tmp/.output.gcdgold.tmp")
        );

        let project = tempfile::tempdir().unwrap();
        let output = project.path().join("existing.txt");
        validate_output_file(&output, false, "output").unwrap();
        fs::write(&output, b"sentinel").unwrap();
        assert!(
            validate_output_file(&output, false, "output")
                .unwrap_err()
                .to_string()
                .contains("already exists")
        );
        validate_output_file(&output, true, "output").unwrap();

        let directory = project.path().join("existing-directory");
        fs::create_dir(&directory).unwrap();
        assert!(validate_output_file(&directory, true, "output").is_err());
        validate_output_directory(&directory, "output").unwrap();

        let nested = project.path().join("new/parent/manifest.yaml");
        create_output_parent(&nested, "manifest").unwrap();
        assert!(nested.parent().unwrap().is_dir());
    }

    #[test]
    fn numbered_asset_paths_increment_terminal_suffixes_and_fill_gaps() {
        let project = tempfile::tempdir().unwrap();
        fs::write(project.path().join("FILE"), b"old").unwrap();
        fs::write(project.path().join("FILE.1"), b"also old").unwrap();
        fs::write(project.path().join("FILE.2"), b"desired").unwrap();
        let mut selected = HashSet::new();
        let reserved = HashSet::from(["FILE".to_owned()]);
        let (path, write) = resolve_extraction_asset_path(
            "FILE",
            b"desired",
            project.path(),
            false,
            &reserved,
            &mut selected,
        )
        .unwrap();
        assert_eq!(path, "FILE.2");
        assert!(!write);

        let mut selected = HashSet::new();
        let reserved = HashSet::from(["FILE".to_owned(), "FILE.1".to_owned()]);
        fs::remove_file(project.path().join("FILE.2")).unwrap();
        let (path, write) = resolve_extraction_asset_path(
            "FILE",
            b"desired",
            project.path(),
            false,
            &reserved,
            &mut selected,
        )
        .unwrap();
        assert_eq!(path, "FILE.2");
        assert!(write);

        fs::write(project.path().join("NUMBERED.7"), b"old").unwrap();
        let mut selected = HashSet::new();
        let reserved = HashSet::from(["NUMBERED.7".to_owned()]);
        let (path, write) = resolve_extraction_asset_path(
            "NUMBERED.7",
            b"new",
            project.path(),
            false,
            &reserved,
            &mut selected,
        )
        .unwrap();
        assert_eq!(path, "NUMBERED.8");
        assert!(write);

        fs::write(project.path().join("GAP"), b"old").unwrap();
        fs::write(project.path().join("GAP.2"), b"new").unwrap();
        let mut selected = HashSet::new();
        let reserved = HashSet::from(["GAP".to_owned()]);
        let (path, write) = resolve_extraction_asset_path(
            "GAP",
            b"new",
            project.path(),
            false,
            &reserved,
            &mut selected,
        )
        .unwrap();
        assert_eq!(path, "GAP.1");
        assert!(write);

        let mut selected = HashSet::new();
        let (path, write) = resolve_extraction_asset_path(
            "GAP",
            b"replacement",
            project.path(),
            true,
            &HashSet::from(["GAP".to_owned()]),
            &mut selected,
        )
        .unwrap();
        assert_eq!(path, "GAP");
        assert!(write);
    }

    #[test]
    fn extraction_output_planning_rewrites_system_and_xa_asset_paths() {
        let project = tempfile::tempdir().unwrap();
        let mut manifest = test_manifest();
        manifest.iso9660.entries[1].xa = Some(crate::manifest::EntryXa {
            form1: Some("FILE.XA1".to_owned()),
            form2: Some("FILE.XA2".to_owned()),
            index: Some("FILE.XAI".to_owned()),
            gap_index: Some("FILE.XAG".to_owned()),
            ..crate::manifest::EntryXa::default()
        });
        manifest
            .iso9660
            .layout
            .push(FileLayoutItem::xa_extent(XaExtentAssets {
                form1: "EXTRA.XA1".to_owned(),
                form1_sha1: None,
                form2: "EXTRA.XA2".to_owned(),
                form2_sha1: None,
                index: "EXTRA.XAI".to_owned(),
                index_sha1: None,
                gap_index: Some("EXTRA.XAG".to_owned()),
                gap_index_sha1: None,
            }));
        let mut assets = HashMap::from([
            ("FILE.XA1".to_owned(), vec![1]),
            ("FILE.XA2".to_owned(), vec![2]),
            ("FILE.XAI".to_owned(), vec![3]),
            ("FILE.XAG".to_owned(), Vec::new()),
            ("EXTRA.XA1".to_owned(), vec![4]),
            ("EXTRA.XA2".to_owned(), vec![5]),
            ("EXTRA.XAI".to_owned(), vec![6]),
            ("EXTRA.XAG".to_owned(), Vec::new()),
        ]);
        for path in extraction_asset_paths(&manifest).unwrap() {
            fs::write(project.path().join(path), b"different").unwrap();
        }
        let plan =
            plan_extraction_outputs(&mut manifest, &mut assets, b"system", project.path(), false)
                .unwrap();
        assert_eq!(manifest.system_area.path, "sample.system.1");
        let xa = manifest.iso9660.entries[1].xa.as_ref().unwrap();
        assert_eq!(xa.form1.as_deref(), Some("FILE.XA1.1"));
        assert_eq!(xa.form2.as_deref(), Some("FILE.XA2.1"));
        assert_eq!(xa.index.as_deref(), Some("FILE.XAI.1"));
        assert_eq!(xa.gap_index.as_deref(), Some("FILE.XAG.1"));
        let extra = manifest
            .iso9660
            .layout
            .last()
            .unwrap()
            .as_xa_extent()
            .unwrap();
        assert_eq!(extra.form1, "EXTRA.XA1.1");
        assert_eq!(extra.form2, "EXTRA.XA2.1");
        assert_eq!(extra.index, "EXTRA.XAI.1");
        assert_eq!(extra.gap_index.as_deref(), Some("EXTRA.XAG.1"));
        assert!(plan.system);
        assert_eq!(plan.assets.len(), assets.len());
        assert!(assets.contains_key("FILE.XAG.1"));
        assert!(assets["FILE.XAG.1"].is_empty());
    }

    #[test]
    fn ordinary_sources_validate_and_build_from_the_resolved_host_path() {
        let project = tempfile::tempdir().unwrap();
        let (raw, _) = build_redump_integration_fixture(project.path());
        let image_path = project.path().join("source.bin");
        let data_dir = project.path().join("shared");
        fs::create_dir(&data_dir).unwrap();
        fs::write(data_dir.join("shared.system"), b"old system").unwrap();
        fs::write(data_dir.join("FILE.BIN"), b"old file").unwrap();

        let first_manifest = project.path().join("first/shared.yaml");
        extract_with_options(
            &image_path,
            &first_manifest,
            &data_dir,
            ExtractOptions { overwrite: false },
        )
        .unwrap();
        let first: Manifest =
            yaml_serde::from_str(&fs::read_to_string(&first_manifest).unwrap()).unwrap();
        assert_eq!(first.system_area.path, "shared.system.1");
        let FileLayoutItem::Path(file) = first
            .iso9660
            .layout
            .iter()
            .find(|item| item.as_path() == Some("FILE.BIN"))
            .unwrap()
        else {
            panic!("expected ordinary file")
        };
        assert_eq!(file.source.as_deref(), Some("FILE.BIN.1"));
        assert_eq!(
            file.sha1.as_deref(),
            Some(sha1_hex(&fs::read(data_dir.join("FILE.BIN.1")).unwrap()).as_str())
        );
        assert_eq!(
            fs::read(data_dir.join("shared.system")).unwrap(),
            b"old system"
        );
        assert_eq!(fs::read(data_dir.join("FILE.BIN")).unwrap(), b"old file");

        let rebuilt = project.path().join("rebuilt.bin");
        let report = build(&first_manifest, &rebuilt, &data_dir, false).unwrap();
        assert!(report.sha1_mismatches.is_empty());
        assert_eq!(fs::read(rebuilt).unwrap(), raw);

        let second_manifest = project.path().join("second/shared.yaml");
        extract_with_options(
            &image_path,
            &second_manifest,
            &data_dir,
            ExtractOptions { overwrite: false },
        )
        .unwrap();
        let second: Manifest =
            yaml_serde::from_str(&fs::read_to_string(second_manifest).unwrap()).unwrap();
        assert_eq!(second.system_area.path, "shared.system.1");
        let FileLayoutItem::Path(file) = second
            .iso9660
            .layout
            .iter()
            .find(|item| item.as_path() == Some("FILE.BIN"))
            .unwrap()
        else {
            panic!("expected ordinary file")
        };
        assert_eq!(file.source.as_deref(), Some("FILE.BIN.1"));

        let overwrite_manifest_path = project.path().join("fourth/shared.yaml");
        extract_with_options(
            &image_path,
            &overwrite_manifest_path,
            &data_dir,
            ExtractOptions { overwrite: true },
        )
        .unwrap();
        let overwritten: Manifest =
            yaml_serde::from_str(&fs::read_to_string(overwrite_manifest_path).unwrap()).unwrap();
        assert_eq!(overwritten.system_area.path, "shared.system");
        let FileLayoutItem::Path(file) = overwritten
            .iso9660
            .layout
            .iter()
            .find(|item| item.as_path() == Some("FILE.BIN"))
            .unwrap()
        else {
            panic!("expected ordinary file")
        };
        assert!(file.source.is_none());

        let mut changed = fs::read(data_dir.join("FILE.BIN.1")).unwrap();
        changed[0] ^= 0xff;
        fs::write(data_dir.join("FILE.BIN.1"), changed).unwrap();
        let report = build(
            &first_manifest,
            &project.path().join("changed-source.bin"),
            &data_dir,
            false,
        )
        .unwrap();
        assert!(report.sha1_mismatches.iter().any(|mismatch| {
            mismatch.target
                == (Sha1Target::Asset {
                    path: "FILE.BIN.1".to_owned(),
                })
        }));
    }

    #[test]
    fn indexed_sources_and_duplicate_or_unsafe_host_paths_are_rejected() {
        let mut manifest = test_manifest();
        manifest.iso9660.entries[1].xa = Some(crate::manifest::EntryXa {
            form1: Some("FILE.XA1".to_owned()),
            form2: Some("FILE.XA2".to_owned()),
            index: Some("FILE.XAI".to_owned()),
            ..crate::manifest::EntryXa::default()
        });
        let FileLayoutItem::Path(file) = &mut manifest.iso9660.layout[0] else {
            panic!("expected path item")
        };
        file.source = Some("OTHER.BIN".to_owned());
        assert!(validate_manifest_hashes(&manifest).is_err());

        manifest.iso9660.entries[1].xa = None;
        if let FileLayoutItem::Path(file) = &mut manifest.iso9660.layout[0] {
            file.source = Some("../escape".to_owned());
        }
        assert!(validate_manifest_asset_paths(&manifest).is_err());

        if let FileLayoutItem::Path(file) = &mut manifest.iso9660.layout[0] {
            file.source = Some("sample.system".to_owned());
        }
        assert!(validate_manifest_asset_paths(&manifest).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn symlink_preflight_rejects_input_and_output_aliases() {
        use std::os::unix::fs::symlink;

        let project = tempfile::tempdir().unwrap();
        let target = project.path().join("target.txt");
        let alias = project.path().join("alias.txt");
        fs::write(&target, b"sentinel").unwrap();
        symlink(&target, &alias).unwrap();

        assert!(validate_input_file(&alias, "input").is_err());
        assert!(validate_output_file(&alias, true, "output").is_err());
        assert_eq!(fs::read(target).unwrap(), b"sentinel");

        let data_dir = project.path().join("data");
        let outside = project.path().join("outside");
        fs::create_dir(&data_dir).unwrap();
        fs::create_dir(&outside).unwrap();
        symlink(&outside, data_dir.join("LINK")).unwrap();
        assert!(validate_output_ancestors(&data_dir, "LINK/FILE.BIN").is_err());
    }

    #[test]
    fn sha1_helper_has_a_known_in_memory_vector() {
        assert_eq!(sha1_hex(b"abc"), "a9993e364706816aba3e25717850c26c9cd0d89d");
    }
}

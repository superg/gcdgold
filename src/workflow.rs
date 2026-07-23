use std::collections::{HashMap, HashSet};
use std::fs::{self, OpenOptions};
use std::io::{ErrorKind, Write};
use std::ops::Range;
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result, ensure};
use sha1::{Digest, Sha1};

use crate::iso9660;
use crate::manifest::{
    EntrySectorSubheader, FileLayoutItem, Form1Sectors, GapKind, IsoMetadataSubheader, Manifest,
    MetadataLayoutItem, MetadataVolume, SYSTEM_AREA_SECTORS, SystemArea, SystemAreaFinalSubheader,
    SystemAreaForm1Framing, SystemAreaSectorKind, SystemAreaSectorRun, Track, TrackMode,
    XaAttributeFlag, XaExtentAssets, XaLengthEncoding, serialize_manifest,
};
use crate::ppf::Ppf2;
use crate::raw_cd::{
    Kind, LOGICAL_BLOCK_SIZE, MODE2_DATA_SIZE, RAW_SECTOR_SIZE, SectorWriter, XaSubheader,
    XaSubmode, format_msf, parse_image, parse_msf, regenerate_mode2_protection,
};

#[derive(Debug, Clone)]
pub struct ExtractReport {
    pub sectors: u32,
    pub sha1: String,
}

#[derive(Debug, Clone)]
pub struct BuildReport {
    pub sectors: u32,
    pub sha1: String,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct ExtractOptions {
    pub manifest_only: bool,
    pub overwrite: bool,
    pub include_defaults: bool,
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

fn apply_ppf_overlay(
    raw: &mut [u8],
    patch: &Ppf2,
    form2_edc: bool,
    noncompliant_trailing_ecc: bool,
) -> Result<()> {
    ensure!(
        raw.len().is_multiple_of(RAW_SECTOR_SIZE),
        "canonical image size is not a multiple of 2352 bytes"
    );
    let sector_count = raw.len() / RAW_SECTOR_SIZE;
    let touched = patch.apply(raw, RAW_SECTOR_SIZE)?;
    for index in touched {
        let start = index * RAW_SECTOR_SIZE;
        regenerate_mode2_protection(
            &mut raw[start..start + RAW_SECTOR_SIZE],
            form2_edc,
            noncompliant_trailing_ecc && index + 1 == sector_count,
        )
        .with_context(|| format!("regenerating protection for patched sector {index}"))?;
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
    writer: &mut SectorWriter,
    frame: u32,
    sector: &XaExtentSector,
    form2_edc: bool,
) -> Result<()> {
    match sector {
        XaExtentSector::Form1(form1) => {
            raw.extend_from_slice(&writer.form1_with_subheaders(
                frame,
                form1.subheader,
                form1.subheader_copy,
                &form1.payload,
            )?);
        }
        XaExtentSector::Form2(record) => {
            raw.extend_from_slice(&writer.form2_with_subheaders(
                frame,
                record.subheader,
                record.subheader_copy,
                &record.payload,
                form2_edc,
            )?);
        }
        XaExtentSector::XaGap => {
            raw.extend_from_slice(&writer.xa_gap(frame, XaSubheader::default())?);
        }
    }
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

fn detach_unbacked_files(sector_count: usize, parsed_iso: &mut iso9660::ParsedIso) -> Result<()> {
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
            entry.extent.is_none() && entry.length.is_none() && !entry.unbacked,
            "unbacked entry already has a fixed reference: {}",
            file.path
        );
        entry.extent = Some(file.extent);
        entry.length = Some(file.length);
        entry.unbacked = true;
        entry.allocation_padding_hex = None;
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
            entry.extent.is_none() && entry.length.is_none() && !entry.unbacked,
            "overlapping entry already has a fixed reference: {}",
            file.path
        );
        entry.extent = Some(file.extent);
        entry.length = Some(file.length);
        entry.unbacked = true;
        entry.allocation_padding_hex = None;
    }
    parsed_iso
        .files
        .retain(|file| !detached_paths.contains(&file.path));
    Ok(())
}

fn detach_overlapping_form2_xa_files(
    sectors: &[crate::raw_cd::ParsedSector],
    parsed_iso: &mut iso9660::ParsedIso,
) -> Result<()> {
    detach_unbacked_files(sectors.len(), parsed_iso)?;
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
        let physical_range_is_form2 = end <= sectors.len()
            && sectors[start..end]
                .iter()
                .all(|sector| sector.kind == Kind::Form2);
        if start < root_end
            || overlaps_directory
            || !entries_are_form2_xa
            || !physical_range_is_form2
        {
            continue;
        }
        for index in component {
            let file = &parsed_iso.files[index];
            let entry = &mut parsed_iso.manifest.entries[entry_indices[file.path.as_str()]];
            ensure!(
                entry.extent.is_none() && entry.length.is_none(),
                "overlapping XA entry already has a fixed reference: {}",
                file.path
            );
            entry.extent = Some(file.extent);
            entry.length = Some(file.length);
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
) -> bool {
    if sectors.is_empty() || sectors.iter().any(|sector| sector.kind != Kind::Form1) {
        return sectors.is_empty();
    }
    let data = entry_file_subheader(entry, FORM1_DATA_SUBHEADER);
    let end_of_file = entry_file_subheader(entry, SYSTEM_END_OF_FILE_SUBHEADER);
    let metadata = entry_file_subheader(entry, ISO_METADATA_SUBHEADER);
    let matches = |index: usize, expected: XaSubheader| {
        sectors[index].subheader == expected && sectors[index].subheader_copy == expected
    };
    let all_data = (0..sectors.len()).all(|index| matches(index, data));
    let all_metadata = (0..sectors.len()).all(|index| matches(index, metadata));
    let data_then_final = |final_subheader| {
        (0..sectors.len() - 1).all(|index| matches(index, data))
            && matches(sectors.len() - 1, final_subheader)
    };
    all_data || all_metadata || data_then_final(metadata) || data_then_final(end_of_file)
}

fn prepare_xa_sidecars(
    sectors: &[crate::raw_cd::ParsedSector],
    parsed_iso: &mut iso9660::ParsedIso,
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
        let observed_mixed = sectors[start..start + count]
            .iter()
            .any(|sector| sector.kind != Kind::Form1);
        let observed_unrepresentable = !file_subheaders_are_representable(
            &sectors[start..start + count],
            &parsed_iso.manifest.entries[entry_index],
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
        form2: format!("{base}.XA2"),
        index: format!("{base}.XAI"),
        gap_index: sectors[start..end]
            .iter()
            .any(|sector| sector.kind == Kind::XaGap)
            .then(|| format!("{base}.XAG")),
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
    manifest_only: bool,
    overwrite: bool,
) -> Result<ExtractReport> {
    extract_with_options(
        image_path,
        manifest_path,
        data_dir,
        ExtractOptions {
            manifest_only,
            overwrite,
            include_defaults: false,
        },
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
    let (start_frame, sectors) = parse_image(&image)?;
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
    } = extract_system_area(&sectors[..SYSTEM_AREA_SECTORS], track_mode)?;
    let manifest_stem = manifest_stem(manifest_path)?;
    let system_name = format!("{manifest_stem}.system");
    let blocks = sectors
        .iter()
        .map(|sector| sector.logical_block().try_into())
        .collect::<Result<Vec<[u8; LOGICAL_BLOCK_SIZE]>, _>>()?;
    let mut parsed_iso = iso9660::parse(&blocks)?;
    let content_end = sectors.len() - trailing_physical_gap;
    if track_mode == TrackMode::Mode2Xa {
        if sectors[16].subheader == FORM1_DATA_SUBHEADER
            && sectors[16].subheader_copy == FORM1_DATA_SUBHEADER
        {
            parsed_iso.manifest.metadata_subheader = IsoMetadataSubheader::Data;
        } else if sectors[16].subheader == SYSTEM_END_OF_FILE_SUBHEADER
            && sectors[16].subheader_copy == SYSTEM_END_OF_FILE_SUBHEADER
        {
            parsed_iso.manifest.metadata_subheader = IsoMetadataSubheader::EndOfFileData;
        } else if sectors[16].subheader == ISO_METADATA_SUBHEADER
            && sectors[16].subheader_copy == ISO_METADATA_SUBHEADER
        {
            parsed_iso.manifest.metadata_subheader = IsoMetadataSubheader::IsoMetadata;
        } else if sectors[16].subheader == PVD_SUBHEADER
            && sectors[16].subheader_copy == PVD_SUBHEADER
        {
        } else if sectors[16].kind == Kind::Form1
            && sectors[16].subheader == sectors[16].subheader_copy
        {
            parsed_iso.manifest.metadata_framing_subheader = Some(sectors[16].subheader);
        }
        detect_path_table_subheader(&sectors[..content_end], &mut parsed_iso)?;
        detect_mode2_2336_file_lengths(content_end, &mut parsed_iso)?;
        detach_overlapping_form2_xa_files(&sectors[..content_end], &mut parsed_iso)?;
        prepare_xa_sidecars(&sectors[..content_end], &mut parsed_iso)?;
        detect_entry_sector_subheaders(&sectors[..content_end], &mut parsed_iso)?;
    } else {
        for item in &mut parsed_iso.manifest.metadata_layout {
            if let MetadataLayoutItem::Gap(gap) = item {
                gap.kind = GapKind::Mode1;
            }
        }
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
        )?;
    }
    parsed_iso.manifest.files = detected_layout.items;
    if trailing_gap > 0 {
        parsed_iso.manifest.files.push(match track_mode {
            TrackMode::Mode1 => FileLayoutItem::mode1_gap(u32::try_from(trailing_gap)?),
            TrackMode::Mode2Xa => FileLayoutItem::xa_gap(u32::try_from(trailing_gap)?),
            TrackMode::Mode2 => unreachable!("raw parser does not accept non-XA Mode 2"),
        });
    }
    if trailing_raw_zero > 0 {
        parsed_iso
            .manifest
            .files
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
    let manifest = Manifest {
        track: Track {
            mode: track_mode,
            start_msf: format_msf(start_frame)?,
            form2_edc,
            noncompliant_trailing_ecc,
            ppf: None,
        },
        system_area: SystemArea {
            path: system_name.clone(),
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
    if !options.manifest_only {
        let authored_file_paths: HashSet<_> = manifest
            .iso9660
            .files
            .iter()
            .filter_map(FileLayoutItem::as_path)
            .collect();
        let referenced_file_paths: HashSet<_> = manifest
            .iso9660
            .entries
            .iter()
            .filter(|entry| entry.extent.is_some())
            .map(|entry| entry.path.as_str())
            .collect();
        let interleaved_paths: HashSet<_> = manifest
            .iso9660
            .entries
            .iter()
            .filter(|entry| entry_uses_xa_sidecar(entry))
            .map(|entry| entry.path.as_str())
            .collect();
        validate_data_directory(data_dir)?;
        let system_path = safe_join(data_dir, &system_name)?;
        validate_output_file(&system_path, options.overwrite, "system output")?;
        for entry in manifest
            .iso9660
            .entries
            .iter()
            .filter(|entry| entry.path != iso9660::ROOT_PATH)
        {
            let output = safe_join(data_dir, &entry.path)?;
            if authored_file_paths.contains(entry.path.as_str()) {
                if !interleaved_paths.contains(entry.path.as_str()) {
                    validate_output_file(&output, options.overwrite, "extraction output")?;
                }
            } else if !referenced_file_paths.contains(entry.path.as_str()) {
                validate_output_directory(&output, options.overwrite, "extraction output")?;
            }
        }
        for path in extracted_files.keys() {
            let output = safe_join(data_dir, path)?;
            validate_output_file(&output, options.overwrite, "extraction output")?;
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
            let output = safe_join(data_dir, &entry.path)?;
            if authored_file_paths.contains(entry.path.as_str()) {
                if !interleaved_paths.contains(entry.path.as_str())
                    && let Some(parent) = output.parent()
                {
                    fs::create_dir_all(parent)?;
                }
            } else if !referenced_file_paths.contains(entry.path.as_str()) {
                fs::create_dir_all(&output)
                    .with_context(|| format!("creating directory {}", output.display()))?;
            }
        }
        fs::write(&system_path, &system_bytes)
            .with_context(|| format!("writing {}", system_path.display()))?;
        for (path, data) in extracted_files {
            let output = safe_join(data_dir, &path)?;
            if let Some(parent) = output.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(&output, data).with_context(|| format!("writing {}", output.display()))?;
        }
    } else {
        create_output_parent(manifest_path, "manifest output")?;
    }
    let yaml = serialize_manifest(&manifest, options.include_defaults)?;
    fs::write(manifest_path, yaml)
        .with_context(|| format!("writing manifest {}", manifest_path.display()))?;
    Ok(ExtractReport {
        sectors: sector_count,
        sha1: source_sha1,
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
            if sector.kind != Kind::Form1 {
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
    let file_gap_kinds = manifest
        .iso9660
        .files
        .iter()
        .filter_map(FileLayoutItem::gap_kind);
    let metadata_gap_kinds =
        manifest
            .iso9660
            .metadata_layout
            .iter()
            .filter_map(|item| match item {
                MetadataLayoutItem::Gap(gap) => Some(gap.kind),
                MetadataLayoutItem::PathTable(_) | MetadataLayoutItem::Directories(_) => None,
            });

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
                manifest.iso9660.metadata_subheader == IsoMetadataSubheader::Canonical
                    && manifest.iso9660.metadata_framing_subheader.is_none()
                    && manifest.iso9660.path_table_subheader == EntrySectorSubheader::Canonical
                    && manifest.iso9660.path_table_framing_subheader.is_none(),
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
                    .files
                    .iter()
                    .all(|item| item.as_xa_extent().is_none()),
                "unreferenced XA extents are not applicable to Mode 1 tracks"
            );
            ensure!(
                file_gap_kinds
                    .chain(metadata_gap_kinds)
                    .all(|kind| matches!(kind, GapKind::Mode1 | GapKind::RawZero)),
                "Mode 1 tracks may contain only Mode 1 or terminal raw-zero gaps"
            );
        }
        TrackMode::Mode2Xa => {
            ensure!(
                file_gap_kinds
                    .chain(metadata_gap_kinds)
                    .all(|kind| kind != GapKind::Mode1),
                "Mode 1 gaps require a Mode 1 track"
            );
        }
        TrackMode::Mode2 => anyhow::bail!("unsupported track mode 2"),
    }
    Ok(())
}

fn path_table_subheader(
    policy: EntrySectorSubheader,
    block_index: u32,
    blocks: u32,
) -> XaSubheader {
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

fn detect_path_table_subheader(
    sectors: &[crate::raw_cd::ParsedSector],
    parsed_iso: &mut iso9660::ParsedIso,
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
                    let Some(sector) = sectors.get(lba) else {
                        return false;
                    };
                    let expected = path_table_subheader(policy, block_index, path_tables.blocks);
                    sector.subheader == expected && sector.subheader_copy == expected
                })
            });
        if matches {
            parsed_iso.manifest.path_table_subheader = policy;
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
        parsed_iso.manifest.path_table_subheader = EntrySectorSubheader::Data;
        parsed_iso.manifest.path_table_framing_subheader = custom;
        return Ok(());
    }
    anyhow::bail!("path-table sectors use an unsupported XA subheader policy")
}

fn detect_entry_sector_subheaders(
    sectors: &[crate::raw_cd::ParsedSector],
    parsed_iso: &mut iso9660::ParsedIso,
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
        let sector = &sectors[final_lba];
        let data_subheader = entry_file_subheader(entry, FORM1_DATA_SUBHEADER);
        let end_of_file_subheader = entry_file_subheader(entry, SYSTEM_END_OF_FILE_SUBHEADER);
        let metadata_subheader = entry_file_subheader(entry, ISO_METADATA_SUBHEADER);
        if blocks > 1
            && sectors[start..=final_lba].iter().all(|sector| {
                sector.subheader == metadata_subheader
                    && sector.subheader_copy == metadata_subheader
            })
        {
            entry.sector_subheader = EntrySectorSubheader::IsoMetadata;
        } else if sector.subheader == data_subheader && sector.subheader_copy == data_subheader {
            entry.sector_subheader = EntrySectorSubheader::Data;
        } else if sector.subheader == end_of_file_subheader
            && sector.subheader_copy == end_of_file_subheader
        {
            entry.sector_subheader = EntrySectorSubheader::EndOfFileData;
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
        let directory_sectors = &sectors[start..start + blocks];
        let data_subheader = entry_file_subheader(entry, FORM1_DATA_SUBHEADER);
        let end_of_file_subheader = entry_file_subheader(entry, SYSTEM_END_OF_FILE_SUBHEADER);
        let metadata_subheader = entry_file_subheader(entry, ISO_METADATA_SUBHEADER);
        if directory_sectors.iter().all(|sector| {
            sector.subheader == data_subheader && sector.subheader_copy == data_subheader
        }) {
            entry.sector_subheader = EntrySectorSubheader::Data;
        } else if blocks > 0
            && directory_sectors[..blocks - 1].iter().all(|sector| {
                sector.subheader == data_subheader && sector.subheader_copy == data_subheader
            })
            && directory_sectors[blocks - 1].subheader == end_of_file_subheader
            && directory_sectors[blocks - 1].subheader_copy == end_of_file_subheader
        {
            entry.sector_subheader = EntrySectorSubheader::EndOfFileData;
        } else if blocks > 1
            && directory_sectors[..blocks - 1].iter().all(|sector| {
                sector.subheader == data_subheader && sector.subheader_copy == data_subheader
            })
            && directory_sectors[blocks - 1].subheader == metadata_subheader
            && directory_sectors[blocks - 1].subheader_copy == metadata_subheader
        {
            entry.sector_subheader = EntrySectorSubheader::DataUntilFinal;
        } else if let Some(first) = directory_sectors.first()
            && first.kind == Kind::Form1
            && first.subheader == first.subheader_copy
            && first.subheader != metadata_subheader
        {
            let custom = first.subheader;
            let prefix_matches =
                directory_sectors[..blocks.saturating_sub(1)]
                    .iter()
                    .all(|sector| {
                        sector.kind == Kind::Form1
                            && sector.subheader == custom
                            && sector.subheader_copy == custom
                    });
            let final_sector = &directory_sectors[blocks - 1];
            let policy = if directory_sectors.iter().all(|sector| {
                sector.kind == Kind::Form1
                    && sector.subheader == custom
                    && sector.subheader_copy == custom
            }) {
                Some(EntrySectorSubheader::Data)
            } else if blocks > 1
                && prefix_matches
                && final_sector.subheader == end_of_file_subheader
                && final_sector.subheader_copy == end_of_file_subheader
            {
                Some(EntrySectorSubheader::EndOfFileData)
            } else if blocks > 1
                && prefix_matches
                && final_sector.subheader == metadata_subheader
                && final_sector.subheader_copy == metadata_subheader
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
    validate_iso_subheaders_with_xa_extents(sectors, parsed_iso, trailing_gap, &[])
}

fn validate_iso_subheaders_with_xa_extents(
    sectors: &[crate::raw_cd::ParsedSector],
    parsed_iso: &iso9660::ParsedIso,
    trailing_gap: usize,
    xa_extent_ranges: &[Range<usize>],
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
                        .insert(lba, {
                            let subheader = path_table_subheader(
                                parsed_iso.manifest.path_table_subheader,
                                block_index,
                                path_tables.blocks,
                            );
                            if subheader == FORM1_DATA_SUBHEADER {
                                parsed_iso
                                    .manifest
                                    .path_table_framing_subheader
                                    .unwrap_or(subheader)
                            } else {
                                subheader
                            }
                        },)
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
        if xa_extent_ranges.iter().any(|range| range.contains(&lba)) {
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
        let expected = if volume_descriptor {
            parsed_iso.manifest.metadata_framing_subheader.unwrap_or(
                match parsed_iso.manifest.metadata_subheader {
                    IsoMetadataSubheader::Canonical => PVD_SUBHEADER,
                    IsoMetadataSubheader::Data => FORM1_DATA_SUBHEADER,
                    IsoMetadataSubheader::EndOfFileData => SYSTEM_END_OF_FILE_SUBHEADER,
                    IsoMetadataSubheader::IsoMetadata => ISO_METADATA_SUBHEADER,
                },
            )
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
            parsed_iso.manifest.metadata_framing_subheader.unwrap_or(
                match parsed_iso.manifest.metadata_subheader {
                    IsoMetadataSubheader::Canonical | IsoMetadataSubheader::IsoMetadata => {
                        ISO_METADATA_SUBHEADER
                    }
                    IsoMetadataSubheader::Data => FORM1_DATA_SUBHEADER,
                    IsoMetadataSubheader::EndOfFileData => SYSTEM_END_OF_FILE_SUBHEADER,
                },
            )
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
    validate_output_file(image_path, overwrite, "image output")?;
    let temp_path = temporary_path(image_path)?;
    validate_output_file(&temp_path, false, "temporary output")?;
    let yaml = fs::read_to_string(manifest_path)
        .with_context(|| format!("reading manifest {}", manifest_path.display()))?;
    let manifest: Manifest = yaml_serde::from_str(&yaml).context("parsing manifest")?;
    ensure!(
        matches!(manifest.track.mode, TrackMode::Mode1 | TrackMode::Mode2Xa),
        "unsupported track mode {}",
        manifest.track.mode
    );
    ensure!(
        manifest.track.mode == TrackMode::Mode2Xa || manifest.track.ppf.is_none(),
        "PPF overlays are unsupported for Mode 1 tracks"
    );
    let patch = if let Some(ppf_path) = manifest.track.ppf.as_deref() {
        ensure!(
            ppf_path != manifest.system_area.path
                && manifest.iso9660.entries.iter().all(|entry| {
                    entry.path != ppf_path
                        && entry.xa.as_ref().is_none_or(|xa| {
                            xa.form1.as_deref() != Some(ppf_path)
                                && xa.form2.as_deref() != Some(ppf_path)
                                && xa.index.as_deref() != Some(ppf_path)
                                && xa.gap_index.as_deref() != Some(ppf_path)
                        })
                })
                && manifest
                    .iso9660
                    .files
                    .iter()
                    .filter_map(FileLayoutItem::as_xa_extent)
                    .all(|assets| {
                        assets.form1 != ppf_path
                            && assets.form2 != ppf_path
                            && assets.index != ppf_path
                            && assets.gap_index.as_deref() != Some(ppf_path)
                    }),
            "PPF asset path collides with another authored asset: {ppf_path}"
        );
        let host_path = safe_join(data_dir, ppf_path)?;
        validate_input_file(&host_path, "PPF input")?;
        let bytes = fs::read(&host_path)
            .with_context(|| format!("reading PPF input {}", host_path.display()))?;
        Some(Ppf2::from_bytes(&bytes).context("parsing PPF2 input")?)
    } else {
        None
    };
    ensure!(
        manifest
            .iso9660
            .entries
            .iter()
            .all(|entry| entry.path != manifest.system_area.path),
        "system asset path collides with an ISO entry"
    );
    iso9660::validate(&manifest.iso9660)?;

    let system_path = safe_join(data_dir, &manifest.system_area.path)?;
    let system = fs::read(&system_path)
        .with_context(|| format!("reading system asset {}", system_path.display()))?;
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
    let iso_paths: HashSet<_> = manifest
        .iso9660
        .entries
        .iter()
        .map(|entry| entry.path.as_str())
        .collect();
    let mut secondary_paths = HashSet::new();
    for file in manifest
        .iso9660
        .files
        .iter()
        .filter_map(FileLayoutItem::as_path)
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
            for (asset, label) in [
                (form1_path, "XA1"),
                (form2_path, "XA2"),
                (index_path, "XAI"),
            ] {
                ensure!(
                    secondary_paths.insert(asset),
                    "duplicate XA secondary asset path {asset}"
                );
                ensure!(
                    !iso_paths.contains(asset)
                        && asset != manifest.system_area.path
                        && manifest.track.ppf.as_deref() != Some(asset),
                    "XA secondary asset path collides with another authored asset: {asset}"
                );
                let host_path = safe_join(data_dir, asset)?;
                validate_input_file(&host_path, label)?;
                assets.push(
                    fs::read(&host_path).with_context(|| {
                        format!("reading {label} asset {}", host_path.display())
                    })?,
                );
            }
            let gap_index = if let Some(asset) = xa.gap_index.as_deref() {
                ensure!(
                    secondary_paths.insert(asset),
                    "duplicate XA secondary asset path {asset}"
                );
                ensure!(
                    !iso_paths.contains(asset)
                        && asset != manifest.system_area.path
                        && manifest.track.ppf.as_deref() != Some(asset),
                    "XA secondary asset path collides with another authored asset: {asset}"
                );
                let host_path = safe_join(data_dir, asset)?;
                validate_input_file(&host_path, "XAG")?;
                fs::read(&host_path)
                    .with_context(|| format!("reading XAG asset {}", host_path.display()))?
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
            let path = safe_join(data_dir, file)?;
            let data = fs::read(&path)
                .with_context(|| format!("reading authored file {}", path.display()))?;
            file_lengths.insert(file.to_owned(), u64::try_from(data.len())?);
            file_data.insert(file.to_owned(), data);
        }
    }
    for assets in manifest
        .iso9660
        .files
        .iter()
        .filter_map(FileLayoutItem::as_xa_extent)
    {
        let mut data = Vec::new();
        for (asset, label) in [
            (assets.form1.as_str(), "XA1"),
            (assets.form2.as_str(), "XA2"),
            (assets.index.as_str(), "XAI"),
        ] {
            ensure!(
                secondary_paths.insert(asset),
                "duplicate XA secondary asset path {asset}"
            );
            ensure!(
                !iso_paths.contains(asset)
                    && asset != manifest.system_area.path
                    && manifest.track.ppf.as_deref() != Some(asset),
                "XA secondary asset path collides with another authored asset: {asset}"
            );
            let host_path = safe_join(data_dir, asset)?;
            validate_input_file(&host_path, label)?;
            data.push(
                fs::read(&host_path)
                    .with_context(|| format!("reading {label} asset {}", host_path.display()))?,
            );
        }
        let gap_index = if let Some(asset) = assets.gap_index.as_deref() {
            ensure!(
                secondary_paths.insert(asset),
                "duplicate XA secondary asset path {asset}"
            );
            ensure!(
                !iso_paths.contains(asset)
                    && asset != manifest.system_area.path
                    && manifest.track.ppf.as_deref() != Some(asset),
                "XA secondary asset path collides with another authored asset: {asset}"
            );
            let host_path = safe_join(data_dir, asset)?;
            validate_input_file(&host_path, "XAG")?;
            fs::read(&host_path)
                .with_context(|| format!("reading XAG asset {}", host_path.display()))?
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
    let mut layout = iso9660::layout(&manifest.iso9660, &file_lengths)?;
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
                    raw.extend_from_slice(&writer.mode1(frame, &payload)?);
                } else {
                    if let Some(framing) = manifest
                        .system_area
                        .form1_framing
                        .iter()
                        .find(|framing| usize::from(framing.sector) == index)
                    {
                        raw.extend_from_slice(&writer.form1_with_subheaders(
                            frame,
                            framing.subheader,
                            framing.subheader_copy,
                            &payload,
                        )?);
                    } else {
                        raw.extend_from_slice(&writer.form1(frame, subheader, &payload)?);
                    }
                }
            }
            SystemAreaSectorKind::Form2 => raw.extend_from_slice(&writer.form2(
                frame,
                FORM2_SUBHEADER,
                &[0; 2324],
                manifest.track.form2_edc,
            )?),
            SystemAreaSectorKind::XaGap => {
                raw.extend_from_slice(&writer.xa_gap(frame, XaSubheader::default())?)
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
            let sector = match gap.kind {
                crate::manifest::GapKind::Mode1 => {
                    writer.mode1(start_frame + lba, &[0; LOGICAL_BLOCK_SIZE])?
                }
                crate::manifest::GapKind::Form1 => writer.form1(
                    start_frame + lba,
                    gap.subheader.expect("validated Form 1 gap subheader"),
                    &[0; LOGICAL_BLOCK_SIZE],
                )?,
                crate::manifest::GapKind::Form2 => writer.form2(
                    start_frame + lba,
                    FORM2_SUBHEADER,
                    &[0; FORM2_PAYLOAD_SIZE],
                    gap.form2_edc.unwrap_or(manifest.track.form2_edc),
                )?,
                crate::manifest::GapKind::Xa => {
                    if manifest.track.mode == TrackMode::Mode1 {
                        writer.mode1(start_frame + lba, &[0; LOGICAL_BLOCK_SIZE])?
                    } else {
                        writer.xa_gap(start_frame + lba, XaSubheader::default())?
                    }
                }
                crate::manifest::GapKind::RawZero => vec![0; RAW_SECTOR_SIZE],
            };
            raw.extend_from_slice(&sector);
            continue;
        }
        if let Some((path, block_index, _)) = file_sector_info.get(&lba)
            && let Some(sectors) = mixed_extents.get(*path)
        {
            write_xa_extent_sector(
                &mut raw,
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
        let mut subheader = if let Some(subheader) = framing_subheader {
            subheader
        } else if volume_descriptor {
            manifest.iso9660.metadata_framing_subheader.unwrap_or(
                match manifest.iso9660.metadata_subheader {
                    IsoMetadataSubheader::Canonical => PVD_SUBHEADER,
                    IsoMetadataSubheader::Data => FORM1_DATA_SUBHEADER,
                    IsoMetadataSubheader::EndOfFileData => SYSTEM_END_OF_FILE_SUBHEADER,
                    IsoMetadataSubheader::IsoMetadata => ISO_METADATA_SUBHEADER,
                },
            )
        } else if layout.data_subheader_sectors.contains(&lba) {
            FORM1_DATA_SUBHEADER
        } else if layout.end_of_file_data_subheader_sectors.contains(&lba) {
            SYSTEM_END_OF_FILE_SUBHEADER
        } else if layout.metadata_subheader_sectors.contains(&lba) {
            manifest
                .iso9660
                .metadata_framing_subheader
                .unwrap_or(ISO_METADATA_SUBHEADER)
        } else if let Some((_, _, is_last)) = file_sector_info.get(&lba) {
            if *is_last {
                ISO_METADATA_SUBHEADER
            } else {
                FORM1_DATA_SUBHEADER
            }
        } else {
            manifest.iso9660.metadata_framing_subheader.unwrap_or(
                match manifest.iso9660.metadata_subheader {
                    IsoMetadataSubheader::Canonical | IsoMetadataSubheader::IsoMetadata => {
                        ISO_METADATA_SUBHEADER
                    }
                    IsoMetadataSubheader::Data => FORM1_DATA_SUBHEADER,
                    IsoMetadataSubheader::EndOfFileData => SYSTEM_END_OF_FILE_SUBHEADER,
                },
            )
        };
        if framing_subheader.is_none()
            && let Some(file_number) = layout.sector_file_numbers.get(&lba)
        {
            subheader.file_number = *file_number;
        }
        let block = &layout.blocks[usize::try_from(lba)?];
        if manifest.track.mode == TrackMode::Mode1 {
            raw.extend_from_slice(&writer.mode1(start_frame + lba, block)?);
        } else {
            raw.extend_from_slice(&writer.form1(start_frame + lba, subheader, block)?);
        }
    }
    for lba in u32::try_from(layout.blocks.len())?..layout.volume_blocks {
        let sector = match layout
            .trailing_gap_kind
            .context("physical track tail has no gap kind")?
        {
            crate::manifest::GapKind::Xa => {
                if manifest.track.noncompliant_trailing_ecc && lba + 1 == layout.volume_blocks {
                    writer.xa_gap_with_recorded_header_ecc(
                        start_frame + lba,
                        XaSubheader::default(),
                    )?
                } else {
                    writer.xa_gap(start_frame + lba, XaSubheader::default())?
                }
            }
            crate::manifest::GapKind::RawZero => vec![0; RAW_SECTOR_SIZE],
            crate::manifest::GapKind::Mode1
            | crate::manifest::GapKind::Form1
            | crate::manifest::GapKind::Form2 => {
                unreachable!("validated terminal gap kind")
            }
        };
        raw.extend_from_slice(&sector);
    }

    if let Some(patch) = &patch {
        apply_ppf_overlay(
            &mut raw,
            patch,
            manifest.track.form2_edc,
            manifest.track.noncompliant_trailing_ecc,
        )
        .context("applying pre-protection PPF2 overlay")?;
    }

    let sha1 = sha1_hex(&raw);
    create_output_parent(image_path, "image output")?;
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp_path)
        .with_context(|| format!("creating temporary image {}", temp_path.display()))?;
    output.write_all(&raw)?;
    output.sync_all()?;
    drop(output);
    install_image(&temp_path, image_path, overwrite)?;
    Ok(BuildReport {
        sectors: layout.volume_blocks,
        sha1,
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

fn validate_output_directory(path: &Path, overwrite: bool, label: &str) -> Result<()> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::Entry;
    use crate::ppf::{Ppf2, PpfRecord};

    fn test_manifest() -> Manifest {
        yaml_serde::from_str(
            "system_area:\n\
             \x20 path: sample.system\n\
             \x20 form1_sectors: auto\n\
             iso9660:\n\
             \x20 primary_volume: {}\n\
             \x20 entries:\n\
             \x20 - path: .\n\
             \x20   recording_time: 1998-03-19T11:58:36+09:00\n\
             \x20 - path: FILE.BIN\n\
             \x20   recording_time: 1998-03-19T11:58:36+09:00\n\
             \x20 files:\n\
             \x20 - path: FILE.BIN\n",
        )
        .unwrap()
    }

    #[test]
    fn mode1_track_accepts_only_mode1_physical_framing() {
        let mut manifest = test_manifest();
        manifest.track.mode = TrackMode::Mode1;
        manifest.iso9660.files.push(FileLayoutItem::mode1_gap(150));
        let system_layout = vec![SystemAreaSectorKind::Form1; SYSTEM_AREA_SECTORS];

        validate_track_structure(&manifest, &system_layout).unwrap();

        manifest.iso9660.files.pop();
        manifest.iso9660.files.push(FileLayoutItem::gap(150));
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

    fn canonical_ppf_target() -> Vec<u8> {
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

    #[test]
    fn generic_ppf_overlay_applies_every_record_before_reprotecting_sectors() {
        let mut raw = canonical_ppf_target();
        let canonical = raw.clone();
        let second = RAW_SECTOR_SIZE as u32;
        let fourth = (3 * RAW_SECTOR_SIZE) as u32;
        let metadata = (16 * RAW_SECTOR_SIZE + 24 + 37) as u32;
        let patch = Ppf2::new(
            &canonical,
            vec![
                PpfRecord::new(20, vec![0x12, 0x34, 0x56, 0x78]).unwrap(),
                PpfRecord::new(second + 18, vec![XaSubmode::FORM2.bits()]).unwrap(),
                PpfRecord::new(second + 24, vec![0xa5]).unwrap(),
                PpfRecord::new(metadata, vec![0x5a]).unwrap(),
                PpfRecord::new(fourth - 2, vec![0xde, 0xad, 0xbe, 0xef]).unwrap(),
            ],
        )
        .unwrap();

        apply_ppf_overlay(&mut raw, &patch, true, false).unwrap();

        assert_eq!(&raw[20..24], &[0x12, 0x34, 0x56, 0x78]);
        let (_, first) = parse_image(&raw[..RAW_SECTOR_SIZE]).unwrap();
        assert_eq!(first[0].kind, Kind::Form1);
        let (_, second_sector) = parse_image(&raw[RAW_SECTOR_SIZE..2 * RAW_SECTOR_SIZE]).unwrap();
        assert_eq!(second_sector[0].kind, Kind::Form2);
        assert!(second_sector[0].form2_edc_valid);
        assert_eq!(second_sector[0].payload()[0], 0xa5);
        assert_eq!(raw[16 * RAW_SECTOR_SIZE + 24 + 37], 0x5a);
        assert_ne!(&raw[fourth as usize - 2..fourth as usize], &[0xde, 0xad]);
        assert_eq!(&raw[fourth as usize..fourth as usize + 2], &[0xbe, 0xef]);
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
        let extracted = extract_system_area(&sectors, TrackMode::Mode2Xa).unwrap();
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
            extract_system_area(&sectors, TrackMode::Mode2Xa)
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
            extract_system_area(&sectors, TrackMode::Mode2Xa)
                .unwrap()
                .form1_framing,
            vec![custom]
        );

        sectors[9].subheader_copy.coding_info = 33;
        assert_eq!(
            extract_system_area(&sectors, TrackMode::Mode2Xa)
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
        let extracted = extract_system_area(&sectors, TrackMode::Mode2Xa).unwrap();

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

        prepare_xa_sidecars(&sectors, &mut parsed).unwrap();

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

        prepare_xa_sidecars(&sectors, &mut parsed).unwrap();

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
            unbacked: false,
            directory_reference: None,
            directory_slack: None,
            allocation_padding_hex: None,
            sector_subheader: EntrySectorSubheader::Canonical,
            xa: None,
            extent: None,
            length: None,
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
        detach_overlapping_form2_xa_files(&sectors, &mut parsed).unwrap();
        prepare_xa_sidecars(&sectors, &mut parsed).unwrap();

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
        parsed.manifest.files.clear();
        parsed.manifest.entries.truncate(1);
        let mut reference = parsed.manifest.entries[0].clone();
        reference.path = "OLD".to_owned();
        reference.directory_reference = Some(crate::manifest::DirectoryReference {
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

        detect_entry_sector_subheaders(&sectors, &mut parsed).unwrap();

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
    fn overlapping_form2_xa_files_become_fixed_references_to_one_physical_extent() {
        let sectors = (0..6)
            .map(|marker| parsed_xa_sector(true, marker))
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
            unbacked: false,
            directory_reference: None,
            directory_slack: None,
            allocation_padding_hex: None,
            sector_subheader: EntrySectorSubheader::Canonical,
            xa: Some(crate::manifest::EntryXa {
                attributes: Some(crate::manifest::XaAttributes::INTERLEAVED),
                ..crate::manifest::EntryXa::default()
            }),
            extent: None,
            length: None,
        });
        parsed.manifest.entries.push(Entry {
            path: "NEXT.BIN".to_owned(),
            recording_time: "1998-03-19T11:58:36+09:00".to_owned(),
            hidden: false,
            associated: false,
            unbacked: false,
            directory_reference: None,
            directory_slack: None,
            allocation_padding_hex: None,
            sector_subheader: EntrySectorSubheader::Canonical,
            xa: None,
            extent: None,
            length: None,
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

        detach_overlapping_form2_xa_files(&sectors, &mut parsed).unwrap();

        assert_eq!(
            parsed
                .files
                .iter()
                .map(|file| file.path.as_str())
                .collect::<Vec<_>>(),
            vec!["NEXT.BIN"]
        );
        assert_eq!(parsed.manifest.entries[1].extent, Some(1));
        assert_eq!(
            parsed.manifest.entries[1].length,
            Some(4 * LOGICAL_BLOCK_SIZE as u32)
        );
        assert_eq!(parsed.manifest.entries[2].extent, Some(2));
        assert_eq!(
            parsed.manifest.entries[2].length,
            Some(3 * LOGICAL_BLOCK_SIZE as u32)
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
            unbacked: false,
            directory_reference: None,
            directory_slack: None,
            allocation_padding_hex: None,
            sector_subheader: EntrySectorSubheader::Canonical,
            xa: None,
            extent: None,
            length: None,
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
            unbacked: false,
            directory_reference: None,
            directory_slack: None,
            allocation_padding_hex: None,
            sector_subheader: EntrySectorSubheader::Canonical,
            xa: None,
            extent: None,
            length: None,
        });
        parsed.files.push(iso9660::ParsedFile {
            path: "PARTIAL.BIN".to_owned(),
            extent: 17,
            length: 2 * LOGICAL_BLOCK_SIZE as u32,
        });

        detach_overlapping_form2_xa_files(&sectors, &mut parsed).unwrap();

        assert!(parsed.files.is_empty());
        assert_eq!(parsed.manifest.entries[1].extent, Some(0));
        assert_eq!(parsed.manifest.entries[2].extent, Some(100));
        assert_eq!(parsed.manifest.entries[3].extent, Some(17));
        assert!(parsed.manifest.entries[1].unbacked);
        assert!(parsed.manifest.entries[2].unbacked);
        assert!(parsed.manifest.entries[3].unbacked);
        assert!(parsed.manifest.entries[1].allocation_padding_hex.is_none());

        parsed.manifest.files.clear();
        assert!(iso9660::layout(&parsed.manifest, &HashMap::new()).is_ok());
    }

    #[test]
    fn overlapping_ordinary_files_become_unbacked_references() {
        let sectors = parsed_form1_sequence(&[FORM1_DATA_SUBHEADER; 8]);
        let mut parsed = parsed_iso();
        parsed.files[0].extent = 1;
        parsed.files[0].length = 4 * LOGICAL_BLOCK_SIZE as u32;
        parsed.manifest.entries.push(Entry {
            path: "SECOND.BIN".to_owned(),
            recording_time: "1998-03-19T11:58:36+09:00".to_owned(),
            hidden: false,
            associated: false,
            unbacked: false,
            directory_reference: None,
            directory_slack: None,
            allocation_padding_hex: None,
            sector_subheader: EntrySectorSubheader::Canonical,
            xa: None,
            extent: None,
            length: None,
        });
        parsed.files.push(iso9660::ParsedFile {
            path: "SECOND.BIN".to_owned(),
            extent: 3,
            length: 2 * LOGICAL_BLOCK_SIZE as u32,
        });

        detach_overlapping_form2_xa_files(&sectors, &mut parsed).unwrap();

        assert!(parsed.files.is_empty());
        assert!(parsed.manifest.entries[1].unbacked);
        assert!(parsed.manifest.entries[2].unbacked);
        assert_eq!(parsed.manifest.entries[1].extent, Some(1));
        assert_eq!(parsed.manifest.entries[2].extent, Some(3));
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
            unbacked: false,
            directory_reference: None,
            directory_slack: None,
            allocation_padding_hex: None,
            sector_subheader: EntrySectorSubheader::Canonical,
            xa: None,
            extent: None,
            length: None,
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
        parsed.manifest.files.clear();

        validate_iso_subheaders(&sectors, &parsed, 0).unwrap();
    }

    #[test]
    fn pvd_iso_metadata_subheader_is_supported_in_memory() {
        let mut subheaders = vec![FORM1_DATA_SUBHEADER; 18];
        subheaders[16] = ISO_METADATA_SUBHEADER;
        subheaders[17] = ISO_METADATA_SUBHEADER;
        let sectors = parsed_form1_sequence(&subheaders);
        let mut parsed = parsed_iso();
        parsed.manifest.metadata_subheader = IsoMetadataSubheader::IsoMetadata;

        validate_iso_subheaders(&sectors, &parsed, 0).unwrap();
    }

    #[test]
    fn pvd_end_of_file_data_subheader_is_supported_in_memory() {
        let mut subheaders = vec![FORM1_DATA_SUBHEADER; 18];
        subheaders[16] = SYSTEM_END_OF_FILE_SUBHEADER;
        subheaders[17] = SYSTEM_END_OF_FILE_SUBHEADER;
        let sectors = parsed_form1_sequence(&subheaders);
        let mut parsed = parsed_iso();
        parsed.manifest.metadata_subheader = IsoMetadataSubheader::EndOfFileData;
        parsed.manifest.entries.truncate(1);
        parsed.manifest.files.clear();
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
        parsed.manifest.metadata_framing_subheader = Some(custom);
        parsed.manifest.entries.truncate(1);
        parsed.manifest.files.clear();
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
        parsed.manifest.files.clear();
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
        parsed.manifest.metadata_subheader = IsoMetadataSubheader::IsoMetadata;
        parsed.files[0].length = (2 * LOGICAL_BLOCK_SIZE) as u32;
        parsed.manifest.entries.push(crate::manifest::Entry {
            path: "SECOND.BIN".to_owned(),
            recording_time: "1998-03-19T11:58:36+09:00".to_owned(),
            hidden: false,
            associated: false,
            unbacked: false,
            directory_reference: None,
            directory_slack: None,
            allocation_padding_hex: None,
            sector_subheader: EntrySectorSubheader::Canonical,
            xa: None,
            extent: None,
            length: None,
        });
        parsed.files.push(iso9660::ParsedFile {
            path: "SECOND.BIN".to_owned(),
            extent: 19,
            length: (2 * LOGICAL_BLOCK_SIZE) as u32,
        });

        detect_entry_sector_subheaders(&sectors, &mut parsed).unwrap();
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
        detect_entry_sector_subheaders(&file_sectors, &mut file_iso).unwrap();
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
            unbacked: false,
            directory_reference: None,
            directory_slack: None,
            allocation_padding_hex: None,
            sector_subheader: EntrySectorSubheader::Canonical,
            xa: None,
            extent: None,
            length: None,
        });
        directory_iso.directories.push(iso9660::ParsedDirectory {
            path: "DIR".to_owned(),
            extent: 17,
            length: (2 * LOGICAL_BLOCK_SIZE) as u32,
        });

        detect_entry_sector_subheaders(&directory_sectors, &mut directory_iso).unwrap();
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
            unbacked: false,
            directory_reference: None,
            directory_slack: None,
            allocation_padding_hex: None,
            sector_subheader: EntrySectorSubheader::Canonical,
            xa: None,
            extent: None,
            length: None,
        });
        parsed.directories.push(iso9660::ParsedDirectory {
            path: "DIR".to_owned(),
            extent: 17,
            length: LOGICAL_BLOCK_SIZE as u32,
        });

        detect_entry_sector_subheaders(&sectors, &mut parsed).unwrap();

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
            unbacked: false,
            directory_reference: None,
            directory_slack: None,
            allocation_padding_hex: None,
            sector_subheader: EntrySectorSubheader::Canonical,
            xa: None,
            extent: None,
            length: None,
        });
        parsed.directories.push(iso9660::ParsedDirectory {
            path: "DIR".to_owned(),
            extent: 17,
            length: (2 * LOGICAL_BLOCK_SIZE) as u32,
        });

        detect_entry_sector_subheaders(&sectors, &mut parsed).unwrap();

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
        validate_iso_subheaders(&sectors, &parsed, 0).unwrap();
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

        detect_path_table_subheader(&sectors, &mut parsed).unwrap();

        assert_eq!(
            parsed.manifest.path_table_subheader,
            EntrySectorSubheader::DataUntilFinal
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

        detect_path_table_subheader(&sectors, &mut parsed).unwrap();

        assert_eq!(
            parsed.manifest.path_table_subheader,
            EntrySectorSubheader::EndOfFileData
        );
        validate_iso_subheaders(&sectors, &parsed, 0).unwrap();
    }

    #[test]
    fn custom_path_table_form1_subheader_is_detected_in_memory() {
        let custom = XaSubheader::default();
        let mut subheaders = vec![ISO_METADATA_SUBHEADER; 20];
        subheaders[..16].fill(FORM1_DATA_SUBHEADER);
        subheaders[16] = PVD_SUBHEADER;
        subheaders[18] = custom;
        subheaders[19] = custom;
        let sectors = parsed_form1_sequence(&subheaders);
        let mut parsed = parsed_iso();
        parsed.path_tables = Some(iso9660::ParsedPathTables {
            extents: [18, 0, 19, 0],
            blocks: 1,
        });

        detect_path_table_subheader(&sectors, &mut parsed).unwrap();

        assert_eq!(
            parsed.manifest.path_table_subheader,
            EntrySectorSubheader::Data
        );
        assert_eq!(parsed.manifest.path_table_framing_subheader, Some(custom));
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
        parsed.manifest.files.clear();
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

        detect_path_table_subheader(&sectors, &mut parsed).unwrap();
        validate_iso_subheaders(&sectors, &parsed, 0).unwrap();
    }

    #[test]
    fn file_end_of_file_data_subheader_is_detected_in_memory() {
        let mut subheaders = vec![FORM1_DATA_SUBHEADER; 18];
        subheaders[16] = PVD_SUBHEADER;
        subheaders[17] = SYSTEM_END_OF_FILE_SUBHEADER;
        let sectors = parsed_form1_sequence(&subheaders);
        let mut parsed = parsed_iso();

        detect_entry_sector_subheaders(&sectors, &mut parsed).unwrap();
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

        detect_entry_sector_subheaders(&sectors, &mut parsed).unwrap();
        validate_iso_subheaders(&sectors, &parsed, 0).unwrap();
    }

    #[test]
    fn compact_and_explicit_manifest_views_are_serialized_from_values() {
        let manifest = test_manifest();
        let compact = serialize_manifest(&manifest, false).unwrap();
        assert!(!compact.contains("track:"));
        assert!(!compact.contains("sha1"));
        assert!(!compact.contains("metadata_subheader:"));
        assert!(!compact.contains("sector_subheader:"));

        let explicit = serialize_manifest(&manifest, true).unwrap();
        for expected in [
            "  mode: 2xa",
            "  start_msf: 00:02:00",
            "  form2_edc: true",
            "  noncompliant_trailing_ecc: false",
            "  metadata_subheader: canonical",
            "    hidden: false",
            "    sector_subheader: canonical",
            "      permissions: 1365",
        ] {
            assert!(explicit.lines().any(|line| line == expected));
        }
        assert!(yaml_serde::from_str::<Manifest>(&explicit).is_ok());
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
        assert!(validate_output_directory(&directory, false, "output").is_err());
        validate_output_directory(&directory, true, "output").unwrap();

        let nested = project.path().join("new/parent/manifest.yaml");
        create_output_parent(&nested, "manifest").unwrap();
        assert!(nested.parent().unwrap().is_dir());
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
    }

    #[test]
    fn sha1_helper_has_a_known_in_memory_vector() {
        assert_eq!(sha1_hex(b"abc"), "a9993e364706816aba3e25717850c26c9cd0d89d");
    }
}

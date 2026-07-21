use std::collections::{HashMap, HashSet};
use std::fs::{self, OpenOptions};
use std::io::{ErrorKind, Write};
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result, ensure};
use sha1::{Digest, Sha1};

use crate::iso9660;
use crate::manifest::{
    EntrySectorSubheader, FileLayoutItem, Form1Sectors, IsoMetadataSubheader, Manifest,
    SYSTEM_AREA_SECTORS, SystemArea, SystemAreaFinalSubheader, Track, TrackMode, XaAttributeFlag,
    serialize_manifest,
};
use crate::ppf::Ppf2;
use crate::raw_cd::{
    Kind, LOGICAL_BLOCK_SIZE, RAW_SECTOR_SIZE, SectorWriter, XaSubheader, XaSubmode, format_msf,
    parse_image, parse_msf, regenerate_mode2_protection,
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
    ensure!(
        bytes.len().is_multiple_of(XA_INDEX_RECORD_SIZE),
        "XAI asset size must be a multiple of {XA_INDEX_RECORD_SIZE} bytes"
    );
    let indices = bytes
        .chunks_exact(XA_INDEX_RECORD_SIZE)
        .map(|chunk| Ok(u32::from_le_bytes(chunk.try_into()?)))
        .collect::<Result<Vec<_>>>()?;
    ensure!(
        indices.windows(2).all(|pair| pair[0] < pair[1]),
        "XAI sector indices must be strictly increasing"
    );
    Ok(indices)
}

fn multiplex_xa_extent(form1: &[u8], form2: &[u8], index: &[u8]) -> Result<Vec<XaExtentSector>> {
    let form1 = parse_xa_form1_records(form1)?;
    let form2 = parse_xa_form2_records(form2)?;
    let indices = parse_xa_index(index)?;
    ensure!(
        indices.len() == form2.len(),
        "XAI record count does not match XA2 record count"
    );
    let sector_count = form1.len() + form2.len();
    ensure!(
        indices
            .last()
            .is_none_or(|index| usize::try_from(*index).is_ok_and(|value| value < sector_count)),
        "XAI sector index is outside the interleaved extent"
    );
    let mut result = Vec::with_capacity(sector_count);
    let mut form1 = form1.into_iter();
    let mut form2 = form2.into_iter();
    let mut indices = indices.into_iter().peekable();
    for sector_index in 0..sector_count {
        if indices
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
    ensure!(form1.next().is_none(), "XA1 record was not consumed");
    ensure!(form2.next().is_none(), "XA2 record was not consumed");
    Ok(result)
}

fn demultiplex_xa_extent(
    sectors: &[crate::raw_cd::ParsedSector],
    form2_edc: bool,
) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    let mut form1 = Vec::new();
    let mut form2 = Vec::new();
    let mut indices = Vec::new();
    for (index, sector) in sectors.iter().enumerate() {
        match sector.kind {
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
            Kind::XaGap => anyhow::bail!("XA gap inside interleaved extent at sector {index}"),
        }
    }
    let index = encode_xa_index(&indices);
    let reconstructed = multiplex_xa_extent(&form1, &form2, &index)?;
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
            _ => anyhow::bail!("mixed XA sector order differs at sector {index}"),
        }
    }
    Ok((form1, form2, index))
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
        .and_then(|xa| xa.attributes)
        .is_some_and(|attributes| {
            attributes.contains(XaAttributeFlag::Interleaved)
                || attributes.contains(XaAttributeFlag::Mode2Form2)
        })
}

#[derive(Clone, Copy)]
enum SourcePlacement<'a> {
    File(&'a iso9660::ParsedFile),
    Directory(&'a iso9660::ParsedDirectory),
}

impl<'a> SourcePlacement<'a> {
    const fn extent(self) -> u32 {
        match self {
            Self::File(file) => file.extent,
            Self::Directory(directory) => directory.extent,
        }
    }

    const fn length(self) -> u32 {
        match self {
            Self::File(file) => file.length,
            Self::Directory(directory) => directory.length,
        }
    }

    fn path(self) -> &'a str {
        match self {
            Self::File(file) => &file.path,
            Self::Directory(directory) => &directory.path,
        }
    }

    fn manifest_item(self) -> FileLayoutItem {
        match self {
            Self::File(file) => FileLayoutItem::path(&file.path),
            Self::Directory(directory) => FileLayoutItem::directory(&directory.path),
        }
    }
}

fn detect_file_layout(
    sectors: &[crate::raw_cd::ParsedSector],
    files: &[iso9660::ParsedFile],
    directories: &[iso9660::ParsedDirectory],
    form2_edc: bool,
) -> Result<Vec<FileLayoutItem>> {
    let mut placements = files
        .iter()
        .map(SourcePlacement::File)
        .chain(
            directories
                .iter()
                .filter(|directory| directory.path != iso9660::ROOT_PATH)
                .map(SourcePlacement::Directory),
        )
        .collect::<Vec<_>>();
    placements.sort_by_key(|placement| placement.extent());
    let mut previous_end = directories
        .iter()
        .find(|directory| directory.path == iso9660::ROOT_PATH)
        .map(|directory| {
            usize::try_from(directory.extent).and_then(|extent| {
                Ok(extent + usize::try_from(directory.length)?.div_ceil(LOGICAL_BLOCK_SIZE))
            })
        })
        .transpose()?
        .unwrap_or(0);
    let mut layout = Vec::new();
    for placement in placements {
        let extent = usize::try_from(placement.extent())?;
        ensure!(
            extent >= previous_end,
            "overlapping physical placement for {}",
            placement.path()
        );
        let mut start = extent;
        while start > previous_end {
            let sector = &sectors[start - 1];
            if sector.kind != Kind::Form2
                || sector.subheader != FORM2_SUBHEADER
                || sector.payload().iter().any(|byte| *byte != 0)
            {
                break;
            }
            ensure!(
                sector_follows_form2_edc_policy(sector, form2_edc),
                "physical gap before {} does not follow track Form 2 EDC policy",
                placement.path()
            );
            start -= 1;
        }
        ensure!(
            start == previous_end,
            "unsupported unallocated sectors before {}",
            placement.path()
        );
        if start < extent {
            layout.push(FileLayoutItem::gap(u32::try_from(extent - start)?));
        }
        layout.push(placement.manifest_item());
        previous_end = extent + usize::try_from(placement.length())?.div_ceil(LOGICAL_BLOCK_SIZE);
    }
    let mut gap_start = sectors.len();
    while gap_start > previous_end {
        let sector = &sectors[gap_start - 1];
        if sector.kind != Kind::Form2
            || sector.subheader != FORM2_SUBHEADER
            || sector.subheader_copy != FORM2_SUBHEADER
            || sector.payload().iter().any(|byte| *byte != 0)
        {
            break;
        }
        ensure!(
            sector_follows_form2_edc_policy(sector, form2_edc),
            "terminal physical gap does not follow track Form 2 EDC policy"
        );
        gap_start -= 1;
    }
    if gap_start < sectors.len() {
        layout.push(FileLayoutItem::gap(u32::try_from(
            sectors.len() - gap_start,
        )?));
    }
    ensure!(
        gap_start == previous_end,
        "unsupported unallocated sectors at the end of ISO content"
    );
    Ok(layout)
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
    let sector_count = u32::try_from(sectors.len())?;
    let noncompliant_trailing_ecc = sectors.last().is_some_and(|sector| sector.noncompliant_ecc);
    ensure!(
        sectors[..sectors.len() - 1]
            .iter()
            .all(|sector| !sector.noncompliant_ecc),
        "noncompliant ECC is supported only on the final track sector"
    );

    let trailing_gap = sectors
        .iter()
        .rev()
        .take_while(|sector| sector.kind == Kind::XaGap)
        .count();
    let (system_bytes, form1_count, form2_edc, final_form1_subheader) =
        extract_system_area(&sectors[..SYSTEM_AREA_SECTORS])?;
    let manifest_stem = manifest_stem(manifest_path)?;
    let system_name = format!("{manifest_stem}.system");
    let blocks = sectors
        .iter()
        .map(|sector| sector.logical_block().try_into())
        .collect::<Result<Vec<[u8; LOGICAL_BLOCK_SIZE]>, _>>()?;
    let mut parsed_iso = iso9660::parse(&blocks)?;
    let content_end = sectors.len() - trailing_gap;
    if sectors[16].subheader == FORM1_DATA_SUBHEADER
        && sectors[16].subheader_copy == FORM1_DATA_SUBHEADER
    {
        parsed_iso.manifest.metadata_subheader = IsoMetadataSubheader::Data;
    }
    detect_entry_sector_subheaders(&sectors[..content_end], &mut parsed_iso)?;
    validate_iso_subheaders(&sectors, &parsed_iso, trailing_gap)?;
    parsed_iso.manifest.files = detect_file_layout(
        &sectors[..content_end],
        &parsed_iso.files,
        &parsed_iso.directories,
        form2_edc,
    )?;
    if trailing_gap > 0 {
        parsed_iso
            .manifest
            .files
            .push(FileLayoutItem::xa_gap(u32::try_from(trailing_gap)?));
    }
    let mut extracted_files = HashMap::new();
    for file in &parsed_iso.files {
        let entry_index = parsed_iso
            .manifest
            .entries
            .iter_mut()
            .position(|entry| entry.path == file.path)
            .context("parsed file has no manifest entry")?;
        if entry_uses_xa_sidecar(&parsed_iso.manifest.entries[entry_index]) {
            ensure!(
                usize::try_from(file.length)?.is_multiple_of(LOGICAL_BLOCK_SIZE),
                "interleaved extent length is not sector aligned for {}",
                file.path
            );
            let start = usize::try_from(file.extent)?;
            let count = usize::try_from(file.length)? / LOGICAL_BLOCK_SIZE;
            ensure!(
                start + count <= sectors.len(),
                "interleaved extent is outside image"
            );
            let (form1, form2, index) =
                demultiplex_xa_extent(&sectors[start..start + count], form2_edc)
                    .with_context(|| format!("demultiplexing {}", file.path))?;
            let form1_path = format!("{}.XA1", file.path);
            let form2_path = format!("{}.XA2", file.path);
            let index_path = format!("{}.XAI", file.path);
            for asset in [&form1_path, &form2_path, &index_path] {
                ensure!(
                    parsed_iso
                        .manifest
                        .entries
                        .iter()
                        .all(|candidate| candidate.path != *asset),
                    "XA asset path collides with ISO entry {asset}"
                );
            }
            let xa = parsed_iso.manifest.entries[entry_index]
                .xa
                .as_mut()
                .expect("checked XA metadata");
            xa.form1 = Some(form1_path.clone());
            xa.form2 = Some(form2_path.clone());
            xa.index = Some(index_path.clone());
            extracted_files.insert(form1_path, form1);
            extracted_files.insert(form2_path, form2);
            extracted_files.insert(index_path, index);
        } else {
            let data = read_extent(&blocks, file.extent, file.length)?;
            extracted_files.insert(file.path.clone(), data);
        }
    }
    let manifest = Manifest {
        track: Track {
            mode: TrackMode::Mode2Xa,
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
            final_form1_subheader,
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
    if !options.manifest_only {
        let file_paths: HashSet<_> = manifest
            .iso9660
            .files
            .iter()
            .filter_map(FileLayoutItem::as_path)
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
            if file_paths.contains(entry.path.as_str()) {
                if !interleaved_paths.contains(entry.path.as_str()) {
                    validate_output_file(&output, options.overwrite, "extraction output")?;
                }
            } else {
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
            if file_paths.contains(entry.path.as_str()) {
                if !interleaved_paths.contains(entry.path.as_str())
                    && let Some(parent) = output.parent()
                {
                    fs::create_dir_all(parent)?;
                }
            } else {
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

fn extract_system_area(
    sectors: &[crate::raw_cd::ParsedSector],
) -> Result<(Vec<u8>, usize, bool, SystemAreaFinalSubheader)> {
    ensure!(
        sectors.len() == SYSTEM_AREA_SECTORS,
        "system area must contain sixteen sectors"
    );
    let form2_start = sectors
        .iter()
        .position(|sector| sector.kind != Kind::Form1)
        .unwrap_or(SYSTEM_AREA_SECTORS);
    ensure!(
        sectors[..form2_start]
            .iter()
            .all(|sector| sector.kind == Kind::Form1),
        "system area Form 1 prefix is not contiguous"
    );
    ensure!(
        sectors[form2_start..]
            .iter()
            .all(|sector| sector.kind == Kind::Form2),
        "system area has an unsupported mixed or zero-EDC layout"
    );
    ensure!(
        sectors[form2_start..]
            .iter()
            .all(|sector| sector.payload().iter().all(|byte| *byte == 0)),
        "system-area Form 2 payload is not zero"
    );
    let mut content = Vec::with_capacity(form2_start * LOGICAL_BLOCK_SIZE);
    for sector in &sectors[..form2_start] {
        content.extend_from_slice(sector.payload());
    }
    while content.last() == Some(&0) {
        content.pop();
    }
    let computed = sectors[form2_start..]
        .iter()
        .all(|sector| sector.form2_edc_valid);
    let zeroed = sectors[form2_start..]
        .iter()
        .all(|sector| sector_follows_form2_edc_policy(sector, false));
    ensure!(computed || zeroed, "mixed Form 2 EDC policy in system area");
    ensure!(
        sectors[..form2_start.saturating_sub(1)]
            .iter()
            .all(|sector| {
                sector.subheader == FORM1_DATA_SUBHEADER
                    && sector.subheader_copy == FORM1_DATA_SUBHEADER
            }),
        "system-area Form 1 sectors use a nonstandard XA subheader"
    );
    let final_form1_subheader = if form2_start == 0 {
        SystemAreaFinalSubheader::Data
    } else {
        let final_form1 = &sectors[form2_start - 1];
        if final_form1.subheader == FORM1_DATA_SUBHEADER
            && final_form1.subheader_copy == FORM1_DATA_SUBHEADER
        {
            SystemAreaFinalSubheader::Data
        } else if final_form1.subheader == SYSTEM_END_OF_FILE_SUBHEADER
            && final_form1.subheader_copy == SYSTEM_END_OF_FILE_SUBHEADER
        {
            SystemAreaFinalSubheader::EndOfFileData
        } else {
            anyhow::bail!("system-area Form 1 sectors use a nonstandard XA subheader")
        }
    };
    ensure!(
        sectors[form2_start..].iter().all(|sector| {
            sector.subheader == FORM2_SUBHEADER && sector.subheader_copy == FORM2_SUBHEADER
        }),
        "system-area Form 2 sectors use a nonstandard XA subheader"
    );
    Ok((content, form2_start, computed, final_form1_subheader))
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
        let final_lba = usize::try_from(file.extent)? + blocks - 1;
        ensure!(final_lba < sectors.len(), "file extent is outside image");
        let sector = &sectors[final_lba];
        if sector.subheader == FORM1_DATA_SUBHEADER && sector.subheader_copy == FORM1_DATA_SUBHEADER
        {
            entry.sector_subheader = EntrySectorSubheader::Data;
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
        ensure!(
            start + blocks <= sectors.len(),
            "directory extent is outside image"
        );
        let directory_sectors = &sectors[start..start + blocks];
        if directory_sectors.iter().all(|sector| {
            sector.subheader == FORM1_DATA_SUBHEADER
                && sector.subheader_copy == FORM1_DATA_SUBHEADER
        }) {
            entry.sector_subheader = EntrySectorSubheader::Data;
        } else if blocks > 1
            && directory_sectors[..blocks - 1].iter().all(|sector| {
                sector.subheader == FORM1_DATA_SUBHEADER
                    && sector.subheader_copy == FORM1_DATA_SUBHEADER
            })
            && directory_sectors[blocks - 1].subheader == ISO_METADATA_SUBHEADER
            && directory_sectors[blocks - 1].subheader_copy == ISO_METADATA_SUBHEADER
        {
            entry.sector_subheader = EntrySectorSubheader::DataUntilFinal;
        }
    }
    Ok(())
}

fn validate_iso_subheaders(
    sectors: &[crate::raw_cd::ParsedSector],
    parsed_iso: &iso9660::ParsedIso,
    trailing_gap: usize,
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
                    .insert(
                        lba,
                        match entry.sector_subheader {
                            EntrySectorSubheader::Data => FORM1_DATA_SUBHEADER,
                            EntrySectorSubheader::DataUntilFinal if block_index + 1 < blocks => {
                                FORM1_DATA_SUBHEADER
                            }
                            EntrySectorSubheader::Canonical
                            | EntrySectorSubheader::DataUntilFinal => ISO_METADATA_SUBHEADER,
                        },
                    )
                    .is_none(),
                "overlapping directory extents at LBA {lba}"
            );
        }
    }

    for (lba, sector) in sectors.iter().enumerate().take(content_end).skip(16) {
        let context = if file_sector_info.contains_key(&lba) {
            "file"
        } else if directory_sector_info.contains_key(&lba) {
            "directory"
        } else {
            "metadata"
        };
        let expected = if lba == 16 {
            match parsed_iso.manifest.metadata_subheader {
                IsoMetadataSubheader::Canonical => PVD_SUBHEADER,
                IsoMetadataSubheader::Data => FORM1_DATA_SUBHEADER,
            }
        } else if let Some((is_last, interleaved, policy)) = file_sector_info.get(&lba) {
            if *interleaved {
                continue;
            }
            if *is_last && *policy != EntrySectorSubheader::Data {
                ISO_METADATA_SUBHEADER
            } else {
                FORM1_DATA_SUBHEADER
            }
        } else if let Some(subheader) = directory_sector_info.get(&lba) {
            *subheader
        } else {
            match parsed_iso.manifest.metadata_subheader {
                IsoMetadataSubheader::Canonical => ISO_METADATA_SUBHEADER,
                IsoMetadataSubheader::Data => FORM1_DATA_SUBHEADER,
            }
        };
        if sector.kind == Kind::Form2
            && sector.subheader == FORM2_SUBHEADER
            && sector.subheader_copy == FORM2_SUBHEADER
            && sector.payload().iter().all(|byte| *byte == 0)
        {
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
            sector.kind == Kind::XaGap
                && sector.subheader == XaSubheader::default()
                && sector.subheader_copy == XaSubheader::default(),
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
        manifest.track.mode == TrackMode::Mode2Xa,
        "unsupported track mode {}",
        manifest.track.mode
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
                        })
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
    let mut file_data = HashMap::new();
    let mut file_lengths = HashMap::new();
    let mut mixed_extents = HashMap::new();
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
            let sectors = multiplex_xa_extent(&assets[0], &assets[1], &assets[2])
                .with_context(|| format!("multiplexing {file}"))?;
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
            || layout.volume_blocks > u32::try_from(layout.blocks.len())?,
        "noncompliant_trailing_ecc requires a final XA gap"
    );
    let mut writer = SectorWriter::new();
    let mut raw = Vec::with_capacity(usize::try_from(layout.volume_blocks)? * RAW_SECTOR_SIZE);
    let padded_system_len = usize::from(form1_count) * LOGICAL_BLOCK_SIZE;
    for index in 0..SYSTEM_AREA_SECTORS {
        let frame = start_frame + u32::try_from(index)?;
        if index < usize::from(form1_count) {
            let mut payload = [0_u8; LOGICAL_BLOCK_SIZE];
            let start = index * LOGICAL_BLOCK_SIZE;
            let end = (start + LOGICAL_BLOCK_SIZE).min(system.len());
            if start < end {
                payload[..end - start].copy_from_slice(&system[start..end]);
            }
            let subheader = if index + 1 == usize::from(form1_count)
                && manifest.system_area.final_form1_subheader
                    == SystemAreaFinalSubheader::EndOfFileData
            {
                SYSTEM_END_OF_FILE_SUBHEADER
            } else {
                FORM1_DATA_SUBHEADER
            };
            raw.extend_from_slice(&writer.form1(frame, subheader, &payload)?);
        } else {
            raw.extend_from_slice(&writer.form2(
                frame,
                FORM2_SUBHEADER,
                &[0; 2324],
                manifest.track.form2_edc,
            )?);
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
    for lba in 16..u32::try_from(layout.blocks.len())? {
        if layout
            .gaps
            .iter()
            .any(|gap| lba >= gap.start && lba < gap.start + gap.sectors)
        {
            raw.extend_from_slice(&writer.form2(
                start_frame + lba,
                FORM2_SUBHEADER,
                &[0; FORM2_PAYLOAD_SIZE],
                manifest.track.form2_edc,
            )?);
            continue;
        }
        if let Some((path, block_index, _)) = file_sector_info.get(&lba)
            && let Some(sectors) = mixed_extents.get(*path)
        {
            match &sectors[*block_index] {
                XaExtentSector::Form1(form1) => {
                    raw.extend_from_slice(&writer.form1_with_subheaders(
                        start_frame + lba,
                        form1.subheader,
                        form1.subheader_copy,
                        &form1.payload,
                    )?);
                }
                XaExtentSector::Form2(record) => {
                    raw.extend_from_slice(&writer.form2_with_subheaders(
                        start_frame + lba,
                        record.subheader,
                        record.subheader_copy,
                        &record.payload,
                        manifest.track.form2_edc,
                    )?)
                }
            }
            continue;
        }
        let subheader = if lba == 16 {
            match manifest.iso9660.metadata_subheader {
                IsoMetadataSubheader::Canonical => PVD_SUBHEADER,
                IsoMetadataSubheader::Data => FORM1_DATA_SUBHEADER,
            }
        } else if layout.data_subheader_sectors.contains(&lba) {
            FORM1_DATA_SUBHEADER
        } else if layout.metadata_subheader_sectors.contains(&lba) {
            ISO_METADATA_SUBHEADER
        } else if let Some((_, _, is_last)) = file_sector_info.get(&lba) {
            if *is_last {
                ISO_METADATA_SUBHEADER
            } else {
                FORM1_DATA_SUBHEADER
            }
        } else {
            match manifest.iso9660.metadata_subheader {
                IsoMetadataSubheader::Canonical => ISO_METADATA_SUBHEADER,
                IsoMetadataSubheader::Data => FORM1_DATA_SUBHEADER,
            }
        };
        raw.extend_from_slice(&writer.form1(
            start_frame + lba,
            subheader,
            &layout.blocks[usize::try_from(lba)?],
        )?);
    }
    for lba in u32::try_from(layout.blocks.len())?..layout.volume_blocks {
        let sector = if manifest.track.noncompliant_trailing_ecc && lba + 1 == layout.volume_blocks
        {
            writer.xa_gap_with_recorded_header_ecc(start_frame + lba, XaSubheader::default())?
        } else {
            writer.xa_gap(start_frame + lba, XaSubheader::default())?
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

    fn parsed_iso() -> iso9660::ParsedIso {
        iso9660::ParsedIso {
            manifest: test_manifest().iso9660,
            files: vec![iso9660::ParsedFile {
                path: "FILE.BIN".to_owned(),
                extent: 17,
                length: LOGICAL_BLOCK_SIZE as u32,
            }],
            directories: Vec::new(),
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
        let (system, form1, computed_edc, policy) = extract_system_area(&sectors).unwrap();
        assert_eq!(system, vec![7]);
        assert_eq!(form1, 12);
        assert!(computed_edc);
        assert_eq!(policy, SystemAreaFinalSubheader::Data);

        sectors[11].subheader = SYSTEM_END_OF_FILE_SUBHEADER;
        sectors[11].subheader_copy = SYSTEM_END_OF_FILE_SUBHEADER;
        assert_eq!(
            extract_system_area(&sectors).unwrap().3,
            SystemAreaFinalSubheader::EndOfFileData
        );

        sectors[0].subheader = XaSubheader::default();
        assert!(
            extract_system_area(&sectors)
                .unwrap_err()
                .to_string()
                .contains("Form 1 sectors use a nonstandard XA subheader")
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
            let (xa1, xa2, xai) = demultiplex_xa_extent(&sectors, true).unwrap();
            let expected_indices = layout
                .iter()
                .enumerate()
                .filter_map(|(index, form2)| form2.then_some(u32::try_from(index).unwrap()))
                .collect::<Vec<_>>();
            assert_eq!(parse_xa_index(&xai).unwrap(), expected_indices);

            let reconstructed = multiplex_xa_extent(&xa1, &xa2, &xai).unwrap();
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
                }
            }
        }
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
        assert!(multiplex_xa_extent(&form1, &form2, &encode_xa_index(&[])).is_err());
        assert!(multiplex_xa_extent(&form1, &form2, &encode_xa_index(&[2])).is_err());

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
            detect_file_layout(&sectors, &files, &[], true).unwrap(),
            vec![FileLayoutItem::path("FILE.BIN"), FileLayoutItem::gap(3)]
        );
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

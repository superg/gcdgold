use std::collections::{HashMap, HashSet};
use std::fs::{self, OpenOptions};
use std::io::{ErrorKind, Write};
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result, ensure};
use sha1::{Digest, Sha1};

use crate::iso9660;
use crate::manifest::{
    FileLayoutItem, Form1Sectors, Manifest, SYSTEM_AREA_SECTORS, SystemArea, Track, TrackMode,
    XaAttributeFlag, serialize_manifest,
};
use crate::raw_cd::{
    Kind, LOGICAL_BLOCK_SIZE, RAW_SECTOR_SIZE, SectorWriter, XaSubheader, XaSubmode, format_msf,
    parse_image, parse_msf,
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
const PVD_SUBHEADER: XaSubheader =
    XaSubheader::with_submode(XaSubmode::END_OF_RECORD.union(XaSubmode::DATA));
const ISO_METADATA_SUBHEADER: XaSubheader = XaSubheader::with_submode(
    XaSubmode::END_OF_RECORD
        .union(XaSubmode::DATA)
        .union(XaSubmode::END_OF_FILE),
);
const FORM2_SUBHEADER: XaSubheader = XaSubheader::with_submode(XaSubmode::FORM2);
const FORM2_PAYLOAD_SIZE: usize = 2324;
const XA_SIDECAR_RECORD_SIZE: usize = 4 + FORM2_PAYLOAD_SIZE;

#[derive(Debug, Clone, PartialEq, Eq)]
struct XaSidecarRecord {
    subheader: XaSubheader,
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
    payload: [u8; LOGICAL_BLOCK_SIZE],
}

fn xa_audio_cadence(coding_info: u8) -> Result<u8> {
    ensure!(
        coding_info & !0x55 == 0,
        "unsupported XA audio coding-info bits 0x{coding_info:02x}"
    );
    let mut cadence = 8_u8;
    if coding_info & 0x01 == 0 {
        cadence *= 2;
    }
    if coding_info & 0x04 != 0 {
        cadence *= 2;
    }
    if coding_info & 0x10 != 0 {
        cadence /= 2;
    }
    Ok(cadence)
}

fn encode_xa_sidecar_record(subheader: XaSubheader, payload: &[u8]) -> Result<Vec<u8>> {
    ensure!(
        subheader
            .submode
            .contains(crate::raw_cd::XaSubmodeFlag::Form2),
        "XA sidecar record is not Form 2"
    );
    ensure!(
        payload.len() == FORM2_PAYLOAD_SIZE,
        "XA sidecar payload must be {FORM2_PAYLOAD_SIZE} bytes"
    );
    let mut result = Vec::with_capacity(XA_SIDECAR_RECORD_SIZE);
    result.extend_from_slice(&<[u8; 4]>::from(subheader));
    result.extend_from_slice(payload);
    Ok(result)
}

fn parse_xa_sidecar(bytes: &[u8]) -> Result<Vec<XaSidecarRecord>> {
    ensure!(
        !bytes.is_empty() && bytes.len().is_multiple_of(XA_SIDECAR_RECORD_SIZE),
        "XA sidecar size must be a nonzero multiple of {XA_SIDECAR_RECORD_SIZE} bytes"
    );
    bytes
        .chunks_exact(XA_SIDECAR_RECORD_SIZE)
        .enumerate()
        .map(|(index, chunk)| {
            let subheader = XaSubheader::from(<[u8; 4]>::try_from(&chunk[..4])?);
            ensure!(
                subheader
                    .submode
                    .contains(crate::raw_cd::XaSubmodeFlag::Form2),
                "XA sidecar record {index} is not Form 2"
            );
            xa_audio_cadence(subheader.coding_info)
                .with_context(|| format!("invalid XA sidecar record {index}"))?;
            Ok(XaSidecarRecord {
                subheader,
                payload: chunk[4..].try_into()?,
            })
        })
        .collect()
}

fn multiplex_xa_extent(
    form1: &[u8],
    sidecar: &[u8],
    file_number: u8,
    form1_subheader: Option<XaSubheader>,
) -> Result<Vec<XaExtentSector>> {
    ensure!(
        form1.len().is_multiple_of(LOGICAL_BLOCK_SIZE),
        "interleaved Form 1 asset size must be a multiple of {LOGICAL_BLOCK_SIZE} bytes"
    );
    let records = parse_xa_sidecar(sidecar)?;
    let cadence = xa_audio_cadence(records[0].subheader.coding_info)?;
    let mut channels = records
        .iter()
        .map(|record| record.subheader.channel)
        .collect::<Vec<_>>();
    channels.sort_unstable();
    channels.dedup();
    ensure!(
        channels.len() <= usize::from(cadence),
        "XA sidecar has more active channels than cadence slots"
    );
    for (index, record) in records.iter().enumerate() {
        ensure!(
            record.subheader.file_number == file_number,
            "XA sidecar record {index} has file number {}, expected {file_number}",
            record.subheader.file_number
        );
        ensure!(
            xa_audio_cadence(record.subheader.coding_info)? == cadence,
            "XA sidecar mixes incompatible audio cadences"
        );
    }

    let default_form1_subheader = XaSubheader {
        file_number,
        ..XaSubheader::default()
    };
    let form1_subheader = form1_subheader.unwrap_or(default_form1_subheader);
    ensure!(
        form1_subheader.file_number == file_number,
        "Form 1 subheader file number does not match the directory record"
    );
    ensure!(
        !form1_subheader
            .submode
            .contains(crate::raw_cd::XaSubmodeFlag::Form2),
        "Form 1 subheader cannot contain the form2 flag"
    );

    let form1_sectors = form1
        .chunks_exact(LOGICAL_BLOCK_SIZE)
        .map(|chunk| <[u8; LOGICAL_BLOCK_SIZE]>::try_from(chunk).expect("exact chunk"))
        .collect::<Vec<_>>();
    let padding_start = form1_sectors
        .iter()
        .rposition(|payload| payload.iter().any(|byte| *byte != 0))
        .map_or(0, |index| index + 1);
    let mut result = Vec::with_capacity(form1_sectors.len() + records.len());
    let mut form1_index = 0;
    let mut record_index = 0;
    let mut slot = 0_usize;
    let audio_start = usize::from(cadence) - channels.len();
    let mut slot_channels = vec![None; usize::from(cadence)];
    for (index, channel) in channels.into_iter().enumerate() {
        slot_channels[audio_start + index] = Some(channel);
    }
    let mut ended_channels = Vec::new();
    while form1_index < form1_sectors.len() || record_index < records.len() {
        let expected_channel = slot_channels[slot].as_ref();
        if records.get(record_index).is_some_and(|record| {
            expected_channel.is_some_and(|channel| record.subheader.channel == *channel)
        }) {
            if records[record_index]
                .subheader
                .submode
                .contains(crate::raw_cd::XaSubmodeFlag::EndOfFile)
            {
                ended_channels.push(records[record_index].subheader.channel);
            }
            result.push(XaExtentSector::Form2(Box::new(
                records[record_index].clone(),
            )));
            record_index += 1;
        } else {
            ensure!(
                form1_index < form1_sectors.len(),
                "XA sidecar channel sequence cannot be filled by the Form 1 asset"
            );
            let subheader = if form1_index >= padding_start {
                default_form1_subheader
            } else {
                form1_subheader
            };
            result.push(XaExtentSector::Form1(Box::new(XaForm1Sector {
                subheader,
                payload: form1_sectors[form1_index],
            })));
            form1_index += 1;
        }
        slot = (slot + 1) % usize::from(cadence);
        if slot == 0 {
            for channel in ended_channels.drain(..) {
                let assigned_slot = slot_channels
                    .iter()
                    .position(|candidate| *candidate == Some(channel))
                    .with_context(|| {
                        format!("XA channel {channel} has multiple end-of-file records")
                    })?;
                slot_channels[assigned_slot] = None;
            }
        }
    }
    if let Some(XaExtentSector::Form1(sector)) = result.last_mut() {
        sector.subheader.submode = sector.subheader.submode.union(XaSubmode::END_OF_FILE);
    }
    Ok(result)
}

fn demultiplex_xa_extent(
    sectors: &[crate::raw_cd::ParsedSector],
    file_number: u8,
    form2_edc: bool,
) -> Result<(Vec<u8>, Vec<u8>, Option<XaSubheader>)> {
    let cadence = sectors
        .iter()
        .find(|sector| sector.kind == Kind::Form2)
        .map(|sector| xa_audio_cadence(sector.subheader.coding_info))
        .transpose()?
        .context("interleaved XA extent contains no Form 2 sectors")?;
    let mut form1 = Vec::new();
    let mut form1_subheaders = Vec::new();
    let mut sidecar = Vec::new();
    for (index, sector) in sectors.iter().enumerate() {
        ensure!(
            sector.subheader.file_number == file_number,
            "interleaved XA sector {index} has file number {}, expected {file_number}",
            sector.subheader.file_number
        );
        match sector.kind {
            Kind::Form1 => {
                form1.extend_from_slice(sector.payload());
                form1_subheaders.push(sector.subheader);
            }
            Kind::Form2 => {
                ensure!(
                    xa_audio_cadence(sector.subheader.coding_info)? == cadence,
                    "interleaved extent mixes incompatible XA audio cadences"
                );
                ensure!(
                    sector_follows_form2_edc_policy(sector, form2_edc),
                    "interleaved Form 2 sector {index} does not follow track Form 2 EDC policy"
                );
                sidecar.extend_from_slice(&encode_xa_sidecar_record(
                    sector.subheader,
                    sector.payload(),
                )?);
            }
            Kind::XaGap => anyhow::bail!("XA gap inside interleaved extent at sector {index}"),
        }
    }
    let form1_sectors = form1.chunks_exact(LOGICAL_BLOCK_SIZE).collect::<Vec<_>>();
    let padding_start = form1_sectors
        .iter()
        .rposition(|payload| payload.iter().any(|byte| *byte != 0))
        .map_or(0, |index| index + 1);
    let default_subheader = XaSubheader {
        file_number,
        ..XaSubheader::default()
    };
    let mut normalized_form1_subheaders = form1_subheaders.clone();
    if sectors
        .last()
        .is_some_and(|sector| sector.kind == Kind::Form1)
        && let Some(subheader) = normalized_form1_subheaders.last_mut()
    {
        subheader.submode =
            XaSubmode::from_bits(subheader.submode.bits() & !XaSubmode::END_OF_FILE.bits());
    }
    let form1_subheader = normalized_form1_subheaders
        .first()
        .copied()
        .filter(|_| padding_start != 0)
        .unwrap_or(default_subheader);
    ensure!(
        normalized_form1_subheaders[..padding_start]
            .iter()
            .all(|subheader| *subheader == form1_subheader),
        "mixed XA extent uses multiple Form 1 data subheaders"
    );
    let stored_form1_subheader = (form1_subheader != default_subheader).then_some(form1_subheader);
    let reconstructed = multiplex_xa_extent(&form1, &sidecar, file_number, stored_form1_subheader)?;
    ensure!(
        reconstructed.len() == sectors.len(),
        "mixed XA cadence does not reproduce the source extent length"
    );
    for (index, (source, authored)) in sectors.iter().zip(&reconstructed).enumerate() {
        match (source.kind, authored) {
            (Kind::Form1, XaExtentSector::Form1(form1)) => ensure!(
                source.subheader == form1.subheader,
                "mixed XA Form 1 framing differs at sector {index}"
            ),
            (Kind::Form2, XaExtentSector::Form2(form2)) => ensure!(
                source.subheader == form2.subheader && source.payload() == form2.payload,
                "mixed XA Form 2 framing differs at sector {index}"
            ),
            _ => anyhow::bail!("mixed XA sector order differs at sector {index}"),
        }
    }
    Ok((form1, sidecar, stored_form1_subheader))
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

fn detect_file_layout(
    sectors: &[crate::raw_cd::ParsedSector],
    files: &[iso9660::ParsedFile],
    form2_edc: bool,
) -> Result<Vec<FileLayoutItem>> {
    let mut files = files.to_vec();
    files.sort_by_key(|file| file.extent);
    let mut previous_end = 0_usize;
    let mut layout = Vec::new();
    for file in files {
        let extent = usize::try_from(file.extent)?;
        ensure!(
            extent >= previous_end,
            "overlapping or unordered file extents"
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
                file.path
            );
            start -= 1;
        }
        if start < extent {
            layout.push(FileLayoutItem::gap(u32::try_from(extent - start)?));
        }
        layout.push(FileLayoutItem::path(&file.path));
        previous_end = extent + usize::try_from(file.length)?.div_ceil(LOGICAL_BLOCK_SIZE);
    }
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
    let (system_bytes, form1_count, form2_edc) =
        extract_system_area(&sectors[..SYSTEM_AREA_SECTORS])?;
    let system_name = format!("{}.system", manifest_stem(manifest_path)?);
    let blocks = sectors
        .iter()
        .map(|sector| sector.logical_block().try_into())
        .collect::<Result<Vec<[u8; LOGICAL_BLOCK_SIZE]>, _>>()?;
    let mut parsed_iso = iso9660::parse(&blocks)?;
    validate_iso_subheaders(&sectors, &parsed_iso, trailing_gap)?;
    parsed_iso.manifest.files = detect_file_layout(&sectors, &parsed_iso.files, form2_edc)?;
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
            let file_number = parsed_iso.manifest.entries[entry_index]
                .xa
                .as_ref()
                .context("missing XA metadata")?
                .file_number;
            let (form1, sidecar, form1_subheader) =
                demultiplex_xa_extent(&sectors[start..start + count], file_number, form2_edc)
                    .with_context(|| format!("demultiplexing {}", file.path))?;
            let sidecar_path = format!("{}.XA", file.path);
            ensure!(
                parsed_iso
                    .manifest
                    .entries
                    .iter()
                    .all(|candidate| candidate.path != sidecar_path),
                "XA sidecar path collides with ISO entry {sidecar_path}"
            );
            let xa = parsed_iso.manifest.entries[entry_index]
                .xa
                .as_mut()
                .expect("checked XA metadata");
            xa.form1_subheader = form1_subheader;
            xa.form2 = Some(sidecar_path.clone());
            extracted_files.insert(file.path.clone(), form1);
            extracted_files.insert(sidecar_path, sidecar);
        } else {
            let data = read_extent(&blocks, file.extent, file.length)?;
            extracted_files.insert(file.path.clone(), data);
        }
    }
    let manifest = Manifest {
        track: Track {
            mode: TrackMode::Mode2Xa,
            start_msf: format_msf(start_frame)?,
            trailing_gap: u32::try_from(trailing_gap)?,
            form2_edc,
            noncompliant_trailing_ecc,
        },
        system_area: SystemArea {
            path: system_name.clone(),
            form1_sectors: if system_bytes.len().div_ceil(LOGICAL_BLOCK_SIZE) == form1_count {
                Form1Sectors::Auto("auto".to_owned())
            } else {
                Form1Sectors::Count(u8::try_from(form1_count)?)
            },
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
                validate_output_file(&output, options.overwrite, "extraction output")?;
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
                if let Some(parent) = output.parent() {
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

fn extract_system_area(sectors: &[crate::raw_cd::ParsedSector]) -> Result<(Vec<u8>, usize, bool)> {
    ensure!(
        sectors.len() == SYSTEM_AREA_SECTORS,
        "system area must contain sixteen sectors"
    );
    let form2_start = sectors
        .iter()
        .position(|sector| sector.kind != Kind::Form1)
        .unwrap_or(SYSTEM_AREA_SECTORS);
    ensure!(
        form2_start > 0 && form2_start < SYSTEM_AREA_SECTORS,
        "system area needs a Form 1 prefix and Form 2 suffix"
    );
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
        sectors[..form2_start]
            .iter()
            .all(|sector| sector.subheader == FORM1_DATA_SUBHEADER),
        "system-area Form 1 sectors use a nonstandard XA subheader"
    );
    ensure!(
        sectors[form2_start..]
            .iter()
            .all(|sector| sector.subheader == FORM2_SUBHEADER),
        "system-area Form 2 sectors use a nonstandard XA subheader"
    );
    Ok((content, form2_start, computed))
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
        let interleaved = parsed_iso
            .manifest
            .entries
            .iter()
            .find(|entry| entry.path == file.path)
            .is_some_and(entry_uses_xa_sidecar);
        for block_index in 0..blocks {
            let lba = usize::try_from(file.extent)? + block_index;
            ensure!(lba < content_end, "file extent reaches outside ISO content");
            ensure!(
                file_sector_info
                    .insert(lba, (block_index + 1 == blocks, interleaved))
                    .is_none(),
                "overlapping file extents at LBA {lba}"
            );
        }
    }

    for (lba, sector) in sectors.iter().enumerate().take(content_end).skip(16) {
        let expected = if lba == 16 {
            PVD_SUBHEADER
        } else if let Some((is_last, interleaved)) = file_sector_info.get(&lba) {
            if *interleaved {
                continue;
            }
            if *is_last {
                ISO_METADATA_SUBHEADER
            } else {
                FORM1_DATA_SUBHEADER
            }
        } else {
            ISO_METADATA_SUBHEADER
        };
        if sector.kind == Kind::Form2
            && sector.subheader == FORM2_SUBHEADER
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
            "ISO sector at LBA {lba} uses a nonstandard XA subheader"
        );
    }
    for (lba, sector) in sectors.iter().enumerate().skip(content_end) {
        ensure!(
            sector.kind == Kind::XaGap && sector.subheader == XaSubheader::default(),
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
    let mut sidecar_paths = HashSet::new();
    for file in manifest
        .iso9660
        .files
        .iter()
        .filter_map(FileLayoutItem::as_path)
    {
        let path = safe_join(data_dir, file)?;
        let data =
            fs::read(&path).with_context(|| format!("reading authored file {}", path.display()))?;
        let entry = entries_by_path[file];
        let sidecar_path = entry.xa.as_ref().and_then(|xa| xa.form2.as_deref());
        ensure!(
            entry_uses_xa_sidecar(entry) == sidecar_path.is_some(),
            "interleaved XA entry {file} must specify exactly one Form 2 sidecar"
        );
        if let Some(sidecar_path) = sidecar_path {
            ensure!(
                sidecar_paths.insert(sidecar_path),
                "duplicate XA sidecar path {sidecar_path}"
            );
            ensure!(
                !iso_paths.contains(sidecar_path) && sidecar_path != manifest.system_area.path,
                "XA sidecar path collides with another authored asset: {sidecar_path}"
            );
            let sidecar_host_path = safe_join(data_dir, sidecar_path)?;
            let sidecar = fs::read(&sidecar_host_path)
                .with_context(|| format!("reading XA sidecar {}", sidecar_host_path.display()))?;
            let xa = entry.xa.as_ref().expect("XA sidecar metadata");
            let sectors = multiplex_xa_extent(&data, &sidecar, xa.file_number, xa.form1_subheader)
                .with_context(|| format!("multiplexing {file}"))?;
            file_lengths.insert(
                file.to_owned(),
                u64::try_from(sectors.len())? * LOGICAL_BLOCK_SIZE as u64,
            );
            mixed_extents.insert(file.to_owned(), sectors);
        } else {
            file_lengths.insert(file.to_owned(), u64::try_from(data.len())?);
        }
        file_data.insert(file.to_owned(), data);
    }
    let mut layout = iso9660::layout(
        &manifest.iso9660,
        &file_lengths,
        manifest.track.trailing_gap,
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
        !manifest.track.noncompliant_trailing_ecc || manifest.track.trailing_gap != 0,
        "noncompliant_trailing_ecc requires a trailing gap"
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
            raw.extend_from_slice(&writer.form1(frame, FORM1_DATA_SUBHEADER, &payload)?);
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
                    raw.extend_from_slice(&writer.form1(
                        start_frame + lba,
                        form1.subheader,
                        &form1.payload,
                    )?);
                }
                XaExtentSector::Form2(record) => raw.extend_from_slice(&writer.form2(
                    start_frame + lba,
                    record.subheader,
                    &record.payload,
                    manifest.track.form2_edc,
                )?),
            }
            continue;
        }
        let subheader = if lba == 16 {
            PVD_SUBHEADER
        } else if let Some((_, _, is_last)) = file_sector_info.get(&lba) {
            if *is_last {
                ISO_METADATA_SUBHEADER
            } else {
                FORM1_DATA_SUBHEADER
            }
        } else {
            ISO_METADATA_SUBHEADER
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

    fn reference_image() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("data/tyco_demo.bin")
    }

    fn spyro_reference_image() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("data/spyro1.bin")
    }

    fn lemmings_reference_image() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("data/3dlemmings.bin")
    }

    fn files_are_equal(left: &Path, right: &Path) -> bool {
        use std::io::Read;

        let mut left = fs::File::open(left).unwrap();
        let mut right = fs::File::open(right).unwrap();
        if left.metadata().unwrap().len() != right.metadata().unwrap().len() {
            return false;
        }
        let mut left_buffer = [0_u8; 64 * 1024];
        let mut right_buffer = [0_u8; 64 * 1024];
        loop {
            let left_count = left.read(&mut left_buffer).unwrap();
            let right_count = right.read(&mut right_buffer).unwrap();
            if left_count != right_count || left_buffer[..left_count] != right_buffer[..right_count]
            {
                return false;
            }
            if left_count == 0 {
                return true;
            }
        }
    }

    #[test]
    fn system_area_trims_only_trailing_zeroes() {
        let mut writer = SectorWriter::new();
        let mut raw = Vec::new();
        let mut first = [0_u8; 2048];
        first[0] = 7;
        for index in 0..12 {
            let data = if index == 0 { &first } else { &[0; 2048] };
            raw.extend_from_slice(
                &writer
                    .form1(150 + index, [0, 0, 8, 0].into(), data)
                    .unwrap(),
            );
        }
        for index in 12..16 {
            raw.extend_from_slice(
                &writer
                    .form2(150 + index, [0, 0, 0x20, 0].into(), &[0; 2324], true)
                    .unwrap(),
            );
        }
        let (_, sectors) = parse_image(&raw).unwrap();
        let (system, form1, _) = extract_system_area(&sectors).unwrap();
        assert_eq!(system, vec![7]);
        assert_eq!(form1, 12);

        let mut nonstandard = sectors;
        nonstandard[0].subheader = XaSubheader::default();
        let error = extract_system_area(&nonstandard).unwrap_err();
        assert!(
            error
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

    #[test]
    fn psx_double_speed_xa_audio_cadence_is_derived_from_coding_info() {
        assert_eq!(xa_audio_cadence(0x01).unwrap(), 8);
        assert_eq!(xa_audio_cadence(0x00).unwrap(), 16);
        assert_eq!(xa_audio_cadence(0x05).unwrap(), 16);
        assert_eq!(xa_audio_cadence(0x04).unwrap(), 32);
        assert_eq!(xa_audio_cadence(0x11).unwrap(), 4);
        assert!(xa_audio_cadence(0x02).is_err());
    }

    #[test]
    fn xa_sidecar_preserves_subheaders_and_form2_payloads() {
        let subheader = XaSubheader {
            file_number: 1,
            channel: 7,
            submode: XaSubmode::AUDIO
                .union(XaSubmode::FORM2)
                .union(XaSubmode::REALTIME)
                .union(XaSubmode::END_OF_FILE),
            coding_info: 1,
        };
        let payload = [0x5a; FORM2_PAYLOAD_SIZE];
        let sidecar = encode_xa_sidecar_record(subheader, &payload).unwrap();
        assert_eq!(sidecar.len(), XA_SIDECAR_RECORD_SIZE);

        let records = parse_xa_sidecar(&sidecar).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].subheader, subheader);
        assert_eq!(records[0].payload, payload);
    }

    #[test]
    fn xa_multiplex_places_active_channels_in_trailing_cadence_slots() {
        let form1 = vec![0x33; 6 * LOGICAL_BLOCK_SIZE];
        let mut sidecar = Vec::new();
        for channel in [0, 1] {
            let subheader = XaSubheader {
                file_number: 1,
                channel,
                submode: XaSubmode::AUDIO
                    .union(XaSubmode::FORM2)
                    .union(XaSubmode::REALTIME),
                coding_info: 1,
            };
            sidecar.extend_from_slice(
                &encode_xa_sidecar_record(subheader, &[channel; FORM2_PAYLOAD_SIZE]).unwrap(),
            );
        }

        let sectors = multiplex_xa_extent(&form1, &sidecar, 1, None).unwrap();
        assert_eq!(sectors.len(), 8);
        assert!(
            sectors[..6]
                .iter()
                .all(|sector| matches!(sector, XaExtentSector::Form1(_)))
        );
        assert!(matches!(sectors[6], XaExtentSector::Form2(_)));
        assert!(matches!(sectors[7], XaExtentSector::Form2(_)));
    }

    #[test]
    fn xa_channel_end_of_file_removes_it_from_later_cadence_groups() {
        let form1 = vec![0x33; 13 * LOGICAL_BLOCK_SIZE];
        let mut sidecar = Vec::new();
        for (channel, end_of_file) in [(0, true), (1, false), (1, false)] {
            let mut submode = XaSubmode::AUDIO
                .union(XaSubmode::FORM2)
                .union(XaSubmode::REALTIME);
            if end_of_file {
                submode = submode.union(XaSubmode::END_OF_FILE);
            }
            let subheader = XaSubheader {
                file_number: 1,
                channel,
                submode,
                coding_info: 1,
            };
            sidecar.extend_from_slice(
                &encode_xa_sidecar_record(subheader, &[channel; FORM2_PAYLOAD_SIZE]).unwrap(),
            );
        }

        let sectors = multiplex_xa_extent(&form1, &sidecar, 1, None).unwrap();
        assert_eq!(sectors.len(), 16);
        assert!(matches!(sectors[6], XaExtentSector::Form2(_)));
        assert!(matches!(sectors[7], XaExtentSector::Form2(_)));
        assert!(matches!(sectors[15], XaExtentSector::Form2(_)));
    }

    #[test]
    fn ended_xa_channel_leaves_its_assigned_cadence_slot_empty() {
        let form1 = vec![0x33; 11 * LOGICAL_BLOCK_SIZE];
        let mut sidecar = Vec::new();
        for (channel, end_of_file) in [(0, false), (1, true), (2, false), (0, false), (2, false)] {
            let mut submode = XaSubmode::AUDIO
                .union(XaSubmode::FORM2)
                .union(XaSubmode::REALTIME);
            if end_of_file {
                submode = submode.union(XaSubmode::END_OF_FILE);
            }
            let subheader = XaSubheader {
                file_number: 1,
                channel,
                submode,
                coding_info: 1,
            };
            sidecar.extend_from_slice(
                &encode_xa_sidecar_record(subheader, &[channel; FORM2_PAYLOAD_SIZE]).unwrap(),
            );
        }

        let sectors = multiplex_xa_extent(&form1, &sidecar, 1, None).unwrap();
        assert_eq!(sectors.len(), 16);
        assert!(matches!(sectors[13], XaExtentSector::Form2(_)));
        assert!(matches!(sectors[14], XaExtentSector::Form1(_)));
        assert!(matches!(sectors[15], XaExtentSector::Form2(_)));
    }

    #[test]
    fn mixed_xa_video_form1_subheader_is_discovered_from_the_extent() {
        use std::io::{Read, Seek, SeekFrom};

        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("data/3dlemmings.bin");
        let mut source = fs::File::open(path).unwrap();
        source
            .seek(SeekFrom::Start((957 * RAW_SECTOR_SIZE) as u64))
            .unwrap();
        let mut raw = vec![0_u8; 8 * RAW_SECTOR_SIZE];
        source.read_exact(&mut raw).unwrap();
        let (_, sectors) = parse_image(&raw).unwrap();

        let (form1, sidecar, form1_subheader) = demultiplex_xa_extent(&sectors, 1, false).unwrap();
        assert_eq!(form1.len(), 7 * LOGICAL_BLOCK_SIZE);
        assert_eq!(sidecar.len(), XA_SIDECAR_RECORD_SIZE);
        assert_eq!(form1_subheader, Some([1, 1, 0x42, 0x80].into()));
    }

    #[test]
    fn final_interleaved_form1_sector_carries_end_of_file() {
        let form1 = vec![0_u8; 8 * LOGICAL_BLOCK_SIZE];
        let subheader = XaSubheader {
            file_number: 1,
            submode: XaSubmode::AUDIO
                .union(XaSubmode::FORM2)
                .union(XaSubmode::REALTIME),
            coding_info: 1,
            ..XaSubheader::default()
        };
        let sidecar = encode_xa_sidecar_record(subheader, &[0; FORM2_PAYLOAD_SIZE]).unwrap();
        let sectors = multiplex_xa_extent(&form1, &sidecar, 1, None).unwrap();
        let XaExtentSector::Form1(final_sector) = sectors.last().unwrap() else {
            panic!("expected final Form 1 sector");
        };
        assert_eq!(<[u8; 4]>::from(final_sector.subheader), [1, 0, 0x80, 0]);
    }

    #[test]
    fn final_nonpadding_form1_eof_is_not_a_second_subheader_template() {
        let form1 = vec![0x33_u8; 8 * LOGICAL_BLOCK_SIZE];
        let form2_subheader = XaSubheader {
            file_number: 1,
            submode: XaSubmode::AUDIO
                .union(XaSubmode::FORM2)
                .union(XaSubmode::REALTIME),
            coding_info: 1,
            ..XaSubheader::default()
        };
        let sidecar =
            encode_xa_sidecar_record(form2_subheader, &[0x44; FORM2_PAYLOAD_SIZE]).unwrap();
        let authored = multiplex_xa_extent(&form1, &sidecar, 1, None).unwrap();
        let mut writer = SectorWriter::new();
        let mut raw = Vec::new();
        for (index, sector) in authored.iter().enumerate() {
            let frame = 150 + u32::try_from(index).unwrap();
            match sector {
                XaExtentSector::Form1(form1) => raw.extend_from_slice(
                    &writer
                        .form1(frame, form1.subheader, &form1.payload)
                        .unwrap(),
                ),
                XaExtentSector::Form2(form2) => raw.extend_from_slice(
                    &writer
                        .form2(frame, form2.subheader, &form2.payload, false)
                        .unwrap(),
                ),
            }
        }
        let (_, sectors) = parse_image(&raw).unwrap();

        let (_, _, form1_subheader) = demultiplex_xa_extent(&sectors, 1, false).unwrap();
        assert_eq!(form1_subheader, None);
    }

    #[test]
    fn zero_form2_physical_gap_sector_is_reproducible() {
        use std::io::{Read, Seek, SeekFrom};

        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("data/spyro1.bin");
        let mut source = fs::File::open(path).unwrap();
        source
            .seek(SeekFrom::Start((24 * RAW_SECTOR_SIZE) as u64))
            .unwrap();
        let mut expected = [0_u8; RAW_SECTOR_SIZE];
        source.read_exact(&mut expected).unwrap();

        let actual = SectorWriter::new()
            .form2(150 + 24, FORM2_SUBHEADER, &[0; FORM2_PAYLOAD_SIZE], true)
            .unwrap();
        assert_eq!(actual, expected);
    }

    #[test]
    fn extraction_rejects_nonstandard_iso_subheaders() {
        let image = fs::read(reference_image()).unwrap();
        let (_, mut sectors) = parse_image(&image).unwrap();
        let blocks = sectors
            .iter()
            .map(|sector| sector.logical_block().try_into().unwrap())
            .collect::<Vec<[u8; LOGICAL_BLOCK_SIZE]>>();
        let parsed_iso = iso9660::parse(&blocks).unwrap();
        sectors[16].subheader = FORM1_DATA_SUBHEADER;

        let error = validate_iso_subheaders(&sectors, &parsed_iso, 150).unwrap_err();
        assert_eq!(
            error.to_string(),
            "ISO sector at LBA 16 uses a nonstandard XA subheader"
        );
    }

    #[test]
    fn safe_join_rejects_escape() {
        assert!(safe_join(Path::new("data"), "../escape").is_err());
        assert_eq!(
            safe_join(Path::new("data"), "DIR/FILE.BIN").unwrap(),
            Path::new("data/DIR/FILE.BIN")
        );
    }

    #[test]
    fn manifest_only_does_not_write_extracted_assets() {
        let project = tempfile::tempdir().unwrap();
        let manifest = project.path().join("sample.yaml");
        extract(&reference_image(), &manifest, project.path(), true, false).unwrap();
        assert!(manifest.is_file());
        let yaml = fs::read_to_string(&manifest).unwrap();
        assert!(!yaml.contains("format_version"));
        assert!(!yaml.contains("sha1"));
        assert!(!yaml.lines().any(|line| line == "source:"));
        assert!(!yaml.lines().any(|line| line.starts_with("track:")));
        assert!(!yaml.lines().any(|line| line.starts_with("  mode:")));
        assert!(!yaml.lines().any(|line| line.starts_with("  start_msf:")));
        assert!(!yaml.lines().any(|line| line.starts_with("  trailing_gap:")));
        assert!(
            !yaml
                .lines()
                .any(|line| line.starts_with("  raw_sector_size:"))
        );
        assert!(!yaml.contains("subheader"));
        assert!(!yaml.contains("file_end_submode"));
        assert!(!yaml.lines().any(|line| line == "  root:"));
        assert!(!yaml.lines().any(|line| line == "  defaults:"));
        let (entries_yaml, files_yaml) = yaml
            .split_once("  entries:\n")
            .unwrap()
            .1
            .split_once("  files:\n")
            .unwrap();
        assert!(entries_yaml.starts_with("  - path: .\n    recording_time:"));
        assert!(entries_yaml.contains("    recording_time: 1900-06-16T09:45:51+09:00\n"));
        assert!(!entries_yaml.contains("recording_time_hex:"));
        assert_eq!(entries_yaml.matches("  - path:").count(), 5);
        assert_eq!(entries_yaml.matches("    recording_time:").count(), 5);
        assert!(!entries_yaml.contains("system_use_hex:"));
        for fixed_or_redundant_field in [
            "version:",
            "flags:",
            "file_unit_size:",
            "interleave_gap_size:",
            "volume_sequence_number:",
            "source_length:",
        ] {
            assert!(!entries_yaml.contains(fixed_or_redundant_field));
        }
        assert!(!entries_yaml.contains("kind:"));
        assert!(!entries_yaml.contains("data_order:"));
        assert_eq!(
            files_yaml,
            "  - path: MAIN.EXE\n  - path: MAINRSRC.BFF\n  - path: SYSTEM.CNF\n  - path: DUMMY.BIN\n"
        );
        let system_area_yaml = yaml
            .split_once("system_area:\n")
            .unwrap()
            .1
            .split_once("iso9660:\n")
            .unwrap()
            .0;
        assert!(!yaml.contains("form2_edc:"));
        assert!(!system_area_yaml.contains("form2_edc:"));
        assert!(!system_area_yaml.contains("source_length:"));
        assert!(!system_area_yaml.contains("total_sectors:"));
        let primary_volume_yaml = yaml
            .split_once("  primary_volume:\n")
            .unwrap()
            .1
            .split_once("  entries:\n")
            .unwrap()
            .0;
        for omitted_field in [
            "volume_set_identifier:",
            "data_preparer_identifier:",
            "abstract_file_identifier:",
            "bibliographic_file_identifier:",
            "volume_set_size:",
            "volume_sequence_number:",
            "logical_block_size:",
            "file_structure_version:",
        ] {
            assert!(!primary_volume_yaml.contains(omitted_field));
        }
        assert!(
            primary_volume_yaml
                .lines()
                .any(|line| line == "    creation_time: 0000-06-16T09:45:51.00+09:00")
        );
        for omitted_time in ["modification_time:", "expiration_time:", "effective_time:"] {
            assert!(!primary_volume_yaml.contains(omitted_time));
        }
        assert!(!primary_volume_yaml.contains("_time_hex:"));
        assert!(!primary_volume_yaml.contains("application_use_hex:"));
        let legacy = yaml.replacen(
            "  entries:\n",
            "    application_use_hex: '00'\n  entries:\n",
            1,
        );
        assert!(yaml_serde::from_str::<Manifest>(&legacy).is_err());
        let legacy = yaml.replacen(
            "system_area:\n",
            "track:\n  pvd_subheader: [0, 0, 9, 0]\nsystem_area:\n",
            1,
        );
        assert!(yaml_serde::from_str::<Manifest>(&legacy).is_err());
        for legacy_field in [
            "source_length: 24576",
            "total_sectors: 16",
            "form2_edc: true",
        ] {
            let legacy = yaml.replacen(
                "system_area:\n",
                &format!("system_area:\n  {legacy_field}\n"),
                1,
            );
            assert!(yaml_serde::from_str::<Manifest>(&legacy).is_err());
        }
        let legacy = yaml.replacen("  entries:\n", "  root: {}\n  entries:\n", 1);
        assert!(yaml_serde::from_str::<Manifest>(&legacy).is_err());
        let legacy = yaml.replacen("  entries:\n", "  defaults: {}\n  entries:\n", 1);
        assert!(yaml_serde::from_str::<Manifest>(&legacy).is_err());
        let legacy = yaml.replacen(
            "  - path: .\n",
            "  - path: .\n    recording_time_hex: 000610092d3324\n",
            1,
        );
        assert!(yaml_serde::from_str::<Manifest>(&legacy).is_err());
        let missing_time = yaml.replacen("    recording_time: 1900-06-16T09:45:51+09:00\n", "", 1);
        assert!(yaml_serde::from_str::<Manifest>(&missing_time).is_err());
        let legacy = yaml.replacen(
            "  - path: .\n",
            "  - path: .\n    system_use_hex: 000000008d555841000000000000\n",
            1,
        );
        assert!(yaml_serde::from_str::<Manifest>(&legacy).is_err());
        for legacy_field in ["kind: directory", "data_order: 0"] {
            let legacy = yaml.replacen(
                "  - path: .\n",
                &format!("  - path: .\n    {legacy_field}\n"),
                1,
            );
            assert!(yaml_serde::from_str::<Manifest>(&legacy).is_err());
        }
        for legacy_field in [
            "version: 1",
            "flags: 0",
            "file_unit_size: 0",
            "interleave_gap_size: 0",
            "volume_sequence_number: 1",
            "source_length: 0",
        ] {
            let legacy = yaml.replacen(
                "  - path: .\n",
                &format!("  - path: .\n    {legacy_field}\n"),
                1,
            );
            assert!(yaml_serde::from_str::<Manifest>(&legacy).is_err());
        }
        for legacy_field in [
            "creation_time_hex: '3030303030363136303934353531303024'",
            "modification_time_hex: '3030303030303030303030303030303000'",
            "expiration_time_hex: '3030303030303030303030303030303000'",
            "effective_time_hex: '3030303030303030303030303030303000'",
        ] {
            let legacy = yaml.replacen(
                "  primary_volume:\n",
                &format!("  primary_volume:\n    {legacy_field}\n"),
                1,
            );
            assert!(yaml_serde::from_str::<Manifest>(&legacy).is_err());
        }
        for legacy_field in [
            "volume_set_size: 1",
            "volume_sequence_number: 1",
            "logical_block_size: 2048",
            "file_structure_version: 1",
        ] {
            let legacy = yaml.replacen(
                "  primary_volume:\n",
                &format!("  primary_volume:\n    {legacy_field}\n"),
                1,
            );
            assert!(yaml_serde::from_str::<Manifest>(&legacy).is_err());
        }
        assert!(!project.path().join("sample.system").exists());
        assert!(!project.path().join("MAIN.EXE").exists());
    }

    #[test]
    fn extract_creates_missing_manifest_parent_directories() {
        let project = tempfile::tempdir().unwrap();
        let manifest = project.path().join("data/manifests/sample.yaml");

        extract(&reference_image(), &manifest, project.path(), true, false).unwrap();

        assert!(manifest.is_file());
    }

    #[test]
    fn include_defaults_writes_explicit_track_defaults() {
        let project = tempfile::tempdir().unwrap();
        let manifest = project.path().join("sample.yaml");
        extract_with_options(
            &reference_image(),
            &manifest,
            project.path(),
            ExtractOptions {
                manifest_only: true,
                overwrite: false,
                include_defaults: true,
            },
        )
        .unwrap();

        let yaml = fs::read_to_string(&manifest).unwrap();
        assert!(yaml.lines().any(|line| line == "  mode: 2xa"));
        assert!(yaml.lines().any(|line| line == "  start_msf: 00:02:00"));
        assert!(yaml.lines().any(|line| line == "  trailing_gap: 150"));
        assert!(yaml.lines().any(|line| line == "  form2_edc: true"));
        assert!(
            yaml.lines()
                .any(|line| line == "  noncompliant_trailing_ecc: false")
        );
        for empty_default in [
            "    volume_set_identifier: ''",
            "    data_preparer_identifier: ''",
            "    abstract_file_identifier: ''",
            "    bibliographic_file_identifier: ''",
        ] {
            assert!(yaml.lines().any(|line| line == empty_default));
        }
        assert!(
            yaml.lines()
                .any(|line| line == "    creation_time: 0000-06-16T09:45:51.00+09:00")
        );
        for null_default in [
            "    modification_time: null",
            "    expiration_time: null",
            "    effective_time: null",
        ] {
            assert!(yaml.lines().any(|line| line == null_default));
        }
        let primary_volume_yaml = yaml
            .split_once("  primary_volume:\n")
            .unwrap()
            .1
            .split_once("  entries:\n")
            .unwrap()
            .0;
        assert!(!primary_volume_yaml.contains("_time_hex:"));
        assert!(!primary_volume_yaml.contains("application_use_hex:"));
        for fixed_field in [
            "volume_set_size:",
            "volume_sequence_number:",
            "logical_block_size:",
            "file_structure_version:",
        ] {
            assert!(!primary_volume_yaml.contains(fixed_field));
        }
        assert!(!yaml.contains("pvd_subheader"));
        assert!(!yaml.contains("metadata_subheader"));
        assert!(!yaml.contains("file_end_submode"));
        assert!(!yaml.contains("raw_sector_size"));
        assert!(!yaml.lines().any(|line| line == "  root:"));
        assert!(!yaml.lines().any(|line| line == "  defaults:"));
        let (entries_yaml, files_yaml) = yaml
            .split_once("  entries:\n")
            .unwrap()
            .1
            .split_once("  files:\n")
            .unwrap();
        assert!(entries_yaml.starts_with("  - path: .\n    recording_time:"));
        assert_eq!(entries_yaml.matches("    xa:\n").count(), 5);
        assert_eq!(entries_yaml.matches("      group_id: 0\n").count(), 5);
        assert_eq!(entries_yaml.matches("      user_id: 0\n").count(), 5);
        assert_eq!(entries_yaml.matches("      file_number: 0\n").count(), 5);
        assert_eq!(
            entries_yaml
                .matches("      form1_subheader: null\n")
                .count(),
            5
        );
        assert_eq!(entries_yaml.matches("      form2: null\n").count(), 5);
        assert!(
            entries_yaml.contains("      attributes:\n      - mode2_form1\n      - directory\n")
        );
        assert!(!entries_yaml.contains("kind:"));
        assert!(!entries_yaml.contains("data_order:"));
        assert_eq!(
            files_yaml,
            "  - path: MAIN.EXE\n  - path: MAINRSRC.BFF\n  - path: SYSTEM.CNF\n  - path: DUMMY.BIN\n"
        );
        let parsed: Manifest = yaml_serde::from_str(&yaml).unwrap();
        assert_eq!(parsed.track.mode, TrackMode::Mode2Xa);
        assert_eq!(parsed.track.start_msf, "00:02:00");
    }

    #[test]
    fn explicit_defaults_manifest_rebuilds_byte_identically() {
        let project = tempfile::tempdir().unwrap();
        let manifest = project.path().join("sample.yaml");
        extract_with_options(
            &reference_image(),
            &manifest,
            project.path(),
            ExtractOptions {
                manifest_only: false,
                overwrite: false,
                include_defaults: true,
            },
        )
        .unwrap();

        let rebuilt = project.path().join("rebuilt.bin");
        let report = build(&manifest, &rebuilt, project.path(), false).unwrap();
        assert_eq!(report.sha1, "5b16aa056dee14eff92891c24ca7cf71d263077d");
        assert_eq!(
            fs::read(rebuilt).unwrap(),
            fs::read(reference_image()).unwrap()
        );
    }

    #[test]
    fn extract_refuses_existing_outputs_without_overwrite() {
        let project = tempfile::tempdir().unwrap();
        let manifest = project.path().join("sample.yaml");
        extract(&reference_image(), &manifest, project.path(), false, false).unwrap();

        let manifest_error =
            extract(&reference_image(), &manifest, project.path(), false, false).unwrap_err();
        assert!(
            manifest_error
                .to_string()
                .contains("manifest output already exists")
        );

        let other_manifest = project.path().join("other.yaml");
        let asset_error = extract(
            &reference_image(),
            &other_manifest,
            project.path(),
            false,
            false,
        )
        .unwrap_err();
        assert!(
            asset_error
                .to_string()
                .contains("extraction output already exists")
        );
    }

    #[test]
    fn extract_overwrite_replaces_listed_outputs_and_preserves_unlisted_files() {
        let project = tempfile::tempdir().unwrap();
        let manifest = project.path().join("sample.yaml");
        extract(&reference_image(), &manifest, project.path(), false, false).unwrap();
        let expected_manifest = fs::read(&manifest).unwrap();
        let expected_system = fs::read(project.path().join("sample.system")).unwrap();
        let expected_main = fs::read(project.path().join("MAIN.EXE")).unwrap();

        fs::write(&manifest, b"stale manifest").unwrap();
        fs::write(project.path().join("sample.system"), b"stale system").unwrap();
        fs::write(project.path().join("MAIN.EXE"), b"stale executable").unwrap();
        fs::write(project.path().join("UNLISTED.TXT"), b"keep me").unwrap();

        extract(&reference_image(), &manifest, project.path(), false, true).unwrap();
        assert_eq!(fs::read(&manifest).unwrap(), expected_manifest);
        assert_eq!(
            fs::read(project.path().join("sample.system")).unwrap(),
            expected_system
        );
        assert_eq!(
            fs::read(project.path().join("MAIN.EXE")).unwrap(),
            expected_main
        );
        assert_eq!(
            fs::read(project.path().join("UNLISTED.TXT")).unwrap(),
            b"keep me"
        );
    }

    #[test]
    fn manifest_only_overwrite_does_not_touch_assets() {
        let project = tempfile::tempdir().unwrap();
        let manifest = project.path().join("sample.yaml");
        extract(&reference_image(), &manifest, project.path(), true, false).unwrap();
        let expected_manifest = fs::read(&manifest).unwrap();
        fs::write(&manifest, b"stale manifest").unwrap();
        fs::write(project.path().join("sample.system"), b"untouched asset").unwrap();

        extract(&reference_image(), &manifest, project.path(), true, true).unwrap();
        assert_eq!(fs::read(&manifest).unwrap(), expected_manifest);
        assert_eq!(
            fs::read(project.path().join("sample.system")).unwrap(),
            b"untouched asset"
        );
    }

    #[test]
    fn extract_overwrite_rejects_file_directory_type_conflicts_before_writing() {
        let project = tempfile::tempdir().unwrap();
        let manifest = project.path().join("sample.yaml");
        fs::create_dir(project.path().join("sample.system")).unwrap();

        let error =
            extract(&reference_image(), &manifest, project.path(), false, true).unwrap_err();
        assert!(error.to_string().contains("not a regular file"));
        assert!(!manifest.exists());
    }

    #[test]
    fn matching_output_directories_are_reused_only_with_overwrite() {
        let project = tempfile::tempdir().unwrap();
        let directory = project.path().join("EXTRA");
        fs::create_dir(&directory).unwrap();

        assert!(
            validate_output_directory(&directory, false, "extraction output")
                .unwrap_err()
                .to_string()
                .contains("already exists")
        );
        validate_output_directory(&directory, true, "extraction output").unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn extract_overwrite_rejects_symlink_destinations_before_writing() {
        use std::os::unix::fs::symlink;

        let project = tempfile::tempdir().unwrap();
        let manifest = project.path().join("sample.yaml");
        let target = project.path().join("target");
        fs::write(&target, b"untouched").unwrap();
        symlink(&target, project.path().join("sample.system")).unwrap();

        let error =
            extract(&reference_image(), &manifest, project.path(), false, true).unwrap_err();
        assert!(error.to_string().contains("symlink"));
        assert!(!manifest.exists());
        assert_eq!(fs::read(target).unwrap(), b"untouched");
    }

    #[test]
    fn build_overwrite_replaces_existing_image_but_not_stale_temporary_output() {
        let project = tempfile::tempdir().unwrap();
        let manifest = project.path().join("sample.yaml");
        extract(&reference_image(), &manifest, project.path(), false, false).unwrap();
        let rebuilt = project.path().join("rebuilt.bin");

        fs::create_dir(&rebuilt).unwrap();
        let type_conflict = build(&manifest, &rebuilt, project.path(), true).unwrap_err();
        assert!(type_conflict.to_string().contains("not a regular file"));
        fs::remove_dir(&rebuilt).unwrap();

        fs::write(&rebuilt, b"old image").unwrap();

        let refusal = build(&manifest, &rebuilt, project.path(), false).unwrap_err();
        assert!(refusal.to_string().contains("image output already exists"));

        let temp_path = temporary_path(&rebuilt).unwrap();
        fs::write(&temp_path, b"stale temporary image").unwrap();
        let stale_temp = build(&manifest, &rebuilt, project.path(), true).unwrap_err();
        assert!(
            stale_temp
                .to_string()
                .contains("temporary output already exists")
        );
        assert_eq!(fs::read(&rebuilt).unwrap(), b"old image");
        fs::remove_file(temp_path).unwrap();

        let report = build(&manifest, &rebuilt, project.path(), true).unwrap();
        assert_eq!(report.sha1, "5b16aa056dee14eff92891c24ca7cf71d263077d");
        assert_eq!(
            fs::read(&rebuilt).unwrap(),
            fs::read(reference_image()).unwrap()
        );
    }

    #[test]
    fn build_creates_missing_image_parent_directories() {
        let project = tempfile::tempdir().unwrap();
        let manifest = project.path().join("sample.yaml");
        extract(&reference_image(), &manifest, project.path(), false, false).unwrap();
        let rebuilt = project.path().join("output/images/rebuilt.bin");

        let report = build(&manifest, &rebuilt, project.path(), false).unwrap();

        assert_eq!(report.sha1, "5b16aa056dee14eff92891c24ca7cf71d263077d");
        assert!(rebuilt.is_file());
    }

    #[cfg(unix)]
    #[test]
    fn build_overwrite_rejects_symlink_destination() {
        use std::os::unix::fs::symlink;

        let project = tempfile::tempdir().unwrap();
        let manifest = project.path().join("sample.yaml");
        extract(&reference_image(), &manifest, project.path(), false, false).unwrap();
        let target = project.path().join("target.bin");
        let rebuilt = project.path().join("rebuilt.bin");
        fs::write(&target, b"untouched").unwrap();
        symlink(&target, &rebuilt).unwrap();

        let error = build(&manifest, &rebuilt, project.path(), true).unwrap_err();
        assert!(error.to_string().contains("symlink"));
        assert_eq!(fs::read(target).unwrap(), b"untouched");
    }

    #[test]
    fn unimplemented_track_modes_are_rejected_before_building() {
        let project = tempfile::tempdir().unwrap();
        let manifest_path = project.path().join("sample.yaml");
        extract(
            &reference_image(),
            &manifest_path,
            project.path(),
            false,
            false,
        )
        .unwrap();
        let mut manifest: Manifest =
            yaml_serde::from_str(&fs::read_to_string(&manifest_path).unwrap()).unwrap();

        for mode in [TrackMode::Mode1, TrackMode::Mode2] {
            manifest.track.mode = mode;
            fs::write(&manifest_path, yaml_serde::to_string(&manifest).unwrap()).unwrap();
            let image = project.path().join(format!("mode-{mode}.bin"));
            let error = build(&manifest_path, &image, project.path(), false).unwrap_err();
            assert_eq!(error.to_string(), format!("unsupported track mode {mode}"));
        }
    }

    #[test]
    fn untouched_reference_round_trip_is_byte_identical() {
        let project = tempfile::tempdir().unwrap();
        let manifest = project.path().join("sample.yaml");
        extract(&reference_image(), &manifest, project.path(), false, false).unwrap();
        let system = fs::read(project.path().join("sample.system")).unwrap();
        assert_eq!(system.len(), 24_576);
        assert_eq!(
            sha1_hex(&system),
            "df9b3d7f3678ef11ecd606d4c820074381506668"
        );

        let rebuilt = project.path().join("rebuilt.bin");
        let report = build(&manifest, &rebuilt, project.path(), false).unwrap();
        assert_eq!(report.sha1, "5b16aa056dee14eff92891c24ca7cf71d263077d");
        assert_eq!(
            fs::read(reference_image()).unwrap(),
            fs::read(rebuilt).unwrap()
        );
    }

    #[test]
    fn untouched_interleaved_spyro_round_trip_is_byte_identical() {
        let project = tempfile::tempdir().unwrap();
        let manifest = project.path().join("spyro.yaml");
        let extract_report = extract(
            &spyro_reference_image(),
            &manifest,
            project.path(),
            false,
            false,
        )
        .unwrap();
        assert_eq!(extract_report.sectors, 281_270);
        assert_eq!(
            extract_report.sha1,
            "cf3ce6bedeb89dfbc40990336180f3b9b0f40d9f"
        );
        let yaml = fs::read_to_string(&manifest).unwrap();
        assert!(yaml.contains("  - gap: 13\n  - path: WAD.WAD\n"));
        assert!(yaml.contains("  - gap: 5921\n  - path: PETEXA0.STR\n"));
        assert!(yaml.contains("form2: PETEXA0.STR.XA\n"));

        let rebuilt = project.path().join("rebuilt.bin");
        let build_report = build(&manifest, &rebuilt, project.path(), false).unwrap();
        assert_eq!(build_report.sectors, 281_270);
        assert_eq!(
            build_report.sha1,
            "cf3ce6bedeb89dfbc40990336180f3b9b0f40d9f"
        );
        assert!(files_are_equal(&spyro_reference_image(), &rebuilt));
    }

    #[test]
    fn untouched_multitrack_lemmings_data_track_is_byte_identical() {
        let project = tempfile::tempdir().unwrap();
        let manifest = project.path().join("3dlemmings.yaml");
        let extract_report = extract(
            &lemmings_reference_image(),
            &manifest,
            project.path(),
            false,
            false,
        )
        .unwrap();
        assert_eq!(extract_report.sectors, 81_711);
        assert_eq!(
            extract_report.sha1,
            "f713cdcb5d0e3d875031dbdc438dbbab0cdd3340"
        );
        let yaml = fs::read_to_string(&manifest).unwrap();
        assert!(yaml.contains("  noncompliant_trailing_ecc: true\n"));
        assert!(yaml.contains("      form1_subheader:\n"));
        assert!(yaml.contains("  - path: L3DMUS/EGYPT1.SWP\n"));
        assert!(yaml.contains("    extent: 81861\n    length: 15140864\n"));
        let files = yaml.split_once("  files:\n").unwrap().1;
        assert!(!files.contains("L3DMUS/EGYPT1.SWP"));

        let rebuilt = project.path().join("rebuilt.bin");
        let build_report = build(&manifest, &rebuilt, project.path(), false).unwrap();
        assert_eq!(build_report.sectors, 81_711);
        assert_eq!(
            build_report.sha1,
            "f713cdcb5d0e3d875031dbdc438dbbab0cdd3340"
        );
        assert!(files_are_equal(&lemmings_reference_image(), &rebuilt));
    }

    #[test]
    fn authored_size_change_and_nested_addition_are_reextractable() {
        let project = tempfile::tempdir().unwrap();
        let manifest_path = project.path().join("project.yaml");
        extract(
            &reference_image(),
            &manifest_path,
            project.path(),
            false,
            false,
        )
        .unwrap();

        let main_path = project.path().join("MAIN.EXE");
        let mut changed_main = fs::read(&main_path).unwrap();
        changed_main.extend_from_slice(b"gcdgold edit");
        fs::write(&main_path, &changed_main).unwrap();
        fs::create_dir(project.path().join("EXTRA")).unwrap();
        fs::write(project.path().join("EXTRA/NEW.BIN"), b"new nested file").unwrap();

        let mut manifest: Manifest =
            yaml_serde::from_str(&fs::read_to_string(&manifest_path).unwrap()).unwrap();
        manifest.iso9660.entries.push(Entry {
            path: "EXTRA".to_owned(),
            recording_time: "1900-06-16T09:45:51+09:00".to_owned(),
            xa: None,
            extent: None,
            length: None,
        });
        manifest.iso9660.entries.push(Entry {
            path: "EXTRA/NEW.BIN".to_owned(),
            recording_time: "1998-03-19T11:58:36+09:00".to_owned(),
            xa: None,
            extent: None,
            length: None,
        });
        manifest
            .iso9660
            .files
            .push(FileLayoutItem::path("EXTRA/NEW.BIN"));
        fs::write(&manifest_path, yaml_serde::to_string(&manifest).unwrap()).unwrap();

        let authored = project.path().join("authored.bin");
        build(&manifest_path, &authored, project.path(), false).unwrap();
        assert_ne!(
            fs::read(&authored).unwrap(),
            fs::read(reference_image()).unwrap()
        );

        let verification = tempfile::tempdir().unwrap();
        let verification_manifest = verification.path().join("verify.yaml");
        extract(
            &authored,
            &verification_manifest,
            verification.path(),
            false,
            false,
        )
        .unwrap();
        assert_eq!(
            fs::read(verification.path().join("MAIN.EXE")).unwrap(),
            changed_main
        );
        assert_eq!(
            fs::read(verification.path().join("EXTRA/NEW.BIN")).unwrap(),
            b"new nested file"
        );
    }

    #[test]
    fn authored_tree_supports_empty_renamed_and_deleted_files() {
        let project = tempfile::tempdir().unwrap();
        let manifest_path = project.path().join("project.yaml");
        extract(
            &reference_image(),
            &manifest_path,
            project.path(),
            false,
            false,
        )
        .unwrap();
        fs::write(project.path().join("MAIN.EXE"), []).unwrap();
        fs::rename(
            project.path().join("SYSTEM.CNF"),
            project.path().join("CONFIG.CNF"),
        )
        .unwrap();

        let mut manifest: Manifest =
            yaml_serde::from_str(&fs::read_to_string(&manifest_path).unwrap()).unwrap();
        manifest
            .iso9660
            .entries
            .retain(|entry| entry.path != "DUMMY.BIN");
        manifest
            .iso9660
            .files
            .retain(|item| item.as_path() != Some("DUMMY.BIN"));
        manifest
            .iso9660
            .entries
            .iter_mut()
            .find(|entry| entry.path == "SYSTEM.CNF")
            .unwrap()
            .path = "CONFIG.CNF".to_owned();
        let renamed = manifest
            .iso9660
            .files
            .iter_mut()
            .find(|item| item.as_path() == Some("SYSTEM.CNF"))
            .unwrap();
        let FileLayoutItem::Path(path) = renamed else {
            unreachable!("matched path item")
        };
        path.path = "CONFIG.CNF".to_owned();
        fs::write(&manifest_path, yaml_serde::to_string(&manifest).unwrap()).unwrap();

        let authored = project.path().join("authored.bin");
        build(&manifest_path, &authored, project.path(), false).unwrap();
        let verification = tempfile::tempdir().unwrap();
        let verification_manifest = verification.path().join("verify.yaml");
        extract(
            &authored,
            &verification_manifest,
            verification.path(),
            false,
            false,
        )
        .unwrap();
        assert_eq!(fs::read(verification.path().join("MAIN.EXE")).unwrap(), []);
        assert!(verification.path().join("CONFIG.CNF").is_file());
        assert!(!verification.path().join("DUMMY.BIN").exists());
    }

    #[test]
    fn authored_filesystem_may_contain_no_files() {
        let project = tempfile::tempdir().unwrap();
        let manifest_path = project.path().join("project.yaml");
        extract(
            &reference_image(),
            &manifest_path,
            project.path(),
            false,
            false,
        )
        .unwrap();
        let mut manifest: Manifest =
            yaml_serde::from_str(&fs::read_to_string(&manifest_path).unwrap()).unwrap();
        manifest.iso9660.entries.retain(|entry| entry.path == ".");
        manifest.iso9660.files.clear();
        fs::write(&manifest_path, yaml_serde::to_string(&manifest).unwrap()).unwrap();

        let authored = project.path().join("empty.bin");
        build(&manifest_path, &authored, project.path(), false).unwrap();
        let verification = tempfile::tempdir().unwrap();
        extract(
            &authored,
            &verification.path().join("verify.yaml"),
            verification.path(),
            false,
            false,
        )
        .unwrap();
    }
}

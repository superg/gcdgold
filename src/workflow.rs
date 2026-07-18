use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result, ensure};
use sha1::{Digest, Sha1};

use crate::iso9660;
use crate::manifest::{
    EntryKind, FORMAT_VERSION, Form1Sectors, Form2Edc, Manifest, SourceInfo, SystemArea, Track,
};
use crate::raw_cd::{
    Kind, LOGICAL_BLOCK_SIZE, RAW_SECTOR_SIZE, SectorWriter, format_msf, parse_image, parse_msf,
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
    pub matches_source: bool,
}

pub fn extract(
    image_path: &Path,
    manifest_path: &Path,
    data_dir: &Path,
    manifest_only: bool,
) -> Result<ExtractReport> {
    ensure!(
        !manifest_path.exists(),
        "manifest output already exists: {}",
        manifest_path.display()
    );
    let image = fs::read(image_path)
        .with_context(|| format!("reading raw image {}", image_path.display()))?;
    let source_sha1 = sha1_hex(&image);
    let (start_frame, sectors) = parse_image(&image)?;
    ensure!(sectors.len() >= 23, "image is too small");

    let trailing_gap = sectors
        .iter()
        .rev()
        .take_while(|sector| sector.kind == Kind::XaGap)
        .count();
    let (system_bytes, form1_count, form2_start, form2_edc) = extract_system_area(&sectors[..16])?;
    let system_name = format!("{}.system", manifest_stem(manifest_path)?);
    let system_sha1 = sha1_hex(&system_bytes);

    let blocks = sectors
        .iter()
        .map(|sector| sector.logical_block().try_into())
        .collect::<Result<Vec<[u8; LOGICAL_BLOCK_SIZE]>, _>>()?;
    let mut parsed_iso = iso9660::parse(&blocks)?;
    let mut extracted_files = HashMap::new();
    for file in &parsed_iso.files {
        let data = read_extent(&blocks, file.extent, file.length)?;
        extracted_files.insert(file.path.clone(), data);
    }
    for entry in &mut parsed_iso.manifest.entries {
        if entry.kind == EntryKind::File {
            let data = &extracted_files[&entry.path];
            entry.source_sha1 = Some(sha1_hex(data));
            entry.source_length = Some(data.len() as u64);
        }
    }
    let first_file = parsed_iso
        .files
        .iter()
        .filter(|file| file.length != 0)
        .min_by_key(|file| file.extent)
        .map(|first_file| {
            let first_sector = usize::try_from(first_file.extent)?;
            ensure!(
                sectors[first_sector].kind == Kind::Form1,
                "first file does not use Form 1 sectors"
            );
            let end_sector =
                first_sector + usize::try_from(first_file.length)?.div_ceil(LOGICAL_BLOCK_SIZE) - 1;
            Ok::<_, anyhow::Error>((
                sectors[first_sector].subheader,
                sectors[end_sector].subheader[2],
            ))
        })
        .transpose()?
        .unwrap_or(([0, 0, 8, 0], 0x89));

    let manifest = Manifest {
        format_version: FORMAT_VERSION,
        source: SourceInfo {
            sha1: source_sha1.clone(),
            sectors: u32::try_from(sectors.len())?,
        },
        track: Track {
            mode: "mode2_xa".to_owned(),
            start_msf: format_msf(start_frame)?,
            raw_sector_size: RAW_SECTOR_SIZE as u16,
            trailing_gap_sectors: u32::try_from(trailing_gap)?,
            pvd_subheader: sectors[16].subheader,
            metadata_subheader: sectors[17].subheader,
            file_subheader: first_file.0,
            file_end_submode: first_file.1,
        },
        system_area: SystemArea {
            path: system_name.clone(),
            source_sha1: system_sha1,
            source_length: system_bytes.len() as u64,
            total_sectors: 16,
            form1_sectors: if system_bytes.len().div_ceil(LOGICAL_BLOCK_SIZE) == form1_count {
                Form1Sectors::Auto("auto".to_owned())
            } else {
                Form1Sectors::Count(u8::try_from(form1_count)?)
            },
            form1_subheader: sectors[0].subheader,
            form2_subheader: sectors[form2_start].subheader,
            form2_edc,
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

    if !manifest_only {
        fs::create_dir_all(data_dir)
            .with_context(|| format!("creating data directory {}", data_dir.display()))?;
        let system_path = safe_join(data_dir, &system_name)?;
        ensure!(
            !system_path.exists(),
            "system output already exists: {}",
            system_path.display()
        );
        for entry in &manifest.iso9660.entries {
            let output = safe_join(data_dir, &entry.path)?;
            ensure!(
                !output.exists(),
                "extraction output already exists: {}",
                output.display()
            );
        }
        for entry in &manifest.iso9660.entries {
            let output = safe_join(data_dir, &entry.path)?;
            match entry.kind {
                EntryKind::Directory => {
                    fs::create_dir(&output)
                        .with_context(|| format!("creating directory {}", output.display()))?;
                }
                EntryKind::File => {
                    if let Some(parent) = output.parent() {
                        fs::create_dir_all(parent)?;
                    }
                }
            }
        }
        fs::write(&system_path, &system_bytes)
            .with_context(|| format!("writing {}", system_path.display()))?;
        for (path, data) in extracted_files {
            let output = safe_join(data_dir, &path)?;
            fs::write(&output, data).with_context(|| format!("writing {}", output.display()))?;
        }
    }
    let yaml = yaml_serde::to_string(&manifest).context("serializing manifest")?;
    fs::write(manifest_path, yaml)
        .with_context(|| format!("writing manifest {}", manifest_path.display()))?;
    Ok(ExtractReport {
        sectors: manifest.source.sectors,
        sha1: source_sha1,
    })
}

fn extract_system_area(
    sectors: &[crate::raw_cd::ParsedSector],
) -> Result<(Vec<u8>, usize, usize, Form2Edc)> {
    ensure!(
        sectors.len() == 16,
        "system area must contain sixteen sectors"
    );
    let form2_start = sectors
        .iter()
        .position(|sector| sector.kind != Kind::Form1)
        .unwrap_or(16);
    ensure!(
        form2_start > 0 && form2_start < 16,
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
        .all(|sector| sector.bytes[2348..2352] != [0, 0, 0, 0]);
    let zeroed = sectors[form2_start..]
        .iter()
        .all(|sector| sector.bytes[2348..2352] == [0, 0, 0, 0]);
    ensure!(computed || zeroed, "mixed Form 2 EDC policy in system area");
    Ok((
        content,
        form2_start,
        form2_start,
        if computed {
            Form2Edc::Computed
        } else {
            Form2Edc::Zeroed
        },
    ))
}

pub fn build(manifest_path: &Path, image_path: &Path, data_dir: &Path) -> Result<BuildReport> {
    ensure!(
        !image_path.exists(),
        "image output already exists: {}",
        image_path.display()
    );
    let yaml = fs::read_to_string(manifest_path)
        .with_context(|| format!("reading manifest {}", manifest_path.display()))?;
    let manifest: Manifest = yaml_serde::from_str(&yaml).context("parsing manifest")?;
    ensure!(
        manifest.format_version == FORMAT_VERSION,
        "unsupported manifest version"
    );
    ensure!(manifest.track.mode == "mode2_xa", "unsupported track mode");
    ensure!(
        manifest.track.raw_sector_size == 2352,
        "unsupported raw sector size"
    );
    ensure!(
        manifest.system_area.total_sectors == 16,
        "ISO system area must contain sixteen sectors"
    );
    ensure!(
        manifest
            .iso9660
            .entries
            .iter()
            .all(|entry| entry.path != manifest.system_area.path),
        "system asset path collides with an ISO entry"
    );

    let system_path = safe_join(data_dir, &manifest.system_area.path)?;
    let system = fs::read(&system_path)
        .with_context(|| format!("reading system asset {}", system_path.display()))?;
    let form1_count = manifest
        .system_area
        .form1_sectors
        .resolve(system.len(), manifest.system_area.total_sectors)?;
    let mut file_data = HashMap::new();
    for entry in &manifest.iso9660.entries {
        if entry.kind == EntryKind::File {
            let path = safe_join(data_dir, &entry.path)?;
            let data = fs::read(&path)
                .with_context(|| format!("reading authored file {}", path.display()))?;
            file_data.insert(entry.path.clone(), data);
        }
    }
    let mut layout = iso9660::layout(
        &manifest.iso9660,
        &file_data,
        manifest.track.trailing_gap_sectors,
    )?;
    for placement in &layout.files {
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
    let mut writer = SectorWriter::new();
    let mut raw = Vec::with_capacity(usize::try_from(layout.volume_blocks)? * RAW_SECTOR_SIZE);
    let padded_system_len = usize::from(form1_count) * LOGICAL_BLOCK_SIZE;
    for index in 0..usize::from(manifest.system_area.total_sectors) {
        let frame = start_frame + u32::try_from(index)?;
        if index < usize::from(form1_count) {
            let mut payload = [0_u8; LOGICAL_BLOCK_SIZE];
            let start = index * LOGICAL_BLOCK_SIZE;
            let end = (start + LOGICAL_BLOCK_SIZE).min(system.len());
            if start < end {
                payload[..end - start].copy_from_slice(&system[start..end]);
            }
            raw.extend_from_slice(&writer.form1(
                frame,
                manifest.system_area.form1_subheader,
                &payload,
            )?);
        } else {
            raw.extend_from_slice(&writer.form2(
                frame,
                manifest.system_area.form2_subheader,
                &[0; 2324],
                matches!(manifest.system_area.form2_edc, Form2Edc::Computed),
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
            file_sector_info.insert(file.extent + block_index, block_index + 1 == file.blocks);
        }
    }
    for lba in 16..u32::try_from(layout.blocks.len())? {
        let mut subheader = if lba == 16 {
            manifest.track.pvd_subheader
        } else if file_sector_info.contains_key(&lba) {
            manifest.track.file_subheader
        } else {
            manifest.track.metadata_subheader
        };
        if file_sector_info.get(&lba) == Some(&true) {
            subheader[2] = manifest.track.file_end_submode;
        }
        raw.extend_from_slice(&writer.form1(
            start_frame + lba,
            subheader,
            &layout.blocks[usize::try_from(lba)?],
        )?);
    }
    for lba in u32::try_from(layout.blocks.len())?..layout.volume_blocks {
        raw.extend_from_slice(&writer.xa_gap(start_frame + lba, [0; 4])?);
    }

    let sha1 = sha1_hex(&raw);
    let temp_path = temporary_path(image_path)?;
    ensure!(
        !temp_path.exists(),
        "temporary output already exists: {}",
        temp_path.display()
    );
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp_path)
        .with_context(|| format!("creating temporary image {}", temp_path.display()))?;
    output.write_all(&raw)?;
    output.sync_all()?;
    drop(output);
    fs::rename(&temp_path, image_path)
        .with_context(|| format!("installing image {}", image_path.display()))?;
    Ok(BuildReport {
        sectors: layout.volume_blocks,
        matches_source: sha1 == manifest.source.sha1,
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

fn sha1_hex(bytes: &[u8]) -> String {
    hex::encode(Sha1::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::Entry;

    fn reference_image() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("data/Tyco R-C - Assault with a Battery (USA) (Demo).bin")
    }

    #[test]
    fn system_area_trims_only_trailing_zeroes() {
        let mut writer = SectorWriter::new();
        let mut raw = Vec::new();
        let mut first = [0_u8; 2048];
        first[0] = 7;
        for index in 0..12 {
            let data = if index == 0 { &first } else { &[0; 2048] };
            raw.extend_from_slice(&writer.form1(150 + index, [0, 0, 8, 0], data).unwrap());
        }
        for index in 12..16 {
            raw.extend_from_slice(
                &writer
                    .form2(150 + index, [0, 0, 0x20, 0], &[0; 2324], true)
                    .unwrap(),
            );
        }
        let (_, sectors) = parse_image(&raw).unwrap();
        let (system, form1, _, _) = extract_system_area(&sectors).unwrap();
        assert_eq!(system, vec![7]);
        assert_eq!(form1, 12);
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
        extract(&reference_image(), &manifest, project.path(), true).unwrap();
        assert!(manifest.is_file());
        assert!(!project.path().join("sample.system").exists());
        assert!(!project.path().join("MAIN.EXE").exists());
    }

    #[test]
    fn untouched_reference_round_trip_is_byte_identical() {
        let project = tempfile::tempdir().unwrap();
        let manifest = project.path().join("sample.yaml");
        extract(&reference_image(), &manifest, project.path(), false).unwrap();
        let system = fs::read(project.path().join("sample.system")).unwrap();
        assert_eq!(system.len(), 24_576);
        assert_eq!(
            sha1_hex(&system),
            "df9b3d7f3678ef11ecd606d4c820074381506668"
        );

        let rebuilt = project.path().join("rebuilt.bin");
        let report = build(&manifest, &rebuilt, project.path()).unwrap();
        assert!(report.matches_source);
        assert_eq!(report.sha1, "5b16aa056dee14eff92891c24ca7cf71d263077d");
        assert_eq!(
            fs::read(reference_image()).unwrap(),
            fs::read(rebuilt).unwrap()
        );
    }

    #[test]
    fn authored_size_change_and_nested_addition_are_reextractable() {
        let project = tempfile::tempdir().unwrap();
        let manifest_path = project.path().join("project.yaml");
        extract(&reference_image(), &manifest_path, project.path(), false).unwrap();

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
            kind: EntryKind::Directory,
            version: 1,
            recording_time_hex: None,
            flags: 0,
            file_unit_size: 0,
            interleave_gap_size: 0,
            volume_sequence_number: 1,
            system_use_hex: None,
            data_order: None,
            source_sha1: None,
            source_length: None,
        });
        manifest.iso9660.entries.push(Entry {
            path: "EXTRA/NEW.BIN".to_owned(),
            kind: EntryKind::File,
            version: 1,
            recording_time_hex: None,
            flags: 0,
            file_unit_size: 0,
            interleave_gap_size: 0,
            volume_sequence_number: 1,
            system_use_hex: None,
            data_order: None,
            source_sha1: None,
            source_length: None,
        });
        fs::write(&manifest_path, yaml_serde::to_string(&manifest).unwrap()).unwrap();

        let authored = project.path().join("authored.bin");
        let report = build(&manifest_path, &authored, project.path()).unwrap();
        assert!(!report.matches_source);

        let verification = tempfile::tempdir().unwrap();
        let verification_manifest = verification.path().join("verify.yaml");
        extract(
            &authored,
            &verification_manifest,
            verification.path(),
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
        extract(&reference_image(), &manifest_path, project.path(), false).unwrap();
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
            .entries
            .iter_mut()
            .find(|entry| entry.path == "SYSTEM.CNF")
            .unwrap()
            .path = "CONFIG.CNF".to_owned();
        fs::write(&manifest_path, yaml_serde::to_string(&manifest).unwrap()).unwrap();

        let authored = project.path().join("authored.bin");
        build(&manifest_path, &authored, project.path()).unwrap();
        let verification = tempfile::tempdir().unwrap();
        let verification_manifest = verification.path().join("verify.yaml");
        extract(
            &authored,
            &verification_manifest,
            verification.path(),
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
        extract(&reference_image(), &manifest_path, project.path(), false).unwrap();
        let mut manifest: Manifest =
            yaml_serde::from_str(&fs::read_to_string(&manifest_path).unwrap()).unwrap();
        manifest
            .iso9660
            .entries
            .retain(|entry| entry.kind == EntryKind::Directory);
        fs::write(&manifest_path, yaml_serde::to_string(&manifest).unwrap()).unwrap();

        let authored = project.path().join("empty.bin");
        build(&manifest_path, &authored, project.path()).unwrap();
        let verification = tempfile::tempdir().unwrap();
        extract(
            &authored,
            &verification.path().join("verify.yaml"),
            verification.path(),
            false,
        )
        .unwrap();
    }
}

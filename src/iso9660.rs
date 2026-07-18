use std::collections::{HashMap, HashSet, VecDeque};

use anyhow::{Context, Result, ensure};

use crate::manifest::{Entry, Iso9660, PrimaryVolume};
use crate::raw_cd::LOGICAL_BLOCK_SIZE;

const VOLUME_SET_SIZE: u16 = 1;
const VOLUME_SEQUENCE_NUMBER: u16 = 1;
const ISO_LOGICAL_BLOCK_SIZE: u16 = 2048;
const FILE_STRUCTURE_VERSION: u8 = 1;
const FILE_VERSION: u8 = 1;
const DIRECTORY_FLAG: u8 = 2;
const FILE_SYSTEM_USE: [u8; 14] = [0, 0, 0, 0, 0x0d, 0x55, b'X', b'A', 0, 0, 0, 0, 0, 0];
const DIRECTORY_SYSTEM_USE: [u8; 14] = [0, 0, 0, 0, 0x8d, 0x55, b'X', b'A', 0, 0, 0, 0, 0, 0];
const APPLICATION_USE_START: usize = 883;
const APPLICATION_USE_END: usize = 1395;
const CD_XA_SIGNATURE_OFFSET: usize = 1024 - APPLICATION_USE_START;
pub const ROOT_PATH: &str = ".";

#[derive(Debug, Clone)]
pub struct ParsedFile {
    pub path: String,
    pub extent: u32,
    pub length: u32,
}

#[derive(Debug, Clone)]
pub struct ParsedIso {
    pub manifest: Iso9660,
    pub files: Vec<ParsedFile>,
}

#[derive(Debug, Clone)]
struct Record {
    extent: u32,
    length: u32,
    recording_time: [u8; 7],
    flags: u8,
    file_unit_size: u8,
    interleave_gap_size: u8,
    volume_sequence_number: u16,
    name: Vec<u8>,
    system_use: Vec<u8>,
}

pub fn parse(blocks: &[[u8; LOGICAL_BLOCK_SIZE]]) -> Result<ParsedIso> {
    ensure!(blocks.len() > 22, "image is too small for ISO 9660");
    let pvd_block = &blocks[16];
    ensure!(
        &pvd_block[0..7] == b"\x01CD001\x01",
        "missing supported PVD at LBA 16"
    );
    ensure!(
        &blocks[17][0..7] == b"\xffCD001\x01",
        "expected volume terminator at LBA 17"
    );
    let pvd = parse_pvd(pvd_block)?;
    let root_record = parse_record(&pvd_block[156..])?;
    validate_standard_record_fields(&root_record, true, false)?;
    let root_records = read_directory(blocks, root_record.extent, root_record.length)?;
    ensure!(root_records.len() >= 2, "root directory lacks dot records");
    let dot = &root_records[0];
    let root = Entry {
        path: ROOT_PATH.to_owned(),
        recording_time: parse_recording_time(dot.recording_time)?,
    };

    let mut entries = vec![root];
    let mut files = Vec::new();
    let mut queue = VecDeque::from([(String::new(), root_record.extent, root_record.length)]);
    let mut seen_dirs = HashSet::new();
    while let Some((parent, extent, length)) = queue.pop_front() {
        ensure!(
            seen_dirs.insert(extent),
            "directory extent cycle at LBA {extent}"
        );
        let records = read_directory(blocks, extent, length)?;
        ensure!(records.len() >= 2, "directory lacks dot records");
        for record in &records {
            validate_standard_record_fields(record, record.flags & DIRECTORY_FLAG != 0, true)?;
        }
        for record in records.into_iter().skip(2) {
            let raw_name =
                String::from_utf8(record.name.clone()).context("non-ASCII ISO identifier")?;
            let is_dir = record.flags & DIRECTORY_FLAG != 0;
            let name = if is_dir {
                raw_name
            } else {
                let (name, version) = raw_name
                    .rsplit_once(';')
                    .context("file identifier has no version")?;
                ensure!(
                    version.parse::<u8>().context("invalid file version")? == FILE_VERSION,
                    "unsupported file version"
                );
                name.to_owned()
            };
            let path = if parent.is_empty() {
                name
            } else {
                format!("{parent}/{name}")
            };
            let entry = Entry {
                path: path.clone(),
                recording_time: parse_recording_time(record.recording_time)?,
            };
            entries.push(entry);
            if is_dir {
                queue.push_back((path, record.extent, record.length));
            } else {
                files.push(ParsedFile {
                    path,
                    extent: record.extent,
                    length: record.length,
                });
            }
        }
    }

    let mut ordered = files.clone();
    ordered.sort_by_key(|file| file.extent);
    let file_order = ordered.iter().map(|file| file.path.clone()).collect();

    Ok(ParsedIso {
        manifest: Iso9660 {
            primary_volume: pvd,
            entries,
            files: file_order,
        },
        files,
    })
}

fn parse_pvd(block: &[u8; LOGICAL_BLOCK_SIZE]) -> Result<PrimaryVolume> {
    ensure!(read_both_u32(block, 80)? > 0, "invalid volume size");
    ensure!(
        read_both_u16(block, 120)? == VOLUME_SET_SIZE,
        "unsupported volume set size"
    );
    ensure!(
        read_both_u16(block, 124)? == VOLUME_SEQUENCE_NUMBER,
        "unsupported volume sequence number"
    );
    ensure!(
        read_both_u16(block, 128)? == ISO_LOGICAL_BLOCK_SIZE,
        "unsupported logical block size"
    );
    ensure!(
        block[881] == FILE_STRUCTURE_VERSION,
        "unsupported file structure version"
    );
    ensure!(
        block[APPLICATION_USE_START..APPLICATION_USE_END] == standard_cd_xa_application_use(),
        "unsupported PVD CD-XA application-use data"
    );
    Ok(PrimaryVolume {
        system_identifier: read_fixed(block, 8, 32)?,
        volume_identifier: read_fixed(block, 40, 32)?,
        volume_set_identifier: read_fixed(block, 190, 128)?,
        publisher_identifier: read_fixed(block, 318, 128)?,
        data_preparer_identifier: read_fixed(block, 446, 128)?,
        application_identifier: read_fixed(block, 574, 128)?,
        copyright_file_identifier: read_fixed(block, 702, 37)?,
        abstract_file_identifier: read_fixed(block, 739, 37)?,
        bibliographic_file_identifier: read_fixed(block, 776, 37)?,
        creation_time: parse_volume_time(&block[813..830]).context("invalid PVD creation time")?,
        modification_time: parse_volume_time(&block[830..847])
            .context("invalid PVD modification time")?,
        expiration_time: parse_volume_time(&block[847..864])
            .context("invalid PVD expiration time")?,
        effective_time: parse_volume_time(&block[864..881])
            .context("invalid PVD effective time")?,
    })
}

fn standard_cd_xa_application_use() -> [u8; APPLICATION_USE_END - APPLICATION_USE_START] {
    let mut data = [0; APPLICATION_USE_END - APPLICATION_USE_START];
    data[CD_XA_SIGNATURE_OFFSET..CD_XA_SIGNATURE_OFFSET + 8].copy_from_slice(b"CD-XA001");
    data
}

fn read_directory(
    blocks: &[[u8; LOGICAL_BLOCK_SIZE]],
    extent: u32,
    length: u32,
) -> Result<Vec<Record>> {
    let start = usize::try_from(extent)?;
    let count = usize::try_from(length)?.div_ceil(LOGICAL_BLOCK_SIZE);
    ensure!(
        start + count <= blocks.len(),
        "directory extent is outside image"
    );
    let mut bytes = Vec::with_capacity(count * LOGICAL_BLOCK_SIZE);
    for block in &blocks[start..start + count] {
        bytes.extend_from_slice(block);
    }
    bytes.truncate(usize::try_from(length)?);
    let mut records = Vec::new();
    let mut offset = 0;
    while offset < bytes.len() {
        let length = usize::from(bytes[offset]);
        if length == 0 {
            offset = (offset / LOGICAL_BLOCK_SIZE + 1) * LOGICAL_BLOCK_SIZE;
            continue;
        }
        ensure!(offset + length <= bytes.len(), "truncated directory record");
        records.push(parse_record(&bytes[offset..offset + length])?);
        offset += length;
    }
    Ok(records)
}

fn parse_record(bytes: &[u8]) -> Result<Record> {
    ensure!(bytes.len() >= 34, "short directory record");
    let record_length = usize::from(bytes[0]);
    ensure!(
        record_length >= 34 && record_length <= bytes.len(),
        "invalid directory record length"
    );
    let name_length = usize::from(bytes[32]);
    ensure!(
        33 + name_length <= record_length,
        "invalid identifier length"
    );
    let system_use_start = 33 + name_length + usize::from(name_length.is_multiple_of(2));
    ensure!(
        system_use_start <= record_length,
        "invalid directory record padding"
    );
    Ok(Record {
        extent: read_both_u32(bytes, 2)?,
        length: read_both_u32(bytes, 10)?,
        recording_time: bytes[18..25].try_into()?,
        flags: bytes[25],
        file_unit_size: bytes[26],
        interleave_gap_size: bytes[27],
        volume_sequence_number: read_both_u16(bytes, 28)?,
        name: bytes[33..33 + name_length].to_vec(),
        system_use: bytes[system_use_start..record_length].to_vec(),
    })
}

fn validate_standard_record_fields(
    record: &Record,
    directory: bool,
    uses_xa_system_use: bool,
) -> Result<()> {
    let expected_flags = if directory { DIRECTORY_FLAG } else { 0 };
    ensure!(
        record.flags == expected_flags,
        "unsupported directory-record flags"
    );
    ensure!(
        record.file_unit_size == 0,
        "unsupported directory-record file unit size"
    );
    ensure!(
        record.interleave_gap_size == 0,
        "unsupported directory-record interleave gap size"
    );
    ensure!(
        record.volume_sequence_number == VOLUME_SEQUENCE_NUMBER,
        "unsupported directory-record volume sequence number"
    );
    let expected_system_use: &[u8] = if uses_xa_system_use {
        standard_system_use(directory)
    } else {
        &[]
    };
    ensure!(
        record.system_use == expected_system_use,
        "unsupported directory-record XA system-use data"
    );
    Ok(())
}

fn standard_system_use(directory: bool) -> &'static [u8; 14] {
    if directory {
        &DIRECTORY_SYSTEM_USE
    } else {
        &FILE_SYSTEM_USE
    }
}

#[derive(Debug, Clone)]
pub struct FilePlacement {
    pub path: String,
    pub extent: u32,
    pub length: u64,
    pub blocks: u32,
}

#[derive(Debug, Clone)]
pub struct Layout {
    pub blocks: Vec<[u8; LOGICAL_BLOCK_SIZE]>,
    pub files: Vec<FilePlacement>,
    pub volume_blocks: u32,
}

pub fn validate(iso: &Iso9660) -> Result<()> {
    validate_entries(iso).map(drop)
}

#[derive(Debug, Clone)]
struct DirectoryPlacement {
    path: String,
    name: String,
    parent: usize,
    extent: u32,
    blocks: u32,
}

pub fn layout(
    iso: &Iso9660,
    file_data: &HashMap<String, Vec<u8>>,
    trailing: u32,
) -> Result<Layout> {
    let file_paths = validate_entries(iso)?;
    let directories = directory_order(&iso.entries, &file_paths)?;
    let path_table_size: usize = directories
        .iter()
        .map(|(_, name, _)| 8 + name.len() + usize::from(name.len() % 2 == 1))
        .sum();
    let path_blocks = path_table_size.div_ceil(LOGICAL_BLOCK_SIZE).max(1) as u32;
    let mut next_extent = 18 + path_blocks * 4;

    let entry_by_path: HashMap<_, _> = iso
        .entries
        .iter()
        .map(|entry| (entry.path.as_str(), entry))
        .collect();
    let mut placements = Vec::with_capacity(directories.len());
    for (path, name, parent) in &directories {
        let record_lengths = directory_record_lengths(path, iso, &file_paths);
        let blocks = packed_blocks(&record_lengths) as u32;
        placements.push(DirectoryPlacement {
            path: path.clone(),
            name: name.clone(),
            parent: *parent,
            extent: next_extent,
            blocks,
        });
        next_extent += blocks;
    }

    let mut files = Vec::with_capacity(iso.files.len());
    for path in &iso.files {
        let entry = entry_by_path[path.as_str()];
        let data = file_data
            .get(path)
            .with_context(|| format!("missing file data for {}", entry.path))?;
        let blocks = u32::try_from(data.len().div_ceil(LOGICAL_BLOCK_SIZE))?;
        files.push(FilePlacement {
            path: entry.path.clone(),
            extent: next_extent,
            length: data.len() as u64,
            blocks,
        });
        next_extent += blocks;
    }
    let volume_blocks = next_extent
        .checked_add(trailing)
        .context("volume size overflow")?;
    let placement_by_path: HashMap<_, _> = files
        .iter()
        .map(|file| (file.path.as_str(), file))
        .collect();
    let directory_by_path: HashMap<_, _> = placements
        .iter()
        .map(|dir| (dir.path.as_str(), dir))
        .collect();

    let mut blocks = vec![[0_u8; LOGICAL_BLOCK_SIZE]; usize::try_from(next_extent)?];
    let pointers = [
        18,
        18 + path_blocks,
        18 + path_blocks * 2,
        18 + path_blocks * 3,
    ];
    blocks[16] = serialize_pvd(
        iso,
        volume_blocks,
        path_table_size as u32,
        pointers,
        placements[0].extent,
        placements[0].blocks * 2048,
        entry_by_path[ROOT_PATH],
    )?;
    blocks[17][0..7].copy_from_slice(b"\xffCD001\x01");
    write_path_tables(&mut blocks, &placements, pointers, path_blocks)?;
    for directory in &placements {
        let data = serialize_directory(
            directory,
            &placements,
            iso,
            &entry_by_path,
            &directory_by_path,
            &placement_by_path,
            &file_paths,
        )?;
        for (index, chunk) in data.chunks_exact(LOGICAL_BLOCK_SIZE).enumerate() {
            blocks[usize::try_from(directory.extent)? + index].copy_from_slice(chunk);
        }
    }
    Ok(Layout {
        blocks,
        files,
        volume_blocks,
    })
}

fn validate_entries(iso: &Iso9660) -> Result<HashSet<&str>> {
    let root = iso
        .entries
        .first()
        .context("filesystem root must be the first entry")?;
    ensure!(
        root.path == ROOT_PATH,
        "filesystem root must be the first entry with path ."
    );
    let mut paths = HashSet::new();
    for entry in &iso.entries {
        ensure!(
            paths.insert(entry.path.as_str()),
            "duplicate ISO path {}",
            entry.path
        );
    }
    let mut file_paths = HashSet::new();
    for path in &iso.files {
        ensure!(path != ROOT_PATH, "filesystem root cannot be a file");
        ensure!(paths.contains(path.as_str()), "unknown file entry {path}");
        ensure!(
            file_paths.insert(path.as_str()),
            "duplicate file entry {path}"
        );
    }
    let directory_paths: HashSet<_> = paths.difference(&file_paths).copied().collect();
    for (index, entry) in iso.entries.iter().enumerate() {
        let is_file = file_paths.contains(entry.path.as_str());
        if index != 0 {
            validate_path(&entry.path, is_file)?;
            let parent = parent_path(&entry.path);
            ensure!(
                directory_paths.contains(parent.as_str()),
                "missing parent directory {parent}"
            );
        }
    }
    Ok(file_paths)
}

fn validate_path(path: &str, is_file: bool) -> Result<()> {
    ensure!(
        !path.is_empty() && !path.starts_with('/') && !path.ends_with('/'),
        "invalid relative ISO path"
    );
    let parts = path.split('/').collect::<Vec<_>>();
    for (index, part) in parts.iter().enumerate() {
        ensure!(*part != "." && *part != "..", "path traversal is forbidden");
        let file_component = is_file && index + 1 == parts.len();
        if file_component {
            let (stem, extension) = part.rsplit_once('.').unwrap_or((part, ""));
            ensure!(
                !stem.is_empty() && stem.len() <= 8 && extension.len() <= 3,
                "file name is not ISO Level 1: {part}"
            );
            ensure!(
                valid_d_chars(stem) && valid_d_chars(extension),
                "invalid ISO file characters: {part}"
            );
        } else {
            ensure!(
                part.len() <= 8 && valid_d_chars(part),
                "directory name is not ISO Level 1: {part}"
            );
        }
    }
    Ok(())
}

fn valid_d_chars(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
}

fn directory_order(
    entries: &[Entry],
    file_paths: &HashSet<&str>,
) -> Result<Vec<(String, String, usize)>> {
    let mut result = vec![(ROOT_PATH.to_owned(), String::from("\0"), 0)];
    let mut queue = VecDeque::from([ROOT_PATH.to_owned()]);
    while let Some(parent) = queue.pop_front() {
        let parent_index = result
            .iter()
            .position(|(path, _, _)| path == &parent)
            .context("missing directory parent")?;
        for entry in entries.iter().filter(|entry| {
            entry.path != ROOT_PATH
                && !file_paths.contains(entry.path.as_str())
                && parent_path(&entry.path) == parent
        }) {
            let name = file_name(&entry.path).to_owned();
            result.push((entry.path.clone(), name, parent_index));
            queue.push_back(entry.path.clone());
        }
    }
    let expected = entries
        .iter()
        .filter(|entry| !file_paths.contains(entry.path.as_str()))
        .count();
    ensure!(
        result.len() == expected,
        "unreachable directory in manifest"
    );
    Ok(result)
}

fn directory_record_lengths(path: &str, iso: &Iso9660, file_paths: &HashSet<&str>) -> Vec<usize> {
    let mut lengths = vec![
        record_size(1, DIRECTORY_SYSTEM_USE.len()),
        record_size(1, DIRECTORY_SYSTEM_USE.len()),
    ];
    for entry in iso
        .entries
        .iter()
        .filter(|entry| entry.path != ROOT_PATH && parent_path(&entry.path) == path)
    {
        let name = identifier(entry, file_paths.contains(entry.path.as_str()));
        lengths.push(record_size(name.len(), FILE_SYSTEM_USE.len()));
    }
    lengths
}

fn packed_blocks(lengths: &[usize]) -> usize {
    let mut offset = 0;
    for length in lengths {
        let in_block = offset % LOGICAL_BLOCK_SIZE;
        if in_block + length > LOGICAL_BLOCK_SIZE {
            offset += LOGICAL_BLOCK_SIZE - in_block;
        }
        offset += length;
    }
    offset.div_ceil(LOGICAL_BLOCK_SIZE).max(1)
}

fn record_size(name_length: usize, system_use_length: usize) -> usize {
    33 + name_length + usize::from(name_length.is_multiple_of(2)) + system_use_length
}

fn serialize_pvd(
    iso: &Iso9660,
    volume_blocks: u32,
    path_table_size: u32,
    pointers: [u32; 4],
    root_extent: u32,
    root_length: u32,
    root: &Entry,
) -> Result<[u8; LOGICAL_BLOCK_SIZE]> {
    let pvd = &iso.primary_volume;
    let mut block = [0_u8; LOGICAL_BLOCK_SIZE];
    block[0..7].copy_from_slice(b"\x01CD001\x01");
    write_fixed(&mut block, 8, 32, &pvd.system_identifier)?;
    write_fixed(&mut block, 40, 32, &pvd.volume_identifier)?;
    write_both_u32(&mut block, 80, volume_blocks);
    write_both_u16(&mut block, 120, VOLUME_SET_SIZE);
    write_both_u16(&mut block, 124, VOLUME_SEQUENCE_NUMBER);
    write_both_u16(&mut block, 128, ISO_LOGICAL_BLOCK_SIZE);
    write_both_u32(&mut block, 132, path_table_size);
    block[140..144].copy_from_slice(&pointers[0].to_le_bytes());
    block[144..148].copy_from_slice(&pointers[1].to_le_bytes());
    block[148..152].copy_from_slice(&pointers[2].to_be_bytes());
    block[152..156].copy_from_slice(&pointers[3].to_be_bytes());
    let root_record = serialize_record(&Record {
        extent: root_extent,
        length: root_length,
        recording_time: serialize_recording_time(&root.recording_time)?,
        flags: DIRECTORY_FLAG,
        file_unit_size: 0,
        interleave_gap_size: 0,
        volume_sequence_number: VOLUME_SEQUENCE_NUMBER,
        name: vec![0],
        system_use: Vec::new(),
    })?;
    ensure!(root_record.len() == 34, "PVD root record must be 34 bytes");
    block[156..190].copy_from_slice(&root_record);
    write_fixed(&mut block, 190, 128, &pvd.volume_set_identifier)?;
    write_fixed(&mut block, 318, 128, &pvd.publisher_identifier)?;
    write_fixed(&mut block, 446, 128, &pvd.data_preparer_identifier)?;
    write_fixed(&mut block, 574, 128, &pvd.application_identifier)?;
    write_fixed(&mut block, 702, 37, &pvd.copyright_file_identifier)?;
    write_fixed(&mut block, 739, 37, &pvd.abstract_file_identifier)?;
    write_fixed(&mut block, 776, 37, &pvd.bibliographic_file_identifier)?;
    block[813..830].copy_from_slice(&serialize_volume_time(pvd.creation_time.as_deref())?);
    block[830..847].copy_from_slice(&serialize_volume_time(pvd.modification_time.as_deref())?);
    block[847..864].copy_from_slice(&serialize_volume_time(pvd.expiration_time.as_deref())?);
    block[864..881].copy_from_slice(&serialize_volume_time(pvd.effective_time.as_deref())?);
    block[881] = FILE_STRUCTURE_VERSION;
    block[APPLICATION_USE_START..APPLICATION_USE_END]
        .copy_from_slice(&standard_cd_xa_application_use());
    Ok(block)
}

fn write_path_tables(
    blocks: &mut [[u8; LOGICAL_BLOCK_SIZE]],
    directories: &[DirectoryPlacement],
    pointers: [u32; 4],
    path_blocks: u32,
) -> Result<()> {
    let little = serialize_path_table(directories, false)?;
    let big = serialize_path_table(directories, true)?;
    for (pointer, bytes) in [
        (pointers[0], &little),
        (pointers[1], &little),
        (pointers[2], &big),
        (pointers[3], &big),
    ] {
        for index in 0..usize::try_from(path_blocks)? {
            let start = index * LOGICAL_BLOCK_SIZE;
            let end = (start + LOGICAL_BLOCK_SIZE).min(bytes.len());
            if start < end {
                blocks[usize::try_from(pointer)? + index][..end - start]
                    .copy_from_slice(&bytes[start..end]);
            }
        }
    }
    Ok(())
}

fn serialize_path_table(directories: &[DirectoryPlacement], big: bool) -> Result<Vec<u8>> {
    let mut result = Vec::new();
    for directory in directories {
        let name = directory.name.as_bytes();
        result.push(u8::try_from(name.len())?);
        result.push(0);
        if big {
            result.extend_from_slice(&directory.extent.to_be_bytes());
            result.extend_from_slice(&u16::try_from(directory.parent + 1)?.to_be_bytes());
        } else {
            result.extend_from_slice(&directory.extent.to_le_bytes());
            result.extend_from_slice(&u16::try_from(directory.parent + 1)?.to_le_bytes());
        }
        result.extend_from_slice(name);
        if name.len() % 2 == 1 {
            result.push(0);
        }
    }
    Ok(result)
}

fn serialize_directory(
    directory: &DirectoryPlacement,
    directories: &[DirectoryPlacement],
    iso: &Iso9660,
    entry_by_path: &HashMap<&str, &Entry>,
    directory_by_path: &HashMap<&str, &DirectoryPlacement>,
    file_by_path: &HashMap<&str, &FilePlacement>,
    file_paths: &HashSet<&str>,
) -> Result<Vec<u8>> {
    let metadata = entry_by_path[directory.path.as_str()];
    let parent = &directories[directory.parent];
    let parent_entry = entry_by_path[parent.path.as_str()];
    let mut records = Vec::new();
    records.push(make_record(
        metadata,
        directory.extent,
        directory.blocks * 2048,
        vec![0],
        true,
    )?);
    records.push(make_record(
        parent_entry,
        parent.extent,
        parent.blocks * 2048,
        vec![1],
        true,
    )?);
    for entry in iso
        .entries
        .iter()
        .filter(|entry| entry.path != ROOT_PATH && parent_path(&entry.path) == directory.path)
    {
        let is_file = file_paths.contains(entry.path.as_str());
        let (extent, length) = if is_file {
            let file = file_by_path[entry.path.as_str()];
            (file.extent, u32::try_from(file.length)?)
        } else {
            let child = directory_by_path[entry.path.as_str()];
            (child.extent, child.blocks * 2048)
        };
        records.push(make_record(
            entry,
            extent,
            length,
            identifier(entry, is_file).into_bytes(),
            !is_file,
        )?);
    }
    let mut result = vec![0_u8; usize::try_from(directory.blocks)? * LOGICAL_BLOCK_SIZE];
    let mut offset = 0;
    for record in records {
        let in_block = offset % LOGICAL_BLOCK_SIZE;
        if in_block + record.len() > LOGICAL_BLOCK_SIZE {
            offset += LOGICAL_BLOCK_SIZE - in_block;
        }
        result[offset..offset + record.len()].copy_from_slice(&record);
        offset += record.len();
    }
    Ok(result)
}

fn make_record(
    entry: &Entry,
    extent: u32,
    length: u32,
    name: Vec<u8>,
    directory: bool,
) -> Result<Vec<u8>> {
    serialize_record(&Record {
        extent,
        length,
        recording_time: serialize_recording_time(&entry.recording_time)?,
        flags: if directory { DIRECTORY_FLAG } else { 0 },
        file_unit_size: 0,
        interleave_gap_size: 0,
        volume_sequence_number: VOLUME_SEQUENCE_NUMBER,
        name,
        system_use: standard_system_use(directory).to_vec(),
    })
}

fn serialize_record(record: &Record) -> Result<Vec<u8>> {
    let length = record_size(record.name.len(), record.system_use.len());
    ensure!(length <= u8::MAX as usize, "directory record is too long");
    let mut bytes = vec![0_u8; length];
    bytes[0] = length as u8;
    write_both_u32(&mut bytes, 2, record.extent);
    write_both_u32(&mut bytes, 10, record.length);
    bytes[18..25].copy_from_slice(&record.recording_time);
    bytes[25] = record.flags;
    bytes[26] = record.file_unit_size;
    bytes[27] = record.interleave_gap_size;
    write_both_u16(&mut bytes, 28, record.volume_sequence_number);
    bytes[32] = u8::try_from(record.name.len())?;
    bytes[33..33 + record.name.len()].copy_from_slice(&record.name);
    let system_use_start =
        33 + record.name.len() + usize::from(record.name.len().is_multiple_of(2));
    bytes[system_use_start..].copy_from_slice(&record.system_use);
    Ok(bytes)
}

fn identifier(entry: &Entry, is_file: bool) -> String {
    let name = file_name(&entry.path);
    if is_file {
        format!("{name};{FILE_VERSION}")
    } else {
        name.to_owned()
    }
}

fn parent_path(path: &str) -> String {
    if path == ROOT_PATH {
        ROOT_PATH.to_owned()
    } else {
        path.rsplit_once('/')
            .map_or_else(|| ROOT_PATH.to_owned(), |(parent, _)| parent.to_owned())
    }
}

fn file_name(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

fn read_fixed(bytes: &[u8], offset: usize, length: usize) -> Result<String> {
    let value = String::from_utf8(bytes[offset..offset + length].to_vec())?;
    Ok(value.trim_end_matches([' ', '\0']).to_owned())
}

fn write_fixed(bytes: &mut [u8], offset: usize, length: usize, value: &str) -> Result<()> {
    ensure!(
        value.is_ascii() && value.len() <= length,
        "fixed ISO string is too long or non-ASCII"
    );
    bytes[offset..offset + length].fill(b' ');
    bytes[offset..offset + value.len()].copy_from_slice(value.as_bytes());
    Ok(())
}

fn read_both_u16(bytes: &[u8], offset: usize) -> Result<u16> {
    let le = u16::from_le_bytes(bytes[offset..offset + 2].try_into()?);
    let be = u16::from_be_bytes(bytes[offset + 2..offset + 4].try_into()?);
    ensure!(le == be, "mismatched both-endian u16 at offset {offset}");
    Ok(le)
}

fn read_both_u32(bytes: &[u8], offset: usize) -> Result<u32> {
    let le = u32::from_le_bytes(bytes[offset..offset + 4].try_into()?);
    let be = u32::from_be_bytes(bytes[offset + 4..offset + 8].try_into()?);
    ensure!(le == be, "mismatched both-endian u32 at offset {offset}");
    Ok(le)
}

fn write_both_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    bytes[offset + 2..offset + 4].copy_from_slice(&value.to_be_bytes());
}

fn write_both_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    bytes[offset + 4..offset + 8].copy_from_slice(&value.to_be_bytes());
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct VolumeTime {
    year: u16,
    month: u8,
    day: u8,
    hour: u8,
    minute: u8,
    second: u8,
    centisecond: u8,
    offset_quarters: i8,
}

fn parse_recording_time(bytes: [u8; 7]) -> Result<String> {
    let time = VolumeTime {
        year: 1900 + u16::from(bytes[0]),
        month: bytes[1],
        day: bytes[2],
        hour: bytes[3],
        minute: bytes[4],
        second: bytes[5],
        centisecond: 0,
        offset_quarters: i8::from_ne_bytes([bytes[6]]),
    };
    validate_volume_time(time).context("invalid directory recording time")?;
    Ok(format_recording_time(time))
}

fn serialize_recording_time(value: &str) -> Result<[u8; 7]> {
    ensure!(
        value.is_ascii() && value.len() == 25 && matches!(value.as_bytes()[19], b'+' | b'-'),
        "recording time must use YYYY-MM-DDTHH:MM:SS+HH:MM"
    );
    let expanded = format!("{}.00{}", &value[..19], &value[19..]);
    let time = parse_human_volume_time(&expanded).context("invalid directory recording time")?;
    ensure!(
        (1900..=2155).contains(&time.year),
        "directory recording time year must be between 1900 and 2155"
    );
    Ok([
        u8::try_from(time.year - 1900)?,
        time.month,
        time.day,
        time.hour,
        time.minute,
        time.second,
        time.offset_quarters.to_ne_bytes()[0],
    ])
}

fn format_recording_time(time: VolumeTime) -> String {
    let offset_minutes = i16::from(time.offset_quarters) * 15;
    let sign = if offset_minutes < 0 { '-' } else { '+' };
    let absolute_offset = offset_minutes.unsigned_abs();
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}{sign}{:02}:{:02}",
        time.year,
        time.month,
        time.day,
        time.hour,
        time.minute,
        time.second,
        absolute_offset / 60,
        absolute_offset % 60
    )
}

fn parse_volume_time(bytes: &[u8]) -> Result<Option<String>> {
    ensure!(
        bytes.len() == 17,
        "volume time must contain seventeen bytes"
    );
    if &bytes[..16] == b"0000000000000000" && bytes[16] == 0 {
        return Ok(None);
    }
    ensure!(
        bytes[..16].iter().all(u8::is_ascii_digit),
        "volume time contains non-digit date bytes"
    );
    let time = VolumeTime {
        year: parse_decimal(&bytes[0..4])?,
        month: u8::try_from(parse_decimal(&bytes[4..6])?)?,
        day: u8::try_from(parse_decimal(&bytes[6..8])?)?,
        hour: u8::try_from(parse_decimal(&bytes[8..10])?)?,
        minute: u8::try_from(parse_decimal(&bytes[10..12])?)?,
        second: u8::try_from(parse_decimal(&bytes[12..14])?)?,
        centisecond: u8::try_from(parse_decimal(&bytes[14..16])?)?,
        offset_quarters: i8::from_ne_bytes([bytes[16]]),
    };
    validate_volume_time(time)?;
    Ok(Some(format_volume_time(time)))
}

fn serialize_volume_time(value: Option<&str>) -> Result<[u8; 17]> {
    let Some(value) = value else {
        let mut bytes = [b'0'; 17];
        bytes[16] = 0;
        return Ok(bytes);
    };
    let time = parse_human_volume_time(value)?;
    let digits = format!(
        "{:04}{:02}{:02}{:02}{:02}{:02}{:02}",
        time.year, time.month, time.day, time.hour, time.minute, time.second, time.centisecond
    );
    let mut bytes = [0_u8; 17];
    bytes[..16].copy_from_slice(digits.as_bytes());
    bytes[16] = time.offset_quarters.to_ne_bytes()[0];
    Ok(bytes)
}

fn parse_human_volume_time(value: &str) -> Result<VolumeTime> {
    let bytes = value.as_bytes();
    ensure!(
        bytes.len() == 28
            && bytes[4] == b'-'
            && bytes[7] == b'-'
            && bytes[10] == b'T'
            && bytes[13] == b':'
            && bytes[16] == b':'
            && bytes[19] == b'.'
            && matches!(bytes[22], b'+' | b'-')
            && bytes[25] == b':',
        "volume time must use YYYY-MM-DDTHH:MM:SS.cc+HH:MM"
    );
    for range in [
        0..4,
        5..7,
        8..10,
        11..13,
        14..16,
        17..19,
        20..22,
        23..25,
        26..28,
    ] {
        ensure!(
            bytes[range].iter().all(u8::is_ascii_digit),
            "volume time contains a non-digit component"
        );
    }
    let offset_hours = parse_decimal(&bytes[23..25])?;
    let offset_minutes = parse_decimal(&bytes[26..28])?;
    ensure!(offset_minutes < 60, "invalid volume time offset minutes");
    let absolute_offset = offset_hours * 60 + offset_minutes;
    ensure!(
        absolute_offset.is_multiple_of(15),
        "volume time offset must use fifteen-minute increments"
    );
    ensure!(
        !(bytes[22] == b'-' && absolute_offset == 0),
        "negative zero volume time offset is not canonical"
    );
    let signed_offset = if bytes[22] == b'-' {
        -i16::try_from(absolute_offset)?
    } else {
        i16::try_from(absolute_offset)?
    };
    let offset_quarters = i8::try_from(signed_offset / 15)?;
    let time = VolumeTime {
        year: parse_decimal(&bytes[0..4])?,
        month: u8::try_from(parse_decimal(&bytes[5..7])?)?,
        day: u8::try_from(parse_decimal(&bytes[8..10])?)?,
        hour: u8::try_from(parse_decimal(&bytes[11..13])?)?,
        minute: u8::try_from(parse_decimal(&bytes[14..16])?)?,
        second: u8::try_from(parse_decimal(&bytes[17..19])?)?,
        centisecond: u8::try_from(parse_decimal(&bytes[20..22])?)?,
        offset_quarters,
    };
    validate_volume_time(time)?;
    Ok(time)
}

fn parse_decimal(bytes: &[u8]) -> Result<u16> {
    bytes.iter().try_fold(0_u16, |value, byte| {
        ensure!(byte.is_ascii_digit(), "decimal field contains a non-digit");
        Ok(value * 10 + u16::from(byte - b'0'))
    })
}

fn validate_volume_time(time: VolumeTime) -> Result<()> {
    ensure!((1..=12).contains(&time.month), "invalid volume time month");
    ensure!(
        (1..=days_in_month(time.year, time.month)).contains(&time.day),
        "invalid volume time day"
    );
    ensure!(time.hour < 24, "invalid volume time hour");
    ensure!(time.minute < 60, "invalid volume time minute");
    ensure!(time.second < 60, "invalid volume time second");
    ensure!(time.centisecond < 100, "invalid volume time centisecond");
    ensure!(
        (-48..=52).contains(&time.offset_quarters),
        "volume time offset is outside the ISO 9660 range"
    );
    Ok(())
}

fn days_in_month(year: u16, month: u8) -> u8 {
    match month {
        4 | 6 | 9 | 11 => 30,
        2 if year.is_multiple_of(400) || (year.is_multiple_of(4) && !year.is_multiple_of(100)) => {
            29
        }
        2 => 28,
        _ => 31,
    }
}

fn format_volume_time(time: VolumeTime) -> String {
    let offset_minutes = i16::from(time.offset_quarters) * 15;
    let sign = if offset_minutes < 0 { '-' } else { '+' };
    let absolute_offset = offset_minutes.unsigned_abs();
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:02}{sign}{:02}:{:02}",
        time.year,
        time.month,
        time.day,
        time.hour,
        time.minute,
        time.second,
        time.centisecond,
        absolute_offset / 60,
        absolute_offset % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_entry(path: &str) -> Entry {
        Entry {
            path: path.to_owned(),
            recording_time: "2000-01-01T00:00:00+00:00".to_owned(),
        }
    }

    fn test_iso(entries: Vec<Entry>, files: Vec<&str>) -> Iso9660 {
        Iso9660 {
            primary_volume: parse_pvd(&standard_pvd_block()).unwrap(),
            entries,
            files: files.into_iter().map(str::to_owned).collect(),
        }
    }

    fn standard_pvd_block() -> [u8; LOGICAL_BLOCK_SIZE] {
        let mut block = [0_u8; LOGICAL_BLOCK_SIZE];
        write_both_u32(&mut block, 80, 1);
        write_both_u16(&mut block, 120, 1);
        write_both_u16(&mut block, 124, 1);
        write_both_u16(&mut block, 128, 2048);
        for offset in [813, 830, 847, 864] {
            block[offset..offset + 16].fill(b'0');
        }
        block[881] = 1;
        block[1024..1032].copy_from_slice(b"CD-XA001");
        block
    }

    #[test]
    fn cd_xa_application_use_is_validated_and_generated() {
        let source = standard_pvd_block();
        let iso = test_iso(vec![test_entry(ROOT_PATH)], vec![]);
        let generated =
            serialize_pvd(&iso, 20, 10, [18, 19, 20, 21], 22, 2048, &iso.entries[0]).unwrap();
        assert_eq!(&generated[883..1395], &source[883..1395]);

        let mut invalid = source;
        invalid[1024] = b'X';
        assert_eq!(
            parse_pvd(&invalid).unwrap_err().to_string(),
            "unsupported PVD CD-XA application-use data"
        );
    }

    #[test]
    fn fixed_primary_volume_values_are_validated() {
        parse_pvd(&standard_pvd_block()).unwrap();

        for (offset, value, expected) in [
            (120, 2, "unsupported volume set size"),
            (124, 2, "unsupported volume sequence number"),
            (128, 1024, "unsupported logical block size"),
        ] {
            let mut block = standard_pvd_block();
            write_both_u16(&mut block, offset, value);
            assert_eq!(parse_pvd(&block).unwrap_err().to_string(), expected);
        }

        let mut block = standard_pvd_block();
        block[881] = 2;
        assert_eq!(
            parse_pvd(&block).unwrap_err().to_string(),
            "unsupported file structure version"
        );
    }

    #[test]
    fn volume_times_use_readable_centiseconds_and_quarter_hour_offsets() {
        let creation: [u8; 17] = hex::decode("3030303030363136303934353531303024")
            .unwrap()
            .try_into()
            .unwrap();
        let readable = "0000-06-16T09:45:51.00+09:00";
        assert_eq!(
            parse_volume_time(&creation).unwrap().as_deref(),
            Some(readable)
        );
        assert_eq!(serialize_volume_time(Some(readable)).unwrap(), creation);

        let mut unspecified = [b'0'; 17];
        unspecified[16] = 0;
        assert_eq!(parse_volume_time(&unspecified).unwrap(), None);
        assert_eq!(serialize_volume_time(None).unwrap(), unspecified);

        let mut negative_offset = *b"2024022903040599\0";
        negative_offset[16] = (-1_i8).to_ne_bytes()[0];
        let readable = "2024-02-29T03:04:05.99-00:15";
        assert_eq!(
            parse_volume_time(&negative_offset).unwrap().as_deref(),
            Some(readable)
        );
        assert_eq!(
            serialize_volume_time(Some(readable)).unwrap(),
            negative_offset
        );
    }

    #[test]
    fn volume_times_reject_invalid_or_lossy_values() {
        for value in [
            "2023-02-29T03:04:05.00+00:00",
            "2024-01-01T24:00:00.00+00:00",
            "2024-01-01T00:00:00.00+00:10",
            "2024-01-01T00:00:00.00-00:00",
            "2024-01-01 00:00:00.00+00:00",
        ] {
            assert!(
                serialize_volume_time(Some(value)).is_err(),
                "accepted {value}"
            );
        }
    }

    #[test]
    fn directory_recording_times_are_human_readable_and_exact() {
        let root = [0x00, 0x06, 0x10, 0x09, 0x2d, 0x33, 0x24];
        let readable = "1900-06-16T09:45:51+09:00";
        assert_eq!(parse_recording_time(root).unwrap(), readable);
        assert_eq!(serialize_recording_time(readable).unwrap(), root);

        let file = [0x62, 0x03, 0x13, 0x0b, 0x3a, 0x24, 0x24];
        let readable = "1998-03-19T11:58:36+09:00";
        assert_eq!(parse_recording_time(file).unwrap(), readable);
        assert_eq!(serialize_recording_time(readable).unwrap(), file);

        let limit = [0xff, 12, 31, 23, 59, 59, (-1_i8).to_ne_bytes()[0]];
        let readable = "2155-12-31T23:59:59-00:15";
        assert_eq!(parse_recording_time(limit).unwrap(), readable);
        assert_eq!(serialize_recording_time(readable).unwrap(), limit);
    }

    #[test]
    fn directory_recording_times_reject_unrepresentable_values() {
        for value in [
            "1899-12-31T23:59:59+00:00",
            "2156-01-01T00:00:00+00:00",
            "2024-02-30T00:00:00+00:00",
            "2024-01-01T00:00:00.00+00:00",
            "2024-01-01T00:00:00+00:10",
        ] {
            assert!(serialize_recording_time(value).is_err(), "accepted {value}");
        }
    }

    #[test]
    fn record_with_odd_identifier_needs_no_padding_byte() {
        assert_eq!(record_size(11, 14), 58);
        assert_eq!(record_size(12, 14), 60);
    }

    #[test]
    fn level_one_names_are_validated() {
        validate_path("DIR/FILE.BIN", true).unwrap();
        assert!(validate_path("dir/file.bin", true).is_err());
        assert!(validate_path("../FILE.BIN", true).is_err());
        assert!(validate_path("TOO_LONG_NAME.BIN", true).is_err());
    }

    #[test]
    fn files_list_declares_kind_and_physical_order() {
        let root = test_entry(".");
        let file = test_entry("FILE.BIN");
        validate_entries(&test_iso(
            vec![root.clone(), file.clone()],
            vec!["FILE.BIN"],
        ))
        .unwrap();

        assert!(validate_entries(&test_iso(vec![file.clone()], vec!["FILE.BIN"])).is_err());
        assert!(
            validate_entries(&test_iso(
                vec![file.clone(), root.clone()],
                vec!["FILE.BIN"]
            ))
            .is_err()
        );
        assert!(validate_entries(&test_iso(vec![root.clone()], vec!["."])).is_err());
        assert!(validate_entries(&test_iso(vec![root.clone()], vec!["MISSING.BIN"])).is_err());
        assert!(
            validate_entries(&test_iso(vec![root, file], vec!["FILE.BIN", "FILE.BIN"],)).is_err()
        );
    }

    #[test]
    fn fixed_directory_record_fields_are_validated_and_generated() {
        let mut record = Record {
            extent: 0,
            length: 0,
            recording_time: [0, 1, 1, 0, 0, 0, 0],
            flags: 0,
            file_unit_size: 0,
            interleave_gap_size: 0,
            volume_sequence_number: 1,
            name: b"FILE.BIN;1".to_vec(),
            system_use: FILE_SYSTEM_USE.to_vec(),
        };
        validate_standard_record_fields(&record, false, true).unwrap();
        record.flags = DIRECTORY_FLAG;
        record.system_use = DIRECTORY_SYSTEM_USE.to_vec();
        validate_standard_record_fields(&record, true, true).unwrap();

        record.flags = 1;
        assert!(validate_standard_record_fields(&record, false, true).is_err());
        record.flags = 0;
        record.system_use = FILE_SYSTEM_USE.to_vec();
        record.file_unit_size = 1;
        assert!(validate_standard_record_fields(&record, false, true).is_err());
        record.file_unit_size = 0;
        record.interleave_gap_size = 1;
        assert!(validate_standard_record_fields(&record, false, true).is_err());
        record.interleave_gap_size = 0;
        record.volume_sequence_number = 2;
        assert!(validate_standard_record_fields(&record, false, true).is_err());
        record.volume_sequence_number = 1;
        record.system_use[4] = 0;
        assert!(validate_standard_record_fields(&record, false, true).is_err());

        assert_eq!(identifier(&test_entry("FILE.BIN"), true), "FILE.BIN;1");
    }
}

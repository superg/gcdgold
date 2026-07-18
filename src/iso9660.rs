use std::collections::{HashMap, HashSet, VecDeque};

use anyhow::{Context, Result, ensure};

use crate::manifest::{DirectoryMetadata, Entry, EntryDefaults, EntryKind, Iso9660, PrimaryVolume};
use crate::raw_cd::LOGICAL_BLOCK_SIZE;

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
    ensure!(
        pvd.logical_block_size == 2048,
        "unsupported logical block size"
    );
    let root_record = parse_record(&pvd_block[156..])?;
    let root_records = read_directory(blocks, root_record.extent, root_record.length)?;
    ensure!(root_records.len() >= 2, "root directory lacks dot records");
    let dot = &root_records[0];
    let root = DirectoryMetadata {
        recording_time_hex: hex::encode(dot.recording_time),
        flags: dot.flags,
        file_unit_size: dot.file_unit_size,
        interleave_gap_size: dot.interleave_gap_size,
        volume_sequence_number: dot.volume_sequence_number,
        system_use_hex: hex::encode(&dot.system_use),
    };

    let mut entries = Vec::new();
    let mut files = Vec::new();
    let mut queue = VecDeque::from([(String::new(), root_record.extent, root_record.length)]);
    let mut seen_dirs = HashSet::new();
    while let Some((parent, extent, length)) = queue.pop_front() {
        ensure!(
            seen_dirs.insert(extent),
            "directory extent cycle at LBA {extent}"
        );
        let records = read_directory(blocks, extent, length)?;
        for record in records.into_iter().skip(2) {
            let raw_name =
                String::from_utf8(record.name.clone()).context("non-ASCII ISO identifier")?;
            let is_dir = record.flags & 2 != 0;
            let (name, version) = if is_dir {
                (raw_name, 1)
            } else {
                let (name, version) = raw_name
                    .rsplit_once(';')
                    .context("file identifier has no version")?;
                (
                    name.to_owned(),
                    version.parse::<u8>().context("invalid file version")?,
                )
            };
            let path = if parent.is_empty() {
                name
            } else {
                format!("{parent}/{name}")
            };
            let kind = if is_dir {
                EntryKind::Directory
            } else {
                EntryKind::File
            };
            let entry = Entry {
                path: path.clone(),
                kind,
                version,
                recording_time_hex: Some(hex::encode(record.recording_time)),
                flags: record.flags & !2,
                file_unit_size: record.file_unit_size,
                interleave_gap_size: record.interleave_gap_size,
                volume_sequence_number: record.volume_sequence_number,
                system_use_hex: Some(hex::encode(&record.system_use)),
                data_order: None,
                source_sha1: None,
                source_length: Some(u64::from(record.length)),
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
    let order_by_path: HashMap<_, _> = ordered
        .iter()
        .enumerate()
        .map(|(index, file)| (file.path.as_str(), index as u32))
        .collect();
    for entry in &mut entries {
        if entry.kind == EntryKind::File {
            entry.data_order = order_by_path.get(entry.path.as_str()).copied();
        }
    }

    let first_file = entries.iter().find(|entry| entry.kind == EntryKind::File);
    let first_dir = entries
        .iter()
        .find(|entry| entry.kind == EntryKind::Directory);
    let defaults = EntryDefaults {
        file_recording_time_hex: first_file
            .and_then(|entry| entry.recording_time_hex.clone())
            .unwrap_or_else(|| root.recording_time_hex.clone()),
        directory_recording_time_hex: first_dir
            .and_then(|entry| entry.recording_time_hex.clone())
            .unwrap_or_else(|| root.recording_time_hex.clone()),
        file_system_use_hex: first_file
            .and_then(|entry| entry.system_use_hex.clone())
            .unwrap_or_else(|| "000000000d555841000000000000".to_owned()),
        directory_system_use_hex: first_dir
            .and_then(|entry| entry.system_use_hex.clone())
            .unwrap_or_else(|| root.system_use_hex.clone()),
    };
    Ok(ParsedIso {
        manifest: Iso9660 {
            primary_volume: pvd,
            root,
            defaults,
            entries,
        },
        files,
    })
}

fn parse_pvd(block: &[u8; LOGICAL_BLOCK_SIZE]) -> Result<PrimaryVolume> {
    ensure!(read_both_u32(block, 80)? > 0, "invalid volume size");
    ensure!(
        read_both_u16(block, 128)? == 2048,
        "invalid logical block size"
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
        volume_set_size: read_both_u16(block, 120)?,
        volume_sequence_number: read_both_u16(block, 124)?,
        logical_block_size: read_both_u16(block, 128)?,
        creation_time_hex: hex::encode(&block[813..830]),
        modification_time_hex: hex::encode(&block[830..847]),
        expiration_time_hex: hex::encode(&block[847..864]),
        effective_time_hex: hex::encode(&block[864..881]),
        file_structure_version: block[881],
        application_use_hex: hex::encode(&block[883..1395]),
    })
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
    validate_entries(&iso.entries)?;
    let directories = directory_order(&iso.entries)?;
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
        let record_lengths = directory_record_lengths(path, iso, &entry_by_path)?;
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

    let mut indexed_files = iso
        .entries
        .iter()
        .enumerate()
        .filter(|(_, entry)| entry.kind == EntryKind::File)
        .collect::<Vec<_>>();
    let fallback_base = indexed_files
        .iter()
        .filter_map(|(_, entry)| entry.data_order)
        .max()
        .unwrap_or(0)
        .saturating_add(1);
    indexed_files.sort_by_key(|(index, entry)| {
        (
            entry.data_order.unwrap_or(fallback_base + *index as u32),
            *index,
        )
    });
    let mut seen_order = HashSet::new();
    for (_, entry) in &indexed_files {
        if let Some(order) = entry.data_order {
            ensure!(
                seen_order.insert(order),
                "duplicate file data_order {order}"
            );
        }
    }
    let mut files = Vec::with_capacity(indexed_files.len());
    for (_, entry) in indexed_files {
        let data = file_data
            .get(&entry.path)
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
        &iso.primary_volume,
        volume_blocks,
        path_table_size as u32,
        pointers,
        placements[0].extent,
        placements[0].blocks * 2048,
        &iso.root,
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

fn validate_entries(entries: &[Entry]) -> Result<()> {
    let mut paths = HashSet::new();
    let directory_paths: HashSet<_> = entries
        .iter()
        .filter(|entry| entry.kind == EntryKind::Directory)
        .map(|entry| entry.path.as_str())
        .collect();
    for entry in entries {
        validate_path(&entry.path, entry.kind == EntryKind::File)?;
        ensure!(
            paths.insert(entry.path.as_str()),
            "duplicate ISO path {}",
            entry.path
        );
        if let Some((parent, _)) = entry.path.rsplit_once('/') {
            ensure!(
                directory_paths.contains(parent),
                "missing parent directory {parent}"
            );
        }
    }
    Ok(())
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

fn directory_order(entries: &[Entry]) -> Result<Vec<(String, String, usize)>> {
    let mut result = vec![(String::new(), String::from("\0"), 0)];
    let mut queue = VecDeque::from([String::new()]);
    while let Some(parent) = queue.pop_front() {
        let parent_index = result
            .iter()
            .position(|(path, _, _)| path == &parent)
            .context("missing directory parent")?;
        for entry in entries.iter().filter(|entry| {
            entry.kind == EntryKind::Directory && parent_path(&entry.path) == parent
        }) {
            let name = file_name(&entry.path).to_owned();
            result.push((entry.path.clone(), name, parent_index));
            queue.push_back(entry.path.clone());
        }
    }
    let expected = entries
        .iter()
        .filter(|entry| entry.kind == EntryKind::Directory)
        .count()
        + 1;
    ensure!(
        result.len() == expected,
        "unreachable directory in manifest"
    );
    Ok(result)
}

fn directory_record_lengths(
    path: &str,
    iso: &Iso9660,
    entries: &HashMap<&str, &Entry>,
) -> Result<Vec<usize>> {
    let self_sys = if path.is_empty() {
        hex::decode(&iso.root.system_use_hex)?
    } else {
        entry_system_use(entries[path], iso)?
    };
    let parent = parent_path(path);
    let parent_sys = if parent.is_empty() {
        hex::decode(&iso.root.system_use_hex)?
    } else {
        entry_system_use(entries[parent.as_str()], iso)?
    };
    let mut lengths = vec![
        record_size(1, self_sys.len()),
        record_size(1, parent_sys.len()),
    ];
    for entry in iso
        .entries
        .iter()
        .filter(|entry| parent_path(&entry.path) == path)
    {
        let name = identifier(entry);
        lengths.push(record_size(name.len(), entry_system_use(entry, iso)?.len()));
    }
    Ok(lengths)
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
    pvd: &PrimaryVolume,
    volume_blocks: u32,
    path_table_size: u32,
    pointers: [u32; 4],
    root_extent: u32,
    root_length: u32,
    root: &DirectoryMetadata,
) -> Result<[u8; LOGICAL_BLOCK_SIZE]> {
    let mut block = [0_u8; LOGICAL_BLOCK_SIZE];
    block[0..7].copy_from_slice(b"\x01CD001\x01");
    write_fixed(&mut block, 8, 32, &pvd.system_identifier)?;
    write_fixed(&mut block, 40, 32, &pvd.volume_identifier)?;
    write_both_u32(&mut block, 80, volume_blocks);
    write_both_u16(&mut block, 120, pvd.volume_set_size);
    write_both_u16(&mut block, 124, pvd.volume_sequence_number);
    write_both_u16(&mut block, 128, pvd.logical_block_size);
    write_both_u32(&mut block, 132, path_table_size);
    block[140..144].copy_from_slice(&pointers[0].to_le_bytes());
    block[144..148].copy_from_slice(&pointers[1].to_le_bytes());
    block[148..152].copy_from_slice(&pointers[2].to_be_bytes());
    block[152..156].copy_from_slice(&pointers[3].to_be_bytes());
    let root_record = serialize_record(&Record {
        extent: root_extent,
        length: root_length,
        recording_time: decode_array7(&root.recording_time_hex)?,
        flags: root.flags | 2,
        file_unit_size: root.file_unit_size,
        interleave_gap_size: root.interleave_gap_size,
        volume_sequence_number: root.volume_sequence_number,
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
    copy_hex_exact(&mut block[813..830], &pvd.creation_time_hex)?;
    copy_hex_exact(&mut block[830..847], &pvd.modification_time_hex)?;
    copy_hex_exact(&mut block[847..864], &pvd.expiration_time_hex)?;
    copy_hex_exact(&mut block[864..881], &pvd.effective_time_hex)?;
    block[881] = pvd.file_structure_version;
    copy_hex_exact(&mut block[883..1395], &pvd.application_use_hex)?;
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
) -> Result<Vec<u8>> {
    let metadata = if directory.path.is_empty() {
        &iso.root
    } else {
        let entry = entry_by_path[directory.path.as_str()];
        return serialize_directory_with_metadata(
            directory,
            directories,
            iso,
            entry_by_path,
            directory_by_path,
            file_by_path,
            entry,
        );
    };
    let synthetic = Entry {
        path: String::new(),
        kind: EntryKind::Directory,
        version: 1,
        recording_time_hex: Some(metadata.recording_time_hex.clone()),
        flags: metadata.flags & !2,
        file_unit_size: metadata.file_unit_size,
        interleave_gap_size: metadata.interleave_gap_size,
        volume_sequence_number: metadata.volume_sequence_number,
        system_use_hex: Some(metadata.system_use_hex.clone()),
        data_order: None,
        source_sha1: None,
        source_length: None,
    };
    serialize_directory_with_metadata(
        directory,
        directories,
        iso,
        entry_by_path,
        directory_by_path,
        file_by_path,
        &synthetic,
    )
}

fn serialize_directory_with_metadata(
    directory: &DirectoryPlacement,
    directories: &[DirectoryPlacement],
    iso: &Iso9660,
    entry_by_path: &HashMap<&str, &Entry>,
    directory_by_path: &HashMap<&str, &DirectoryPlacement>,
    file_by_path: &HashMap<&str, &FilePlacement>,
    metadata: &Entry,
) -> Result<Vec<u8>> {
    let parent = &directories[directory.parent];
    let parent_entry = if parent.path.is_empty() {
        None
    } else {
        Some(entry_by_path[parent.path.as_str()])
    };
    let mut records = Vec::new();
    records.push(make_record(
        metadata,
        iso,
        directory.extent,
        directory.blocks * 2048,
        vec![0],
        true,
    )?);
    let parent_meta = parent_entry.unwrap_or(metadata);
    records.push(make_record(
        parent_meta,
        iso,
        parent.extent,
        parent.blocks * 2048,
        vec![1],
        true,
    )?);
    for entry in iso
        .entries
        .iter()
        .filter(|entry| parent_path(&entry.path) == directory.path)
    {
        let (extent, length) = match entry.kind {
            EntryKind::Directory => {
                let child = directory_by_path[entry.path.as_str()];
                (child.extent, child.blocks * 2048)
            }
            EntryKind::File => {
                let file = file_by_path[entry.path.as_str()];
                (file.extent, u32::try_from(file.length)?)
            }
        };
        records.push(make_record(
            entry,
            iso,
            extent,
            length,
            identifier(entry).into_bytes(),
            entry.kind == EntryKind::Directory,
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
    iso: &Iso9660,
    extent: u32,
    length: u32,
    name: Vec<u8>,
    directory: bool,
) -> Result<Vec<u8>> {
    serialize_record(&Record {
        extent,
        length,
        recording_time: decode_array7(entry.recording_time_hex.as_deref().unwrap_or(
            if directory {
                &iso.defaults.directory_recording_time_hex
            } else {
                &iso.defaults.file_recording_time_hex
            },
        ))?,
        flags: if directory {
            entry.flags | 2
        } else {
            entry.flags & !2
        },
        file_unit_size: entry.file_unit_size,
        interleave_gap_size: entry.interleave_gap_size,
        volume_sequence_number: entry.volume_sequence_number,
        name,
        system_use: entry_system_use(entry, iso)?,
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

fn entry_system_use(entry: &Entry, iso: &Iso9660) -> Result<Vec<u8>> {
    hex::decode(entry.system_use_hex.as_deref().unwrap_or(match entry.kind {
        EntryKind::File => &iso.defaults.file_system_use_hex,
        EntryKind::Directory => &iso.defaults.directory_system_use_hex,
    }))
    .context("invalid system-use hex")
}

fn identifier(entry: &Entry) -> String {
    let name = file_name(&entry.path);
    if entry.kind == EntryKind::File {
        format!("{name};{}", entry.version)
    } else {
        name.to_owned()
    }
}

fn parent_path(path: &str) -> String {
    path.rsplit_once('/')
        .map_or_else(String::new, |(parent, _)| parent.to_owned())
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

fn decode_array7(value: &str) -> Result<[u8; 7]> {
    let bytes = hex::decode(value).context("invalid recording-time hex")?;
    ensure!(bytes.len() == 7, "recording time must contain seven bytes");
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("recording time must contain seven bytes"))
}

fn copy_hex_exact(target: &mut [u8], value: &str) -> Result<()> {
    let bytes = hex::decode(value).context("invalid hex field")?;
    ensure!(
        bytes.len() == target.len(),
        "hex field has incorrect length"
    );
    target.copy_from_slice(&bytes);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
}

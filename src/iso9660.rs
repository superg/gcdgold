use std::collections::{HashMap, HashSet, VecDeque};

use anyhow::{Context, Result, ensure};

use crate::manifest::{
    DEFAULT_XA_PERMISSIONS, DirectoryLengthPolicy, DirectoryParentRecordingTime,
    DirectoryRecordPacking, DirectoryReference, DirectorySlack, Entry, EntrySectorSubheader,
    EntryXa, FileLayoutItem, GapKind, IdentifierPolicy, Iso9660, JolietEntry, JolietLevel,
    JolietVolume, MetadataLayoutItem, MetadataPathTable, MetadataVolume, PathTableCopies,
    PathTableOrder, PrimaryVolume, PrimaryVolumeApplicationUse, PvdU16Encoding,
    RootDirectoryIdentifier, XaAttributes, XaLengthEncoding,
};
use crate::raw_cd::{LOGICAL_BLOCK_SIZE, MODE2_DATA_SIZE, XaSubheader};

const VOLUME_SET_SIZE: u16 = 1;
const VOLUME_SEQUENCE_NUMBER: u16 = 1;
const ISO_LOGICAL_BLOCK_SIZE: u16 = 2048;
const FILE_STRUCTURE_VERSION: u8 = 1;
const FILE_VERSION: u8 = 1;
const HIDDEN_FLAG: u8 = 1;
const DIRECTORY_FLAG: u8 = 2;
const ASSOCIATED_FLAG: u8 = 4;
const XA_SYSTEM_USE_SIZE: usize = 14;
const XA_ATTRIBUTE_MASK: u16 = 0xf800;
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
pub struct ParsedDirectory {
    pub path: String,
    pub extent: u32,
    pub length: u32,
}

#[derive(Debug, Clone)]
pub struct ParsedIso {
    pub manifest: Iso9660,
    pub files: Vec<ParsedFile>,
    pub directories: Vec<ParsedDirectory>,
    pub path_tables: Option<ParsedPathTables>,
    pub supplementary_directories: Vec<ParsedDirectory>,
    pub supplementary_path_tables: Option<ParsedPathTables>,
    pub metadata_gaps: Vec<GapPlacement>,
}

#[derive(Debug, Clone)]
pub struct ParsedPathTables {
    pub extents: [u32; 4],
    pub blocks: u32,
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
    trailing_system_use_padding: bool,
}

pub fn parse(blocks: &[[u8; LOGICAL_BLOCK_SIZE]]) -> Result<ParsedIso> {
    ensure!(blocks.len() > 22, "image is too small for ISO 9660");
    let pvd_block = &blocks[16];
    ensure!(
        &pvd_block[0..7] == b"\x01CD001\x01",
        "missing supported PVD at LBA 16"
    );
    let mut primary_volume_copies = 1_usize;
    while blocks
        .get(16 + primary_volume_copies)
        .is_some_and(|block| &block[..7] == b"\x01CD001\x01")
    {
        ensure!(
            blocks[16 + primary_volume_copies] == *pvd_block,
            "additional primary volume descriptors must be identical"
        );
        primary_volume_copies += 1;
    }
    ensure!(
        (1..=3).contains(&primary_volume_copies),
        "unsupported primary volume descriptor copy count {primary_volume_copies}"
    );
    let supplementary_lba = 16 + primary_volume_copies;
    let supplementary = blocks
        .get(supplementary_lba)
        .filter(|block| &block[..7] == b"\x02CD001\x01")
        .map(|block| (supplementary_lba, block));
    let terminator_lba = supplementary_lba + usize::from(supplementary.is_some());
    ensure!(
        blocks
            .get(terminator_lba)
            .is_some_and(|block| &block[..7] == b"\xffCD001\x01"),
        "expected volume terminator at LBA {terminator_lba}"
    );
    let source_volume_space_size = read_both_u32(pvd_block, 80)?;
    ensure!(source_volume_space_size > 0, "invalid volume space size");
    let path_table_size = read_both_u32(pvd_block, 132)?;
    ensure!(path_table_size > 0, "invalid path table size");
    let path_table_blocks = path_table_size.div_ceil(LOGICAL_BLOCK_SIZE as u32);
    let path_table_extents = [
        u32::from_le_bytes(pvd_block[140..144].try_into()?),
        u32::from_le_bytes(pvd_block[144..148].try_into()?),
        u32::from_be_bytes(pvd_block[148..152].try_into()?),
        u32::from_be_bytes(pvd_block[152..156].try_into()?),
    ];
    ensure!(
        path_table_extents[0] != 0 && path_table_extents[2] != 0,
        "missing required path table"
    );
    let path_table_copies = match (path_table_extents[1], path_table_extents[3]) {
        (0, 0) => PathTableCopies::Single,
        (little, big) if little != 0 && big != 0 => PathTableCopies::Duplicate,
        _ => anyhow::bail!("optional path-table copies must both be present or absent"),
    };
    let first_little = path_table_extents[..2]
        .iter()
        .copied()
        .filter(|extent| *extent != 0)
        .min()
        .expect("required little-endian path table");
    let first_big = path_table_extents[2..]
        .iter()
        .copied()
        .filter(|extent| *extent != 0)
        .min()
        .expect("required big-endian path table");
    let path_table_order = if first_little < first_big {
        PathTableOrder::LittleEndianFirst
    } else if first_big < first_little {
        PathTableOrder::BigEndianFirst
    } else {
        anyhow::bail!("little- and big-endian path tables share one extent")
    };
    for extent in path_table_extents.into_iter().filter(|extent| *extent != 0) {
        ensure!(
            extent
                .checked_add(path_table_blocks)
                .is_some_and(|end| usize::try_from(end).is_ok_and(|end| end <= blocks.len())),
            "path table extent is outside image"
        );
    }
    let mut pvd = parse_pvd(pvd_block)?;
    let root_record = parse_record(&pvd_block[156..])?;
    let mut ordered_path_tables = path_table_extents
        .iter()
        .copied()
        .filter(|extent| *extent != 0)
        .collect::<Vec<_>>();
    ordered_path_tables.sort_unstable();
    let path_table_stride = ordered_path_tables[1] - ordered_path_tables[0];
    let path_table_padding = if supplementary.is_none()
        && path_table_stride >= path_table_blocks
        && ordered_path_tables
            .windows(2)
            .all(|pair| pair[1] - pair[0] == path_table_stride)
        && ordered_path_tables
            .last()
            .and_then(|extent| extent.checked_add(path_table_stride))
            == Some(root_record.extent)
    {
        path_table_stride - path_table_blocks
    } else {
        0
    };
    validate_record_fields(&root_record, true)?;
    let root_record_length = pvd_block[156];
    if root_record_length == 34 {
        ensure!(
            root_record.system_use.is_empty(),
            "unsupported PVD root directory-record system-use data"
        );
    } else {
        ensure!(
            root_record_length > 34,
            "unsupported PVD root directory-record length {root_record_length}"
        );
        pvd.root_directory_record_length = Some(root_record_length);
    }
    let (root_records, mut packing_observation, _) =
        read_directory(blocks, root_record.extent, root_record.length)
            .context("reading root directory")?;
    ensure!(root_records.len() >= 2, "root directory lacks dot records");
    let dot = &root_records[0];
    let xa_system_use = !dot.system_use.is_empty();
    let root_recording_time = parse_recording_time(dot.recording_time)?;
    let pvd_root_recording_time = parse_recording_time(root_record.recording_time)?;
    pvd.root_directory_recording_time =
        (pvd_root_recording_time != root_recording_time).then_some(pvd_root_recording_time);
    let root = Entry {
        path: ROOT_PATH.to_owned(),
        recording_time: root_recording_time,
        hidden: root_record.flags & 1 != 0,
        associated: root_record.flags & ASSOCIATED_FLAG != 0,
        unbacked: false,
        directory_reference: None,
        directory_slack: None,
        allocation_padding_hex: None,
        sector_subheader: crate::manifest::EntrySectorSubheader::Canonical,
        xa: entry_xa(dot, true, xa_system_use)?,
        extent: None,
        length: None,
    };

    let mut entries = vec![root];
    let mut files = Vec::new();
    let mut xa_system_use_omissions = Vec::new();
    let mut directories = vec![ParsedDirectory {
        path: ROOT_PATH.to_owned(),
        extent: root_record.extent,
        length: root_record.length,
    }];
    let mut identifier_policy = IdentifierPolicy::IsoLevel1;
    let mut directory_parent_recording_time = None;
    let mut queue = VecDeque::from([(String::new(), root_record.extent, root_record.length)]);
    let mut seen_dirs = HashSet::new();
    while let Some((parent, extent, length)) = queue.pop_front() {
        ensure!(
            seen_dirs.insert(extent),
            "directory extent cycle at LBA {extent}"
        );
        let directory_path = if parent.is_empty() {
            ROOT_PATH
        } else {
            parent.as_str()
        };
        let (records, observation, directory_slack) = read_directory(blocks, extent, length)
            .with_context(|| format!("reading directory {directory_path} at LBA {extent}"))?;
        packing_observation.merge(observation);
        entries
            .iter_mut()
            .find(|entry| entry.path == directory_path)
            .context("directory entry is missing")?
            .directory_slack = directory_slack;
        ensure!(records.len() >= 2, "directory lacks dot records");
        if directory_path != ROOT_PATH {
            let current_time = &entries
                .iter()
                .find(|entry| entry.path == directory_path)
                .context("directory entry is missing")?
                .recording_time;
            let parent_directory = parent_path(directory_path);
            let parent_time = &entries
                .iter()
                .find(|entry| entry.path == parent_directory)
                .context("parent directory entry is missing")?
                .recording_time;
            let recorded_time = parse_recording_time(records[1].recording_time)?;
            if current_time != parent_time {
                let observed = if recorded_time == parent_time.as_str() {
                    DirectoryParentRecordingTime::Parent
                } else if recorded_time == current_time.as_str() {
                    DirectoryParentRecordingTime::Current
                } else {
                    anyhow::bail!(
                        "directory parent record has an unsupported recording time: {directory_path} at LBA {extent}"
                    )
                };
                ensure!(
                    directory_parent_recording_time.is_none_or(|value| value == observed),
                    "directories use inconsistent parent-record recording times"
                );
                directory_parent_recording_time = Some(observed);
            }
        }
        for (record_index, record) in records.iter().enumerate() {
            let directory = record.flags & DIRECTORY_FLAG != 0;
            let record_uses_xa = xa_system_use && !record.system_use.is_empty();
            ensure!(
                !xa_system_use || record_uses_xa || (record_index >= 2 && !directory),
                "XA system-use omission is supported only for file records"
            );
            validate_standard_record_fields(record, directory, record_uses_xa)?;
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
            let component = file_name(&path);
            if !identifier_is_iso_level1(component, !is_dir) {
                ensure!(
                    valid_nonstandard_ascii_identifier(component),
                    "unsupported non-ASCII ISO identifier: {component}"
                );
                identifier_policy = IdentifierPolicy::NonstandardAscii;
            }
            let record_uses_xa = xa_system_use && !record.system_use.is_empty();
            let xa = entry_xa(&record, is_dir, record_uses_xa)?;
            if xa_system_use && !record_uses_xa {
                xa_system_use_omissions.push(path.clone());
            }
            let external_cdda = !is_dir && xa.as_ref().is_some_and(entry_xa_is_cdda);
            let directory_reference =
                (is_dir && record.length == 0).then_some(DirectoryReference {
                    extent: record.extent,
                    length: record.length,
                });
            let entry = Entry {
                path: path.clone(),
                recording_time: parse_recording_time(record.recording_time)?,
                hidden: record.flags & 1 != 0,
                associated: record.flags & ASSOCIATED_FLAG != 0,
                unbacked: false,
                directory_reference,
                directory_slack: None,
                allocation_padding_hex: (!is_dir && !external_cdda)
                    .then(|| file_allocation_padding_hex(blocks, &record))
                    .flatten(),
                sector_subheader: crate::manifest::EntrySectorSubheader::Canonical,
                xa,
                extent: external_cdda.then_some(record.extent),
                length: external_cdda.then_some(record.length),
            };
            entries.push(entry);
            if is_dir {
                directories.push(ParsedDirectory {
                    path: path.clone(),
                    extent: record.extent,
                    length: record.length,
                });
                if directory_reference.is_none() {
                    queue.push_back((path, record.extent, record.length));
                }
            } else if !external_cdda {
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
    let file_order = ordered
        .iter()
        .map(|file| FileLayoutItem::path(&file.path))
        .collect();
    ensure!(
        !(packing_observation.skipped_exact_fit && packing_observation.packed_exact_fit),
        "directories use inconsistent exact-fit record packing"
    );
    let inferred_volume_space_size = entries.iter().try_fold(
        u32::try_from(blocks.len())?,
        |maximum, entry| -> Result<u32> {
            let Some(extent) = entry.extent else {
                return Ok(maximum);
            };
            let blocks = entry
                .length
                .context("external CDDA entry has no length")?
                .div_ceil(LOGICAL_BLOCK_SIZE as u32);
            Ok(maximum.max(
                extent
                    .checked_add(blocks)
                    .context("external CDDA extent overflow")?,
            ))
        },
    )?;
    pvd.volume_space_size = (source_volume_space_size != inferred_volume_space_size)
        .then_some(source_volume_space_size);
    let generated_path_table_size = directories.iter().try_fold(0_u32, |size, directory| {
        let name_length = if directory.path == ROOT_PATH {
            1
        } else {
            u32::try_from(file_name(&directory.path).len())?
        };
        size.checked_add(8 + name_length + u32::from(name_length % 2 == 1))
            .context("path table size overflow")
    })?;
    ensure!(
        path_table_size.div_ceil(LOGICAL_BLOCK_SIZE as u32)
            == generated_path_table_size.div_ceil(LOGICAL_BLOCK_SIZE as u32),
        "PVD path table size changes the physical path table allocation"
    );
    let directory_indices = directories
        .iter()
        .enumerate()
        .map(|(index, directory)| (directory.path.as_str(), index))
        .collect::<HashMap<_, _>>();
    let parsed_placements = directories
        .iter()
        .map(|directory| -> Result<DirectoryPlacement> {
            let root = directory.path == ROOT_PATH;
            let parent = if root {
                0
            } else {
                *directory_indices
                    .get(parent_path(&directory.path).as_str())
                    .context("path table directory parent is missing")?
            };
            Ok(DirectoryPlacement {
                path: directory.path.clone(),
                name: if root {
                    vec![0]
                } else {
                    file_name(&directory.path).as_bytes().to_vec()
                },
                parent,
                extent: directory.extent,
                blocks: directory.length.div_ceil(LOGICAL_BLOCK_SIZE as u32),
                length: directory.length,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let canonical_little = serialize_path_table(&parsed_placements, false)?;
    let canonical_big = serialize_path_table(&parsed_placements, true)?;
    let little = read_path_table(blocks, path_table_extents[0], path_table_size)?;
    let big = read_path_table(blocks, path_table_extents[2], path_table_size)?;
    validate_directory_reference_path_tables(&entries, &parsed_placements, &little, &big)?;
    let noncanonical_path_tables = little != canonical_little
        || big != canonical_big
        || path_table_size != generated_path_table_size;
    let (path_table_little_hex, path_table_big_hex) = if noncanonical_path_tables {
        if path_table_extents[1] != 0 {
            ensure!(
                read_path_table(blocks, path_table_extents[1], path_table_size)? == little,
                "little-endian path table copies differ"
            );
        }
        if path_table_extents[3] != 0 {
            ensure!(
                read_path_table(blocks, path_table_extents[3], path_table_size)? == big,
                "big-endian path table copies differ"
            );
        }
        (Some(hex::encode(little)), Some(hex::encode(big)))
    } else {
        (None, None)
    };

    let primary_path_tables = ParsedPathTables {
        extents: path_table_extents,
        blocks: path_table_blocks,
    };
    let mut manifest = Iso9660 {
        primary_volume: pvd,
        primary_volume_copies: u8::try_from(primary_volume_copies)?,
        supplementary_volumes: Vec::new(),
        metadata_layout: Vec::new(),
        xa_system_use,
        xa_system_use_omissions,
        metadata_subheader: crate::manifest::IsoMetadataSubheader::Canonical,
        metadata_framing_subheader: None,
        identifier_policy,
        directory_record_packing: if packing_observation.skipped_exact_fit {
            DirectoryRecordPacking::AvoidExactFit
        } else {
            DirectoryRecordPacking::Fill
        },
        directory_parent_recording_time: directory_parent_recording_time.unwrap_or_default(),
        directory_length_policy: DirectoryLengthPolicy::Allocated,
        path_table_size: (path_table_size != generated_path_table_size).then_some(path_table_size),
        path_table_padding,
        path_table_little_hex,
        path_table_big_hex,
        path_table_copies,
        path_table_order,
        path_table_subheader: EntrySectorSubheader::Canonical,
        path_table_framing_subheader: None,
        entries,
        files: file_order,
    };
    let mut supplementary_directories = Vec::new();
    let mut supplementary_path_tables = None;
    let mut metadata_gaps = Vec::new();
    if let Some((_, block)) = supplementary {
        ensure!(
            manifest.path_table_copies == PathTableCopies::Single,
            "Joliet support requires single primary path-table copies"
        );
        let parsed = parse_joliet(blocks, block, &files)?;
        manifest.supplementary_volumes.push(parsed.volume);
        let (metadata_layout, gaps) = derive_metadata_layout(
            blocks,
            u32::try_from(terminator_lba + 1)?,
            &primary_path_tables,
            &directories,
            &parsed.path_tables,
            &parsed.directories,
        )?;
        manifest.metadata_layout = metadata_layout;
        metadata_gaps = gaps;
        supplementary_directories = parsed.directories;
        supplementary_path_tables = Some(parsed.path_tables);
        manifest.directory_length_policy =
            infer_directory_length_policy(&manifest, &directories, &supplementary_directories)?;
    }
    Ok(ParsedIso {
        manifest,
        files,
        directories,
        path_tables: Some(primary_path_tables),
        supplementary_directories,
        supplementary_path_tables,
        metadata_gaps,
    })
}

#[derive(Debug)]
struct MetadataObject {
    start: u32,
    end: u32,
    item: MetadataLayoutItem,
}

fn derive_metadata_layout(
    blocks: &[[u8; LOGICAL_BLOCK_SIZE]],
    start: u32,
    primary_tables: &ParsedPathTables,
    primary_directories: &[ParsedDirectory],
    joliet_tables: &ParsedPathTables,
    joliet_directories: &[ParsedDirectory],
) -> Result<(Vec<MetadataLayoutItem>, Vec<GapPlacement>)> {
    let mut objects = Vec::new();
    for (extent, path_table) in [
        (primary_tables.extents[0], MetadataPathTable::PrimaryLittle),
        (primary_tables.extents[2], MetadataPathTable::PrimaryBig),
        (joliet_tables.extents[0], MetadataPathTable::JolietLittle),
        (joliet_tables.extents[2], MetadataPathTable::JolietBig),
    ] {
        objects.push(MetadataObject {
            start: extent,
            end: extent
                .checked_add(
                    if matches!(
                        path_table,
                        MetadataPathTable::PrimaryLittle | MetadataPathTable::PrimaryBig
                    ) {
                        primary_tables.blocks
                    } else {
                        joliet_tables.blocks
                    },
                )
                .context("metadata path-table extent overflow")?,
            item: MetadataLayoutItem::path_table(path_table),
        });
    }
    let grouped_directories =
        [primary_directories, joliet_directories]
            .into_iter()
            .all(|directories| {
                !directories.is_empty()
                    && directories.windows(2).all(|pair| {
                        pair[0]
                            .extent
                            .checked_add(pair[0].length.div_ceil(LOGICAL_BLOCK_SIZE as u32))
                            == Some(pair[1].extent)
                    })
            });
    if grouped_directories {
        for (directories, volume) in [
            (primary_directories, MetadataVolume::Primary),
            (joliet_directories, MetadataVolume::Joliet),
        ] {
            let first = directories
                .first()
                .context("metadata directory set is empty")?;
            let mut end = first.extent;
            for directory in directories {
                ensure!(
                    directory.extent == end,
                    "metadata directory set is not physically contiguous"
                );
                end = end
                    .checked_add(directory.length.div_ceil(LOGICAL_BLOCK_SIZE as u32))
                    .context("metadata directory extent overflow")?;
            }
            objects.push(MetadataObject {
                start: first.extent,
                end,
                item: MetadataLayoutItem::directories(volume),
            });
        }
    }
    objects.sort_by_key(|object| object.start);
    let mut cursor = start;
    let mut layout = Vec::new();
    let mut gaps = Vec::new();
    for object in objects {
        ensure!(object.start >= cursor, "overlapping ISO metadata extents");
        if object.start > cursor {
            ensure!(
                blocks[usize::try_from(cursor)?..usize::try_from(object.start)?]
                    .iter()
                    .all(|block| block.iter().all(|byte| *byte == 0)),
                "unsupported nonzero sectors between ISO metadata extents"
            );
            let sectors = object.start - cursor;
            layout.push(MetadataLayoutItem::gap(sectors, GapKind::Xa));
            gaps.push(GapPlacement {
                start: cursor,
                sectors,
                kind: GapKind::Xa,
                subheader: None,
                form2_edc: None,
            });
        }
        layout.push(object.item);
        cursor = object.end;
    }
    Ok((layout, gaps))
}

fn infer_directory_length_policy(
    iso: &Iso9660,
    primary: &[ParsedDirectory],
    joliet: &[ParsedDirectory],
) -> Result<DirectoryLengthPolicy> {
    let primary_files = iso
        .files
        .iter()
        .filter_map(FileLayoutItem::as_path)
        .collect::<HashSet<_>>();
    let primary_records = primary.iter().map(|directory| {
        let lengths = directory_record_lengths(&directory.path, iso, &primary_files);
        (
            directory.length,
            packed_length(&lengths, iso.directory_record_packing),
        )
    });
    let volume = iso
        .supplementary_volumes
        .first()
        .context("missing Joliet volume")?;
    let joliet_records = joliet.iter().map(|directory| {
        let lengths = joliet_directory_record_lengths(&directory.path, volume)?;
        Ok((
            directory.length,
            packed_length(&lengths, iso.directory_record_packing),
        ))
    });
    let values = primary_records
        .map(Ok)
        .chain(joliet_records)
        .collect::<Result<Vec<(u32, usize)>>>()?;
    if values
        .iter()
        .all(|(length, _)| length.is_multiple_of(LOGICAL_BLOCK_SIZE as u32))
    {
        Ok(DirectoryLengthPolicy::Allocated)
    } else if values
        .iter()
        .all(|(length, records)| usize::try_from(*length) == Ok(*records))
    {
        Ok(DirectoryLengthPolicy::Records)
    } else {
        anyhow::bail!("primary and Joliet directories use inconsistent recorded lengths")
    }
}

fn file_allocation_padding_hex(
    blocks: &[[u8; LOGICAL_BLOCK_SIZE]],
    record: &Record,
) -> Option<String> {
    let offset = usize::try_from(record.length).ok()? % LOGICAL_BLOCK_SIZE;
    if offset == 0 {
        return None;
    }
    let final_lba = record
        .extent
        .checked_add(record.length / LOGICAL_BLOCK_SIZE as u32)?;
    let padding = blocks
        .get(usize::try_from(final_lba).ok()?)?
        .get(offset..)?;
    let last = padding.iter().rposition(|byte| *byte != 0)?;
    Some(hex::encode(&padding[..=last]))
}

fn parse_pvd(block: &[u8; LOGICAL_BLOCK_SIZE]) -> Result<PrimaryVolume> {
    ensure!(read_both_u32(block, 80)? > 0, "invalid volume size");
    let u16_encoding = pvd_u16_encoding(block)?;
    ensure!(
        u16::from_le_bytes(block[120..122].try_into()?) == VOLUME_SET_SIZE,
        "unsupported volume set size"
    );
    ensure!(
        u16::from_le_bytes(block[124..126].try_into()?) == VOLUME_SEQUENCE_NUMBER,
        "unsupported volume sequence number"
    );
    ensure!(
        u16::from_le_bytes(block[128..130].try_into()?) == ISO_LOGICAL_BLOCK_SIZE,
        "unsupported logical block size"
    );
    let file_structure_version = match block[881] {
        FILE_STRUCTURE_VERSION => None,
        0 => Some(0),
        _ => anyhow::bail!("unsupported file structure version"),
    };
    let application_use = [
        PrimaryVolumeApplicationUse::CdXa001,
        PrimaryVolumeApplicationUse::CdXa001_1_1,
        PrimaryVolumeApplicationUse::CdXa001Xcd3221Revision13,
        PrimaryVolumeApplicationUse::CdRep20131,
    ]
    .into_iter()
    .find(|kind| {
        block[APPLICATION_USE_START..APPLICATION_USE_END] == primary_volume_application_use(*kind)
    });
    Ok(PrimaryVolume {
        volume_space_size: None,
        file_structure_version,
        u16_encoding,
        application_use: application_use.unwrap_or_default(),
        application_use_hex: application_use
            .is_none()
            .then(|| hex::encode(&block[APPLICATION_USE_START..APPLICATION_USE_END])),
        root_directory_record_length: None,
        root_directory_recording_time: None,
        root_directory_identifier: match block[189] {
            0 => RootDirectoryIdentifier::Current,
            1 => RootDirectoryIdentifier::Parent,
            value => anyhow::bail!("unsupported PVD root directory identifier {value}"),
        },
        escape_sequence: parse_optional_joliet_level(&block[88..120])?,
        system_identifier: read_fixed(block, 8, 32)?,
        volume_identifier: read_fixed(block, 40, 32)?,
        volume_set_identifier: read_fixed(block, 190, 128)?,
        publisher_identifier: read_fixed(block, 318, 128)?,
        data_preparer_identifier: read_fixed(block, 446, 128)?,
        application_identifier: read_fixed(block, 574, 128)?,
        copyright_file_identifier: read_fixed(block, 702, 37)?,
        abstract_file_identifier: read_fixed(block, 739, 37)?,
        bibliographic_file_identifier: read_fixed(block, 776, 37)?,
        reserved_hex: block[APPLICATION_USE_END..]
            .iter()
            .rposition(|byte| *byte != 0)
            .map(|last| hex::encode(&block[APPLICATION_USE_END..=APPLICATION_USE_END + last])),
        creation_time: parse_volume_time(&block[813..830]).context("invalid PVD creation time")?,
        modification_time: parse_volume_time(&block[830..847])
            .context("invalid PVD modification time")?,
        expiration_time: parse_volume_time(&block[847..864])
            .context("invalid PVD expiration time")?,
        effective_time: parse_volume_time(&block[864..881])
            .context("invalid PVD effective time")?,
    })
}

struct ParsedJoliet {
    volume: JolietVolume,
    directories: Vec<ParsedDirectory>,
    path_tables: ParsedPathTables,
}

fn parse_joliet(
    blocks: &[[u8; LOGICAL_BLOCK_SIZE]],
    block: &[u8; LOGICAL_BLOCK_SIZE],
    primary_files: &[ParsedFile],
) -> Result<ParsedJoliet> {
    let level = parse_joliet_level(&block[88..120])?;
    let path_table_size = read_both_u32(block, 132)?;
    ensure!(path_table_size > 0, "invalid Joliet path table size");
    let path_blocks = path_table_size.div_ceil(LOGICAL_BLOCK_SIZE as u32);
    let pointers = [
        u32::from_le_bytes(block[140..144].try_into()?),
        u32::from_le_bytes(block[144..148].try_into()?),
        u32::from_be_bytes(block[148..152].try_into()?),
        u32::from_be_bytes(block[152..156].try_into()?),
    ];
    ensure!(
        pointers[0] != 0 && pointers[1] == 0 && pointers[2] != 0 && pointers[3] == 0,
        "Joliet volume requires one little- and one big-endian path table"
    );
    for extent in [pointers[0], pointers[2]] {
        ensure!(
            extent
                .checked_add(path_blocks)
                .is_some_and(|end| usize::try_from(end).is_ok_and(|end| end <= blocks.len())),
            "Joliet path table extent is outside image"
        );
    }
    let mut descriptor = parse_joliet_descriptor(block)?;
    let root_record = parse_record(&block[156..])?;
    validate_record_fields(&root_record, true)?;
    ensure!(
        root_record.system_use.is_empty(),
        "unsupported Joliet descriptor root system-use data"
    );
    let (root_records, _, _) = read_directory(blocks, root_record.extent, root_record.length)?;
    ensure!(
        root_records.len() >= 2,
        "Joliet root directory lacks dot records"
    );
    let dot = &root_records[0];
    let xa_system_use = !dot.system_use.is_empty();
    descriptor.root_directory_recording_time = {
        let descriptor_time = parse_recording_time(root_record.recording_time)?;
        let dot_time = parse_recording_time(dot.recording_time)?;
        (descriptor_time != dot_time).then_some(descriptor_time)
    };
    let root = JolietEntry {
        path: ROOT_PATH.to_owned(),
        source: None,
        omit_version: false,
        recording_time: parse_recording_time(dot.recording_time)?,
        hidden: root_record.flags & HIDDEN_FLAG != 0,
        associated: root_record.flags & ASSOCIATED_FLAG != 0,
        xa: entry_xa(dot, true, xa_system_use)?,
    };
    let primary_sources = primary_files.iter().fold(
        HashMap::<(u32, u32), Vec<&str>>::new(),
        |mut result, file| {
            result
                .entry((file.extent, file.length))
                .or_default()
                .push(file.path.as_str());
            result
        },
    );
    let mut entries = vec![root];
    let mut directories = vec![ParsedDirectory {
        path: ROOT_PATH.to_owned(),
        extent: root_record.extent,
        length: root_record.length,
    }];
    let mut queue = VecDeque::from([(String::new(), root_record.extent, root_record.length)]);
    let mut seen_dirs = HashSet::new();
    while let Some((parent, extent, length)) = queue.pop_front() {
        ensure!(
            seen_dirs.insert(extent),
            "Joliet directory extent cycle at LBA {extent}"
        );
        let (records, _, slack) = read_directory(blocks, extent, length)?;
        ensure!(slack.is_none(), "unsupported Joliet directory slack");
        ensure!(records.len() >= 2, "Joliet directory lacks dot records");
        for record in &records {
            let directory = record.flags & DIRECTORY_FLAG != 0;
            validate_standard_record_fields(record, directory, xa_system_use)?;
        }
        for record in records.into_iter().skip(2) {
            let is_dir = record.flags & DIRECTORY_FLAG != 0;
            let raw_name = decode_joliet_identifier(&record.name)?;
            let (name, omit_version) = if is_dir {
                (raw_name, false)
            } else if let Some((name, version)) = raw_name.rsplit_once(';') {
                ensure!(version == "1", "unsupported Joliet file version");
                (name.to_owned(), false)
            } else {
                (raw_name, true)
            };
            let path = if parent.is_empty() {
                name
            } else {
                format!("{parent}/{name}")
            };
            let source = if is_dir {
                None
            } else {
                let candidates = primary_sources
                    .get(&(record.extent, record.length))
                    .context("Joliet file has no matching primary extent and length")?;
                ensure!(
                    candidates.len() == 1,
                    "Joliet file extent and length match multiple primary files"
                );
                Some(candidates[0].to_owned())
            };
            entries.push(JolietEntry {
                path: path.clone(),
                source,
                omit_version,
                recording_time: parse_recording_time(record.recording_time)?,
                hidden: record.flags & HIDDEN_FLAG != 0,
                associated: record.flags & ASSOCIATED_FLAG != 0,
                xa: entry_xa(&record, is_dir, xa_system_use)?,
            });
            if is_dir {
                directories.push(ParsedDirectory {
                    path: path.clone(),
                    extent: record.extent,
                    length: record.length,
                });
                queue.push_back((path, record.extent, record.length));
            }
        }
    }
    let placements = parsed_joliet_placements(&directories)?;
    let generated_size = u32::try_from(serialize_path_table(&placements, false)?.len())?;
    ensure!(
        generated_size.div_ceil(LOGICAL_BLOCK_SIZE as u32) == path_blocks,
        "Joliet path table size changes its physical allocation"
    );
    let canonical_little = serialize_path_table(&placements, false)?;
    let canonical_big = serialize_path_table(&placements, true)?;
    let little = read_path_table(blocks, pointers[0], path_table_size)?;
    let big = read_path_table(blocks, pointers[2], path_table_size)?;
    let noncanonical =
        path_table_size != generated_size || little != canonical_little || big != canonical_big;
    let odd_bytes = [block[738], block[775], block[812]];
    let (zero_fill_empty_strings, zero_pad_strings, volume_set_identifier_raw_hex) =
        joliet_string_padding(block, &descriptor)?;
    descriptor.volume_space_size = None;
    Ok(ParsedJoliet {
        volume: JolietVolume {
            level,
            flags: block[7],
            zero_fill_empty_strings,
            zero_pad_strings,
            volume_set_identifier_raw_hex,
            descriptor,
            xa_system_use,
            path_table_size: (path_table_size != generated_size).then_some(path_table_size),
            path_table_little_hex: noncanonical.then(|| hex::encode(little)),
            path_table_big_hex: noncanonical.then(|| hex::encode(big)),
            file_identifier_odd_bytes_hex: (odd_bytes != [0; 3]).then(|| hex::encode(odd_bytes)),
            entries,
        },
        directories,
        path_tables: ParsedPathTables {
            extents: pointers,
            blocks: path_blocks,
        },
    })
}

fn joliet_string_padding(
    block: &[u8; LOGICAL_BLOCK_SIZE],
    descriptor: &PrimaryVolume,
) -> Result<(bool, bool, Option<String>)> {
    let fields = [
        (8, 32, descriptor.system_identifier.as_str()),
        (40, 32, descriptor.volume_identifier.as_str()),
        (190, 128, descriptor.volume_set_identifier.as_str()),
        (318, 128, descriptor.publisher_identifier.as_str()),
        (446, 128, descriptor.data_preparer_identifier.as_str()),
        (574, 128, descriptor.application_identifier.as_str()),
    ];
    let mut empty_fill = None;
    let mut nonempty_padding = None;
    let mut volume_set_identifier_raw_hex = None;
    for (offset, length, value) in fields {
        let encoded = if value.is_empty() {
            Vec::new()
        } else {
            encode_joliet_identifier(value)?
        };
        let padding = &block[offset + encoded.len()..offset + length];
        if padding.is_empty() {
            continue;
        }
        let zero = padding.iter().all(|byte| *byte == 0);
        let spaces = padding.chunks_exact(2).all(|pair| pair == [0, b' ']);
        if !zero && !spaces && offset == 190 && value.is_empty() {
            volume_set_identifier_raw_hex = Some(hex::encode(&block[offset..offset + length]));
            continue;
        }
        ensure!(zero || spaces, "unsupported Joliet string padding");
        let detected = if value.is_empty() {
            &mut empty_fill
        } else {
            &mut nonempty_padding
        };
        ensure!(
            detected.is_none_or(|previous| previous == zero),
            "mixed Joliet string padding"
        );
        *detected = Some(zero);
    }
    Ok((
        empty_fill.unwrap_or(false),
        nonempty_padding.unwrap_or(false),
        volume_set_identifier_raw_hex,
    ))
}

fn parsed_joliet_placements(directories: &[ParsedDirectory]) -> Result<Vec<DirectoryPlacement>> {
    let indices = directories
        .iter()
        .enumerate()
        .map(|(index, directory)| (directory.path.as_str(), index))
        .collect::<HashMap<_, _>>();
    directories
        .iter()
        .map(|directory| {
            let root = directory.path == ROOT_PATH;
            Ok(DirectoryPlacement {
                path: directory.path.clone(),
                name: if root {
                    vec![0]
                } else {
                    encode_joliet_identifier(file_name(&directory.path))?
                },
                parent: if root {
                    0
                } else {
                    *indices
                        .get(parent_path(&directory.path).as_str())
                        .context("Joliet path-table parent is missing")?
                },
                extent: directory.extent,
                blocks: directory.length.div_ceil(LOGICAL_BLOCK_SIZE as u32),
                length: directory.length,
            })
        })
        .collect()
}

fn parse_joliet_descriptor(block: &[u8; LOGICAL_BLOCK_SIZE]) -> Result<PrimaryVolume> {
    let mut descriptor = parse_pvd_fields(block, read_joliet_fixed)?;
    descriptor.escape_sequence = None;
    Ok(descriptor)
}

fn parse_pvd_fields(
    block: &[u8; LOGICAL_BLOCK_SIZE],
    read_string: fn(&[u8], usize, usize) -> Result<String>,
) -> Result<PrimaryVolume> {
    ensure!(read_both_u32(block, 80)? > 0, "invalid volume size");
    let u16_encoding = pvd_u16_encoding(block)?;
    ensure!(
        u16::from_le_bytes(block[120..122].try_into()?) == VOLUME_SET_SIZE,
        "unsupported volume set size"
    );
    ensure!(
        u16::from_le_bytes(block[124..126].try_into()?) == VOLUME_SEQUENCE_NUMBER,
        "unsupported volume sequence number"
    );
    ensure!(
        u16::from_le_bytes(block[128..130].try_into()?) == ISO_LOGICAL_BLOCK_SIZE,
        "unsupported logical block size"
    );
    let file_structure_version = match block[881] {
        FILE_STRUCTURE_VERSION => None,
        0 => Some(0),
        _ => anyhow::bail!("unsupported file structure version"),
    };
    let application_use = [
        PrimaryVolumeApplicationUse::CdXa001,
        PrimaryVolumeApplicationUse::CdXa001_1_1,
        PrimaryVolumeApplicationUse::CdXa001Xcd3221Revision13,
        PrimaryVolumeApplicationUse::CdRep20131,
    ]
    .into_iter()
    .find(|kind| {
        block[APPLICATION_USE_START..APPLICATION_USE_END] == primary_volume_application_use(*kind)
    });
    Ok(PrimaryVolume {
        volume_space_size: None,
        file_structure_version,
        u16_encoding,
        application_use: application_use.unwrap_or_default(),
        application_use_hex: application_use
            .is_none()
            .then(|| hex::encode(&block[APPLICATION_USE_START..APPLICATION_USE_END])),
        root_directory_record_length: None,
        root_directory_recording_time: None,
        root_directory_identifier: match block[189] {
            0 => RootDirectoryIdentifier::Current,
            1 => RootDirectoryIdentifier::Parent,
            value => anyhow::bail!("unsupported PVD root directory identifier {value}"),
        },
        escape_sequence: None,
        system_identifier: read_string(block, 8, 32)?,
        volume_identifier: read_string(block, 40, 32)?,
        volume_set_identifier: read_string(block, 190, 128)?,
        publisher_identifier: read_string(block, 318, 128)?,
        data_preparer_identifier: read_string(block, 446, 128)?,
        application_identifier: read_string(block, 574, 128)?,
        copyright_file_identifier: read_string(block, 702, 37)?,
        abstract_file_identifier: read_string(block, 739, 37)?,
        bibliographic_file_identifier: read_string(block, 776, 37)?,
        reserved_hex: block[APPLICATION_USE_END..]
            .iter()
            .rposition(|byte| *byte != 0)
            .map(|last| hex::encode(&block[APPLICATION_USE_END..=APPLICATION_USE_END + last])),
        creation_time: parse_volume_time(&block[813..830]).context("invalid PVD creation time")?,
        modification_time: parse_volume_time(&block[830..847])
            .context("invalid PVD modification time")?,
        expiration_time: parse_volume_time(&block[847..864])
            .context("invalid PVD expiration time")?,
        effective_time: parse_volume_time(&block[864..881])
            .context("invalid PVD effective time")?,
    })
}

fn parse_optional_joliet_level(bytes: &[u8]) -> Result<Option<JolietLevel>> {
    if bytes.iter().all(|byte| *byte == 0) {
        Ok(None)
    } else {
        parse_joliet_level(bytes).map(Some)
    }
}

fn parse_joliet_level(bytes: &[u8]) -> Result<JolietLevel> {
    ensure!(
        bytes.len() == 32 && bytes[3..].iter().all(|byte| *byte == 0),
        "unsupported volume-descriptor escape sequence"
    );
    match &bytes[..3] {
        b"%/@" => Ok(JolietLevel::Level1),
        b"%/C" => Ok(JolietLevel::Level2),
        b"%/E" => Ok(JolietLevel::Level3),
        _ => anyhow::bail!("unsupported volume-descriptor escape sequence"),
    }
}

fn joliet_escape_sequence(level: JolietLevel) -> [u8; 3] {
    match level {
        JolietLevel::Level1 => *b"%/@",
        JolietLevel::Level2 => *b"%/C",
        JolietLevel::Level3 => *b"%/E",
    }
}

fn decode_joliet_identifier(bytes: &[u8]) -> Result<String> {
    ensure!(
        bytes.len().is_multiple_of(2),
        "Joliet identifier has an odd byte length"
    );
    let units = bytes
        .chunks_exact(2)
        .map(|pair| u16::from_be_bytes([pair[0], pair[1]]))
        .collect::<Vec<_>>();
    String::from_utf16(&units).context("invalid Joliet UCS-2 identifier")
}

fn encode_joliet_identifier(value: &str) -> Result<Vec<u8>> {
    let mut result = Vec::new();
    for character in value.chars() {
        ensure!(
            u32::from(character) <= u32::from(u16::MAX),
            "Joliet identifier contains a non-UCS-2 character"
        );
        result.extend_from_slice(&u16::try_from(u32::from(character))?.to_be_bytes());
    }
    ensure!(
        !result.is_empty() && result.len() <= 128,
        "Joliet identifier must contain between 1 and 64 UCS-2 characters"
    );
    Ok(result)
}

fn read_joliet_fixed(bytes: &[u8], offset: usize, length: usize) -> Result<String> {
    let value = decode_joliet_identifier(&bytes[offset..offset + length / 2 * 2])?;
    Ok(value.trim_end_matches([' ', '\0']).to_owned())
}

fn primary_volume_application_use(
    kind: PrimaryVolumeApplicationUse,
) -> [u8; APPLICATION_USE_END - APPLICATION_USE_START] {
    let mut data = [0; APPLICATION_USE_END - APPLICATION_USE_START];
    if kind == PrimaryVolumeApplicationUse::CdRep20131 {
        data[..14].copy_from_slice(b"CD Rep 2.0.131");
        return data;
    }
    data[CD_XA_SIGNATURE_OFFSET..CD_XA_SIGNATURE_OFFSET + 8].copy_from_slice(b"CD-XA001");
    if kind == PrimaryVolumeApplicationUse::CdXa001_1_1 {
        data[CD_XA_SIGNATURE_OFFSET + 8..CD_XA_SIGNATURE_OFFSET + 18]
            .copy_from_slice(&[0, 0, b'1', b' ', b'1', b' ', b' ', b' ', b' ', b' ']);
    }
    if kind == PrimaryVolumeApplicationUse::CdXa001Xcd3221Revision13 {
        data[APPLICATION_USE_END - APPLICATION_USE_START - 12..].copy_from_slice(b"XCD322.1 (13");
    }
    data
}

#[derive(Clone, Copy, Default)]
struct DirectoryPackingObservation {
    skipped_exact_fit: bool,
    packed_exact_fit: bool,
}

impl DirectoryPackingObservation {
    fn merge(&mut self, other: Self) {
        self.skipped_exact_fit |= other.skipped_exact_fit;
        self.packed_exact_fit |= other.packed_exact_fit;
    }
}

fn read_directory(
    blocks: &[[u8; LOGICAL_BLOCK_SIZE]],
    extent: u32,
    length: u32,
) -> Result<(
    Vec<Record>,
    DirectoryPackingObservation,
    Option<DirectorySlack>,
)> {
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
    let mut observation = DirectoryPackingObservation::default();
    let mut offset = 0;
    let mut final_record_end = 0;
    while offset < bytes.len() {
        let length = usize::from(bytes[offset]);
        if length == 0 {
            let next_block = (offset / LOGICAL_BLOCK_SIZE + 1) * LOGICAL_BLOCK_SIZE;
            if next_block < bytes.len()
                && bytes[next_block] != 0
                && next_block - offset == usize::from(bytes[next_block])
                && bytes[offset..next_block].iter().all(|byte| *byte == 0)
            {
                observation.skipped_exact_fit = true;
            }
            offset = next_block;
            continue;
        }
        ensure!(offset + length <= bytes.len(), "truncated directory record");
        records.push(parse_record(&bytes[offset..offset + length])?);
        offset += length;
        final_record_end = offset;
        if offset.is_multiple_of(LOGICAL_BLOCK_SIZE) {
            observation.packed_exact_fit = true;
        }
    }
    let trailing = &bytes[final_record_end..];
    let directory_slack = trailing.iter().position(|byte| *byte != 0).map(|first| {
        let last = trailing
            .iter()
            .rposition(|byte| *byte != 0)
            .expect("nonzero trailing byte");
        DirectorySlack {
            offset: u32::try_from(final_record_end + first).expect("directory offset fits u32"),
            hex: hex::encode(&trailing[first..=last]),
        }
    });
    Ok((records, observation, directory_slack))
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
    let unpadded_system_use_start = 33 + name_length;
    let standard_system_use_start =
        unpadded_system_use_start + usize::from(name_length.is_multiple_of(2));
    ensure!(
        standard_system_use_start <= record_length,
        "invalid directory record padding"
    );
    let standard_system_use = &bytes[standard_system_use_start..record_length];
    let trailing_system_use_padding = name_length.is_multiple_of(2)
        && record_length > unpadded_system_use_start
        && bytes[record_length - 1] == 0
        && !is_xa_system_use(standard_system_use)
        && is_xa_system_use(&bytes[unpadded_system_use_start..record_length - 1]);
    let system_use = if trailing_system_use_padding {
        &bytes[unpadded_system_use_start..record_length - 1]
    } else {
        standard_system_use
    };
    Ok(Record {
        extent: read_both_u32(bytes, 2)?,
        length: read_both_u32(bytes, 10)?,
        recording_time: bytes[18..25].try_into()?,
        flags: bytes[25],
        file_unit_size: bytes[26],
        interleave_gap_size: bytes[27],
        volume_sequence_number: read_both_u16(bytes, 28)?,
        name: bytes[33..33 + name_length].to_vec(),
        system_use: system_use.to_vec(),
        trailing_system_use_padding,
    })
}

fn is_xa_system_use(bytes: &[u8]) -> bool {
    bytes.len() == XA_SYSTEM_USE_SIZE && bytes[6..8] == *b"XA" && bytes[9..14] == [0; 5]
}

fn validate_standard_record_fields(
    record: &Record,
    directory: bool,
    uses_xa_system_use: bool,
) -> Result<()> {
    validate_record_fields(record, directory)?;
    entry_xa(record, directory, uses_xa_system_use)?;
    Ok(())
}

fn validate_record_fields(record: &Record, directory: bool) -> Result<()> {
    let expected_directory_flag = if directory { DIRECTORY_FLAG } else { 0 };
    ensure!(
        record.flags & DIRECTORY_FLAG == expected_directory_flag
            && record.flags & !(HIDDEN_FLAG | DIRECTORY_FLAG | ASSOCIATED_FLAG) == 0,
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
    Ok(())
}

fn entry_xa(record: &Record, directory: bool, uses_xa_system_use: bool) -> Result<Option<EntryXa>> {
    if !uses_xa_system_use {
        ensure!(
            record.system_use.is_empty(),
            "unsupported PVD root directory-record system-use data"
        );
        return Ok(None);
    }

    ensure!(
        record.system_use.len() == XA_SYSTEM_USE_SIZE,
        "unsupported directory-record XA system-use data"
    );
    let bytes = &record.system_use;
    ensure!(
        is_xa_system_use(bytes),
        "unsupported directory-record XA system-use data"
    );
    let group_id = u16::from_be_bytes(bytes[0..2].try_into()?);
    let user_id = u16::from_be_bytes(bytes[2..4].try_into()?);
    let raw_attributes = u16::from_be_bytes(bytes[4..6].try_into()?);
    let permissions = raw_attributes & !XA_ATTRIBUTE_MASK;
    let attributes = XaAttributes::from_bits(raw_attributes & XA_ATTRIBUTE_MASK);
    ensure!(
        directory || !attributes.contains(crate::manifest::XaAttributeFlag::Directory),
        "file directory record has XA directory attribute"
    );
    let default_attributes = if directory {
        XaAttributes::MODE2_FORM1.bits() | XaAttributes::DIRECTORY.bits()
    } else {
        XaAttributes::MODE2_FORM1.bits()
    };
    let file_number = bytes[8];
    if group_id == 0
        && user_id == 0
        && permissions == DEFAULT_XA_PERMISSIONS
        && attributes.bits() == default_attributes
        && file_number == 0
    {
        Ok(None)
    } else {
        Ok(Some(EntryXa {
            group_id,
            user_id,
            permissions,
            attributes: Some(attributes),
            file_number,
            form1: None,
            form2: None,
            index: None,
            gap_index: None,
            logical_length: None,
            length_encoding: XaLengthEncoding::default(),
            framing_subheader: None,
        }))
    }
}

fn entry_xa_is_cdda(xa: &EntryXa) -> bool {
    xa.attributes
        .is_some_and(|attributes| attributes.contains(crate::manifest::XaAttributeFlag::Cdda))
}

fn serialize_xa_system_use(entry: &Entry, directory: bool) -> Result<Vec<u8>> {
    serialize_xa_system_use_parts(&entry.path, entry.xa.as_ref(), directory)
}

fn serialize_xa_system_use_parts(
    path: &str,
    xa: Option<&EntryXa>,
    directory: bool,
) -> Result<Vec<u8>> {
    let attributes = xa.and_then(|value| value.attributes).unwrap_or_else(|| {
        if directory {
            XaAttributes::from_bits(
                XaAttributes::MODE2_FORM1.bits() | XaAttributes::DIRECTORY.bits(),
            )
        } else {
            XaAttributes::MODE2_FORM1
        }
    });
    ensure!(
        directory || !attributes.contains(crate::manifest::XaAttributeFlag::Directory),
        "file entry has XA directory attribute: {path}"
    );
    let permissions = xa.map_or(DEFAULT_XA_PERMISSIONS, |value| value.permissions);
    ensure!(
        permissions & XA_ATTRIBUTE_MASK == 0,
        "XA permissions overlap attribute bits for {path}"
    );
    let mut result = vec![0_u8; XA_SYSTEM_USE_SIZE];
    result[0..2].copy_from_slice(&xa.map_or(0, |value| value.group_id).to_be_bytes());
    result[2..4].copy_from_slice(&xa.map_or(0, |value| value.user_id).to_be_bytes());
    result[4..6].copy_from_slice(&(permissions | attributes.bits()).to_be_bytes());
    result[6..8].copy_from_slice(b"XA");
    result[8] = xa.map_or(0, |value| value.file_number);
    Ok(result)
}

fn serialize_directory_record_system_use(
    entry: &Entry,
    directory: bool,
    xa_system_use: bool,
) -> Result<Vec<u8>> {
    if xa_system_use {
        serialize_xa_system_use(entry, directory)
    } else {
        Ok(Vec::new())
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
    pub xa_extents: Vec<XaExtentPlacement>,
    pub gaps: Vec<GapPlacement>,
    pub data_subheader_sectors: HashSet<u32>,
    pub trailing_gap_kind: Option<GapKind>,
    pub end_of_file_data_subheader_sectors: HashSet<u32>,
    pub metadata_subheader_sectors: HashSet<u32>,
    pub framing_subheader_sectors: HashMap<u32, XaSubheader>,
    pub sector_file_numbers: HashMap<u32, u8>,
    pub volume_blocks: u32,
}

#[derive(Debug, Clone)]
pub struct XaExtentPlacement {
    pub index: String,
    pub start: u32,
    pub sectors: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GapPlacement {
    pub start: u32,
    pub sectors: u32,
    pub kind: GapKind,
    pub subheader: Option<XaSubheader>,
    pub form2_edc: Option<bool>,
}

pub fn validate(iso: &Iso9660) -> Result<()> {
    validate_entries(iso).map(drop)
}

#[derive(Debug, Clone)]
struct DirectoryPlacement {
    path: String,
    name: Vec<u8>,
    parent: usize,
    extent: u32,
    blocks: u32,
    length: u32,
}

#[derive(Debug)]
struct JolietLayout<'a> {
    volume: &'a JolietVolume,
    placements: Vec<DirectoryPlacement>,
    pointers: [u32; 4],
    path_blocks: u32,
    path_table_size: u32,
}

pub fn layout(iso: &Iso9660, file_lengths: &HashMap<String, u64>) -> Result<Layout> {
    let file_paths = validate_entries(iso)?;
    let directories = directory_order(&iso.entries, &file_paths)?;
    let path_table_size: usize = directories
        .iter()
        .map(|(_, name, _)| 8 + name.len() + usize::from(name.len() % 2 == 1))
        .sum();
    let path_blocks = path_table_size.div_ceil(LOGICAL_BLOCK_SIZE).max(1) as u32;
    let generated_path_table_size = u32::try_from(path_table_size)?;
    let pvd_path_table_size = iso.path_table_size.unwrap_or(generated_path_table_size);
    ensure!(pvd_path_table_size > 0, "path_table_size must be nonzero");
    ensure!(
        pvd_path_table_size.div_ceil(LOGICAL_BLOCK_SIZE as u32) == path_blocks,
        "path_table_size must retain the generated physical allocation"
    );
    let path_table_start = 17 + u32::from(iso.primary_volume_copies);
    let path_table_stride = path_blocks
        .checked_add(iso.path_table_padding)
        .context("path-table allocation stride overflow")?;
    let (mut path_table_pointers, mut next_extent) =
        match (iso.path_table_copies, iso.path_table_order) {
            (PathTableCopies::Duplicate, PathTableOrder::LittleEndianFirst) => (
                [
                    path_table_start,
                    path_table_start + path_table_stride,
                    path_table_start + path_table_stride * 2,
                    path_table_start + path_table_stride * 3,
                ],
                path_table_start + path_table_stride * 4,
            ),
            (PathTableCopies::Duplicate, PathTableOrder::BigEndianFirst) => (
                [
                    path_table_start + path_table_stride * 2,
                    path_table_start + path_table_stride * 3,
                    path_table_start,
                    path_table_start + path_table_stride,
                ],
                path_table_start + path_table_stride * 4,
            ),
            (PathTableCopies::Single, PathTableOrder::LittleEndianFirst) => (
                [path_table_start, 0, path_table_start + path_table_stride, 0],
                path_table_start + path_table_stride * 2,
            ),
            (PathTableCopies::Single, PathTableOrder::BigEndianFirst) => (
                [path_table_start + path_table_stride, 0, path_table_start, 0],
                path_table_start + path_table_stride * 2,
            ),
        };
    let mut path_table_padding_gaps = path_table_pointers
        .iter()
        .copied()
        .filter(|pointer| *pointer != 0 && iso.path_table_padding != 0)
        .map(|pointer| GapPlacement {
            start: pointer + path_blocks,
            sectors: iso.path_table_padding,
            kind: GapKind::Xa,
            form2_edc: None,
            subheader: None,
        })
        .collect::<Vec<_>>();
    path_table_padding_gaps.sort_by_key(|gap| gap.start);

    let entry_by_path: HashMap<_, _> = iso
        .entries
        .iter()
        .map(|entry| (entry.path.as_str(), entry))
        .collect();
    let mut placements = Vec::with_capacity(directories.len());
    for (path, name, parent) in &directories {
        let entry = entry_by_path[path.as_str()];
        let (extent, blocks, length) = match entry.directory_reference {
            Some(reference) => (reference.extent, 0, reference.length),
            None => {
                let record_lengths = directory_record_lengths(path, iso, &file_paths);
                let records_length = packed_length(&record_lengths, iso.directory_record_packing);
                let allocated_length = if let Some(slack) = &entry.directory_slack {
                    let slack_length = hex::decode(&slack.hex)
                        .with_context(|| format!("decoding directory_slack for {path}"))?
                        .len();
                    records_length.max(
                        usize::try_from(slack.offset)?
                            .checked_add(slack_length)
                            .context("directory_slack allocation overflow")?,
                    )
                } else {
                    records_length
                };
                let blocks = allocated_length.div_ceil(LOGICAL_BLOCK_SIZE).max(1) as u32;
                let length = match iso.directory_length_policy {
                    DirectoryLengthPolicy::Allocated => blocks * LOGICAL_BLOCK_SIZE as u32,
                    DirectoryLengthPolicy::Records => u32::try_from(records_length)?,
                };
                (0, blocks, length)
            }
        };
        placements.push(DirectoryPlacement {
            path: path.clone(),
            name: name.clone(),
            parent: *parent,
            extent,
            blocks,
            length,
        });
    }
    let directory_index: HashMap<_, _> = directories
        .iter()
        .enumerate()
        .map(|(index, (path, _, _))| (path.as_str(), index))
        .collect();
    let mut placed_directories = placements
        .iter()
        .map(|directory| {
            entry_by_path[directory.path.as_str()]
                .directory_reference
                .is_some()
        })
        .collect::<Vec<_>>();
    let mut joliet_layout = None;
    let mut joliet_directory_index = HashMap::new();
    let mut placed_joliet_directories = Vec::new();
    if let Some(volume) = iso.supplementary_volumes.first() {
        let joliet_directories = joliet_directory_order(&volume.entries)?;
        let generated_size = joliet_directories
            .iter()
            .map(|(_, name, _)| 8 + name.len() + usize::from(name.len() % 2 == 1))
            .sum::<usize>();
        let joliet_path_blocks = generated_size.div_ceil(LOGICAL_BLOCK_SIZE).max(1) as u32;
        let joliet_path_table_size = volume
            .path_table_size
            .unwrap_or(u32::try_from(generated_size)?);
        ensure!(
            joliet_path_table_size > 0
                && joliet_path_table_size.div_ceil(LOGICAL_BLOCK_SIZE as u32) == joliet_path_blocks,
            "Joliet path_table_size must retain the generated physical allocation"
        );
        let mut joliet_placements = Vec::with_capacity(joliet_directories.len());
        for (path, name, parent) in joliet_directories {
            let record_lengths = joliet_directory_record_lengths(&path, volume)?;
            let records_length = packed_length(&record_lengths, iso.directory_record_packing);
            let blocks = records_length.div_ceil(LOGICAL_BLOCK_SIZE).max(1) as u32;
            let length = match iso.directory_length_policy {
                DirectoryLengthPolicy::Allocated => blocks * LOGICAL_BLOCK_SIZE as u32,
                DirectoryLengthPolicy::Records => u32::try_from(records_length)?,
            };
            joliet_placements.push(DirectoryPlacement {
                path,
                name,
                parent,
                extent: 0,
                blocks,
                length,
            });
        }

        joliet_directory_index = joliet_placements
            .iter()
            .enumerate()
            .map(|(index, directory)| (directory.path.clone(), index))
            .collect();
        placed_joliet_directories = vec![false; joliet_placements.len()];
        path_table_pointers = [0; 4];
        next_extent = 17
            + u32::from(iso.primary_volume_copies)
            + u32::try_from(iso.supplementary_volumes.len())?;
        path_table_padding_gaps.clear();
        let mut joliet_pointers = [0; 4];
        for item in &iso.metadata_layout {
            match item {
                MetadataLayoutItem::PathTable(item) => {
                    let (pointer, blocks) = match item.path_table {
                        MetadataPathTable::PrimaryLittle => {
                            (&mut path_table_pointers[0], path_blocks)
                        }
                        MetadataPathTable::PrimaryBig => (&mut path_table_pointers[2], path_blocks),
                        MetadataPathTable::JolietLittle => {
                            (&mut joliet_pointers[0], joliet_path_blocks)
                        }
                        MetadataPathTable::JolietBig => {
                            (&mut joliet_pointers[2], joliet_path_blocks)
                        }
                    };
                    *pointer = next_extent;
                    next_extent = next_extent
                        .checked_add(blocks)
                        .context("metadata path-table placement overflow")?;
                }
                MetadataLayoutItem::Directories(item) => match item.directories {
                    MetadataVolume::Primary => {
                        for (index, directory) in placements.iter_mut().enumerate() {
                            if !placed_directories[index] {
                                directory.extent = next_extent;
                                next_extent = next_extent
                                    .checked_add(directory.blocks)
                                    .context("metadata directory placement overflow")?;
                                placed_directories[index] = true;
                            }
                        }
                    }
                    MetadataVolume::Joliet => {
                        for directory in &mut joliet_placements {
                            directory.extent = next_extent;
                            next_extent = next_extent
                                .checked_add(directory.blocks)
                                .context("metadata directory placement overflow")?;
                        }
                        placed_joliet_directories.fill(true);
                    }
                },
                MetadataLayoutItem::Gap(item) => {
                    path_table_padding_gaps.push(GapPlacement {
                        start: next_extent,
                        sectors: item.gap,
                        form2_edc: None,
                        kind: item.kind,
                        subheader: None,
                    });
                    next_extent = next_extent
                        .checked_add(item.gap)
                        .context("metadata gap placement overflow")?;
                }
            }
        }
        joliet_layout = Some(JolietLayout {
            volume,
            placements: joliet_placements,
            pointers: joliet_pointers,
            path_blocks: joliet_path_blocks,
            path_table_size: joliet_path_table_size,
        });
    } else {
        placements[0].extent = next_extent;
        next_extent += placements[0].blocks;
        placed_directories[0] = true;
    }
    let explicit_directory_paths = iso
        .files
        .iter()
        .filter_map(FileLayoutItem::as_directory_placement)
        .collect::<HashSet<_>>();

    let mut external_ancestors = HashSet::new();
    for entry in iso.entries.iter().filter(|entry| entry.extent.is_some()) {
        let mut ancestor = parent_path(&entry.path);
        while ancestor != ROOT_PATH {
            let index = directory_index[ancestor.as_str()];
            external_ancestors.insert(index);
            ancestor = parent_path(&ancestor);
        }
    }
    for index in 1..placements.len() {
        if !placed_directories[index]
            && external_ancestors.contains(&index)
            && !explicit_directory_paths
                .contains(&(MetadataVolume::Primary, placements[index].path.as_str()))
        {
            placements[index].extent = next_extent;
            next_extent += placements[index].blocks;
            placed_directories[index] = true;
        }
    }

    let mut files = Vec::with_capacity(file_paths.len());
    let mut xa_extents = Vec::new();
    let mut gaps = path_table_padding_gaps;
    let mut pending_gaps = Vec::new();
    let mut trailing_gap = None;
    for item in &iso.files {
        if let Some((volume, path)) = item.as_directory_placement() {
            match volume {
                MetadataVolume::Primary => {
                    let mut ancestors = Vec::new();
                    let mut ancestor = parent_path(path);
                    while ancestor != ROOT_PATH {
                        ancestors.push(directory_index[ancestor.as_str()]);
                        ancestor = parent_path(&ancestor);
                    }
                    for index in ancestors.into_iter().rev() {
                        if !placed_directories[index]
                            && !explicit_directory_paths.contains(&(
                                MetadataVolume::Primary,
                                placements[index].path.as_str(),
                            ))
                        {
                            placements[index].extent = next_extent;
                            next_extent += placements[index].blocks;
                            placed_directories[index] = true;
                        }
                    }
                }
                MetadataVolume::Joliet => {
                    let mut ancestors = Vec::new();
                    let mut ancestor = parent_path(path);
                    while ancestor != ROOT_PATH {
                        ancestors.push(joliet_directory_index[ancestor.as_str()]);
                        ancestor = parent_path(&ancestor);
                    }
                    let joliet = joliet_layout
                        .as_mut()
                        .context("Joliet directory placement requires a supplementary volume")?;
                    for index in ancestors.into_iter().rev() {
                        if !placed_joliet_directories[index]
                            && !explicit_directory_paths.contains(&(
                                MetadataVolume::Joliet,
                                joliet.placements[index].path.as_str(),
                            ))
                        {
                            joliet.placements[index].extent = next_extent;
                            next_extent += joliet.placements[index].blocks;
                            placed_joliet_directories[index] = true;
                        }
                    }
                }
            }
            for (sectors, kind, subheader, form2_edc) in pending_gaps.drain(..) {
                gaps.push(GapPlacement {
                    start: next_extent,
                    sectors,
                    kind,
                    subheader,
                    form2_edc,
                });
                next_extent = next_extent
                    .checked_add(sectors)
                    .context("gap placement overflow")?;
            }
            match volume {
                MetadataVolume::Primary => {
                    let index = directory_index[path];
                    ensure!(
                        !placed_directories[index],
                        "directory placement was already allocated: {path}"
                    );
                    placements[index].extent = next_extent;
                    next_extent += placements[index].blocks;
                    placed_directories[index] = true;
                }
                MetadataVolume::Joliet => {
                    let index = joliet_directory_index[path];
                    ensure!(
                        !placed_joliet_directories[index],
                        "Joliet directory placement was already allocated: {path}"
                    );
                    let joliet = joliet_layout
                        .as_mut()
                        .context("Joliet directory placement requires a supplementary volume")?;
                    joliet.placements[index].extent = next_extent;
                    next_extent += joliet.placements[index].blocks;
                    placed_joliet_directories[index] = true;
                }
            }
            continue;
        }
        if let Some(assets) = item.as_xa_extent() {
            for (sectors, kind, subheader, form2_edc) in pending_gaps.drain(..) {
                gaps.push(GapPlacement {
                    start: next_extent,
                    sectors,
                    kind,
                    subheader,
                    form2_edc,
                });
                next_extent = next_extent
                    .checked_add(sectors)
                    .context("gap placement overflow")?;
            }
            let length = *file_lengths.get(&assets.index).with_context(|| {
                format!("missing unreferenced XA extent data for {}", assets.index)
            })?;
            ensure!(
                length > 0 && length.is_multiple_of(LOGICAL_BLOCK_SIZE as u64),
                "unreferenced XA extent must contain whole sectors"
            );
            let sectors = u32::try_from(length / LOGICAL_BLOCK_SIZE as u64)?;
            xa_extents.push(XaExtentPlacement {
                index: assets.index.clone(),
                start: next_extent,
                sectors,
            });
            next_extent = next_extent
                .checked_add(sectors)
                .context("unreferenced XA extent placement overflow")?;
            continue;
        }
        let Some(path) = item.as_path() else {
            let sectors = item.gap_sectors().expect("file layout item kind");
            let kind = item.gap_kind().expect("file layout item kind");
            match kind {
                GapKind::Mode1 | GapKind::Form1 | GapKind::Form2 => {
                    pending_gaps.push((sectors, kind, item.gap_subheader(), item.gap_form2_edc()))
                }
                GapKind::Xa | GapKind::RawZero => trailing_gap = Some((sectors, kind)),
            }
            continue;
        };
        let mut ancestors = Vec::new();
        let mut ancestor = parent_path(path);
        while ancestor != ROOT_PATH {
            ancestors.push(directory_index[ancestor.as_str()]);
            ancestor = parent_path(&ancestor);
        }
        for index in ancestors.into_iter().rev() {
            if !placed_directories[index]
                && !explicit_directory_paths
                    .contains(&(MetadataVolume::Primary, placements[index].path.as_str()))
            {
                placements[index].extent = next_extent;
                next_extent += placements[index].blocks;
                placed_directories[index] = true;
            }
        }

        for (sectors, kind, subheader, form2_edc) in pending_gaps.drain(..) {
            gaps.push(GapPlacement {
                start: next_extent,
                sectors,
                kind,
                subheader,
                form2_edc,
            });
            next_extent = next_extent
                .checked_add(sectors)
                .context("gap placement overflow")?;
        }

        let entry = entry_by_path[path];
        let length = *file_lengths
            .get(path)
            .with_context(|| format!("missing file data for {}", entry.path))?;
        let blocks = u32::try_from(length.div_ceil(LOGICAL_BLOCK_SIZE as u64))?;
        files.push(FilePlacement {
            path: entry.path.clone(),
            extent: next_extent,
            length,
            blocks,
        });
        next_extent += blocks;
    }
    if joliet_layout.is_some() {
        ensure!(
            placed_directories.iter().all(|placed| *placed)
                && placed_joliet_directories.iter().all(|placed| *placed),
            "Joliet metadata/files layout must place every primary and Joliet directory exactly once"
        );
    } else {
        for (index, directory) in placements.iter_mut().enumerate() {
            if !placed_directories[index] {
                directory.extent = next_extent;
                next_extent += directory.blocks;
            }
        }
    }
    for (sectors, kind, subheader, form2_edc) in pending_gaps {
        gaps.push(GapPlacement {
            start: next_extent,
            sectors,
            kind,
            subheader,
            form2_edc,
        });
        next_extent = next_extent
            .checked_add(sectors)
            .context("gap placement overflow")?;
    }
    let volume_blocks = next_extent
        .checked_add(trailing_gap.map_or(0, |(sectors, _)| sectors))
        .context("volume size overflow")?;
    let referenced_files = iso
        .entries
        .iter()
        .filter_map(|entry| {
            entry.extent.map(|extent| FilePlacement {
                path: entry.path.clone(),
                extent,
                length: u64::from(entry.length.expect("validated fixed-reference length")),
                blocks: entry
                    .length
                    .expect("validated fixed-reference length")
                    .div_ceil(LOGICAL_BLOCK_SIZE as u32),
            })
        })
        .collect::<Vec<_>>();
    for reference in &referenced_files {
        let entry = entry_by_path[reference.path.as_str()];
        if !entry.unbacked && !entry.xa.as_ref().is_some_and(entry_xa_is_cdda) {
            let reference_end = reference
                .extent
                .checked_add(reference.blocks)
                .context("fixed XA reference overflow")?;
            ensure!(
                reference.blocks > 0
                    && xa_extents.iter().any(|extent| {
                        reference.extent >= extent.start
                            && reference_end <= extent.start + extent.sectors
                    }),
                "fixed XA reference is not backed by a physical XA extent: {}",
                reference.path
            );
        }
    }
    let inferred_logical_volume_blocks =
        referenced_files
            .iter()
            .try_fold(volume_blocks, |maximum, reference| -> Result<u32> {
                Ok(maximum.max(
                    reference
                        .extent
                        .checked_add(reference.blocks)
                        .context("fixed reference extent overflow")?,
                ))
            })?;
    let logical_volume_blocks = if let Some(explicit) = iso.primary_volume.volume_space_size {
        ensure!(explicit > 0, "volume_space_size must be nonzero");
        explicit
    } else {
        inferred_logical_volume_blocks
    };
    let placement_by_path: HashMap<_, _> = files
        .iter()
        .chain(&referenced_files)
        .map(|file| (file.path.as_str(), file))
        .collect();
    let directory_by_path: HashMap<_, _> = placements
        .iter()
        .map(|dir| (dir.path.as_str(), dir))
        .collect();
    let mut data_subheader_sectors = HashSet::new();
    let mut end_of_file_data_subheader_sectors = HashSet::new();
    let mut metadata_subheader_sectors = HashSet::new();
    let mut framing_subheader_sectors = HashMap::new();
    let mut sector_file_numbers = HashMap::new();
    let path_table_data_blocks = match iso.path_table_subheader {
        EntrySectorSubheader::Canonical | EntrySectorSubheader::IsoMetadata => 0,
        EntrySectorSubheader::Data => path_blocks,
        EntrySectorSubheader::EndOfFileData | EntrySectorSubheader::DataUntilFinal => {
            path_blocks - 1
        }
    };
    for pointer in path_table_pointers
        .into_iter()
        .filter(|pointer| *pointer != 0)
    {
        for lba in pointer..pointer + path_table_data_blocks {
            data_subheader_sectors.insert(lba);
            if let Some(subheader) = iso.path_table_framing_subheader {
                framing_subheader_sectors.insert(lba, subheader);
            }
        }
        for lba in pointer + path_table_data_blocks..pointer + path_blocks {
            metadata_subheader_sectors.insert(lba);
        }
        if iso.path_table_subheader == EntrySectorSubheader::EndOfFileData {
            let final_lba = pointer + path_blocks - 1;
            metadata_subheader_sectors.remove(&final_lba);
            end_of_file_data_subheader_sectors.insert(final_lba);
        }
    }
    if let Some(joliet) = &joliet_layout {
        for pointer in joliet
            .pointers
            .into_iter()
            .chain(path_table_pointers)
            .filter(|pointer| *pointer != 0)
        {
            metadata_subheader_sectors.extend(
                pointer
                    ..pointer
                        + if joliet.pointers.contains(&pointer) {
                            joliet.path_blocks
                        } else {
                            path_blocks
                        },
            );
        }
        for directory in &joliet.placements {
            metadata_subheader_sectors
                .extend(directory.extent..directory.extent + directory.blocks);
        }
    }
    for entry in &iso.entries {
        if file_paths.contains(entry.path.as_str()) {
            let file = placement_by_path[entry.path.as_str()];
            let file_number = entry.xa.as_ref().map_or(0, |xa| xa.file_number);
            if file_number != 0 {
                for lba in file.extent..file.extent + file.blocks {
                    sector_file_numbers.insert(lba, file_number);
                }
            }
            if entry.sector_subheader != EntrySectorSubheader::Canonical {
                ensure!(
                    file.blocks > 0,
                    "noncanonical-subheader file cannot be empty"
                );
            }
            let final_extent = file.extent + file.blocks.saturating_sub(1);
            match entry.sector_subheader {
                EntrySectorSubheader::Canonical => {}
                EntrySectorSubheader::Data => {
                    data_subheader_sectors.extend(file.extent..file.extent + file.blocks);
                }
                EntrySectorSubheader::EndOfFileData => {
                    data_subheader_sectors.extend(file.extent..final_extent);
                    end_of_file_data_subheader_sectors.insert(final_extent);
                }
                EntrySectorSubheader::DataUntilFinal => {
                    data_subheader_sectors.extend(file.extent..final_extent);
                    metadata_subheader_sectors.insert(final_extent);
                }
                EntrySectorSubheader::IsoMetadata => {
                    metadata_subheader_sectors.extend(file.extent..file.extent + file.blocks);
                }
            }
        } else {
            let directory = directory_by_path[entry.path.as_str()];
            let file_number = entry.xa.as_ref().map_or(0, |xa| xa.file_number);
            if file_number != 0 {
                for lba in directory.extent..directory.extent + directory.blocks {
                    sector_file_numbers.insert(lba, file_number);
                }
            }
            let data_blocks = match entry.sector_subheader {
                EntrySectorSubheader::Canonical | EntrySectorSubheader::IsoMetadata => 0,
                EntrySectorSubheader::Data => directory.blocks,
                EntrySectorSubheader::EndOfFileData | EntrySectorSubheader::DataUntilFinal => {
                    directory.blocks - 1
                }
            };
            for lba in directory.extent..directory.extent + data_blocks {
                data_subheader_sectors.insert(lba);
            }
            for lba in directory.extent + data_blocks..directory.extent + directory.blocks {
                metadata_subheader_sectors.insert(lba);
            }
            if entry.sector_subheader == EntrySectorSubheader::EndOfFileData {
                let final_lba = directory.extent + directory.blocks - 1;
                metadata_subheader_sectors.remove(&final_lba);
                end_of_file_data_subheader_sectors.insert(final_lba);
            }
            if let Some(subheader) = entry.xa.as_ref().and_then(|xa| xa.framing_subheader) {
                for lba in directory.extent..directory.extent + data_blocks {
                    framing_subheader_sectors.insert(lba, subheader);
                }
            }
        }
    }

    let mut blocks = vec![[0_u8; LOGICAL_BLOCK_SIZE]; usize::try_from(next_extent)?];
    let pvd = serialize_pvd(
        iso,
        logical_volume_blocks,
        pvd_path_table_size,
        path_table_pointers,
        placements[0].extent,
        placements[0].length,
        entry_by_path[ROOT_PATH],
    )?;
    for copy in 0..u32::from(iso.primary_volume_copies) {
        blocks[usize::try_from(16 + copy)?] = pvd;
    }
    if let Some(joliet) = &joliet_layout {
        let descriptor_lba = 16 + u32::from(iso.primary_volume_copies);
        blocks[usize::try_from(descriptor_lba)?] =
            serialize_joliet_svd(joliet, logical_volume_blocks)?;
    }
    let terminator_lba =
        16 + u32::from(iso.primary_volume_copies) + u32::try_from(iso.supplementary_volumes.len())?;
    blocks[usize::try_from(terminator_lba)?][0..7].copy_from_slice(b"\xffCD001\x01");
    write_path_tables(
        &mut blocks,
        &placements,
        path_table_pointers,
        path_blocks,
        pvd_path_table_size,
        iso.path_table_little_hex.as_deref(),
        iso.path_table_big_hex.as_deref(),
    )?;
    if let Some(joliet) = &joliet_layout {
        write_path_tables(
            &mut blocks,
            &joliet.placements,
            joliet.pointers,
            joliet.path_blocks,
            joliet.path_table_size,
            joliet.volume.path_table_little_hex.as_deref(),
            joliet.volume.path_table_big_hex.as_deref(),
        )?;
    }
    for directory in &placements {
        if entry_by_path[directory.path.as_str()]
            .directory_reference
            .is_some()
        {
            continue;
        }
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
    if let Some(joliet) = &joliet_layout {
        let joliet_directory_by_path = joliet
            .placements
            .iter()
            .map(|directory| (directory.path.as_str(), directory))
            .collect::<HashMap<_, _>>();
        for directory in &joliet.placements {
            let data = serialize_joliet_directory(
                directory,
                &joliet.placements,
                joliet.volume,
                iso,
                &joliet_directory_by_path,
                &placement_by_path,
            )?;
            for (index, chunk) in data.chunks_exact(LOGICAL_BLOCK_SIZE).enumerate() {
                blocks[usize::try_from(directory.extent)? + index].copy_from_slice(chunk);
            }
        }
    }
    for entry in &iso.entries {
        let Some(value) = &entry.allocation_padding_hex else {
            continue;
        };
        let file = placement_by_path[entry.path.as_str()];
        let offset = usize::try_from(file.length % LOGICAL_BLOCK_SIZE as u64)?;
        ensure!(
            offset != 0,
            "allocation_padding_hex requires a file whose length is not block-aligned: {}",
            entry.path
        );
        let padding = hex::decode(value)
            .with_context(|| format!("decoding allocation_padding_hex for {}", entry.path))?;
        ensure!(
            !padding.is_empty()
                && padding.last() != Some(&0)
                && padding.len() <= LOGICAL_BLOCK_SIZE - offset,
            "invalid allocation_padding_hex for {}",
            entry.path
        );
        let final_lba = usize::try_from(file.extent + file.blocks - 1)?;
        blocks[final_lba][offset..offset + padding.len()].copy_from_slice(&padding);
    }
    Ok(Layout {
        blocks,
        files,
        xa_extents,
        gaps,
        data_subheader_sectors,
        end_of_file_data_subheader_sectors,
        metadata_subheader_sectors,
        framing_subheader_sectors,
        sector_file_numbers,
        volume_blocks,
        trailing_gap_kind: trailing_gap.map(|(_, kind)| kind),
    })
}

fn validate_entries(iso: &Iso9660) -> Result<HashSet<&str>> {
    ensure!(
        iso.primary_volume
            .file_structure_version
            .is_none_or(|version| version == 0)
            && iso.supplementary_volumes.iter().all(|volume| {
                volume
                    .descriptor
                    .file_structure_version
                    .is_none_or(|version| version == 0)
            }),
        "file_structure_version must be 0 or omitted for the standard value 1"
    );
    ensure!(
        (1..=3).contains(&iso.primary_volume_copies),
        "primary_volume_copies must be between 1 and 3"
    );
    ensure!(
        iso.supplementary_volumes.len() <= 1,
        "at most one Joliet supplementary volume is supported"
    );
    let mut metadata_directory_groups = HashSet::new();
    if iso.supplementary_volumes.is_empty() {
        ensure!(
            iso.metadata_layout.is_empty(),
            "metadata_layout requires a Joliet supplementary volume"
        );
    } else {
        ensure!(
            iso.path_table_copies == PathTableCopies::Single && iso.path_table_padding == 0,
            "Joliet metadata layout requires one primary path table of each endian"
        );
        let mut tables = HashSet::new();
        for item in &iso.metadata_layout {
            match item {
                MetadataLayoutItem::PathTable(item) => ensure!(
                    tables.insert(item.path_table),
                    "duplicate metadata path-table placement"
                ),
                MetadataLayoutItem::Directories(item) => ensure!(
                    metadata_directory_groups.insert(item.directories),
                    "duplicate metadata directory placement"
                ),
                MetadataLayoutItem::Gap(item) => ensure!(
                    item.gap > 0 && matches!(item.kind, GapKind::Mode1 | GapKind::Xa),
                    "Joliet metadata gaps must be nonempty Mode 1 or XA gaps"
                ),
            }
        }
        ensure!(
            tables
                == HashSet::from([
                    MetadataPathTable::PrimaryLittle,
                    MetadataPathTable::PrimaryBig,
                    MetadataPathTable::JolietLittle,
                    MetadataPathTable::JolietBig,
                ]),
            "metadata_layout must place every primary and Joliet path table exactly once"
        );
    }
    ensure!(
        iso.metadata_framing_subheader.is_none()
            || (iso.metadata_subheader == crate::manifest::IsoMetadataSubheader::Canonical
                && iso.metadata_framing_subheader.is_none_or(|subheader| {
                    !subheader
                        .submode
                        .contains(crate::raw_cd::XaSubmodeFlag::Form2)
                })),
        "custom metadata framing requires the canonical Form 1 metadata policy"
    );
    ensure!(
        iso.path_table_framing_subheader.is_none()
            || (iso.path_table_subheader == EntrySectorSubheader::Data
                && iso.path_table_framing_subheader.is_none_or(|subheader| {
                    !subheader
                        .submode
                        .contains(crate::raw_cd::XaSubmodeFlag::Form2)
                })),
        "custom path-table framing requires a Form 1 data policy"
    );
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
    let directory_reference_paths = iso
        .entries
        .iter()
        .filter_map(|entry| entry.directory_reference.map(|_| entry.path.as_str()))
        .collect::<HashSet<_>>();
    let referenced_paths = iso
        .entries
        .iter()
        .filter_map(|entry| entry.extent.map(|_| entry.path.as_str()))
        .collect::<HashSet<_>>();
    let joliet_paths = iso
        .supplementary_volumes
        .first()
        .map(|volume| {
            volume
                .entries
                .iter()
                .map(|entry| entry.path.as_str())
                .collect::<HashSet<_>>()
        })
        .unwrap_or_default();
    let mut authored_file_paths = HashSet::new();
    let mut explicit_directories = HashSet::new();
    let mut xa_extent_asset_paths = HashSet::new();
    let mut previous_gap = None;
    for (index, item) in iso.files.iter().enumerate() {
        if let Some(path) = item.as_path() {
            ensure!(path != ROOT_PATH, "filesystem root cannot be a file");
            ensure!(paths.contains(path), "unknown file entry {path}");
            ensure!(
                !referenced_paths.contains(path),
                "fixed-reference entry cannot appear in files: {path}"
            );
            ensure!(
                authored_file_paths.insert(path),
                "duplicate file entry {path}"
            );
            previous_gap = None;
            continue;
        }
        if let Some((volume, path)) = item.as_directory_placement() {
            let known_paths = match volume {
                MetadataVolume::Primary => &paths,
                MetadataVolume::Joliet => &joliet_paths,
            };
            ensure!(
                known_paths.contains(path),
                "unknown {volume:?} directory entry {path}"
            );
            ensure!(
                !metadata_directory_groups.contains(&volume),
                "directory group and individual placements cannot both place {volume:?} directories"
            );
            ensure!(
                path != ROOT_PATH || !iso.supplementary_volumes.is_empty(),
                "filesystem root placement is fixed without Joliet metadata layout"
            );
            ensure!(
                explicit_directories.insert((volume, path)),
                "duplicate {volume:?} directory placement {path}"
            );
            previous_gap = None;
            continue;
        }
        if let Some(assets) = item.as_xa_extent() {
            for path in [&assets.form1, &assets.form2, &assets.index]
                .into_iter()
                .chain(assets.gap_index.iter())
            {
                ensure!(
                    !path.is_empty(),
                    "unreferenced XA asset path must not be empty"
                );
                ensure!(
                    !paths.contains(path.as_str()),
                    "unreferenced XA asset path collides with ISO entry {path}"
                );
                ensure!(
                    xa_extent_asset_paths.insert(path),
                    "duplicate unreferenced XA asset path {path}"
                );
            }
            previous_gap = None;
            continue;
        }
        {
            let sectors = item.gap_sectors().expect("file layout item kind");
            let kind = item.gap_kind().expect("file layout item kind");
            let subheader = item.gap_subheader();
            let form2_edc = item.gap_form2_edc();
            ensure!(sectors > 0, "physical gap must contain at least one sector");
            ensure!(
                previous_gap != Some((kind, subheader, form2_edc)),
                "consecutive identical physical gaps are redundant"
            );
            ensure!(
                form2_edc.is_none() || kind == GapKind::Form2,
                "form2_edc is valid only on a Form 2 gap"
            );
            if matches!(kind, GapKind::Xa | GapKind::RawZero) {
                ensure!(
                    index + 1 == iso.files.len(),
                    "XA and raw-zero gaps must end files list"
                );
            }
            match kind {
                GapKind::Form1 => {
                    let subheader = subheader.context("Form 1 gap requires an XA subheader")?;
                    ensure!(
                        !subheader
                            .submode
                            .contains(crate::raw_cd::XaSubmodeFlag::Form2),
                        "Form 1 gap subheader cannot declare Form 2"
                    );
                }
                GapKind::Mode1 | GapKind::Form2 | GapKind::Xa | GapKind::RawZero => ensure!(
                    subheader.is_none(),
                    "only a Form 1 gap may declare an XA subheader"
                ),
            }
            previous_gap = Some((kind, subheader, form2_edc));
            continue;
        }
    }
    let file_paths = authored_file_paths
        .union(&referenced_paths)
        .copied()
        .collect::<HashSet<_>>();
    let mut xa_system_use_omissions = HashSet::new();
    for path in &iso.xa_system_use_omissions {
        ensure!(
            iso.xa_system_use,
            "xa_system_use_omissions requires xa_system_use"
        );
        ensure!(
            xa_system_use_omissions.insert(path.as_str()),
            "duplicate XA system-use omission {path}"
        );
        ensure!(
            file_paths.contains(path.as_str()),
            "XA system-use omission must name a file entry: {path}"
        );
    }
    let directory_paths: HashSet<_> = paths.difference(&file_paths).copied().collect();
    for (volume, path) in explicit_directories {
        let is_directory = match volume {
            MetadataVolume::Primary => directory_paths.contains(path),
            MetadataVolume::Joliet => iso.supplementary_volumes.first().is_some_and(|joliet| {
                joliet
                    .entries
                    .iter()
                    .any(|entry| entry.path == path && entry.source.is_none())
            }),
        };
        ensure!(
            is_directory,
            "{volume:?} directory placement names a file entry: {path}"
        );
        ensure!(
            volume != MetadataVolume::Primary || !directory_reference_paths.contains(path),
            "directory reference cannot have a physical directory placement: {path}"
        );
    }
    if let Some(volume) = iso.supplementary_volumes.first() {
        ensure!(
            volume.descriptor.escape_sequence.is_none(),
            "Joliet descriptor escape sequence is selected by level"
        );
        if let Some(value) = volume.file_identifier_odd_bytes_hex.as_deref() {
            ensure!(
                hex::decode(value).is_ok_and(|bytes| bytes.len() == 3),
                "Joliet file_identifier_odd_bytes_hex must contain exactly 3 bytes"
            );
        }
        if let Some(value) = volume.volume_set_identifier_raw_hex.as_deref() {
            ensure!(
                volume.descriptor.volume_set_identifier.is_empty()
                    && hex::decode(value).is_ok_and(|bytes| bytes.len() == 128),
                "Joliet volume_set_identifier_raw_hex requires an empty structured value and exactly 128 raw bytes"
            );
        }
        let joliet_root = volume
            .entries
            .first()
            .context("Joliet filesystem root must be the first entry")?;
        ensure!(
            joliet_root.path == ROOT_PATH && joliet_root.source.is_none(),
            "Joliet filesystem root must be the first directory entry"
        );
        let mut joliet_paths = HashSet::new();
        for (index, entry) in volume.entries.iter().enumerate() {
            ensure!(
                joliet_paths.insert(entry.path.as_str()),
                "duplicate Joliet path {}",
                entry.path
            );
            let directory = entry.source.is_none();
            if index != 0 {
                validate_joliet_path(&entry.path)?;
                let parent = parent_path(&entry.path);
                let parent_entry = volume
                    .entries
                    .iter()
                    .find(|candidate| candidate.path == parent)
                    .with_context(|| format!("missing Joliet parent directory {parent}"))?;
                ensure!(
                    parent_entry.source.is_none(),
                    "Joliet parent is not a directory: {parent}"
                );
            }
            if let Some(source) = entry.source.as_deref() {
                ensure!(
                    file_paths.contains(source),
                    "Joliet source does not name a primary file: {source}"
                );
            }
            ensure!(
                !entry.omit_version || entry.source.is_some(),
                "omit_version is supported only for Joliet files: {}",
                entry.path
            );
            if volume.xa_system_use {
                serialize_xa_system_use_parts(&entry.path, entry.xa.as_ref(), directory)?;
            } else {
                ensure!(
                    entry.xa.is_none(),
                    "Joliet XA fields require xa_system_use: {}",
                    entry.path
                );
            }
            ensure!(
                entry.xa.as_ref().is_none_or(|xa| {
                    xa.form1.is_none()
                        && xa.form2.is_none()
                        && xa.index.is_none()
                        && xa.gap_index.is_none()
                        && xa.logical_length.is_none()
                        && xa.length_encoding.is_default()
                        && xa.framing_subheader.is_none()
                }),
                "Joliet entries support only directory-record XA fields: {}",
                entry.path
            );
        }
    }
    for (index, entry) in iso.entries.iter().enumerate() {
        let has_extent = entry.extent.is_some();
        let has_length = entry.length.is_some();
        if let Some(reference) = entry.directory_reference {
            ensure!(
                index != 0 && !file_paths.contains(entry.path.as_str()),
                "directory_reference is supported only for non-root directories: {}",
                entry.path
            );
            ensure!(
                reference.length == 0,
                "directory_reference currently requires a zero length: {}",
                entry.path
            );
            ensure!(
                !has_extent && !has_length,
                "directory_reference cannot be combined with a file fixed reference: {}",
                entry.path
            );
            ensure!(
                entry.directory_slack.is_none()
                    && entry.sector_subheader == EntrySectorSubheader::Canonical,
                "directory_reference cannot have physical directory data: {}",
                entry.path
            );
            ensure!(
                !iso.entries.iter().any(|candidate| {
                    candidate.path != entry.path && parent_path(&candidate.path) == entry.path
                }),
                "directory_reference must be childless: {}",
                entry.path
            );
        }
        ensure!(
            has_extent == has_length,
            "fixed-reference entry requires both extent and length: {}",
            entry.path
        );
        let cdda = entry.xa.as_ref().is_some_and(entry_xa_is_cdda);
        let unbacked = entry.unbacked;
        ensure!(
            !cdda || has_extent,
            "external CDDA entry requires a fixed extent and length: {}",
            entry.path
        );
        ensure!(
            !unbacked || (has_extent && entry.length.is_some_and(|length| length > 0) && !cdda),
            "unbacked entry requires a nonempty non-CDDA fixed reference: {}",
            entry.path
        );
        let form2_xa = entry
            .xa
            .as_ref()
            .and_then(|xa| xa.attributes)
            .is_some_and(|attributes| {
                attributes.contains(crate::manifest::XaAttributeFlag::Interleaved)
                    || attributes.contains(crate::manifest::XaAttributeFlag::Mode2Form2)
            });
        ensure!(
            !has_extent || cdda || form2_xa || unbacked,
            "fixed extent and length require external CDDA, Form 2 XA attributes, or unbacked: {}",
            entry.path
        );
        let is_file = file_paths.contains(entry.path.as_str());
        ensure!(
            !unbacked || is_file,
            "unbacked is supported only for files: {}",
            entry.path
        );
        ensure!(
            !is_file || entry.directory_slack.is_none(),
            "directory_slack is supported only for directories: {}",
            entry.path
        );
        ensure!(
            is_file || entry.allocation_padding_hex.is_none(),
            "allocation_padding_hex is supported only for files: {}",
            entry.path
        );
        serialize_directory_record_system_use(
            entry,
            !is_file,
            iso.xa_system_use && !xa_system_use_omissions.contains(entry.path.as_str()),
        )?;
        ensure!(
            is_file
                || entry.xa.as_ref().is_none_or(|xa| {
                    xa.form1.is_none() && xa.form2.is_none() && xa.index.is_none()
                }),
            "directory entry cannot have mixed XA framing: {}",
            entry.path
        );
        ensure!(
            entry.xa.as_ref().is_none_or(|xa| {
                let count = usize::from(xa.form1.is_some())
                    + usize::from(xa.form2.is_some())
                    + usize::from(xa.index.is_some());
                count == 0 || count == 3
            }),
            "interleaved XA entry requires Form 1, Form 2, and index assets: {}",
            entry.path
        );
        ensure!(
            entry.xa.as_ref().is_none_or(|xa| {
                xa.framing_subheader.is_none_or(|subheader| {
                    !is_file
                        && matches!(
                            entry.sector_subheader,
                            EntrySectorSubheader::Data
                                | EntrySectorSubheader::EndOfFileData
                                | EntrySectorSubheader::DataUntilFinal
                        )
                        && !subheader
                            .submode
                            .contains(crate::raw_cd::XaSubmodeFlag::Form2)
                })
            }),
            "custom XA framing requires a data-framed Form 1 directory entry: {}",
            entry.path
        );
        let indexed_assets = entry.xa.as_ref().is_some_and(|xa| xa.form1.is_some());
        ensure!(
            entry.allocation_padding_hex.is_none() || (!has_extent && !indexed_assets),
            "allocation_padding_hex is unsupported for fixed-reference or mixed XA entry: {}",
            entry.path
        );
        ensure!(
            !unbacked || (!indexed_assets && !form2_xa),
            "unbacked file cannot declare mixed XA framing: {}",
            entry.path
        );
        ensure!(
            entry.xa.as_ref().is_none_or(|xa| {
                xa.logical_length
                    .is_none_or(|length| is_file && indexed_assets && length > 0)
            }),
            "XA logical length requires a nonempty indexed file extent: {}",
            entry.path
        );
        ensure!(
            entry.xa.as_ref().is_none_or(|xa| {
                xa.length_encoding.is_default()
                    || (is_file && indexed_assets && xa.logical_length.is_none())
            }),
            "XA length encoding requires an indexed file extent without logical_length: {}",
            entry.path
        );
        ensure!(
            entry
                .xa
                .as_ref()
                .is_none_or(|xa| xa.gap_index.is_none() || xa.form1.is_some()),
            "XA gap index requires interleaved XA assets: {}",
            entry.path
        );
        let mixed_attributes =
            entry
                .xa
                .as_ref()
                .and_then(|xa| xa.attributes)
                .is_some_and(|attributes| {
                    attributes.contains(crate::manifest::XaAttributeFlag::Interleaved)
                        || attributes.contains(crate::manifest::XaAttributeFlag::Mode2Form2)
                });
        ensure!(
            !mixed_attributes || (is_file && (indexed_assets || has_extent)),
            "interleaved or Form 2 file attributes require indexed assets or a fixed reference: {}",
            entry.path
        );
        ensure!(
            entry.sector_subheader == EntrySectorSubheader::Canonical
                || (!has_extent && !indexed_assets),
            "data sector subheader policy is unsupported for fixed-reference or mixed XA entry: {}",
            entry.path
        );
        ensure!(
            entry.sector_subheader != EntrySectorSubheader::DataUntilFinal || !is_file,
            "data_until_final sector subheader policy is supported only for directories: {}",
            entry.path
        );
        if index != 0 {
            validate_path(&entry.path, is_file, iso.identifier_policy)?;
            let parent = parent_path(&entry.path);
            ensure!(
                directory_paths.contains(parent.as_str()),
                "missing parent directory {parent}"
            );
        }
    }
    Ok(file_paths)
}

fn validate_path(path: &str, is_file: bool, identifier_policy: IdentifierPolicy) -> Result<()> {
    ensure!(
        !path.is_empty() && !path.starts_with('/') && !path.ends_with('/'),
        "invalid relative ISO path"
    );
    let parts = path.split('/').collect::<Vec<_>>();
    for (index, part) in parts.iter().enumerate() {
        ensure!(*part != "." && *part != "..", "path traversal is forbidden");
        let file_component = is_file && index + 1 == parts.len();
        match identifier_policy {
            IdentifierPolicy::IsoLevel1 if file_component => {
                let (stem, extension) = part.rsplit_once('.').unwrap_or((part, ""));
                ensure!(
                    !stem.is_empty() && stem.len() <= 8 && extension.len() <= 3,
                    "file name is not ISO Level 1: {part}"
                );
                ensure!(
                    valid_d_chars(stem) && valid_d_chars(extension),
                    "invalid ISO file characters: {part}"
                );
            }
            IdentifierPolicy::IsoLevel1 => ensure!(
                part.len() <= 8 && valid_d_chars(part),
                "directory name is not ISO Level 1: {part}"
            ),
            IdentifierPolicy::NonstandardAscii => ensure!(
                valid_nonstandard_ascii_identifier(part),
                "invalid nonstandard ASCII ISO identifier: {part}"
            ),
        }
    }
    Ok(())
}

fn validate_joliet_path(path: &str) -> Result<()> {
    ensure!(
        !path.is_empty()
            && !path.starts_with('/')
            && !path.ends_with('/')
            && !path
                .split('/')
                .any(|component| { component.is_empty() || component == "." || component == ".." }),
        "invalid Joliet path {path:?}"
    );
    for component in path.split('/') {
        encode_joliet_identifier(component)
            .with_context(|| format!("invalid Joliet path component {component:?}"))?;
    }
    Ok(())
}

fn identifier_is_iso_level1(value: &str, file: bool) -> bool {
    if file {
        let (stem, extension) = value.rsplit_once('.').unwrap_or((value, ""));
        !stem.is_empty()
            && stem.len() <= 8
            && extension.len() <= 3
            && valid_d_chars(stem)
            && valid_d_chars(extension)
    } else {
        value.len() <= 8 && valid_d_chars(value)
    }
}

fn valid_nonstandard_ascii_identifier(value: &str) -> bool {
    !value.is_empty()
        && value != "."
        && value != ".."
        && value
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && byte != b'/' && byte != b'\\')
}

fn valid_d_chars(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
}

fn directory_order(
    entries: &[Entry],
    file_paths: &HashSet<&str>,
) -> Result<Vec<(String, Vec<u8>, usize)>> {
    let mut result = vec![(ROOT_PATH.to_owned(), vec![0], 0)];
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
            let name = file_name(&entry.path).as_bytes().to_vec();
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

fn joliet_directory_order(entries: &[JolietEntry]) -> Result<Vec<(String, Vec<u8>, usize)>> {
    let mut result = vec![(ROOT_PATH.to_owned(), vec![0], 0)];
    let mut queue = VecDeque::from([ROOT_PATH.to_owned()]);
    while let Some(parent) = queue.pop_front() {
        let parent_index = result
            .iter()
            .position(|(path, _, _)| path == &parent)
            .context("missing Joliet directory parent")?;
        for entry in entries.iter().filter(|entry| {
            entry.path != ROOT_PATH && entry.source.is_none() && parent_path(&entry.path) == parent
        }) {
            result.push((
                entry.path.clone(),
                encode_joliet_identifier(file_name(&entry.path))?,
                parent_index,
            ));
            queue.push_back(entry.path.clone());
        }
    }
    let expected = entries
        .iter()
        .filter(|entry| entry.source.is_none())
        .count();
    ensure!(
        result.len() == expected,
        "unreachable Joliet directory in manifest"
    );
    Ok(result)
}

fn directory_record_lengths(path: &str, iso: &Iso9660, file_paths: &HashSet<&str>) -> Vec<usize> {
    let system_use_size = usize::from(iso.xa_system_use) * XA_SYSTEM_USE_SIZE;
    let mut lengths = vec![
        record_size(1, system_use_size),
        record_size(1, system_use_size),
    ];
    for entry in iso
        .entries
        .iter()
        .filter(|entry| entry.path != ROOT_PATH && parent_path(&entry.path) == path)
    {
        let name = identifier(entry, file_paths.contains(entry.path.as_str()));
        let entry_system_use_size = if iso
            .xa_system_use_omissions
            .iter()
            .any(|path| path == &entry.path)
        {
            0
        } else {
            system_use_size
        };
        lengths.push(record_size(name.len(), entry_system_use_size));
    }
    lengths
}

fn joliet_directory_record_lengths(path: &str, volume: &JolietVolume) -> Result<Vec<usize>> {
    let system_use_size = usize::from(volume.xa_system_use) * XA_SYSTEM_USE_SIZE;
    let mut lengths = vec![
        record_size(1, system_use_size),
        record_size(1, system_use_size),
    ];
    for entry in volume
        .entries
        .iter()
        .filter(|entry| entry.path != ROOT_PATH && parent_path(&entry.path) == path)
    {
        let mut identifier = encode_joliet_identifier(file_name(&entry.path))?;
        if entry.source.is_some() && !entry.omit_version {
            identifier.extend_from_slice(&encode_joliet_identifier(";1")?);
        }
        lengths.push(record_size(identifier.len(), system_use_size));
    }
    Ok(lengths)
}

fn packed_length(lengths: &[usize], packing: DirectoryRecordPacking) -> usize {
    let mut offset = 0;
    for length in lengths {
        let in_block = offset % LOGICAL_BLOCK_SIZE;
        if in_block + length > LOGICAL_BLOCK_SIZE
            || (in_block + length == LOGICAL_BLOCK_SIZE
                && packing == DirectoryRecordPacking::AvoidExactFit)
        {
            offset += LOGICAL_BLOCK_SIZE - in_block;
        }
        offset += length;
    }
    offset
}

#[cfg(test)]
fn packed_blocks(lengths: &[usize], packing: DirectoryRecordPacking) -> usize {
    packed_length(lengths, packing)
        .div_ceil(LOGICAL_BLOCK_SIZE)
        .max(1)
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
    if let Some(level) = pvd.escape_sequence {
        block[88..91].copy_from_slice(&joliet_escape_sequence(level));
    }
    write_pvd_u16(&mut block, 120, VOLUME_SET_SIZE, pvd.u16_encoding);
    write_pvd_u16(&mut block, 124, VOLUME_SEQUENCE_NUMBER, pvd.u16_encoding);
    write_pvd_u16(&mut block, 128, ISO_LOGICAL_BLOCK_SIZE, pvd.u16_encoding);
    write_both_u32(&mut block, 132, path_table_size);
    block[140..144].copy_from_slice(&pointers[0].to_le_bytes());
    block[144..148].copy_from_slice(&pointers[1].to_le_bytes());
    block[148..152].copy_from_slice(&pointers[2].to_be_bytes());
    block[152..156].copy_from_slice(&pointers[3].to_be_bytes());
    let root_record = serialize_record(&Record {
        extent: root_extent,
        length: root_length,
        recording_time: serialize_recording_time(
            pvd.root_directory_recording_time
                .as_deref()
                .unwrap_or(&root.recording_time),
        )?,
        flags: DIRECTORY_FLAG
            | (u8::from(root.hidden) * HIDDEN_FLAG)
            | (u8::from(root.associated) * ASSOCIATED_FLAG),
        file_unit_size: 0,
        interleave_gap_size: 0,
        volume_sequence_number: VOLUME_SEQUENCE_NUMBER,
        name: vec![match pvd.root_directory_identifier {
            RootDirectoryIdentifier::Current => 0,
            RootDirectoryIdentifier::Parent => 1,
        }],
        system_use: Vec::new(),
        trailing_system_use_padding: false,
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
    block[881] = iso
        .primary_volume
        .file_structure_version
        .unwrap_or(FILE_STRUCTURE_VERSION);
    if let Some(value) = &pvd.application_use_hex {
        ensure!(
            pvd.application_use == PrimaryVolumeApplicationUse::default(),
            "primary-volume application_use_hex cannot be combined with a nondefault application_use"
        );
        let application_use =
            hex::decode(value).context("decoding primary-volume application_use_hex")?;
        ensure!(
            application_use.len() == APPLICATION_USE_END - APPLICATION_USE_START,
            "primary-volume application_use_hex must contain exactly {} bytes",
            APPLICATION_USE_END - APPLICATION_USE_START
        );
        block[APPLICATION_USE_START..APPLICATION_USE_END].copy_from_slice(&application_use);
    } else {
        block[APPLICATION_USE_START..APPLICATION_USE_END]
            .copy_from_slice(&primary_volume_application_use(pvd.application_use));
    }
    if let Some(value) = &pvd.reserved_hex {
        let reserved = hex::decode(value).context("decoding primary-volume reserved_hex")?;
        ensure!(
            !reserved.is_empty() && reserved.len() <= LOGICAL_BLOCK_SIZE - APPLICATION_USE_END,
            "primary-volume reserved_hex must contain between 1 and {} bytes",
            LOGICAL_BLOCK_SIZE - APPLICATION_USE_END
        );
        block[APPLICATION_USE_END..APPLICATION_USE_END + reserved.len()].copy_from_slice(&reserved);
    }
    if let Some(length) = pvd.root_directory_record_length {
        ensure!(
            length > 34,
            "primary-volume root_directory_record_length must be greater than 34"
        );
        block[156] = length;
    }
    Ok(block)
}

fn serialize_joliet_svd(
    joliet: &JolietLayout<'_>,
    volume_blocks: u32,
) -> Result<[u8; LOGICAL_BLOCK_SIZE]> {
    let volume = joliet.volume;
    let descriptor = &volume.descriptor;
    let root = volume
        .entries
        .first()
        .context("missing Joliet root entry")?;
    let root_placement = joliet
        .placements
        .first()
        .context("missing Joliet root directory placement")?;
    let mut block = [0_u8; LOGICAL_BLOCK_SIZE];
    block[0..7].copy_from_slice(b"\x02CD001\x01");
    block[7] = volume.flags;
    write_joliet_fixed(
        &mut block,
        8,
        32,
        &descriptor.system_identifier,
        volume.zero_fill_empty_strings,
        volume.zero_pad_strings,
        None,
    )?;
    write_joliet_fixed(
        &mut block,
        40,
        32,
        &descriptor.volume_identifier,
        volume.zero_fill_empty_strings,
        volume.zero_pad_strings,
        None,
    )?;
    write_both_u32(
        &mut block,
        80,
        descriptor.volume_space_size.unwrap_or(volume_blocks),
    );
    block[88..91].copy_from_slice(&joliet_escape_sequence(volume.level));
    write_pvd_u16(&mut block, 120, VOLUME_SET_SIZE, descriptor.u16_encoding);
    write_pvd_u16(
        &mut block,
        124,
        VOLUME_SEQUENCE_NUMBER,
        descriptor.u16_encoding,
    );
    write_pvd_u16(
        &mut block,
        128,
        ISO_LOGICAL_BLOCK_SIZE,
        descriptor.u16_encoding,
    );
    write_both_u32(&mut block, 132, joliet.path_table_size);
    block[140..144].copy_from_slice(&joliet.pointers[0].to_le_bytes());
    block[144..148].copy_from_slice(&joliet.pointers[1].to_le_bytes());
    block[148..152].copy_from_slice(&joliet.pointers[2].to_be_bytes());
    block[152..156].copy_from_slice(&joliet.pointers[3].to_be_bytes());
    let root_record = serialize_record(&Record {
        extent: root_placement.extent,
        length: root_placement.length,
        recording_time: serialize_recording_time(
            descriptor
                .root_directory_recording_time
                .as_deref()
                .unwrap_or(&root.recording_time),
        )?,
        flags: DIRECTORY_FLAG
            | (u8::from(root.hidden) * HIDDEN_FLAG)
            | (u8::from(root.associated) * ASSOCIATED_FLAG),
        file_unit_size: 0,
        interleave_gap_size: 0,
        volume_sequence_number: VOLUME_SEQUENCE_NUMBER,
        name: vec![match descriptor.root_directory_identifier {
            RootDirectoryIdentifier::Current => 0,
            RootDirectoryIdentifier::Parent => 1,
        }],
        system_use: Vec::new(),
        trailing_system_use_padding: false,
    })?;
    ensure!(root_record.len() == 34, "SVD root record must be 34 bytes");
    block[156..190].copy_from_slice(&root_record);
    if let Some(value) = volume.volume_set_identifier_raw_hex.as_deref() {
        let value = hex::decode(value).context("decoding Joliet volume_set_identifier_raw_hex")?;
        ensure!(
            value.len() == 128,
            "Joliet volume_set_identifier_raw_hex must contain exactly 128 bytes"
        );
        block[190..318].copy_from_slice(&value);
    } else {
        write_joliet_fixed(
            &mut block,
            190,
            128,
            &descriptor.volume_set_identifier,
            volume.zero_fill_empty_strings,
            volume.zero_pad_strings,
            None,
        )?;
    }
    write_joliet_fixed(
        &mut block,
        318,
        128,
        &descriptor.publisher_identifier,
        volume.zero_fill_empty_strings,
        volume.zero_pad_strings,
        None,
    )?;
    write_joliet_fixed(
        &mut block,
        446,
        128,
        &descriptor.data_preparer_identifier,
        volume.zero_fill_empty_strings,
        volume.zero_pad_strings,
        None,
    )?;
    write_joliet_fixed(
        &mut block,
        574,
        128,
        &descriptor.application_identifier,
        volume.zero_fill_empty_strings,
        volume.zero_pad_strings,
        None,
    )?;
    let odd_bytes = match volume.file_identifier_odd_bytes_hex.as_deref() {
        Some(value) => {
            let bytes =
                hex::decode(value).context("decoding Joliet file_identifier_odd_bytes_hex")?;
            ensure!(
                bytes.len() == 3,
                "Joliet file_identifier_odd_bytes_hex must contain exactly 3 bytes"
            );
            [bytes[0], bytes[1], bytes[2]]
        }
        None => [0; 3],
    };
    write_joliet_fixed(
        &mut block,
        702,
        37,
        &descriptor.copyright_file_identifier,
        volume.zero_fill_empty_strings,
        volume.zero_pad_strings,
        Some(odd_bytes[0]),
    )?;
    write_joliet_fixed(
        &mut block,
        739,
        37,
        &descriptor.abstract_file_identifier,
        volume.zero_fill_empty_strings,
        volume.zero_pad_strings,
        Some(odd_bytes[1]),
    )?;
    write_joliet_fixed(
        &mut block,
        776,
        37,
        &descriptor.bibliographic_file_identifier,
        volume.zero_fill_empty_strings,
        volume.zero_pad_strings,
        Some(odd_bytes[2]),
    )?;
    block[813..830].copy_from_slice(&serialize_volume_time(descriptor.creation_time.as_deref())?);
    block[830..847].copy_from_slice(&serialize_volume_time(
        descriptor.modification_time.as_deref(),
    )?);
    block[847..864].copy_from_slice(&serialize_volume_time(
        descriptor.expiration_time.as_deref(),
    )?);
    block[864..881].copy_from_slice(&serialize_volume_time(
        descriptor.effective_time.as_deref(),
    )?);
    block[881] = descriptor
        .file_structure_version
        .unwrap_or(FILE_STRUCTURE_VERSION);
    write_descriptor_application_and_reserved(&mut block, descriptor, "Joliet")?;
    if let Some(length) = descriptor.root_directory_record_length {
        ensure!(
            length > 34,
            "Joliet root_directory_record_length must be greater than 34"
        );
        block[156] = length;
    }
    Ok(block)
}

fn write_descriptor_application_and_reserved(
    block: &mut [u8; LOGICAL_BLOCK_SIZE],
    descriptor: &PrimaryVolume,
    kind: &str,
) -> Result<()> {
    if let Some(value) = &descriptor.application_use_hex {
        ensure!(
            descriptor.application_use == PrimaryVolumeApplicationUse::default(),
            "{kind} application_use_hex cannot be combined with a nondefault application_use"
        );
        let application_use =
            hex::decode(value).with_context(|| format!("decoding {kind} application_use_hex"))?;
        ensure!(
            application_use.len() == APPLICATION_USE_END - APPLICATION_USE_START,
            "{kind} application_use_hex must contain exactly {} bytes",
            APPLICATION_USE_END - APPLICATION_USE_START
        );
        block[APPLICATION_USE_START..APPLICATION_USE_END].copy_from_slice(&application_use);
    } else {
        block[APPLICATION_USE_START..APPLICATION_USE_END]
            .copy_from_slice(&primary_volume_application_use(descriptor.application_use));
    }
    if let Some(value) = &descriptor.reserved_hex {
        let reserved =
            hex::decode(value).with_context(|| format!("decoding {kind} reserved_hex"))?;
        ensure!(
            !reserved.is_empty() && reserved.len() <= LOGICAL_BLOCK_SIZE - APPLICATION_USE_END,
            "{kind} reserved_hex must contain between 1 and {} bytes",
            LOGICAL_BLOCK_SIZE - APPLICATION_USE_END
        );
        block[APPLICATION_USE_END..APPLICATION_USE_END + reserved.len()].copy_from_slice(&reserved);
    }
    Ok(())
}

fn write_path_tables(
    blocks: &mut [[u8; LOGICAL_BLOCK_SIZE]],
    directories: &[DirectoryPlacement],
    pointers: [u32; 4],
    path_blocks: u32,
    path_table_size: u32,
    little_hex: Option<&str>,
    big_hex: Option<&str>,
) -> Result<()> {
    let (little, big) = match (little_hex, big_hex) {
        (None, None) => (
            serialize_path_table(directories, false)?,
            serialize_path_table(directories, true)?,
        ),
        (Some(little), Some(big)) => {
            let little = hex::decode(little).context("decoding path_table_little_hex")?;
            let big = hex::decode(big).context("decoding path_table_big_hex")?;
            let expected = usize::try_from(path_table_size)?;
            ensure!(
                little.len() == expected && big.len() == expected,
                "raw path tables must each contain exactly {path_table_size} bytes"
            );
            (little, big)
        }
        _ => anyhow::bail!("path_table_little_hex and path_table_big_hex must be used together"),
    };
    for (pointer, bytes) in [
        (pointers[0], &little),
        (pointers[1], &little),
        (pointers[2], &big),
        (pointers[3], &big),
    ]
    .into_iter()
    .filter(|(pointer, _)| *pointer != 0)
    {
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

fn read_path_table(blocks: &[[u8; LOGICAL_BLOCK_SIZE]], extent: u32, size: u32) -> Result<Vec<u8>> {
    let block_count = size.div_ceil(LOGICAL_BLOCK_SIZE as u32);
    let mut result = Vec::with_capacity(usize::try_from(block_count)? * LOGICAL_BLOCK_SIZE);
    for index in 0..block_count {
        result.extend_from_slice(&blocks[usize::try_from(extent + index)?]);
    }
    result.truncate(usize::try_from(size)?);
    Ok(result)
}

struct PathTableRecord {
    extent: u32,
    parent: u16,
    name: Vec<u8>,
}

fn parse_path_table_records(bytes: &[u8], big: bool) -> Result<Vec<PathTableRecord>> {
    let mut records = Vec::new();
    let mut offset = 0;
    while offset < bytes.len() {
        ensure!(
            offset + 8 <= bytes.len(),
            "truncated path-table directory record"
        );
        let name_length = usize::from(bytes[offset]);
        ensure!(name_length > 0, "empty path-table directory identifier");
        let record_length = 8 + name_length + usize::from(name_length % 2 == 1);
        ensure!(
            offset + record_length <= bytes.len(),
            "truncated path-table directory identifier"
        );
        let extent_bytes: [u8; 4] = bytes[offset + 2..offset + 6].try_into()?;
        let parent_bytes: [u8; 2] = bytes[offset + 6..offset + 8].try_into()?;
        records.push(PathTableRecord {
            extent: if big {
                u32::from_be_bytes(extent_bytes)
            } else {
                u32::from_le_bytes(extent_bytes)
            },
            parent: if big {
                u16::from_be_bytes(parent_bytes)
            } else {
                u16::from_le_bytes(parent_bytes)
            },
            name: bytes[offset + 8..offset + 8 + name_length].to_vec(),
        });
        offset += record_length;
    }
    Ok(records)
}

fn validate_directory_reference_path_tables(
    entries: &[Entry],
    directories: &[DirectoryPlacement],
    little: &[u8],
    big: &[u8],
) -> Result<()> {
    let references = entries
        .iter()
        .filter_map(|entry| {
            entry
                .directory_reference
                .map(|reference| (entry.path.as_str(), reference))
        })
        .collect::<Vec<_>>();
    if references.is_empty() {
        return Ok(());
    }

    let little = parse_path_table_records(little, false)?;
    let big = parse_path_table_records(big, true)?;
    for (path, reference) in references {
        let index = directories
            .iter()
            .position(|directory| directory.path == path)
            .with_context(|| format!("directory reference is absent from path tables: {path}"))?;
        let directory = &directories[index];
        let expected_parent = u16::try_from(directory.parent + 1)?;
        for records in [&little, &big] {
            let record = records.get(index).with_context(|| {
                format!("directory reference is absent from path table: {path}")
            })?;
            ensure!(
                record.extent == reference.extent
                    && record.parent == expected_parent
                    && record.name == directory.name,
                "directory reference disagrees with path table: {path}"
            );
            ensure!(
                !records.iter().enumerate().any(
                    |(child, record)| child != index && usize::from(record.parent) == index + 1
                ),
                "directory reference has path-table children: {path}"
            );
        }
    }
    Ok(())
}

fn serialize_path_table(directories: &[DirectoryPlacement], big: bool) -> Result<Vec<u8>> {
    let mut result = Vec::new();
    for directory in directories {
        let name = &directory.name;
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
    let trailing_system_use_padding =
        iso.primary_volume.application_use == PrimaryVolumeApplicationUse::CdRep20131;
    let metadata = entry_by_path[directory.path.as_str()];
    let parent = &directories[directory.parent];
    let parent_entry = entry_by_path[parent.path.as_str()];
    let mut records = Vec::new();
    records.push(make_record_with_padding(
        metadata,
        directory.extent,
        directory.length,
        vec![0],
        true,
        trailing_system_use_padding,
        iso.xa_system_use,
    )?);
    let mut parent_record = make_record_with_padding(
        parent_entry,
        parent.extent,
        parent.length,
        vec![1],
        true,
        trailing_system_use_padding,
        iso.xa_system_use,
    )?;
    if iso.directory_parent_recording_time == DirectoryParentRecordingTime::Current {
        parent_record[18..25].copy_from_slice(&serialize_recording_time(&metadata.recording_time)?);
    }
    records.push(parent_record);
    for entry in iso
        .entries
        .iter()
        .filter(|entry| entry.path != ROOT_PATH && parent_path(&entry.path) == directory.path)
    {
        let is_file = file_paths.contains(entry.path.as_str());
        let (extent, length) = if is_file {
            let file = file_by_path[entry.path.as_str()];
            (file.extent, directory_record_file_length(entry, file)?)
        } else {
            let child = directory_by_path[entry.path.as_str()];
            (child.extent, child.length)
        };
        records.push(make_record_with_padding(
            entry,
            extent,
            length,
            identifier(entry, is_file).into_bytes(),
            !is_file,
            trailing_system_use_padding,
            iso.xa_system_use
                && !iso
                    .xa_system_use_omissions
                    .iter()
                    .any(|path| path == &entry.path),
        )?);
    }
    let mut result = vec![0_u8; usize::try_from(directory.blocks)? * LOGICAL_BLOCK_SIZE];
    let mut offset = 0;
    for record in records {
        let in_block = offset % LOGICAL_BLOCK_SIZE;
        if in_block + record.len() > LOGICAL_BLOCK_SIZE
            || (in_block + record.len() == LOGICAL_BLOCK_SIZE
                && iso.directory_record_packing == DirectoryRecordPacking::AvoidExactFit)
        {
            offset += LOGICAL_BLOCK_SIZE - in_block;
        }
        result[offset..offset + record.len()].copy_from_slice(&record);
        offset += record.len();
    }
    if let Some(slack) = &metadata.directory_slack {
        let data = hex::decode(&slack.hex)
            .with_context(|| format!("decoding directory_slack for {}", metadata.path))?;
        ensure!(
            !data.is_empty(),
            "directory_slack must contain at least one byte: {}",
            metadata.path
        );
        let slack_offset = usize::try_from(slack.offset)?;
        ensure!(
            slack_offset >= offset,
            "directory_slack overlaps generated records for {}",
            metadata.path
        );
        let slack_end = slack_offset
            .checked_add(data.len())
            .context("directory_slack range overflow")?;
        ensure!(
            slack_end <= usize::try_from(directory.length)?,
            "directory_slack extends beyond the directory extent for {}",
            metadata.path
        );
        result[slack_offset..slack_end].copy_from_slice(&data);
    }
    Ok(result)
}

fn serialize_joliet_directory(
    directory: &DirectoryPlacement,
    directories: &[DirectoryPlacement],
    volume: &JolietVolume,
    iso: &Iso9660,
    directory_by_path: &HashMap<&str, &DirectoryPlacement>,
    file_by_path: &HashMap<&str, &FilePlacement>,
) -> Result<Vec<u8>> {
    let trailing_system_use_padding =
        volume.descriptor.application_use == PrimaryVolumeApplicationUse::CdRep20131;
    let entry_by_path = volume
        .entries
        .iter()
        .map(|entry| (entry.path.as_str(), entry))
        .collect::<HashMap<_, _>>();
    let primary_entry_by_path = iso
        .entries
        .iter()
        .map(|entry| (entry.path.as_str(), entry))
        .collect::<HashMap<_, _>>();
    let metadata = entry_by_path[directory.path.as_str()];
    let parent = &directories[directory.parent];
    let parent_entry = entry_by_path[parent.path.as_str()];
    let mut records = Vec::new();
    records.push(make_joliet_record(
        metadata,
        directory.extent,
        directory.length,
        vec![0],
        true,
        trailing_system_use_padding,
        volume.xa_system_use,
    )?);
    let mut parent_record = make_joliet_record(
        parent_entry,
        parent.extent,
        parent.length,
        vec![1],
        true,
        trailing_system_use_padding,
        volume.xa_system_use,
    )?;
    if iso.directory_parent_recording_time == DirectoryParentRecordingTime::Current {
        parent_record[18..25].copy_from_slice(&serialize_recording_time(&metadata.recording_time)?);
    }
    records.push(parent_record);
    for entry in volume
        .entries
        .iter()
        .filter(|entry| entry.path != ROOT_PATH && parent_path(&entry.path) == directory.path)
    {
        let (extent, length, directory_entry) = if let Some(source) = entry.source.as_deref() {
            let file = file_by_path[source];
            (
                file.extent,
                directory_record_file_length(primary_entry_by_path[source], file)?,
                false,
            )
        } else {
            let child = directory_by_path[entry.path.as_str()];
            (child.extent, child.length, true)
        };
        let mut identifier = encode_joliet_identifier(file_name(&entry.path))?;
        if !directory_entry && !entry.omit_version {
            identifier.extend_from_slice(&encode_joliet_identifier(";1")?);
        }
        records.push(make_joliet_record(
            entry,
            extent,
            length,
            identifier,
            directory_entry,
            trailing_system_use_padding,
            volume.xa_system_use,
        )?);
    }
    let mut result = vec![0_u8; usize::try_from(directory.blocks)? * LOGICAL_BLOCK_SIZE];
    let mut offset = 0;
    for record in records {
        let in_block = offset % LOGICAL_BLOCK_SIZE;
        if in_block + record.len() > LOGICAL_BLOCK_SIZE
            || (in_block + record.len() == LOGICAL_BLOCK_SIZE
                && iso.directory_record_packing == DirectoryRecordPacking::AvoidExactFit)
        {
            offset += LOGICAL_BLOCK_SIZE - in_block;
        }
        result[offset..offset + record.len()].copy_from_slice(&record);
        offset += record.len();
    }
    Ok(result)
}

fn directory_record_file_length(entry: &Entry, file: &FilePlacement) -> Result<u32> {
    let Some(xa) = entry.xa.as_ref() else {
        return u32::try_from(file.length).context("file length exceeds ISO 9660 limit");
    };
    if let Some(length) = xa.logical_length {
        return Ok(length);
    }
    match xa.length_encoding {
        XaLengthEncoding::Logical2048 => {
            u32::try_from(file.length).context("file length exceeds ISO 9660 limit")
        }
        XaLengthEncoding::Mode2_2336 => {
            ensure!(
                file.length == u64::from(file.blocks) * LOGICAL_BLOCK_SIZE as u64,
                "mode2_2336 length encoding requires a whole-sector physical extent: {}",
                entry.path
            );
            file.blocks
                .checked_mul(u32::try_from(MODE2_DATA_SIZE)?)
                .context("mode2_2336 directory-record length overflow")
        }
    }
}

fn make_joliet_record(
    entry: &JolietEntry,
    extent: u32,
    length: u32,
    name: Vec<u8>,
    directory: bool,
    trailing_system_use_padding: bool,
    xa_system_use: bool,
) -> Result<Vec<u8>> {
    serialize_record(&Record {
        extent,
        length,
        recording_time: serialize_recording_time(&entry.recording_time)?,
        flags: (if directory { DIRECTORY_FLAG } else { 0 })
            | (u8::from(entry.hidden) * HIDDEN_FLAG)
            | (u8::from(entry.associated) * ASSOCIATED_FLAG),
        file_unit_size: 0,
        interleave_gap_size: 0,
        volume_sequence_number: VOLUME_SEQUENCE_NUMBER,
        name,
        system_use: if xa_system_use {
            serialize_xa_system_use_parts(&entry.path, entry.xa.as_ref(), directory)?
        } else {
            Vec::new()
        },
        trailing_system_use_padding,
    })
}

#[cfg(test)]
fn make_record(
    entry: &Entry,
    extent: u32,
    length: u32,
    name: Vec<u8>,
    directory: bool,
) -> Result<Vec<u8>> {
    make_record_with_padding(entry, extent, length, name, directory, false, true)
}

fn make_record_with_padding(
    entry: &Entry,
    extent: u32,
    length: u32,
    name: Vec<u8>,
    directory: bool,
    trailing_system_use_padding: bool,
    xa_system_use: bool,
) -> Result<Vec<u8>> {
    serialize_record(&Record {
        extent,
        length,
        recording_time: serialize_recording_time(&entry.recording_time)?,
        flags: (if directory { DIRECTORY_FLAG } else { 0 })
            | (u8::from(entry.hidden) * HIDDEN_FLAG)
            | (u8::from(entry.associated) * ASSOCIATED_FLAG),
        file_unit_size: 0,
        interleave_gap_size: 0,
        volume_sequence_number: VOLUME_SEQUENCE_NUMBER,
        name,
        system_use: serialize_directory_record_system_use(entry, directory, xa_system_use)?,
        trailing_system_use_padding,
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
    let system_use_start = 33
        + record.name.len()
        + usize::from(record.name.len().is_multiple_of(2) && !record.trailing_system_use_padding);
    bytes[system_use_start..system_use_start + record.system_use.len()]
        .copy_from_slice(&record.system_use);
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

fn write_joliet_fixed(
    bytes: &mut [u8],
    offset: usize,
    length: usize,
    value: &str,
    zero_fill_empty: bool,
    zero_pad: bool,
    odd_byte: Option<u8>,
) -> Result<()> {
    let encoded = if value.is_empty() {
        Vec::new()
    } else {
        encode_joliet_identifier(value)?
    };
    let encoded_capacity = length / 2 * 2;
    ensure!(
        encoded.len() <= encoded_capacity,
        "fixed Joliet string is too long"
    );
    for chunk in bytes[offset..offset + encoded_capacity].chunks_exact_mut(2) {
        chunk.copy_from_slice(
            if (value.is_empty() && zero_fill_empty) || (!value.is_empty() && zero_pad) {
                &[0, 0]
            } else {
                &[0, b' ']
            },
        );
    }
    bytes[offset..offset + encoded.len()].copy_from_slice(&encoded);
    if length % 2 == 1 {
        bytes[offset + length - 1] = odd_byte.unwrap_or(0);
    } else {
        ensure!(
            odd_byte.is_none(),
            "even-length Joliet string has an odd byte"
        );
    }
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

fn pvd_u16_encoding(block: &[u8; LOGICAL_BLOCK_SIZE]) -> Result<PvdU16Encoding> {
    let offsets = [120, 124, 128];
    let both_endian = offsets.iter().all(|offset| {
        u16::from_le_bytes(block[*offset..*offset + 2].try_into().expect("fixed slice"))
            == u16::from_be_bytes(
                block[*offset + 2..*offset + 4]
                    .try_into()
                    .expect("fixed slice"),
            )
    });
    if both_endian {
        return Ok(PvdU16Encoding::BothEndian);
    }
    let little_only = offsets
        .iter()
        .all(|offset| block[*offset + 2..*offset + 4] == [0, 0]);
    ensure!(
        little_only,
        "unsupported PVD 16-bit both-endian field encoding"
    );
    Ok(PvdU16Encoding::LittleEndianOnly)
}

fn write_pvd_u16(bytes: &mut [u8], offset: usize, value: u16, encoding: PvdU16Encoding) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    if encoding == PvdU16Encoding::BothEndian {
        bytes[offset + 2..offset + 4].copy_from_slice(&value.to_be_bytes());
    }
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

const RAW_TIME_PREFIX: &str = "hex:";

fn raw_time(bytes: &[u8]) -> String {
    format!("{RAW_TIME_PREFIX}{}", hex::encode(bytes))
}

fn parse_raw_time<const N: usize>(value: &str, label: &str) -> Result<Option<[u8; N]>> {
    let Some(value) = value.strip_prefix(RAW_TIME_PREFIX) else {
        return Ok(None);
    };
    let bytes = hex::decode(value).with_context(|| format!("invalid raw {label} time hex"))?;
    ensure!(
        bytes.len() == N,
        "raw {label} time must contain exactly {N} bytes"
    );
    Ok(Some(bytes.try_into().expect("checked raw time length")))
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
    Ok(if validate_volume_time(time).is_ok() {
        format_recording_time(time)
    } else {
        raw_time(&bytes)
    })
}

fn serialize_recording_time(value: &str) -> Result<[u8; 7]> {
    if let Some(bytes) = parse_raw_time(value, "directory recording")? {
        return Ok(bytes);
    }
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
    let parsed = (|| -> Result<VolumeTime> {
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
        Ok(time)
    })();
    Ok(Some(
        parsed.map_or_else(|_| raw_time(bytes), format_volume_time),
    ))
}

fn serialize_volume_time(value: Option<&str>) -> Result<[u8; 17]> {
    let Some(value) = value else {
        let mut bytes = [b'0'; 17];
        bytes[16] = 0;
        return Ok(bytes);
    };
    if let Some(bytes) = parse_raw_time(value, "volume")? {
        return Ok(bytes);
    }
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
            hidden: false,
            associated: false,
            unbacked: false,
            directory_reference: None,
            directory_slack: None,
            allocation_padding_hex: None,
            sector_subheader: crate::manifest::EntrySectorSubheader::Canonical,
            xa: None,
            extent: None,
            length: None,
        }
    }

    fn test_iso(entries: Vec<Entry>, files: Vec<&str>) -> Iso9660 {
        Iso9660 {
            primary_volume: parse_pvd(&standard_pvd_block()).unwrap(),
            primary_volume_copies: 1,
            supplementary_volumes: Vec::new(),
            metadata_layout: Vec::new(),
            xa_system_use: true,
            xa_system_use_omissions: Vec::new(),
            metadata_subheader: crate::manifest::IsoMetadataSubheader::Canonical,
            metadata_framing_subheader: None,
            identifier_policy: IdentifierPolicy::IsoLevel1,
            directory_record_packing: DirectoryRecordPacking::Fill,
            directory_parent_recording_time: DirectoryParentRecordingTime::Parent,
            directory_length_policy: DirectoryLengthPolicy::Allocated,
            path_table_size: None,
            path_table_padding: 0,
            path_table_little_hex: None,
            path_table_big_hex: None,
            path_table_copies: PathTableCopies::Duplicate,
            path_table_order: PathTableOrder::LittleEndianFirst,
            path_table_subheader: EntrySectorSubheader::Canonical,
            path_table_framing_subheader: None,
            entries,
            files: files.into_iter().map(FileLayoutItem::path).collect(),
        }
    }

    #[test]
    fn childless_directory_reference_roundtrips_without_physical_directory() {
        let mut reference = test_entry("DATA/OLD");
        reference.directory_reference = Some(crate::manifest::DirectoryReference {
            extent: 0,
            length: 0,
        });
        let iso = test_iso(
            vec![test_entry(ROOT_PATH), test_entry("DATA"), reference],
            Vec::new(),
        );

        let authored = layout(&iso, &HashMap::new()).unwrap();
        let parsed = parse(&authored.blocks).unwrap();
        let parsed_reference = parsed
            .manifest
            .entries
            .iter()
            .find(|entry| entry.path == "DATA/OLD")
            .unwrap();

        assert_eq!(
            parsed_reference.directory_reference,
            Some(crate::manifest::DirectoryReference {
                extent: 0,
                length: 0,
            })
        );
        assert_eq!(
            parsed
                .directories
                .iter()
                .find(|directory| directory.path == "DATA/OLD")
                .map(|directory| (directory.extent, directory.length)),
            Some((0, 0))
        );
        assert_eq!(
            layout(&parsed.manifest, &HashMap::new()).unwrap().blocks,
            authored.blocks
        );
    }

    #[test]
    fn metadata_derivation_allows_interleaved_primary_and_joliet_directories() {
        let mut blocks = vec![[0_u8; LOGICAL_BLOCK_SIZE]; 32];
        blocks[26][0] = 1;
        let primary_tables = ParsedPathTables {
            extents: [20, 0, 22, 0],
            blocks: 1,
        };
        let joliet_tables = ParsedPathTables {
            extents: [21, 0, 23, 0],
            blocks: 1,
        };
        let primary_directories = vec![
            ParsedDirectory {
                path: ROOT_PATH.to_owned(),
                extent: 24,
                length: LOGICAL_BLOCK_SIZE as u32,
            },
            ParsedDirectory {
                path: "DATA".to_owned(),
                extent: 30,
                length: LOGICAL_BLOCK_SIZE as u32,
            },
        ];
        let joliet_directories = vec![
            ParsedDirectory {
                path: ROOT_PATH.to_owned(),
                extent: 25,
                length: LOGICAL_BLOCK_SIZE as u32,
            },
            ParsedDirectory {
                path: "DATA".to_owned(),
                extent: 31,
                length: LOGICAL_BLOCK_SIZE as u32,
            },
        ];

        assert!(
            derive_metadata_layout(
                &blocks,
                20,
                &primary_tables,
                &primary_directories,
                &joliet_tables,
                &joliet_directories,
            )
            .is_ok()
        );
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
            parse_pvd(&invalid).unwrap().application_use_hex.as_deref(),
            Some(hex::encode(&invalid[APPLICATION_USE_START..APPLICATION_USE_END]).as_str())
        );

        let mut extended = source;
        extended[1032..1042]
            .copy_from_slice(&[0, 0, b'1', b' ', b'1', b' ', b' ', b' ', b' ', b' ']);
        let mut iso = test_iso(vec![test_entry(ROOT_PATH)], vec![]);
        iso.primary_volume = parse_pvd(&extended).unwrap();
        assert_eq!(
            iso.primary_volume.application_use,
            PrimaryVolumeApplicationUse::CdXa001_1_1
        );
        let generated =
            serialize_pvd(&iso, 20, 10, [18, 19, 20, 21], 22, 2048, &iso.entries[0]).unwrap();
        assert_eq!(&generated[883..1395], &extended[883..1395]);

        let mut xcd = source;
        xcd[APPLICATION_USE_END - 12..APPLICATION_USE_END].copy_from_slice(b"XCD322.1 (13");
        let mut iso = test_iso(vec![test_entry(ROOT_PATH)], vec![]);
        iso.primary_volume = parse_pvd(&xcd).unwrap();
        assert_eq!(
            iso.primary_volume.application_use,
            PrimaryVolumeApplicationUse::CdXa001Xcd3221Revision13
        );
        let generated =
            serialize_pvd(&iso, 20, 10, [18, 19, 20, 21], 22, 2048, &iso.entries[0]).unwrap();
        assert_eq!(&generated[883..1395], &xcd[883..1395]);
    }

    #[test]
    fn cd_rep_application_use_is_preserved() {
        let mut source = standard_pvd_block();
        source[APPLICATION_USE_START..APPLICATION_USE_END].fill(0);
        source[APPLICATION_USE_START..APPLICATION_USE_START + 14]
            .copy_from_slice(b"CD Rep 2.0.131");

        let mut iso = test_iso(vec![test_entry(ROOT_PATH)], vec![]);
        iso.primary_volume = parse_pvd(&source).unwrap();
        let generated =
            serialize_pvd(&iso, 20, 10, [18, 19, 20, 21], 22, 2048, &iso.entries[0]).unwrap();

        assert_eq!(&generated[883..1395], &source[883..1395]);
    }

    #[test]
    fn nonstandard_application_use_is_preserved_as_bounded_metadata() {
        let mut source = standard_pvd_block();
        source[APPLICATION_USE_START..APPLICATION_USE_END].fill(0);
        source[APPLICATION_USE_START..APPLICATION_USE_START + 5].copy_from_slice(b"EB111");
        source[1024..1032].copy_from_slice(b"CD-XA001");

        let mut iso = test_iso(vec![test_entry(ROOT_PATH)], vec![]);
        iso.primary_volume = parse_pvd(&source).unwrap();
        assert_eq!(
            iso.primary_volume.application_use_hex.as_deref(),
            Some(hex::encode(&source[APPLICATION_USE_START..APPLICATION_USE_END]).as_str())
        );
        let generated =
            serialize_pvd(&iso, 20, 10, [18, 19, 20, 21], 22, 2048, &iso.entries[0]).unwrap();

        assert_eq!(
            &generated[APPLICATION_USE_START..APPLICATION_USE_END],
            &source[APPLICATION_USE_START..APPLICATION_USE_END]
        );

        iso.primary_volume.application_use_hex = Some("00".repeat(511));
        assert!(serialize_pvd(&iso, 20, 10, [18, 19, 20, 21], 22, 2048, &iso.entries[0]).is_err());

        iso.primary_volume.application_use_hex = Some("00".repeat(512));
        iso.primary_volume.application_use = PrimaryVolumeApplicationUse::CdRep20131;
        assert!(serialize_pvd(&iso, 20, 10, [18, 19, 20, 21], 22, 2048, &iso.entries[0]).is_err());
    }

    #[test]
    fn pvd_reserved_bytes_are_preserved_as_bounded_hex() {
        let mut source = standard_pvd_block();
        source[APPLICATION_USE_END..APPLICATION_USE_END + 2].copy_from_slice(&[0x37, 0x29]);
        let mut iso = test_iso(vec![test_entry(ROOT_PATH)], vec![]);
        iso.primary_volume = parse_pvd(&source).unwrap();

        assert_eq!(iso.primary_volume.reserved_hex.as_deref(), Some("3729"));
        let generated =
            serialize_pvd(&iso, 20, 10, [18, 19, 20, 21], 22, 2048, &iso.entries[0]).unwrap();
        assert_eq!(
            &generated[APPLICATION_USE_END..],
            &source[APPLICATION_USE_END..]
        );

        iso.primary_volume.reserved_hex = Some("00".repeat(LOGICAL_BLOCK_SIZE));
        assert!(serialize_pvd(&iso, 20, 10, [18, 19, 20, 21], 22, 2048, &iso.entries[0]).is_err());
    }

    #[test]
    fn trailing_directory_record_padding_is_recognized() {
        let entry = test_entry("ZDUMMY.DAT");
        let bytes = make_record_with_padding(
            &entry,
            24,
            LOGICAL_BLOCK_SIZE as u32,
            b"ZDUMMY.DAT;1".to_vec(),
            false,
            true,
            true,
        )
        .unwrap();
        let expected_system_use = serialize_xa_system_use(&entry, false).unwrap();
        assert_eq!(&bytes[45..59], expected_system_use);
        assert_eq!(bytes[59], 0);

        let record = parse_record(&bytes).unwrap();
        assert!(record.trailing_system_use_padding);
        entry_xa(&record, false, true).unwrap();
    }

    #[test]
    fn pvd_parent_root_identifier_is_preserved() {
        let mut source = standard_pvd_block();
        source[189] = 1;
        let mut iso = test_iso(vec![test_entry(ROOT_PATH)], vec![]);
        iso.primary_volume = parse_pvd(&source).unwrap();

        let generated =
            serialize_pvd(&iso, 20, 10, [18, 19, 20, 21], 22, 2048, &iso.entries[0]).unwrap();

        assert_eq!(generated[189], 1);
    }

    #[test]
    fn overlong_pvd_root_record_length_is_preserved() {
        let iso = test_iso(vec![test_entry(ROOT_PATH)], vec![]);
        let mut authored = layout(&iso, &HashMap::new()).unwrap();
        authored.blocks[16][156] = 68;

        let mut parsed = parse(&authored.blocks).unwrap();
        assert_eq!(
            parsed.manifest.primary_volume.root_directory_record_length,
            Some(68)
        );
        let rebuilt = layout(&parsed.manifest, &HashMap::new()).unwrap();

        assert_eq!(rebuilt.blocks[16], authored.blocks[16]);

        parsed.manifest.primary_volume.root_directory_record_length = Some(34);
        assert!(layout(&parsed.manifest, &HashMap::new()).is_err());
    }

    #[test]
    fn distinct_pvd_root_recording_time_is_preserved() {
        let iso = test_iso(vec![test_entry(ROOT_PATH)], vec![]);
        let mut authored = layout(&iso, &HashMap::new()).unwrap();
        let pvd_time = "2002-01-07T14:58:33-03:00";
        authored.blocks[16][174..181].copy_from_slice(&serialize_recording_time(pvd_time).unwrap());

        let parsed = parse(&authored.blocks).unwrap();
        assert_eq!(
            parsed.manifest.primary_volume.root_directory_recording_time,
            Some(String::from(pvd_time))
        );
        let rebuilt = layout(&parsed.manifest, &HashMap::new()).unwrap();

        assert_eq!(rebuilt.blocks, authored.blocks);
    }

    #[test]
    fn trailing_directory_slack_is_preserved() {
        let iso = test_iso(vec![test_entry(ROOT_PATH)], vec![]);
        let mut authored = layout(&iso, &HashMap::new()).unwrap();
        let root_extent =
            usize::try_from(read_both_u32(&authored.blocks[16], 158).unwrap()).unwrap();
        authored.blocks[root_extent][512] = 0xc0;
        authored.blocks[root_extent][700] = 0x5a;

        let mut parsed = parse(&authored.blocks).unwrap();
        let slack = parsed.manifest.entries[0].directory_slack.as_ref().unwrap();
        assert_eq!(slack.offset, 512);
        assert_eq!(hex::decode(&slack.hex).unwrap().len(), 189);
        let rebuilt = layout(&parsed.manifest, &HashMap::new()).unwrap();

        assert_eq!(rebuilt.blocks[root_extent], authored.blocks[root_extent]);

        parsed.manifest.entries[0]
            .directory_slack
            .as_mut()
            .unwrap()
            .offset = 0;
        assert!(layout(&parsed.manifest, &HashMap::new()).is_err());
    }

    #[test]
    fn nonzero_file_allocation_padding_is_preserved() {
        let mut iso = test_iso(
            vec![test_entry(ROOT_PATH), test_entry("FILE.BIN")],
            vec!["FILE.BIN"],
        );
        let lengths = HashMap::from([(String::from("FILE.BIN"), 5_u64)]);
        let mut authored = layout(&iso, &lengths).unwrap();
        let extent = usize::try_from(authored.files[0].extent).unwrap();
        authored.blocks[extent][5] = 0x85;
        authored.blocks[extent][17] = 0x39;

        let parsed = parse(&authored.blocks).unwrap();
        iso = parsed.manifest;
        let rebuilt = layout(&iso, &lengths).unwrap();

        assert_eq!(rebuilt.blocks, authored.blocks);
    }

    #[test]
    fn explicit_volume_space_size_may_exceed_the_authored_data_track() {
        let mut iso = test_iso(vec![test_entry(ROOT_PATH)], vec![]);
        iso.primary_volume.volume_space_size = Some(294_418);
        iso.files.push(FileLayoutItem::xa_gap(150));
        let lengths = HashMap::new();

        let authored = layout(&iso, &lengths).unwrap();

        assert_eq!(authored.volume_blocks, 173);
        assert_eq!(read_both_u32(&authored.blocks[16], 80).unwrap(), 294_418);
    }

    #[test]
    fn file_structure_version_zero_round_trips_as_bounded_descriptor_metadata() {
        let mut iso = test_iso(vec![test_entry(ROOT_PATH)], vec![]);
        iso.primary_volume.file_structure_version = Some(0);

        let authored = layout(&iso, &HashMap::new()).unwrap();
        assert_eq!(authored.blocks[16][881], 0);

        let parsed = parse(&authored.blocks).unwrap();
        assert_eq!(
            parsed.manifest.primary_volume.file_structure_version,
            Some(0)
        );
    }

    #[test]
    fn explicit_volume_space_size_can_exclude_terminal_form2_gap() {
        let mut iso = test_iso(vec![test_entry(ROOT_PATH)], vec![]);
        iso.primary_volume.volume_space_size = Some(23);
        iso.files.push(FileLayoutItem::gap(300));

        let authored = layout(&iso, &HashMap::new()).unwrap();

        assert_eq!(authored.volume_blocks, 323);
        assert_eq!(read_both_u32(&authored.blocks[16], 80).unwrap(), 23);
        assert_eq!(
            parse(&authored.blocks)
                .unwrap()
                .manifest
                .primary_volume
                .volume_space_size,
            Some(23)
        );
    }

    #[test]
    fn explicit_volume_space_size_can_be_smaller_than_referenced_content() {
        let iso = test_iso(vec![test_entry(ROOT_PATH)], vec![]);
        let mut authored = layout(&iso, &HashMap::new()).unwrap();
        write_both_u32(&mut authored.blocks[16], 80, 22);

        let parsed = parse(&authored.blocks).unwrap();
        assert_eq!(parsed.manifest.primary_volume.volume_space_size, Some(22));
        let rebuilt = layout(&parsed.manifest, &HashMap::new()).unwrap();

        assert_eq!(rebuilt.blocks, authored.blocks);
    }

    #[test]
    fn pvd_little_endian_only_u16_fields_are_preserved() {
        let iso = test_iso(vec![test_entry(ROOT_PATH)], vec![]);
        let mut authored = layout(&iso, &HashMap::new()).unwrap();
        for offset in [120, 124, 128] {
            authored.blocks[16][offset + 2..offset + 4].fill(0);
        }

        let parsed = parse(&authored.blocks).unwrap();
        let rebuilt = layout(&parsed.manifest, &HashMap::new()).unwrap();

        assert_eq!(rebuilt.blocks, authored.blocks);
    }

    #[test]
    fn path_table_data_until_final_policy_applies_to_each_copy() {
        let mut entries = vec![test_entry(ROOT_PATH)];
        entries.extend((0..200).map(|index| test_entry(&format!("D{index:03}"))));
        let mut iso = test_iso(entries, vec![]);
        iso.path_table_subheader = EntrySectorSubheader::DataUntilFinal;

        let authored = layout(&iso, &HashMap::new()).unwrap();

        assert!(
            [18, 20, 22, 24]
                .into_iter()
                .all(|lba| authored.data_subheader_sectors.contains(&lba))
        );
        assert!(
            [19, 21, 23, 25]
                .into_iter()
                .all(|lba| authored.metadata_subheader_sectors.contains(&lba))
        );
    }

    #[test]
    fn path_table_end_of_file_data_policy_applies_to_each_copy() {
        let mut entries = vec![test_entry(ROOT_PATH)];
        entries.extend((0..200).map(|index| test_entry(&format!("D{index:03}"))));
        let mut iso = test_iso(entries, vec![]);
        iso.path_table_subheader = EntrySectorSubheader::EndOfFileData;

        let authored = layout(&iso, &HashMap::new()).unwrap();

        assert!(
            [18, 20, 22, 24]
                .into_iter()
                .all(|lba| authored.data_subheader_sectors.contains(&lba))
        );
        assert!(
            [19, 21, 23, 25]
                .into_iter()
                .all(|lba| authored.end_of_file_data_subheader_sectors.contains(&lba))
        );
    }

    #[test]
    fn single_path_table_copies_omit_optional_pointers_and_sectors() {
        let mut iso = test_iso(vec![test_entry(ROOT_PATH)], vec![]);
        iso.path_table_copies = PathTableCopies::Single;

        let authored = layout(&iso, &HashMap::new()).unwrap();
        let pvd = &authored.blocks[16];

        assert_eq!(u32::from_le_bytes(pvd[140..144].try_into().unwrap()), 18);
        assert_eq!(u32::from_le_bytes(pvd[144..148].try_into().unwrap()), 0);
        assert_eq!(u32::from_be_bytes(pvd[148..152].try_into().unwrap()), 19);
        assert_eq!(u32::from_be_bytes(pvd[152..156].try_into().unwrap()), 0);
        assert_eq!(read_both_u32(pvd, 158).unwrap(), 20);
        assert_eq!(authored.blocks.len(), 21);
    }

    #[test]
    fn path_table_copies_can_have_structured_xa_gap_padding() {
        let mut iso = test_iso(vec![test_entry(ROOT_PATH)], vec![]);
        iso.path_table_copies = PathTableCopies::Single;
        iso.path_table_padding = 1;

        let authored = layout(&iso, &HashMap::new()).unwrap();
        let pvd = &authored.blocks[16];

        assert_eq!(u32::from_le_bytes(pvd[140..144].try_into().unwrap()), 18);
        assert_eq!(u32::from_be_bytes(pvd[148..152].try_into().unwrap()), 20);
        assert_eq!(read_both_u32(pvd, 158).unwrap(), 22);
        assert_eq!(
            authored.gaps,
            vec![
                GapPlacement {
                    start: 19,
                    sectors: 1,
                    kind: GapKind::Xa,
                    subheader: None,
                    form2_edc: None,
                },
                GapPlacement {
                    start: 21,
                    sectors: 1,
                    kind: GapKind::Xa,
                    subheader: None,
                    form2_edc: None,
                },
            ]
        );
        assert_eq!(
            parse(&authored.blocks).unwrap().manifest.path_table_padding,
            1
        );
    }

    fn test_joliet_iso() -> Iso9660 {
        let root = test_entry(ROOT_PATH);
        let file = test_entry("FILE.BIN");
        let mut iso = test_iso(vec![root, file], vec!["FILE.BIN"]);
        iso.path_table_copies = PathTableCopies::Single;
        iso.supplementary_volumes = vec![crate::manifest::JolietVolume {
            level: crate::manifest::JolietLevel::Level3,
            flags: 0,
            zero_fill_empty_strings: false,
            zero_pad_strings: false,
            volume_set_identifier_raw_hex: None,
            descriptor: iso.primary_volume.clone(),
            xa_system_use: true,
            path_table_size: None,
            path_table_little_hex: None,
            path_table_big_hex: None,
            file_identifier_odd_bytes_hex: None,
            entries: vec![
                crate::manifest::JolietEntry {
                    path: ROOT_PATH.to_owned(),
                    source: None,
                    omit_version: false,
                    recording_time: "2000-01-01T00:00:00+00:00".to_owned(),
                    hidden: false,
                    associated: false,
                    xa: None,
                },
                crate::manifest::JolietEntry {
                    path: "file.bin".to_owned(),
                    source: Some("FILE.BIN".to_owned()),
                    omit_version: false,
                    recording_time: "2000-01-01T00:00:00+00:00".to_owned(),
                    hidden: false,
                    associated: false,
                    xa: None,
                },
            ],
        }];
        iso.metadata_layout = vec![
            crate::manifest::MetadataLayoutItem::path_table(
                crate::manifest::MetadataPathTable::PrimaryLittle,
            ),
            crate::manifest::MetadataLayoutItem::path_table(
                crate::manifest::MetadataPathTable::PrimaryBig,
            ),
            crate::manifest::MetadataLayoutItem::path_table(
                crate::manifest::MetadataPathTable::JolietLittle,
            ),
            crate::manifest::MetadataLayoutItem::path_table(
                crate::manifest::MetadataPathTable::JolietBig,
            ),
            crate::manifest::MetadataLayoutItem::directories(
                crate::manifest::MetadataVolume::Primary,
            ),
            crate::manifest::MetadataLayoutItem::directories(
                crate::manifest::MetadataVolume::Joliet,
            ),
        ];
        iso
    }

    #[test]
    fn joliet_directories_can_use_the_ordered_file_layout() {
        let mut iso = test_joliet_iso();
        iso.metadata_layout.truncate(4);
        iso.files = vec![
            FileLayoutItem::directory(ROOT_PATH),
            FileLayoutItem::volume_directory(MetadataVolume::Joliet, ROOT_PATH),
            FileLayoutItem::path("FILE.BIN"),
        ];
        let lengths = HashMap::from([("FILE.BIN".to_owned(), 17_u64)]);

        let authored = layout(&iso, &lengths).unwrap();

        assert_eq!(read_both_u32(&authored.blocks[16], 158).unwrap(), 23);
        assert_eq!(read_both_u32(&authored.blocks[17], 158).unwrap(), 24);
        assert_eq!(authored.files[0].extent, 25);
    }

    #[test]
    fn joliet_supplementary_volume_has_its_own_structured_metadata() {
        let iso = test_joliet_iso();
        let lengths = HashMap::from([("FILE.BIN".to_owned(), 17_u64)]);

        let authored = layout(&iso, &lengths).unwrap();

        assert_eq!(&authored.blocks[17][..7], b"\x02CD001\x01");
        let parsed = parse(&authored.blocks).unwrap();
        assert_eq!(parsed.manifest.supplementary_volumes.len(), 1);
        assert_eq!(
            parsed.manifest.supplementary_volumes[0].entries[1].path,
            "file.bin"
        );
        assert_eq!(
            layout(&parsed.manifest, &lengths).unwrap().blocks,
            authored.blocks
        );
    }

    #[test]
    fn joliet_descriptor_padding_variants_round_trip_in_memory() {
        let iso = test_joliet_iso();
        let lengths = HashMap::from([("FILE.BIN".to_owned(), 17_u64)]);
        let mut authored = layout(&iso, &lengths).unwrap();
        let svd = &mut authored.blocks[17];
        svd[8..40].fill(0);
        svd[40..72].fill(0);
        svd[40..42].copy_from_slice(&[0, b'X']);
        svd[190..258].fill(0);
        svd[318..813].fill(0);

        let parsed = parse(&authored.blocks).unwrap();
        let volume = &parsed.manifest.supplementary_volumes[0];
        assert!(volume.zero_fill_empty_strings);
        assert!(volume.zero_pad_strings);
        assert!(volume.volume_set_identifier_raw_hex.is_some());
        assert_eq!(
            layout(&parsed.manifest, &lengths).unwrap().blocks,
            authored.blocks
        );
    }

    #[test]
    fn structured_joliet_metadata_keeps_fixed_reference_ancestors_in_place() {
        let mut iso = test_joliet_iso();
        iso.entries.insert(1, test_entry("DIR"));
        iso.entries[2].path = "DIR/FILE.BIN".to_owned();
        iso.entries[2].extent = Some(100);
        iso.entries[2].length = Some(17);
        iso.entries[2].unbacked = true;
        iso.files.clear();
        let volume = &mut iso.supplementary_volumes[0];
        volume.entries.insert(
            1,
            JolietEntry {
                path: "dir".to_owned(),
                source: None,
                omit_version: false,
                recording_time: "2000-01-01T00:00:00+00:00".to_owned(),
                hidden: false,
                associated: false,
                xa: None,
            },
        );
        volume.entries[2].path = "dir/file.bin".to_owned();
        volume.entries[2].source = Some("DIR/FILE.BIN".to_owned());

        let authored = layout(&iso, &HashMap::new()).unwrap();
        let primary_little = u32::from_le_bytes(authored.blocks[16][140..144].try_into().unwrap());

        assert_eq!(
            u32::from_le_bytes(
                authored.blocks[usize::try_from(primary_little).unwrap()][12..16]
                    .try_into()
                    .unwrap()
            ),
            24
        );
        assert_eq!(authored.blocks.len(), 27);
    }

    #[test]
    fn single_big_endian_path_table_can_precede_little_endian() {
        let mut iso = test_iso(vec![test_entry(ROOT_PATH)], vec![]);
        iso.path_table_copies = PathTableCopies::Single;
        iso.path_table_order = crate::manifest::PathTableOrder::BigEndianFirst;

        let authored = layout(&iso, &HashMap::new()).unwrap();
        let pvd = &authored.blocks[16];

        assert_eq!(u32::from_le_bytes(pvd[140..144].try_into().unwrap()), 19);
        assert_eq!(u32::from_le_bytes(pvd[144..148].try_into().unwrap()), 0);
        assert_eq!(u32::from_be_bytes(pvd[148..152].try_into().unwrap()), 18);
        assert_eq!(u32::from_be_bytes(pvd[152..156].try_into().unwrap()), 0);
    }

    #[test]
    fn inconsistent_pvd_path_table_size_is_preserved() {
        let iso = test_iso(vec![test_entry(ROOT_PATH)], vec![]);
        let mut authored = layout(&iso, &HashMap::new()).unwrap();
        write_both_u32(&mut authored.blocks[16], 132, 236);
        for lba in 18..=21 {
            authored.blocks[lba][10] = 3;
        }

        let mut parsed = parse(&authored.blocks).unwrap();
        assert_eq!(parsed.manifest.path_table_size, Some(236));
        assert_eq!(
            hex::decode(parsed.manifest.path_table_little_hex.as_ref().unwrap())
                .unwrap()
                .len(),
            236
        );
        assert_eq!(
            hex::decode(parsed.manifest.path_table_big_hex.as_ref().unwrap())
                .unwrap()
                .len(),
            236
        );
        let rebuilt = layout(&parsed.manifest, &HashMap::new()).unwrap();

        assert_eq!(rebuilt.blocks, authored.blocks);

        parsed.manifest.path_table_big_hex = None;
        assert!(layout(&parsed.manifest, &HashMap::new()).is_err());
        parsed.manifest.path_table_big_hex = parsed.manifest.path_table_little_hex.clone();
        parsed.manifest.path_table_size = Some(2049);
        assert!(layout(&parsed.manifest, &HashMap::new()).is_err());
    }

    #[test]
    fn noncanonical_path_table_payload_is_preserved() {
        let iso = test_iso(vec![test_entry(ROOT_PATH)], vec![]);
        let mut authored = layout(&iso, &HashMap::new()).unwrap();
        for lba in 18..=19 {
            authored.blocks[lba][2] = 23;
        }
        for lba in 20..=21 {
            authored.blocks[lba][5] = 23;
        }

        let parsed = parse(&authored.blocks).unwrap();
        assert!(parsed.manifest.path_table_size.is_none());
        assert!(parsed.manifest.path_table_little_hex.is_some());
        assert!(parsed.manifest.path_table_big_hex.is_some());
        let rebuilt = layout(&parsed.manifest, &HashMap::new()).unwrap();

        assert_eq!(rebuilt.blocks, authored.blocks);
    }

    #[test]
    fn entry_iso_metadata_subheader_marks_every_file_sector() {
        let mut iso = test_iso(
            vec![test_entry(ROOT_PATH), test_entry("FILE.BIN")],
            vec!["FILE.BIN"],
        );
        iso.entries[1].sector_subheader = EntrySectorSubheader::IsoMetadata;
        let lengths = HashMap::from([("FILE.BIN".to_owned(), (2 * LOGICAL_BLOCK_SIZE) as u64)]);

        let authored = layout(&iso, &lengths).unwrap();

        assert_eq!(authored.files[0].extent, 23);
        assert!(authored.metadata_subheader_sectors.contains(&23));
        assert!(authored.metadata_subheader_sectors.contains(&24));
    }

    #[test]
    fn directory_end_of_file_data_subheader_marks_its_final_sector() {
        let mut root = test_entry(ROOT_PATH);
        root.sector_subheader = EntrySectorSubheader::EndOfFileData;
        let iso = test_iso(vec![root], vec![]);

        let authored = layout(&iso, &HashMap::new()).unwrap();

        assert!(authored.end_of_file_data_subheader_sectors.contains(&22));
    }

    #[test]
    fn directory_parent_record_can_use_current_directory_time() {
        let root = test_entry(ROOT_PATH);
        let mut directory = test_entry("DIR");
        directory.recording_time = "2001-02-03T04:05:06+00:00".to_owned();
        let mut iso = test_iso(vec![root, directory], vec![]);
        iso.directory_parent_recording_time = DirectoryParentRecordingTime::Current;

        let authored = layout(&iso, &HashMap::new()).unwrap();
        let parsed = parse(&authored.blocks).unwrap();

        assert_eq!(
            parsed.manifest.directory_parent_recording_time,
            DirectoryParentRecordingTime::Current
        );
        assert_eq!(
            layout(&parsed.manifest, &HashMap::new()).unwrap().blocks,
            authored.blocks
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
    fn three_primary_volume_copies_precede_the_terminator() {
        let mut iso = test_iso(vec![test_entry(ROOT_PATH)], vec![]);
        iso.primary_volume_copies = 3;

        let authored = layout(&iso, &HashMap::new()).unwrap();

        assert_eq!(&authored.blocks[16][..7], b"\x01CD001\x01");
        assert_eq!(authored.blocks[16], authored.blocks[17]);
        assert_eq!(authored.blocks[16], authored.blocks[18]);
        assert_eq!(&authored.blocks[19][..7], b"\xffCD001\x01");
        assert_eq!(
            parse(&authored.blocks)
                .unwrap()
                .manifest
                .primary_volume_copies,
            3
        );
    }

    #[test]
    fn two_primary_volume_copies_precede_the_terminator() {
        let mut iso = test_iso(vec![test_entry(ROOT_PATH)], vec![]);
        iso.primary_volume_copies = 2;

        let authored = layout(&iso, &HashMap::new()).unwrap();

        assert_eq!(authored.blocks[16], authored.blocks[17]);
        assert_eq!(&authored.blocks[18][..7], b"\xffCD001\x01");
        assert_eq!(
            parse(&authored.blocks)
                .unwrap()
                .manifest
                .primary_volume_copies,
            2
        );
    }

    #[test]
    fn iso_can_omit_all_directory_record_xa_system_use() {
        let mut iso = test_iso(
            vec![test_entry(ROOT_PATH), test_entry("FILE.BIN")],
            vec!["FILE.BIN"],
        );
        iso.xa_system_use = false;
        let lengths = HashMap::from([(String::from("FILE.BIN"), 1_u64)]);

        let authored = layout(&iso, &lengths).unwrap();
        let parsed = parse(&authored.blocks).unwrap();

        assert!(!parsed.manifest.xa_system_use);
        assert_eq!(
            layout(&parsed.manifest, &lengths).unwrap().blocks,
            authored.blocks
        );
    }

    #[test]
    fn file_can_omit_directory_record_xa_system_use() {
        let mut iso = test_iso(
            vec![test_entry(ROOT_PATH), test_entry("FILE.BIN")],
            vec!["FILE.BIN"],
        );
        iso.xa_system_use_omissions = vec![String::from("FILE.BIN")];
        let lengths = HashMap::from([(String::from("FILE.BIN"), 1_u64)]);

        let authored = layout(&iso, &lengths).unwrap();
        let parsed = parse(&authored.blocks).unwrap();

        assert_eq!(parsed.manifest.xa_system_use_omissions, vec!["FILE.BIN"]);
        assert_eq!(
            layout(&parsed.manifest, &lengths).unwrap().blocks,
            authored.blocks
        );
    }

    #[test]
    fn avoid_exact_fit_directory_packing_starts_the_record_in_the_next_block() {
        assert_eq!(
            packed_blocks(&[1986, 62], DirectoryRecordPacking::AvoidExactFit),
            2
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
    fn invalid_volume_time_bytes_round_trip_through_hex_fallback() {
        let invalid = *b"1995063103150000$";
        let raw = "hex:3139393530363331303331353030303024";

        assert_eq!(parse_volume_time(&invalid).unwrap().as_deref(), Some(raw));
        assert_eq!(serialize_volume_time(Some(raw)).unwrap(), invalid);
        assert!(serialize_volume_time(Some("hex:00")).is_err());
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
    fn invalid_directory_time_bytes_round_trip_through_hex_fallback() {
        let invalid = [0x5f, 0x06, 0x1f, 0x03, 0x0f, 0x00, 0x24];
        let raw = "hex:5f061f030f0024";

        assert_eq!(parse_recording_time(invalid).unwrap(), raw);
        assert_eq!(serialize_recording_time(raw).unwrap(), invalid);
        assert!(serialize_recording_time("hex:00").is_err());
    }

    #[test]
    fn record_with_odd_identifier_needs_no_padding_byte() {
        assert_eq!(record_size(11, 14), 58);
        assert_eq!(record_size(12, 14), 60);
    }

    #[test]
    fn level_one_names_are_validated() {
        validate_path("DIR/FILE.BIN", true, IdentifierPolicy::IsoLevel1).unwrap();
        assert!(validate_path("dir/file.bin", true, IdentifierPolicy::IsoLevel1).is_err());
        assert!(validate_path("../FILE.BIN", true, IdentifierPolicy::IsoLevel1).is_err());
        assert!(validate_path("TOO_LONG_NAME.BIN", true, IdentifierPolicy::IsoLevel1).is_err());
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
    fn directories_are_placed_immediately_before_their_first_file() {
        let iso = test_iso(
            vec![
                test_entry(ROOT_PATH),
                test_entry("ROOT.BIN"),
                test_entry("S0"),
                test_entry("S0/A.BIN"),
                test_entry("S1"),
                test_entry("S1/B.BIN"),
            ],
            vec!["ROOT.BIN", "S0/A.BIN", "S1/B.BIN"],
        );
        let file_lengths = HashMap::from([
            ("ROOT.BIN".to_owned(), LOGICAL_BLOCK_SIZE as u64),
            ("S0/A.BIN".to_owned(), LOGICAL_BLOCK_SIZE as u64),
            ("S1/B.BIN".to_owned(), LOGICAL_BLOCK_SIZE as u64),
        ]);

        let authored = layout(&iso, &file_lengths).unwrap();
        assert_eq!(
            authored
                .files
                .iter()
                .map(|file| (file.path.as_str(), file.extent))
                .collect::<Vec<_>>(),
            vec![("ROOT.BIN", 23), ("S0/A.BIN", 25), ("S1/B.BIN", 27)]
        );
        assert_eq!(
            [2, 12, 22].map(|offset| {
                u32::from_le_bytes(authored.blocks[18][offset..offset + 4].try_into().unwrap())
            }),
            [22, 24, 26]
        );
    }

    #[test]
    fn mode2_2336_length_encoding_changes_only_the_directory_record_length() {
        let mut stream = test_entry("MOVIE.STR");
        stream.xa = Some(EntryXa {
            form1: Some("MOVIE.STR.XA1".to_owned()),
            form2: Some("MOVIE.STR.XA2".to_owned()),
            index: Some("MOVIE.STR.XAI".to_owned()),
            length_encoding: XaLengthEncoding::Mode2_2336,
            ..EntryXa::default()
        });
        let iso = test_iso(vec![test_entry(ROOT_PATH), stream], vec!["MOVIE.STR"]);
        let lengths = HashMap::from([("MOVIE.STR".to_owned(), 2 * LOGICAL_BLOCK_SIZE as u64)]);

        let authored = layout(&iso, &lengths).unwrap();
        let root = parse_record(&authored.blocks[16][156..]).unwrap();
        let (records, _, _) = read_directory(&authored.blocks, root.extent, root.length).unwrap();

        assert_eq!(authored.files[0].blocks, 2);
        assert_eq!(records[2].length, 2 * 2336);
    }

    #[test]
    fn explicit_directory_item_controls_empty_directory_placement() {
        let mut iso = test_iso(
            vec![
                test_entry(ROOT_PATH),
                test_entry("EMPTY"),
                test_entry("FILE.BIN"),
            ],
            vec!["FILE.BIN"],
        );
        iso.files.insert(0, FileLayoutItem::directory("EMPTY"));
        let lengths = HashMap::from([("FILE.BIN".to_owned(), LOGICAL_BLOCK_SIZE as u64)]);

        let authored = layout(&iso, &lengths).unwrap();

        assert_eq!(authored.files[0].extent, 24);
        assert_eq!(
            u32::from_le_bytes(authored.blocks[18][12..16].try_into().unwrap()),
            23
        );
    }

    #[test]
    fn explicit_directory_item_can_follow_a_file_in_that_directory() {
        let mut iso = test_iso(
            vec![
                test_entry(ROOT_PATH),
                test_entry("DD"),
                test_entry("DD/A.BIN"),
            ],
            vec!["DD/A.BIN"],
        );
        iso.files.push(FileLayoutItem::directory("DD"));
        let lengths = HashMap::from([("DD/A.BIN".to_owned(), LOGICAL_BLOCK_SIZE as u64)]);

        let authored = layout(&iso, &lengths).unwrap();

        assert_eq!(authored.files[0].extent, 23);
        assert_eq!(
            u32::from_le_bytes(authored.blocks[18][12..16].try_into().unwrap()),
            24
        );
    }

    #[test]
    fn unreferenced_xa_extent_occupies_its_physical_position() {
        let mut iso = test_iso(
            vec![
                test_entry(ROOT_PATH),
                test_entry("A.BIN"),
                test_entry("B.BIN"),
            ],
            vec!["A.BIN", "B.BIN"],
        );
        let assets = crate::manifest::XaExtentAssets {
            form1: "disc.unreferenced.000.XA1".to_owned(),
            form2: "disc.unreferenced.000.XA2".to_owned(),
            index: "disc.unreferenced.000.XAI".to_owned(),
            gap_index: None,
        };
        iso.files
            .insert(1, FileLayoutItem::xa_extent(assets.clone()));
        let lengths = HashMap::from([
            ("A.BIN".to_owned(), LOGICAL_BLOCK_SIZE as u64),
            ("B.BIN".to_owned(), LOGICAL_BLOCK_SIZE as u64),
            (assets.index.clone(), 2 * LOGICAL_BLOCK_SIZE as u64),
        ]);

        let authored = layout(&iso, &lengths).unwrap();

        assert_eq!(
            authored
                .files
                .iter()
                .map(|file| (file.path.as_str(), file.extent))
                .collect::<Vec<_>>(),
            vec![("A.BIN", 23), ("B.BIN", 26)]
        );
        assert_eq!(authored.xa_extents.len(), 1);
        assert_eq!(authored.xa_extents[0].index, assets.index);
        assert_eq!(authored.xa_extents[0].start, 24);
        assert_eq!(authored.xa_extents[0].sectors, 2);
    }

    #[test]
    fn ordered_gaps_shift_only_the_following_and_later_files() {
        let mut iso = test_iso(
            vec![
                test_entry(ROOT_PATH),
                test_entry("A.BIN"),
                test_entry("B.BIN"),
            ],
            vec!["A.BIN", "B.BIN"],
        );
        iso.files.insert(1, FileLayoutItem::gap(3));
        let lengths = HashMap::from([
            ("A.BIN".to_owned(), LOGICAL_BLOCK_SIZE as u64),
            ("B.BIN".to_owned(), LOGICAL_BLOCK_SIZE as u64),
        ]);

        let authored = layout(&iso, &lengths).unwrap();
        assert_eq!(authored.files[0].extent, 23);
        assert_eq!(authored.files[1].extent, 27);
    }

    #[test]
    fn consecutive_different_gap_kinds_are_placed_in_order() {
        let mut iso = test_iso(
            vec![
                test_entry(ROOT_PATH),
                test_entry("A.BIN"),
                test_entry("B.BIN"),
            ],
            vec!["A.BIN", "B.BIN"],
        );
        iso.files.splice(
            1..1,
            [
                FileLayoutItem::form1_gap(1, crate::raw_cd::XaSubheader::default()),
                FileLayoutItem::gap(2),
            ],
        );
        let lengths = HashMap::from([
            ("A.BIN".to_owned(), LOGICAL_BLOCK_SIZE as u64),
            ("B.BIN".to_owned(), LOGICAL_BLOCK_SIZE as u64),
        ]);

        let authored = layout(&iso, &lengths).unwrap();

        assert_eq!(authored.files[0].extent, 23);
        assert_eq!(authored.files[1].extent, 27);
        assert_eq!(authored.gaps[0].start, 24);
        assert_eq!(authored.gaps[1].start, 25);
    }

    #[test]
    fn consecutive_form1_gaps_with_different_subheaders_are_placed_in_order() {
        let mut iso = test_iso(
            vec![
                test_entry(ROOT_PATH),
                test_entry("A.BIN"),
                test_entry("B.BIN"),
            ],
            vec!["A.BIN", "B.BIN"],
        );
        let second_subheader = crate::raw_cd::XaSubheader {
            file_number: 1,
            ..crate::raw_cd::XaSubheader::default()
        };
        iso.files.splice(
            1..1,
            [
                FileLayoutItem::form1_gap(1, crate::raw_cd::XaSubheader::default()),
                FileLayoutItem::form1_gap(2, second_subheader),
            ],
        );
        let lengths = HashMap::from([
            ("A.BIN".to_owned(), LOGICAL_BLOCK_SIZE as u64),
            ("B.BIN".to_owned(), LOGICAL_BLOCK_SIZE as u64),
        ]);

        let authored = layout(&iso, &lengths).unwrap();

        assert_eq!(authored.files[0].extent, 23);
        assert_eq!(authored.files[1].extent, 27);
        assert_eq!(authored.gaps[0].start, 24);
        assert_eq!(authored.gaps[1].start, 25);
    }

    #[test]
    fn physical_gaps_reject_zero_redundant_and_nonfinal_xa_items() {
        let base = test_iso(
            vec![
                test_entry(ROOT_PATH),
                test_entry("A.BIN"),
                test_entry("B.BIN"),
            ],
            vec!["A.BIN", "B.BIN"],
        );
        for files in [
            vec![
                FileLayoutItem::path("A.BIN"),
                FileLayoutItem::gap(0),
                FileLayoutItem::path("B.BIN"),
            ],
            vec![
                FileLayoutItem::path("A.BIN"),
                FileLayoutItem::gap(1),
                FileLayoutItem::gap(2),
                FileLayoutItem::path("B.BIN"),
            ],
            vec![
                FileLayoutItem::path("A.BIN"),
                FileLayoutItem::xa_gap(1),
                FileLayoutItem::path("B.BIN"),
            ],
        ] {
            let mut iso = base.clone();
            iso.files = files;
            assert!(validate(&iso).is_err());
        }
    }

    #[test]
    fn entry_xa_metadata_must_match_entry_structure() {
        let mut file = test_entry("FILE.BIN");
        file.xa = Some(EntryXa {
            group_id: 0,
            user_id: 0,
            permissions: DEFAULT_XA_PERMISSIONS,
            attributes: Some(XaAttributes::from_bits(
                XaAttributes::MODE2_FORM1.bits() | XaAttributes::DIRECTORY.bits(),
            )),
            file_number: 0,
            form1: None,
            form2: None,
            index: None,
            gap_index: None,
            logical_length: None,
            length_encoding: XaLengthEncoding::default(),
            framing_subheader: None,
        });
        assert!(
            validate(&test_iso(
                vec![test_entry(ROOT_PATH), file],
                vec!["FILE.BIN"]
            ))
            .is_err()
        );

        let mut directory = test_entry(ROOT_PATH);
        directory.xa = Some(EntryXa {
            group_id: 0,
            user_id: 0,
            permissions: DEFAULT_XA_PERMISSIONS,
            attributes: Some(XaAttributes::from_bits(
                XaAttributes::MODE2_FORM1.bits() | XaAttributes::DIRECTORY.bits(),
            )),
            file_number: 0,
            form1: Some("ROOT.XA1".to_owned()),
            form2: Some("ROOT.XA2".to_owned()),
            index: Some("ROOT.XAI".to_owned()),
            gap_index: None,
            logical_length: None,
            length_encoding: XaLengthEncoding::default(),
            framing_subheader: None,
        });
        assert!(validate(&test_iso(vec![directory], vec![])).is_err());

        let mut mixed_without_assets = test_entry("MOVIE.STR");
        mixed_without_assets.xa = Some(EntryXa {
            attributes: Some(XaAttributes::from_bits(
                XaAttributes::MODE2_FORM1.bits() | XaAttributes::MODE2_FORM2.bits(),
            )),
            ..EntryXa::default()
        });
        assert!(
            validate(&test_iso(
                vec![test_entry(ROOT_PATH), mixed_without_assets],
                vec!["MOVIE.STR"],
            ))
            .is_err()
        );

        let mut assets_without_mixed_attributes = test_entry("MOVIE.STR");
        assets_without_mixed_attributes.xa = Some(EntryXa {
            form1: Some("MOVIE.STR.XA1".to_owned()),
            form2: Some("MOVIE.STR.XA2".to_owned()),
            index: Some("MOVIE.STR.XAI".to_owned()),
            ..EntryXa::default()
        });
        validate(&test_iso(
            vec![test_entry(ROOT_PATH), assets_without_mixed_attributes],
            vec!["MOVIE.STR"],
        ))
        .unwrap();
    }

    #[test]
    fn explicit_nonstandard_ascii_identifier_policy_accepts_tilde() {
        let mut iso = test_iso(
            vec![test_entry(ROOT_PATH), test_entry("ALPHA~5V.BAK")],
            vec!["ALPHA~5V.BAK"],
        );
        iso.identifier_policy = IdentifierPolicy::NonstandardAscii;
        let lengths = HashMap::from([("ALPHA~5V.BAK".to_owned(), 1)]);

        layout(&iso, &lengths).unwrap();
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
            system_use: serialize_xa_system_use(&test_entry("FILE.BIN"), false).unwrap(),
            trailing_system_use_padding: false,
        };
        validate_standard_record_fields(&record, false, true).unwrap();
        record.flags = DIRECTORY_FLAG;
        record.system_use = serialize_xa_system_use(&test_entry("DIR"), true).unwrap();
        validate_standard_record_fields(&record, true, true).unwrap();

        record.flags = 4;
        assert!(validate_standard_record_fields(&record, false, true).is_err());
        record.flags = 0;
        record.system_use = serialize_xa_system_use(&test_entry("FILE.BIN"), false).unwrap();
        record.file_unit_size = 1;
        assert!(validate_standard_record_fields(&record, false, true).is_err());
        record.file_unit_size = 0;
        record.interleave_gap_size = 1;
        assert!(validate_standard_record_fields(&record, false, true).is_err());
        record.interleave_gap_size = 0;
        record.volume_sequence_number = 2;
        assert!(validate_standard_record_fields(&record, false, true).is_err());

        assert_eq!(identifier(&test_entry("FILE.BIN"), true), "FILE.BIN;1");
    }

    #[test]
    fn hidden_directory_record_flag_is_structured_and_rebuilt() {
        let mut entry = test_entry("SECRET.BIN");
        entry.hidden = true;

        let bytes = make_record(&entry, 24, 7, b"SECRET.BIN;1".to_vec(), false).unwrap();
        let record = parse_record(&bytes).unwrap();

        assert_eq!(record.flags, 1);
        validate_standard_record_fields(&record, false, true).unwrap();
    }

    #[test]
    fn associated_directory_record_flag_is_supported() {
        let mut entry = test_entry("RESOURCE.BIN");
        entry.associated = true;
        let bytes = make_record(
            &entry,
            24,
            LOGICAL_BLOCK_SIZE as u32,
            b"RESOURCE.BIN;1".to_vec(),
            false,
        )
        .unwrap();
        let mut record = parse_record(&bytes).unwrap();
        assert_eq!(record.flags, ASSOCIATED_FLAG);
        validate_standard_record_fields(&record, false, true).unwrap();

        record.flags |= DIRECTORY_FLAG;
        record.name = b"RESOURCE".to_vec();
        record.system_use = serialize_xa_system_use(&entry, true).unwrap();
        validate_standard_record_fields(&record, true, true).unwrap();
    }

    #[test]
    fn directory_can_omit_xa_directory_attribute() {
        let record = Record {
            extent: 22,
            length: LOGICAL_BLOCK_SIZE as u32,
            recording_time: [100, 1, 1, 0, 0, 0, 0],
            flags: DIRECTORY_FLAG,
            file_unit_size: 0,
            interleave_gap_size: 0,
            volume_sequence_number: 1,
            name: b"DIR".to_vec(),
            system_use: [0, 0, 0, 0, 0, 0x88, b'X', b'A', 0, 0, 0, 0, 0, 0].to_vec(),
            trailing_system_use_padding: false,
        };

        let xa = entry_xa(&record, true, true).unwrap().unwrap();
        assert_eq!(xa.attributes, Some(XaAttributes::from_bits(0)));
        assert_eq!(
            serialize_xa_system_use(
                &Entry {
                    path: "DIR".to_owned(),
                    recording_time: "2000-01-01T00:00:00+00:00".to_owned(),
                    hidden: false,
                    associated: false,
                    unbacked: false,
                    directory_reference: None,
                    directory_slack: None,
                    allocation_padding_hex: None,
                    sector_subheader: crate::manifest::EntrySectorSubheader::Canonical,
                    xa: Some(xa),
                    extent: None,
                    length: None,
                },
                true,
            )
            .unwrap(),
            record.system_use
        );
    }

    #[test]
    fn interleaved_xa_system_use_decodes_named_attributes() {
        let record = Record {
            extent: 60_000,
            length: 50_348_032,
            recording_time: [98, 1, 1, 0, 0, 0, 0],
            flags: 0,
            file_unit_size: 0,
            interleave_gap_size: 0,
            volume_sequence_number: 1,
            name: b"PETEXA0.STR;1".to_vec(),
            system_use: [0, 0, 0, 0, 0x25, 0x55, b'X', b'A', 1, 0, 0, 0, 0, 0].to_vec(),
            trailing_system_use_padding: false,
        };

        let xa = entry_xa(&record, false, true).unwrap().unwrap();
        assert_eq!(xa.attributes, Some(XaAttributes::INTERLEAVED));
        assert_eq!(xa.file_number, 1);
        assert_eq!(
            serialize_xa_system_use(
                &Entry {
                    path: "PETEXA0.STR".to_owned(),
                    recording_time: "1998-01-01T00:00:00+00:00".to_owned(),
                    hidden: false,
                    associated: false,
                    unbacked: false,
                    directory_reference: None,
                    directory_slack: None,
                    allocation_padding_hex: None,
                    sector_subheader: crate::manifest::EntrySectorSubheader::Canonical,
                    xa: Some(xa),
                    extent: None,
                    length: None,
                },
                false,
            )
            .unwrap(),
            record.system_use
        );
    }

    #[test]
    fn nondefault_xa_permission_bits_are_preserved() {
        let record = Record {
            extent: 24,
            length: 61,
            recording_time: [99, 1, 1, 0, 0, 0, 0],
            flags: 0,
            file_unit_size: 0,
            interleave_gap_size: 0,
            volume_sequence_number: 1,
            name: b"SYSTEM.CNF;1".to_vec(),
            system_use: [0, 0, 0, 0, 0x09, 0x11, b'X', b'A', 0, 0, 0, 0, 0, 0].to_vec(),
            trailing_system_use_padding: false,
        };

        let xa = entry_xa(&record, false, true).unwrap().unwrap();
        assert_eq!(xa.permissions, 0x0111);
        assert_eq!(
            serialize_xa_system_use(
                &Entry {
                    path: "SYSTEM.CNF".to_owned(),
                    recording_time: "1999-01-01T00:00:00+00:00".to_owned(),
                    hidden: false,
                    associated: false,
                    unbacked: false,
                    directory_reference: None,
                    directory_slack: None,
                    allocation_padding_hex: None,
                    sector_subheader: crate::manifest::EntrySectorSubheader::Canonical,
                    xa: Some(xa),
                    extent: None,
                    length: None,
                },
                false,
            )
            .unwrap(),
            record.system_use
        );
    }

    #[test]
    fn cdda_directory_records_are_external_references_not_authored_files() {
        let mut audio = test_entry("MUSIC.SWP");
        audio.xa = Some(EntryXa {
            attributes: Some(XaAttributes::CDDA),
            ..EntryXa::default()
        });
        audio.extent = Some(25);
        audio.length = Some(2048);
        let iso = test_iso(vec![test_entry(ROOT_PATH), audio], vec![]);
        let lengths = HashMap::new();
        let authored = layout(&iso, &lengths).unwrap();
        assert_eq!(authored.volume_blocks, 23);
        assert_eq!(read_both_u32(&authored.blocks[16], 80).unwrap(), 26);

        let parsed = parse(&authored.blocks).unwrap();
        assert!(parsed.files.is_empty());
        assert_eq!(parsed.manifest.entries[1].extent, Some(25));
        assert_eq!(parsed.manifest.entries[1].length, Some(2048));
    }

    #[test]
    fn empty_external_cdda_directory_record_is_preserved() {
        let mut audio = test_entry("BLANK.RAW");
        audio.xa = Some(EntryXa {
            attributes: Some(XaAttributes::CDDA),
            ..EntryXa::default()
        });
        audio.extent = Some(30_692);
        audio.length = Some(0);
        let iso = test_iso(vec![test_entry(ROOT_PATH), audio], vec![]);

        let authored = layout(&iso, &HashMap::new()).unwrap();
        let parsed = parse(&authored.blocks).unwrap();

        assert_eq!(parsed.manifest.entries[1].extent, Some(30_692));
        assert_eq!(parsed.manifest.entries[1].length, Some(0));
    }

    #[test]
    fn external_cdda_extent_may_overlap_the_authored_data_track() {
        let mut audio = test_entry("SILENCE.DA");
        audio.xa = Some(EntryXa {
            attributes: Some(XaAttributes::CDDA),
            ..EntryXa::default()
        });
        audio.extent = Some(0);
        audio.length = Some(2048);
        let iso = test_iso(vec![test_entry(ROOT_PATH), audio], vec![]);

        let authored = layout(&iso, &HashMap::new()).unwrap();
        let parsed = parse(&authored.blocks).unwrap();

        assert_eq!(parsed.manifest.entries[1].extent, Some(0));
        assert_eq!(parsed.manifest.entries[1].length, Some(2048));
    }

    #[test]
    fn overlapping_xa_references_must_be_backed_by_one_physical_xa_extent() {
        let mut first = test_entry("FIRST.XA");
        first.xa = Some(EntryXa {
            attributes: Some(XaAttributes::INTERLEAVED),
            ..EntryXa::default()
        });
        first.extent = Some(23);
        first.length = Some(4096);
        let mut second = test_entry("SECOND.XA");
        second.xa = Some(EntryXa {
            attributes: Some(XaAttributes::MODE2_FORM2),
            ..EntryXa::default()
        });
        second.extent = Some(24);
        second.length = Some(4096);
        let mut iso = test_iso(vec![test_entry(ROOT_PATH), first, second], vec![]);
        assert_eq!(
            layout(&iso, &HashMap::new()).unwrap_err().to_string(),
            "fixed XA reference is not backed by a physical XA extent: FIRST.XA"
        );
        iso.files
            .push(FileLayoutItem::xa_extent(crate::manifest::XaExtentAssets {
                form1: "stream.XA1".to_owned(),
                form2: "stream.XA2".to_owned(),
                index: "stream.XAI".to_owned(),
                gap_index: None,
            }));
        let lengths = HashMap::from([(String::from("stream.XAI"), 6144_u64)]);

        let authored = layout(&iso, &lengths).unwrap();

        assert_eq!(authored.xa_extents[0].start, 23);
        assert_eq!(authored.xa_extents[0].sectors, 3);
        let parsed = parse(&authored.blocks).unwrap();
        assert_eq!(parsed.files[0].extent, 23);
        assert_eq!(parsed.files[0].length, 4096);
        assert_eq!(parsed.files[1].extent, 24);
        assert_eq!(parsed.files[1].length, 4096);
    }

    #[test]
    fn external_cdda_parent_directory_precedes_local_file_data() {
        let mut external = test_entry("AUDIO/MUSIC.SWP");
        external.xa = Some(EntryXa {
            attributes: Some(XaAttributes::CDDA),
            ..EntryXa::default()
        });
        external.extent = Some(100);
        external.length = Some(2048);
        let iso = test_iso(
            vec![
                test_entry(ROOT_PATH),
                test_entry("AUDIO"),
                test_entry("LOCAL.BIN"),
                external,
            ],
            vec!["LOCAL.BIN"],
        );
        let lengths = HashMap::from([(String::from("LOCAL.BIN"), 2048_u64)]);

        let authored = layout(&iso, &lengths).unwrap();
        assert_eq!(authored.files[0].extent, 24);
    }
}

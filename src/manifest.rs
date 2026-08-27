use std::fmt;

use anyhow::{Context, Result, ensure};
use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::raw_cd::{XaSubheader, XaSubmode};

pub const SYSTEM_AREA_SECTORS: usize = 16;
pub const DEFAULT_XA_PERMISSIONS: u16 = 0x0555;
pub(crate) const GCDGOLD_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub gcdgold: GcdgoldMetadata,
    pub track: Track,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub system_area: Option<SystemArea>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iso9660: Option<Iso9660>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub form1: Option<Form1Project>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Form1Project {
    pub layout: Vec<Form1LayoutItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum Form1LayoutItem {
    Asset(Form1Asset),
    Gap(FileGapItem),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Form1Asset {
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha1: Option<String>,
    pub subheader: EntrySectorSubheader,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GcdgoldMetadata {
    #[serde(deserialize_with = "deserialize_version_string")]
    pub version: String,
}

fn deserialize_version_string<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    struct VersionStringVisitor;

    impl Visitor<'_> for VersionStringVisitor {
        type Value = String;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("a gcdgold version string")
        }

        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(value.to_owned())
        }

        fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(value)
        }
    }

    deserializer.deserialize_any(VersionStringVisitor)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Track {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha1: Option<String>,
    pub mode: TrackMode,
    #[serde(
        default = "default_start_msf",
        skip_serializing_if = "is_default_start_msf"
    )]
    pub start_msf: String,
    #[serde(
        default = "default_form2_edc",
        skip_serializing_if = "is_default_form2_edc"
    )]
    pub form2_edc: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub noncompliant_trailing_ecc: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub redump_0x55: Vec<Redump0x55Run>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mode1_reserved: Vec<Mode1ReservedRun>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode1_protection: Option<Mode1Protection>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub patches: Vec<SectorPatch>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Redump0x55Run {
    pub lba: i32,
    pub sectors: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Mode1ReservedRun {
    pub lba: i32,
    pub sectors: u32,
    pub hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Mode1Protection {
    pub edc_xor: String,
    pub reserved: String,
    pub ecc_xor: String,
    #[serde(default, skip_serializing_if = "is_false")]
    pub payload_inverted: bool,
    pub runs: Vec<Mode1ProtectionRun>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Mode1ProtectionRun {
    pub lba: i32,
    pub sectors: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SectorPatch {
    pub lba: i32,
    pub hex: String,
}

pub(crate) fn format_sector_patch_hex(bytes: &[u8]) -> String {
    bytes
        .chunks(32)
        .map(hex::encode)
        .collect::<Vec<_>>()
        .join("\n")
}

pub(crate) fn decode_sector_patch(patch: &SectorPatch) -> Result<[u8; 2352]> {
    let compact: String = patch
        .hex
        .chars()
        .filter(|character| !character.is_ascii_whitespace())
        .collect();
    let bytes =
        hex::decode(&compact).with_context(|| format!("decoding patch at LBA {}", patch.lba))?;
    ensure!(
        bytes.len() == 2352,
        "patch at LBA {} decodes to {} bytes, expected 2352",
        patch.lba,
        bytes.len()
    );
    Ok(bytes.try_into().expect("validated patch sector length"))
}

impl Default for Track {
    fn default() -> Self {
        Self {
            sha1: None,
            mode: TrackMode::default(),
            start_msf: default_start_msf(),
            form2_edc: default_form2_edc(),
            noncompliant_trailing_ecc: false,
            redump_0x55: Vec::new(),
            mode1_reserved: Vec::new(),
            mode1_protection: None,
            patches: Vec::new(),
        }
    }
}

pub(crate) fn serialize_manifest(manifest: &Manifest) -> anyhow::Result<String> {
    yaml_serde::to_string(manifest).context("serializing manifest")
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum TrackMode {
    Mode1,
    Mode2,
    #[default]
    Mode2Xa,
}

impl fmt::Display for TrackMode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Mode1 => formatter.write_str("1"),
            Self::Mode2 => formatter.write_str("2"),
            Self::Mode2Xa => formatter.write_str("2xa"),
        }
    }
}

impl Serialize for TrackMode {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Mode1 => serializer.serialize_u8(1),
            Self::Mode2 => serializer.serialize_u8(2),
            Self::Mode2Xa => serializer.serialize_str("2xa"),
        }
    }
}

impl<'de> Deserialize<'de> for TrackMode {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct TrackModeVisitor;

        impl<'de> Visitor<'de> for TrackModeVisitor {
            type Value = TrackMode;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("track mode 1, 2, or 2xa")
            }

            fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                match value {
                    1 => Ok(TrackMode::Mode1),
                    2 => Ok(TrackMode::Mode2),
                    _ => Err(E::custom("track mode must be 1, 2, or 2xa")),
                }
            }

            fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                u64::try_from(value)
                    .map_err(|_| E::custom("track mode must be 1, 2, or 2xa"))
                    .and_then(|value| self.visit_u64(value))
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                match value {
                    "1" => Ok(TrackMode::Mode1),
                    "2" => Ok(TrackMode::Mode2),
                    "2xa" => Ok(TrackMode::Mode2Xa),
                    _ => Err(E::custom("track mode must be 1, 2, or 2xa")),
                }
            }
        }

        deserializer.deserialize_any(TrackModeVisitor)
    }
}

fn default_start_msf() -> String {
    "00:02:00".to_owned()
}

fn is_default_start_msf(value: &String) -> bool {
    value == "00:02:00"
}

fn default_form2_edc() -> bool {
    true
}

fn is_default_form2_edc(value: &bool) -> bool {
    *value
}

const fn is_false(value: &bool) -> bool {
    !*value
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SystemArea {
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha1: Option<String>,
    pub form1_sectors: Form1Sectors,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sector_layout: Vec<SystemAreaSectorRun>,
    #[serde(default, skip_serializing_if = "SystemAreaFinalSubheader::is_default")]
    pub final_form1_subheader: SystemAreaFinalSubheader,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub form1_framing: Vec<SystemAreaForm1Framing>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SystemAreaSectorRun {
    pub kind: SystemAreaSectorKind,
    pub sectors: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SystemAreaSectorKind {
    Form1,
    Form2,
    XaGap,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SystemAreaForm1Framing {
    pub sector: u8,
    pub subheader: XaSubheader,
    pub subheader_copy: XaSubheader,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SystemAreaFinalSubheader {
    #[default]
    Data,
    EndOfFileData,
}

impl SystemAreaFinalSubheader {
    const fn is_default(&self) -> bool {
        matches!(self, Self::Data)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Form1Sectors {
    Auto(String),
    Count(u8),
}

impl Form1Sectors {
    pub fn resolve(&self, content_len: usize) -> anyhow::Result<u8> {
        let needed = content_len.div_ceil(2048);
        let count = match self {
            Self::Auto(value) if value == "auto" => needed,
            Self::Auto(value) => anyhow::bail!("unknown form1_sectors value {value:?}"),
            Self::Count(count) => usize::from(*count),
        };
        anyhow::ensure!(
            count <= SYSTEM_AREA_SECTORS,
            "system content exceeds system area"
        );
        anyhow::ensure!(
            content_len <= count * 2048,
            "system content exceeds configured Form 1 sectors"
        );
        Ok(count as u8)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Iso9660 {
    pub primary_volume: PrimaryVolume,
    #[serde(
        default = "default_primary_volume_copies",
        skip_serializing_if = "is_one"
    )]
    pub primary_volume_copies: u8,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub supplementary_volumes: Vec<JolietVolume>,
    #[serde(default = "default_xa_system_use", skip_serializing_if = "is_true")]
    pub xa_system_use: bool,
    #[serde(default, skip_serializing_if = "MetadataSubheader::is_default")]
    pub metadata_subheader: MetadataSubheader,
    #[serde(default, skip_serializing_if = "VolumeTerminatorSubheader::is_default")]
    pub volume_terminator_subheader: VolumeTerminatorSubheader,
    #[serde(default, skip_serializing_if = "DirectoryRecordPacking::is_default")]
    pub directory_record_packing: DirectoryRecordPacking,
    #[serde(
        default,
        skip_serializing_if = "DirectoryParentRecordingTime::is_default"
    )]
    pub directory_parent_recording_time: DirectoryParentRecordingTime,
    #[serde(default, skip_serializing_if = "DirectoryLengthPolicy::is_default")]
    pub directory_length_policy: DirectoryLengthPolicy,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub directory_record_volume_sequence_number: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path_table_size: Option<u32>,
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub path_table_padding: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path_table_little_hex: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path_table_big_hex: Option<String>,
    #[serde(default, skip_serializing_if = "PathTableCopies::is_default")]
    pub path_table_copies: PathTableCopies,
    #[serde(default, skip_serializing_if = "PathTableOrder::is_default")]
    pub path_table_order: PathTableOrder,
    #[serde(default, skip_serializing_if = "PathTableSubheader::is_default")]
    pub path_table_subheader: PathTableSubheader,
    pub entries: Vec<Entry>,
    pub layout: Vec<FileLayoutItem>,
}

const fn default_primary_volume_copies() -> u8 {
    1
}

const fn default_xa_system_use() -> bool {
    true
}

const fn is_true(value: &bool) -> bool {
    *value
}

const fn is_one(value: &u8) -> bool {
    *value == 1
}

const fn is_zero_u32(value: &u32) -> bool {
    *value == 0
}

const fn default_one_u32() -> u32 {
    1
}

const fn is_one_u32(value: &u32) -> bool {
    *value == 1
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DirectoryRecordPacking {
    #[default]
    Fill,
    AvoidExactFit,
}

impl DirectoryRecordPacking {
    const fn is_default(&self) -> bool {
        matches!(self, Self::Fill)
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DirectoryParentRecordingTime {
    #[default]
    Parent,
    Current,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DirectoryLengthPolicy {
    #[default]
    Allocated,
    Records,
}

impl DirectoryLengthPolicy {
    const fn is_default(&self) -> bool {
        matches!(self, Self::Allocated)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JolietLevel {
    Level1,
    Level2,
    Level3,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JolietVolume {
    pub level: JolietLevel,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub flags: u8,
    #[serde(default, skip_serializing_if = "is_false")]
    pub zero_fill_empty_strings: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub zero_pad_strings: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub nul_terminated_space_padded_strings: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub volume_identifier_nul_terminated: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub space_pad_escape_sequence: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub aliased_path_table_pointers: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub volume_set_identifier_raw_hex: Option<String>,
    pub descriptor: PrimaryVolume,
    #[serde(default = "default_xa_system_use", skip_serializing_if = "is_true")]
    pub xa_system_use: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path_table_size: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path_table_little_hex: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path_table_big_hex: Option<String>,
    #[serde(default, skip_serializing_if = "PathTableSubheader::is_default")]
    pub path_table_subheader: PathTableSubheader,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_identifier_odd_bytes_hex: Option<String>,
    pub entries: Vec<JolietEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JolietEntry {
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub omit_version: bool,
    pub recording_time: String,
    #[serde(default, skip_serializing_if = "is_false")]
    pub hidden: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub associated: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub system_use_hex: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identifier_padding: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub directory_self_system_use_hex: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub directory_parent_system_use_hex: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub directory_self_recording_time: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub directory_parent_recording_time: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub directory_self_length: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub directory_parent_length: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub directory_self_hidden: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub directory_parent_hidden: Option<bool>,
    #[serde(default, skip_serializing_if = "EntrySectorSubheader::is_default")]
    pub sector_subheader: EntrySectorSubheader,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub xa: Option<EntryXa>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub directory_self_xa: Option<EntryXa>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub directory_parent_xa: Option<EntryXa>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MetadataPathTableItem {
    pub path_table: MetadataPathTable,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum MetadataPathTable {
    PrimaryLittle,
    PrimaryLittleCopy,
    PrimaryBig,
    PrimaryBigCopy,
    JolietLittle,
    JolietBig,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum MetadataVolume {
    #[default]
    Primary,
    Joliet,
}

impl MetadataVolume {
    const fn is_primary(&self) -> bool {
        matches!(self, Self::Primary)
    }
}

impl DirectoryParentRecordingTime {
    const fn is_default(&self) -> bool {
        matches!(self, Self::Parent)
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PathTableCopies {
    #[default]
    Duplicate,
    Single,
    Aliased,
}

impl PathTableCopies {
    const fn is_default(&self) -> bool {
        matches!(self, Self::Duplicate)
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PathTableOrder {
    #[default]
    LittleEndianFirst,
    BigEndianFirst,
}

impl PathTableOrder {
    const fn is_default(&self) -> bool {
        matches!(self, Self::LittleEndianFirst)
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IsoMetadataSubheader {
    #[default]
    Canonical,
    Data,
    EndOfFileData,
    IsoMetadata,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VolumeTerminatorSubheader {
    #[default]
    Metadata,
    Pvd,
}

impl VolumeTerminatorSubheader {
    const fn is_default(&self) -> bool {
        matches!(self, Self::Metadata)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum MetadataSubheader {
    Named(IsoMetadataSubheader),
    Explicit(XaSubheader),
}

impl Default for MetadataSubheader {
    fn default() -> Self {
        Self::Named(IsoMetadataSubheader::Canonical)
    }
}

impl MetadataSubheader {
    const fn is_default(&self) -> bool {
        matches!(self, Self::Named(IsoMetadataSubheader::Canonical))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum PathTableSubheader {
    Named(EntrySectorSubheader),
    Explicit(XaSubheader),
}

impl Default for PathTableSubheader {
    fn default() -> Self {
        Self::Named(EntrySectorSubheader::Canonical)
    }
}

impl PathTableSubheader {
    const fn is_default(&self) -> bool {
        matches!(self, Self::Named(EntrySectorSubheader::Canonical))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum FileLayoutItem {
    Path(FilePathItem),
    Directory(FileDirectoryItem),
    PathTable(MetadataPathTableItem),
    Mode1Extent(FileMode1ExtentItem),
    AppleHfs(FileAppleHfsItem),
    DuplicateBlock(FileDuplicateBlockItem),
    CeQuadratJolietLinks(FileCeQuadratJolietLinksItem),
    CeQuadratFormatter(FileCeQuadratFormatterItem),
    XaExtent(FileXaExtentItem),
    Gap(FileGapItem),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FilePathItem {
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha1: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub xa_assets: Option<XaAssets>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FileDirectoryItem {
    pub directory: String,
    #[serde(default, skip_serializing_if = "MetadataVolume::is_primary")]
    pub volume: MetadataVolume,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FileAppleHfsItem {
    pub apple_hfs: HostAsset,
    pub start_block: u32,
    pub block_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FileMode1ExtentItem {
    pub mode1_extent: HostAsset,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FileDuplicateBlockItem {
    pub duplicate_block: DuplicateBlock,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DuplicateBlock {
    pub path: String,
    pub block: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FileCeQuadratJolietLinksItem {
    pub cequadrat_joliet_links: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FileCeQuadratFormatterItem {
    pub cequadrat_formatter: HostAsset,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FileXaExtentItem {
    pub xa_extent: XaAssets,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HostAsset {
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha1: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct XaFormAsset {
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha1: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub framing: Option<XaFraming>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum XaFraming {
    Named(XaFramingPolicy),
    Detailed(XaFramingSettings),
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum XaFramingPolicy {
    Channel,
    ChannelOrGeneric,
    Phase,
    Runs,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct XaAssetSubheader {
    #[serde(skip_serializing_if = "is_zero")]
    pub file: u8,
    #[serde(skip_serializing_if = "is_zero")]
    pub channel: u8,
    #[serde(skip_serializing_if = "XaSubmode::is_empty")]
    pub submode: XaSubmode,
    #[serde(skip_serializing_if = "is_zero")]
    pub coding_info: u8,
}

impl From<XaSubheader> for XaAssetSubheader {
    fn from(value: XaSubheader) -> Self {
        Self {
            file: value.file_number,
            channel: value.channel,
            submode: value.submode,
            coding_info: value.coding_info,
        }
    }
}

impl From<XaAssetSubheader> for XaSubheader {
    fn from(value: XaAssetSubheader) -> Self {
        Self {
            file_number: value.file,
            channel: value.channel,
            submode: value.submode,
            coding_info: value.coding_info,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct XaFramingSettings {
    pub policy: XaFramingPolicy,
    #[serde(default, skip_serializing_if = "XaEofPolicy::is_default")]
    pub eof: XaEofPolicy,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default: Option<XaAssetSubheader>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tail: Option<XaFramingTail>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub phases: Vec<XaPhaseFraming>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub states: Vec<XaStateFraming>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub runs: Vec<XaFramingRun>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub overrides: Vec<XaFramingOverride>,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum XaEofPolicy {
    #[default]
    None,
    FinalRecord,
    ChannelSegmentEnd,
}

impl XaEofPolicy {
    const fn is_default(&self) -> bool {
        matches!(self, Self::None)
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct XaFramingTail {
    pub sectors: u32,
    pub subheader: XaAssetSubheader,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct XaPhaseFraming {
    pub phase: u32,
    pub subheader: XaAssetSubheader,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum XaChannelState {
    UnusedFirst,
    Unused,
    BeforeStart,
    Active,
    FirstAfterEnd,
    AfterEnd,
    BetweenSegments,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct XaStateFraming {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub phase: Option<u32>,
    pub state: XaChannelState,
    pub subheader: XaAssetSubheader,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct XaFramingRun {
    pub sectors: u32,
    pub subheader: XaAssetSubheader,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct XaPositionSpan {
    pub start: u32,
    #[serde(default = "default_one_u32", skip_serializing_if = "is_one_u32")]
    pub stride: u32,
    pub count: u32,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct XaFramingOverride {
    #[serde(flatten)]
    pub positions: XaPositionSpan,
    pub subheader: XaAssetSubheader,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct XaInterleave {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stride: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cycles: Option<u32>,
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub tail_slots: u32,
    pub channels: Vec<XaInterleaveChannel>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct XaInterleaveChannel {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub channel: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub phase: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start_cycle: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub end_cycle: Option<u32>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub segments: Vec<XaCycleSegment>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stride: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub count: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub before_start: Option<XaPadding>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub between_segments: Option<XaPadding>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after_end: Option<XaPadding>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fill: Option<XaPadding>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct XaCycleSegment {
    pub start_cycle: u32,
    pub end_cycle: u32,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum XaPadding {
    XaGap,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct XaAssets {
    pub form1: XaFormAsset,
    pub form2: XaFormAsset,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub index: Option<HostAsset>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interleave: Option<XaInterleave>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub gap_overrides: Vec<XaPositionSpan>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FileGapItem {
    pub gap: u32,
    #[serde(default, skip_serializing_if = "GapKind::is_default")]
    pub kind: GapKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subheader: Option<XaSubheader>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub form2_edc: Option<bool>,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GapKind {
    #[default]
    Form2,
    Mode1,
    Form1,
    Xa,
    RawZero,
}

impl GapKind {
    const fn is_default(&self) -> bool {
        matches!(self, Self::Form2)
    }
}

impl FileLayoutItem {
    pub fn path(path: impl Into<String>) -> Self {
        Self::Path(FilePathItem {
            path: path.into(),
            source: None,
            sha1: None,
            xa_assets: None,
        })
    }

    pub fn directory(path: impl Into<String>) -> Self {
        Self::Directory(FileDirectoryItem {
            directory: path.into(),
            volume: MetadataVolume::Primary,
        })
    }

    pub fn volume_directory(volume: MetadataVolume, path: impl Into<String>) -> Self {
        Self::Directory(FileDirectoryItem {
            directory: path.into(),
            volume,
        })
    }

    pub fn apple_hfs(asset: HostAsset, start_block: u32, block_count: u32) -> Self {
        Self::AppleHfs(FileAppleHfsItem {
            apple_hfs: asset,
            start_block,
            block_count,
        })
    }

    pub fn mode1_extent(asset: HostAsset) -> Self {
        Self::Mode1Extent(FileMode1ExtentItem {
            mode1_extent: asset,
        })
    }

    pub fn duplicate_block(path: impl Into<String>, block: u32) -> Self {
        Self::DuplicateBlock(FileDuplicateBlockItem {
            duplicate_block: DuplicateBlock {
                path: path.into(),
                block,
            },
        })
    }

    pub const fn cequadrat_joliet_links() -> Self {
        Self::CeQuadratJolietLinks(FileCeQuadratJolietLinksItem {
            cequadrat_joliet_links: true,
        })
    }

    pub fn cequadrat_formatter(asset: HostAsset) -> Self {
        Self::CeQuadratFormatter(FileCeQuadratFormatterItem {
            cequadrat_formatter: asset,
        })
    }

    pub fn xa_extent(assets: XaAssets) -> Self {
        Self::XaExtent(FileXaExtentItem { xa_extent: assets })
    }

    pub const fn gap(sectors: u32) -> Self {
        Self::Gap(FileGapItem {
            gap: sectors,
            kind: GapKind::Form2,
            subheader: None,
            form2_edc: None,
        })
    }

    pub const fn form2_gap(sectors: u32, form2_edc: bool) -> Self {
        Self::Gap(FileGapItem {
            gap: sectors,
            kind: GapKind::Form2,
            subheader: None,
            form2_edc: Some(form2_edc),
        })
    }

    pub const fn mode1_gap(sectors: u32) -> Self {
        Self::Gap(FileGapItem {
            gap: sectors,
            kind: GapKind::Mode1,
            subheader: None,
            form2_edc: None,
        })
    }

    pub const fn form1_gap(sectors: u32, subheader: XaSubheader) -> Self {
        Self::Gap(FileGapItem {
            gap: sectors,
            kind: GapKind::Form1,
            subheader: Some(subheader),
            form2_edc: None,
        })
    }

    pub const fn xa_gap(sectors: u32) -> Self {
        Self::Gap(FileGapItem {
            gap: sectors,
            kind: GapKind::Xa,
            subheader: None,
            form2_edc: None,
        })
    }

    pub const fn raw_zero_gap(sectors: u32) -> Self {
        Self::Gap(FileGapItem {
            gap: sectors,
            kind: GapKind::RawZero,
            subheader: None,
            form2_edc: None,
        })
    }

    pub fn as_path(&self) -> Option<&str> {
        match self {
            Self::Path(item) => Some(&item.path),
            Self::Directory(_)
            | Self::PathTable(_)
            | Self::Mode1Extent(_)
            | Self::AppleHfs(_)
            | Self::DuplicateBlock(_)
            | Self::CeQuadratJolietLinks(_)
            | Self::CeQuadratFormatter(_)
            | Self::XaExtent(_)
            | Self::Gap(_) => None,
        }
    }

    pub const fn as_path_item(&self) -> Option<&FilePathItem> {
        match self {
            Self::Path(item) => Some(item),
            Self::Directory(_)
            | Self::PathTable(_)
            | Self::Mode1Extent(_)
            | Self::AppleHfs(_)
            | Self::DuplicateBlock(_)
            | Self::CeQuadratJolietLinks(_)
            | Self::CeQuadratFormatter(_)
            | Self::XaExtent(_)
            | Self::Gap(_) => None,
        }
    }

    pub const fn as_directory_placement(&self) -> Option<(MetadataVolume, &str)> {
        match self {
            Self::Directory(item) => Some((item.volume, item.directory.as_str())),
            Self::Path(_)
            | Self::PathTable(_)
            | Self::Mode1Extent(_)
            | Self::AppleHfs(_)
            | Self::DuplicateBlock(_)
            | Self::CeQuadratJolietLinks(_)
            | Self::CeQuadratFormatter(_)
            | Self::XaExtent(_)
            | Self::Gap(_) => None,
        }
    }

    pub const fn path_table(path_table: MetadataPathTable) -> Self {
        Self::PathTable(MetadataPathTableItem { path_table })
    }

    pub const fn as_path_table(&self) -> Option<MetadataPathTable> {
        match self {
            Self::PathTable(item) => Some(item.path_table),
            Self::Path(_)
            | Self::Directory(_)
            | Self::Mode1Extent(_)
            | Self::AppleHfs(_)
            | Self::DuplicateBlock(_)
            | Self::CeQuadratJolietLinks(_)
            | Self::CeQuadratFormatter(_)
            | Self::XaExtent(_)
            | Self::Gap(_) => None,
        }
    }

    pub const fn as_xa_extent(&self) -> Option<&XaAssets> {
        match self {
            Self::XaExtent(item) => Some(&item.xa_extent),
            Self::Path(_)
            | Self::Directory(_)
            | Self::PathTable(_)
            | Self::Mode1Extent(_)
            | Self::AppleHfs(_)
            | Self::DuplicateBlock(_)
            | Self::CeQuadratJolietLinks(_)
            | Self::CeQuadratFormatter(_)
            | Self::Gap(_) => None,
        }
    }

    pub const fn gap_sectors(&self) -> Option<u32> {
        match self {
            Self::Path(_)
            | Self::Directory(_)
            | Self::PathTable(_)
            | Self::Mode1Extent(_)
            | Self::AppleHfs(_)
            | Self::DuplicateBlock(_)
            | Self::CeQuadratJolietLinks(_)
            | Self::CeQuadratFormatter(_)
            | Self::XaExtent(_) => None,
            Self::Gap(item) => Some(item.gap),
        }
    }

    pub const fn gap_kind(&self) -> Option<GapKind> {
        match self {
            Self::Path(_)
            | Self::Directory(_)
            | Self::PathTable(_)
            | Self::Mode1Extent(_)
            | Self::AppleHfs(_)
            | Self::DuplicateBlock(_)
            | Self::CeQuadratJolietLinks(_)
            | Self::CeQuadratFormatter(_)
            | Self::XaExtent(_) => None,
            Self::Gap(item) => Some(item.kind),
        }
    }

    pub const fn gap_subheader(&self) -> Option<XaSubheader> {
        match self {
            Self::Path(_)
            | Self::Directory(_)
            | Self::PathTable(_)
            | Self::Mode1Extent(_)
            | Self::AppleHfs(_)
            | Self::DuplicateBlock(_)
            | Self::CeQuadratJolietLinks(_)
            | Self::CeQuadratFormatter(_)
            | Self::XaExtent(_) => None,
            Self::Gap(item) => item.subheader,
        }
    }

    pub const fn gap_form2_edc(&self) -> Option<bool> {
        match self {
            Self::Path(_)
            | Self::Directory(_)
            | Self::PathTable(_)
            | Self::Mode1Extent(_)
            | Self::AppleHfs(_)
            | Self::DuplicateBlock(_)
            | Self::CeQuadratJolietLinks(_)
            | Self::CeQuadratFormatter(_)
            | Self::XaExtent(_) => None,
            Self::Gap(item) => item.form2_edc,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrimaryVolume {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub volume_space_size: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub volume_set_size: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub volume_sequence_number: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_structure_version: Option<u8>,
    #[serde(default, skip_serializing_if = "PvdU16Encoding::is_default")]
    pub u16_encoding: PvdU16Encoding,
    #[serde(
        default,
        skip_serializing_if = "PrimaryVolumeApplicationUse::is_default"
    )]
    pub application_use: PrimaryVolumeApplicationUse,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub application_use_hex: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root_directory_record_length: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root_directory_recording_time: Option<String>,
    #[serde(default, skip_serializing_if = "RootDirectoryIdentifier::is_default")]
    pub root_directory_identifier: RootDirectoryIdentifier,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub escape_sequence: Option<JolietLevel>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub system_identifier: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub volume_identifier: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub volume_set_identifier: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub publisher_identifier: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub data_preparer_identifier: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub application_identifier: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub copyright_file_identifier: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub abstract_file_identifier: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub bibliographic_file_identifier: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reserved_hex: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub creation_time: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub modification_time: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expiration_time: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effective_time: Option<String>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PvdU16Encoding {
    #[default]
    BothEndian,
    LittleEndianOnly,
}

impl PvdU16Encoding {
    const fn is_default(&self) -> bool {
        matches!(self, Self::BothEndian)
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RootDirectoryIdentifier {
    #[default]
    Current,
    Parent,
    Empty,
}

impl RootDirectoryIdentifier {
    const fn is_default(&self) -> bool {
        matches!(self, Self::Current)
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrimaryVolumeApplicationUse {
    #[default]
    CdXa001,
    CdXa001_1_1,
    CdXa001Xcd3221Revision13,
    #[serde(rename = "cd_rep_2_0_131")]
    CdRep20131,
}

impl PrimaryVolumeApplicationUse {
    const fn is_default(&self) -> bool {
        matches!(self, Self::CdXa001)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    pub path: String,
    #[serde(default, skip_serializing_if = "is_false")]
    pub omit_version: bool,
    pub recording_time: String,
    #[serde(default, skip_serializing_if = "is_false")]
    pub hidden: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub associated: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reference: Option<EntryReference>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub xa_system_use: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub directory_slack: Option<DirectorySlack>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub directory_length_policy: Option<DirectoryLengthPolicy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allocation_padding_hex: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub directory_self_xa: Option<EntryXa>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub directory_parent_xa: Option<EntryXa>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub system_use_hex: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identifier_padding: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub directory_self_system_use_hex: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub directory_parent_system_use_hex: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub directory_self_recording_time: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub directory_parent_recording_time: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub directory_self_length: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub directory_parent_length: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub directory_self_hidden: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub directory_parent_hidden: Option<bool>,
    #[serde(default, skip_serializing_if = "EntrySectorSubheader::is_default")]
    pub sector_subheader: EntrySectorSubheader,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub xa: Option<EntryXa>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EntryReference {
    pub kind: EntryReferenceKind,
    pub extent: u32,
    pub length: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntryReferenceKind {
    Layout,
    RecordOnly,
    External,
    Directory,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectorySlack {
    pub offset: u32,
    pub hex: String,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntrySectorSubheader {
    #[default]
    Canonical,
    Data,
    EndOfFileData,
    DataUntilFinal,
    IsoMetadata,
}

impl EntrySectorSubheader {
    const fn is_default(&self) -> bool {
        matches!(self, Self::Canonical)
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum XaLengthEncoding {
    #[default]
    Logical2048,
    Mode2_2336,
}

impl Serialize for XaLengthEncoding {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u16(match self {
            Self::Logical2048 => 2048,
            Self::Mode2_2336 => 2336,
        })
    }
}

impl<'de> Deserialize<'de> for XaLengthEncoding {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        match u16::deserialize(deserializer)? {
            2048 => Ok(Self::Logical2048),
            2336 => Ok(Self::Mode2_2336),
            value => Err(de::Error::custom(format_args!(
                "XA length encoding must be 2048 or 2336, not {value}"
            ))),
        }
    }
}

impl XaLengthEncoding {
    pub(crate) const fn is_default(&self) -> bool {
        matches!(self, Self::Logical2048)
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(default)]
pub struct EntryXa {
    #[serde(skip_serializing_if = "is_zero_u16")]
    pub group_id: u16,
    #[serde(skip_serializing_if = "is_zero_u16")]
    pub user_id: u16,
    #[serde(skip_serializing_if = "is_default_xa_permissions")]
    pub permissions: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attributes: Option<XaAttributes>,
    #[serde(skip_serializing_if = "is_zero")]
    pub file_number: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logical_length: Option<u32>,
    #[serde(skip_serializing_if = "XaLengthEncoding::is_default")]
    pub length_encoding: XaLengthEncoding,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub framing_subheader: Option<XaSubheader>,
}

impl Default for EntryXa {
    fn default() -> Self {
        Self {
            group_id: 0,
            user_id: 0,
            permissions: DEFAULT_XA_PERMISSIONS,
            attributes: None,
            file_number: 0,
            logical_length: None,
            length_encoding: XaLengthEncoding::default(),
            framing_subheader: None,
        }
    }
}

#[derive(Deserialize)]
#[serde(default, deny_unknown_fields)]
struct EntryXaFields {
    group_id: u16,
    user_id: u16,
    permissions: u16,
    attributes: Option<XaAttributes>,
    file_number: u8,
    logical_length: Option<u32>,
    length_encoding: XaLengthEncoding,
    framing_subheader: Option<XaSubheader>,
}

impl Default for EntryXaFields {
    fn default() -> Self {
        Self {
            group_id: 0,
            user_id: 0,
            permissions: DEFAULT_XA_PERMISSIONS,
            attributes: None,
            file_number: 0,
            logical_length: None,
            length_encoding: XaLengthEncoding::default(),
            framing_subheader: None,
        }
    }
}

impl<'de> Deserialize<'de> for EntryXa {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let fields = EntryXaFields::deserialize(deserializer)?;
        if !fields.length_encoding.is_default() && fields.logical_length.is_some() {
            return Err(de::Error::custom(
                "XA length encoding cannot be combined with logical_length",
            ));
        }
        Ok(Self {
            group_id: fields.group_id,
            user_id: fields.user_id,
            permissions: fields.permissions,
            attributes: fields.attributes,
            file_number: fields.file_number,
            logical_length: fields.logical_length,
            length_encoding: fields.length_encoding,
            framing_subheader: fields.framing_subheader,
        })
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct XaAttributes(u16);

impl XaAttributes {
    pub const MODE2_FORM1: Self = Self(0x0800);
    pub const MODE2_FORM2: Self = Self(0x1000);
    pub const INTERLEAVED: Self = Self(0x2000);
    pub const CDDA: Self = Self(0x4000);
    pub const DIRECTORY: Self = Self(0x8000);

    pub const fn from_bits(bits: u16) -> Self {
        Self(bits)
    }

    pub const fn bits(self) -> u16 {
        self.0
    }

    pub const fn contains(self, flag: XaAttributeFlag) -> bool {
        self.0 & flag.bit() != 0
    }
}

impl Serialize for XaAttributes {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeSeq;

        let mut sequence = serializer.serialize_seq(Some(self.0.count_ones() as usize))?;
        for flag in XaAttributeFlag::ALL {
            if self.contains(flag) {
                sequence.serialize_element(&flag)?;
            }
        }
        sequence.end()
    }
}

impl<'de> Deserialize<'de> for XaAttributes {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let flags = Vec::<XaAttributeFlag>::deserialize(deserializer)?;
        let mut bits = 0_u16;
        for flag in flags {
            let bit = flag.bit();
            if bits & bit != 0 {
                return Err(de::Error::custom(format_args!(
                    "duplicate XA attribute flag {flag}"
                )));
            }
            bits |= bit;
        }
        Ok(Self(bits))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum XaAttributeFlag {
    Mode2Form1,
    Mode2Form2,
    Interleaved,
    Cdda,
    Directory,
}

impl XaAttributeFlag {
    const ALL: [Self; 5] = [
        Self::Mode2Form1,
        Self::Mode2Form2,
        Self::Interleaved,
        Self::Cdda,
        Self::Directory,
    ];

    const fn bit(self) -> u16 {
        match self {
            Self::Mode2Form1 => XaAttributes::MODE2_FORM1.bits(),
            Self::Mode2Form2 => XaAttributes::MODE2_FORM2.bits(),
            Self::Interleaved => XaAttributes::INTERLEAVED.bits(),
            Self::Cdda => XaAttributes::CDDA.bits(),
            Self::Directory => XaAttributes::DIRECTORY.bits(),
        }
    }
}

impl fmt::Display for XaAttributeFlag {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Mode2Form1 => formatter.write_str("mode2_form1"),
            Self::Mode2Form2 => formatter.write_str("mode2_form2"),
            Self::Interleaved => formatter.write_str("interleaved"),
            Self::Cdda => formatter.write_str("cdda"),
            Self::Directory => formatter.write_str("directory"),
        }
    }
}

const fn is_zero(value: &u8) -> bool {
    *value == 0
}

const fn is_zero_u16(value: &u16) -> bool {
    *value == 0
}

const fn is_default_xa_permissions(value: &u16) -> bool {
    *value == DEFAULT_XA_PERMISSIONS
}

#[cfg(test)]
mod tests {
    use super::*;

    fn track(mode: TrackMode, start_msf: &str) -> Track {
        Track {
            sha1: None,
            mode,
            start_msf: start_msf.to_owned(),
            form2_edc: true,
            noncompliant_trailing_ecc: false,
            redump_0x55: Vec::new(),
            mode1_reserved: Vec::new(),
            mode1_protection: None,
            patches: Vec::new(),
        }
    }

    #[test]
    fn track_mode_is_required_while_other_defaults_are_omitted() {
        let yaml = yaml_serde::to_string(&track(TrackMode::Mode2Xa, "00:02:00")).unwrap();
        assert!(yaml.lines().any(|line| line == "mode: 2xa"));
        assert!(!yaml.lines().any(|line| line.starts_with("start_msf:")));
        assert!(!yaml.lines().any(|line| line.starts_with("form2_edc:")));
        assert!(
            !yaml
                .lines()
                .any(|line| line.starts_with("noncompliant_trailing_ecc:"))
        );
        assert!(!yaml.contains("raw_sector_size"));

        let parsed: Track = yaml_serde::from_str(&yaml).unwrap();
        assert_eq!(parsed.mode, TrackMode::Mode2Xa);
        assert_eq!(parsed.start_msf, "00:02:00");
        assert!(parsed.form2_edc);
        assert!(!parsed.noncompliant_trailing_ecc);
        assert!(yaml_serde::from_str::<Track>("start_msf: 00:02:00\n").is_err());
    }

    #[test]
    fn redump_0x55_runs_roundtrip_at_track_level() {
        let mut value = track(TrackMode::Mode2Xa, "00:02:00");
        value.redump_0x55 = vec![Redump0x55Run {
            lba: 145_707,
            sectors: 2,
        }];

        let yaml = yaml_serde::to_string(&value).unwrap();
        assert!(yaml.contains("redump_0x55:\n- lba: 145707\n  sectors: 2"));
        let parsed = yaml_serde::from_str::<Track>(&yaml).unwrap();
        assert_eq!(parsed.redump_0x55, value.redump_0x55);
    }

    #[test]
    fn mode1_reserved_runs_roundtrip_at_track_level() {
        let mut value = track(TrackMode::Mode1, "00:02:00");
        value.mode1_reserved = vec![Mode1ReservedRun {
            lba: 33,
            sectors: 5,
            hex: "ffffffffffffffff".to_owned(),
        }];

        let yaml = yaml_serde::to_string(&value).unwrap();
        assert!(yaml.contains("mode1_reserved:\n- lba: 33\n  sectors: 5\n  hex: ffffffffffffffff"));
        assert_eq!(
            yaml_serde::from_str::<Track>(&yaml).unwrap().mode1_reserved,
            value.mode1_reserved
        );
    }

    #[test]
    fn mode1_protection_roundtrips_as_one_policy_with_sparse_runs() {
        let value = Track {
            mode1_protection: Some(Mode1Protection {
                edc_xor: "014f8e03".to_owned(),
                reserved: "ffffffffffffffff".to_owned(),
                ecc_xor: "55".repeat(276),
                payload_inverted: true,
                runs: vec![
                    Mode1ProtectionRun {
                        lba: 33,
                        sectors: 5,
                    },
                    Mode1ProtectionRun {
                        lba: 46,
                        sectors: 4,
                    },
                ],
            }),
            ..Track::default()
        };
        let yaml = yaml_serde::to_string(&value).unwrap();
        assert!(yaml.contains("mode1_protection:\n  edc_xor: 014f8e03"));
        assert!(yaml.contains("payload_inverted: true"));
        assert_eq!(
            yaml_serde::from_str::<Track>(&yaml)
                .unwrap()
                .mode1_protection,
            value.mode1_protection
        );
    }

    #[test]
    fn optional_sha1_fields_round_trip_without_changing_legacy_defaults() {
        let hash = "0123456789abcdef0123456789abcdef0123456789";
        let mut value = track(TrackMode::Mode2Xa, "00:02:00");
        value.sha1 = Some(hash.to_owned());
        let yaml = yaml_serde::to_string(&value).unwrap();
        assert!(yaml.starts_with(&format!("sha1: {hash}\n")));
        assert_eq!(
            yaml_serde::from_str::<Track>(&yaml)
                .unwrap()
                .sha1
                .as_deref(),
            Some(hash)
        );
        assert!(track(TrackMode::Mode2Xa, "00:02:00").sha1.is_none());

        let asset: HostAsset =
            yaml_serde::from_str(&format!("path: FILE.XA1\nsha1: {hash}\n")).unwrap();
        assert_eq!(asset.sha1.as_deref(), Some(hash));
        assert!(yaml_serde::from_str::<HostAsset>(&format!("sha1: {hash}\n")).is_err());
    }

    #[test]
    fn track_mode_accepts_only_1_2_and_2xa() {
        for (mode, expected) in [(TrackMode::Mode1, "mode: 1"), (TrackMode::Mode2, "mode: 2")] {
            let yaml = yaml_serde::to_string(&track(mode, "00:02:00")).unwrap();
            assert!(yaml.lines().any(|line| line == expected));
            let parsed: Track = yaml_serde::from_str(&yaml).unwrap();
            assert_eq!(parsed.mode, mode);
        }

        let parsed: Track = yaml_serde::from_str("mode: 2xa\nform2_edc: true\n").unwrap();
        assert_eq!(parsed.mode, TrackMode::Mode2Xa);

        assert!(yaml_serde::from_str::<Track>("mode: 3\n").is_err());
        for legacy_value in ["computed", "zeroed"] {
            assert!(
                yaml_serde::from_str::<Track>(&format!("form2_edc: {legacy_value}\n")).is_err()
            );
        }
    }

    #[test]
    fn nondefault_start_msf_is_stored() {
        let yaml = yaml_serde::to_string(&track(TrackMode::Mode2Xa, "01:00:00")).unwrap();
        assert!(yaml.lines().any(|line| line == "start_msf: 01:00:00"));
    }

    #[test]
    fn track_rejects_removed_trailing_gap_fields() {
        assert!(yaml_serde::from_str::<Track>("trailing_gap: 151\n").is_err());
        assert!(yaml_serde::from_str::<Track>("trailing_gap_sectors: 151\n").is_err());
    }

    #[test]
    fn physical_gap_kinds_round_trip_without_ambiguity() {
        let form2 = yaml_serde::to_string(&FileLayoutItem::gap(3)).unwrap();
        assert_eq!(form2, "gap: 3\n");
        assert_eq!(
            yaml_serde::from_str::<FileLayoutItem>(&form2).unwrap(),
            FileLayoutItem::gap(3)
        );

        let xa = yaml_serde::to_string(&FileLayoutItem::xa_gap(150)).unwrap();
        assert_eq!(xa, "gap: 150\nkind: xa\n");
        assert_eq!(
            yaml_serde::from_str::<FileLayoutItem>(&xa).unwrap(),
            FileLayoutItem::xa_gap(150)
        );

        let mode1 = yaml_serde::to_string(&FileLayoutItem::mode1_gap(150)).unwrap();
        assert_eq!(mode1, "gap: 150\nkind: mode1\n");
        assert_eq!(
            yaml_serde::from_str::<FileLayoutItem>(&mode1).unwrap(),
            FileLayoutItem::mode1_gap(150)
        );
    }

    #[test]
    fn typed_non_file_layout_items_round_trip_without_opaque_data() {
        let items = vec![
            FileLayoutItem::apple_hfs(
                HostAsset {
                    path: "disc.hfs".to_owned(),
                    sha1: Some("1".repeat(40)),
                },
                225_867,
                229_275,
            ),
            FileLayoutItem::duplicate_block("MWREGI~1.EXE", 330),
            FileLayoutItem::cequadrat_joliet_links(),
            FileLayoutItem::cequadrat_formatter(HostAsset {
                path: "disc.cequadrat".to_owned(),
                sha1: Some("2".repeat(40)),
            }),
        ];
        let yaml = yaml_serde::to_string(&items).unwrap();
        assert_eq!(
            yaml_serde::from_str::<Vec<FileLayoutItem>>(&yaml).unwrap(),
            items
        );
        assert!(yaml.contains("start_block: 225867"));
        assert!(yaml.contains("duplicate_block:"));
        assert!(yaml.contains("cequadrat_joliet_links: true"));
    }

    #[test]
    fn removed_metadata_layout_field_is_rejected() {
        let yaml = "primary_volume: {}\nmetadata_layout: []\nentries: []\nlayout: []\n";
        assert!(yaml_serde::from_str::<Iso9660>(yaml).is_err());
    }

    #[test]
    fn unreferenced_xa_extent_assets_round_trip_without_ambiguity() {
        let item = FileLayoutItem::xa_extent(XaAssets {
            form1: XaFormAsset {
                path: "disc.unreferenced.000.F1S".to_owned(),
                sha1: Some("1111111111111111111111111111111111111111".to_owned()),
                framing: None,
            },
            form2: XaFormAsset {
                path: "disc.unreferenced.000.F2S".to_owned(),
                sha1: None,
                framing: None,
            },
            index: Some(HostAsset {
                path: "disc.unreferenced.000.I".to_owned(),
                sha1: None,
            }),
            interleave: None,
            gap_overrides: vec![XaPositionSpan {
                start: 7,
                stride: 8,
                count: 2,
            }],
        });
        let yaml = yaml_serde::to_string(&item).unwrap();
        assert_eq!(
            yaml,
            "xa_extent:\n  form1:\n    path: disc.unreferenced.000.F1S\n    sha1: '1111111111111111111111111111111111111111'\n  form2:\n    path: disc.unreferenced.000.F2S\n  index:\n    path: disc.unreferenced.000.I\n  gap_overrides:\n  - start: 7\n    stride: 8\n    count: 2\n"
        );
        assert_eq!(yaml_serde::from_str::<FileLayoutItem>(&yaml).unwrap(), item);
        assert!(
            yaml_serde::from_str::<FileLayoutItem>(
                "xa_extent:\n  form1: OLD.XA1\n  form2: OLD.XA2\n  index: OLD.XAI\n"
            )
            .is_err()
        );
    }

    #[test]
    fn indexed_xa_assets_are_nested_on_the_layout_path() {
        let hash = "0123456789abcdef0123456789abcdef0123456789";
        let yaml = format!(
            "path: MOVIE.STR\nxa_assets:\n  form1:\n    path: MOVIE.STR.F1S\n    sha1: {hash}\n  form2:\n    path: MOVIE.STR.F2S\n  index:\n    path: MOVIE.STR.I\n"
        );
        let item: FileLayoutItem = yaml_serde::from_str(&yaml).unwrap();
        assert_eq!(yaml_serde::to_string(&item).unwrap(), yaml);

        for invalid in [
            "path: MOVIE.STR\nxa_assets:\n  form1:\n    sha1: 0123456789abcdef0123456789abcdef0123456789\n  form2:\n    path: MOVIE.STR.F2S\n  index:\n    path: MOVIE.STR.I\n",
            "path: MOVIE.STR\nxa_assets:\n  form1:\n    path: MOVIE.STR.F1S\n    checksum: bad\n  form2:\n    path: MOVIE.STR.F2S\n  index:\n    path: MOVIE.STR.I\n",
        ] {
            assert!(yaml_serde::from_str::<FileLayoutItem>(invalid).is_err());
        }

        let legacy_entry = "path: MOVIE.STR\nrecording_time: 1998-01-01T00:00:00+00:00\nxa:\n  form1: MOVIE.STR.XA1\n";
        assert!(yaml_serde::from_str::<Entry>(legacy_entry).is_err());
    }

    #[test]
    fn xa_framing_supports_scalar_and_parameterized_forms() {
        let scalar: XaFormAsset =
            yaml_serde::from_str("path: MOVIE.F2\nframing: channel\n").unwrap();
        assert_eq!(
            scalar.framing,
            Some(XaFraming::Named(XaFramingPolicy::Channel))
        );

        let detailed: XaFormAsset = yaml_serde::from_str(
            "path: MOVIE.F1\nframing:\n  policy: runs\n  eof: final_record\n  default:\n    submode:\n    - data\n  runs:\n  - sectors: 2\n    subheader:\n      file: 1\n      submode:\n      - data\n  overrides:\n  - start: 3\n    stride: 8\n    count: 2\n    subheader:\n      submode:\n      - data\n",
        )
        .unwrap();
        let yaml = yaml_serde::to_string(&detailed).unwrap();
        assert_eq!(
            yaml_serde::from_str::<XaFormAsset>(&yaml).unwrap(),
            detailed
        );
    }

    #[test]
    fn removed_xa_gap_asset_field_is_rejected() {
        let yaml = "path: MOVIE.STR\nxa_assets:\n  form1:\n    path: MOVIE.F1S\n  form2:\n    path: MOVIE.F2S\n  index:\n    path: MOVIE.I\n  gap_index:\n    path: MOVIE.XAG\n";
        assert!(yaml_serde::from_str::<FileLayoutItem>(yaml).is_err());
    }

    #[test]
    fn form2_edc_boolean_round_trips() {
        let mut track = track(TrackMode::Mode2Xa, "00:02:00");
        track.form2_edc = false;
        let yaml = yaml_serde::to_string(&track).unwrap();
        assert!(yaml.lines().any(|line| line == "form2_edc: false"));

        let parsed: Track = yaml_serde::from_str(&yaml).unwrap();
        assert!(!parsed.form2_edc);
    }

    #[test]
    fn noncompliant_trailing_ecc_is_stored_only_when_enabled() {
        let mut track = track(TrackMode::Mode2Xa, "00:02:00");
        track.noncompliant_trailing_ecc = true;
        let yaml = yaml_serde::to_string(&track).unwrap();
        assert!(
            yaml.lines()
                .any(|line| line == "noncompliant_trailing_ecc: true")
        );

        let parsed: Track = yaml_serde::from_str(&yaml).unwrap();
        assert!(parsed.noncompliant_trailing_ecc);
    }

    #[test]
    fn track_patches_are_optional_and_round_trip_as_multiline_raw_sectors() {
        let mut track = track(TrackMode::Mode2Xa, "00:02:00");
        assert!(!yaml_serde::to_string(&track).unwrap().contains("patches:"));

        track.patches.push(SectorPatch {
            lba: 123,
            hex: format_sector_patch_hex(&[0xa5; 2352]),
        });
        let yaml = yaml_serde::to_string(&track).unwrap();
        assert!(yaml.lines().any(|line| line == "patches:"));
        assert!(yaml.lines().any(|line| line == "- lba: 123"));
        assert!(yaml.lines().any(|line| line == "  hex: |-"));
        let parsed: Track = yaml_serde::from_str(&yaml).unwrap();
        assert_eq!(parsed.patches, track.patches);
        assert_eq!(
            decode_sector_patch(&parsed.patches[0]).unwrap(),
            [0xa5; 2352]
        );
    }

    #[test]
    fn patch_hex_ignores_ascii_whitespace_but_requires_one_complete_sector() {
        let bytes = [0x5a; 2352];
        let compact = hex::encode(bytes);
        let spaced = compact
            .as_bytes()
            .chunks(64)
            .map(|chunk| std::str::from_utf8(chunk).unwrap())
            .collect::<Vec<_>>()
            .join(" \n\t");
        let patch = SectorPatch {
            lba: -150,
            hex: spaced,
        };
        assert_eq!(decode_sector_patch(&patch).unwrap(), bytes);

        for invalid in ["", "00", &"00".repeat(2353)] {
            let patch = SectorPatch {
                lba: 0,
                hex: invalid.to_owned(),
            };
            assert!(decode_sector_patch(&patch).is_err());
        }
    }

    #[test]
    fn form1_sector_count_supports_auto_and_explicit_layouts() {
        assert_eq!(
            Form1Sectors::Auto("auto".to_owned()).resolve(2049).unwrap(),
            2
        );
        assert_eq!(Form1Sectors::Count(12).resolve(1).unwrap(), 12);
        assert!(Form1Sectors::Count(12).resolve(24_577).is_err());
        assert!(
            Form1Sectors::Auto("auto".to_owned())
                .resolve(32_769)
                .is_err()
        );
    }

    #[test]
    fn interleaved_xa_entry_metadata_round_trips_as_named_fields() {
        let yaml = "path: PETEXA0.STR\nrecording_time: 1998-01-01T00:00:00+00:00\nxa:\n  attributes:\n  - interleaved\n  file_number: 1\n";
        let entry: Entry = yaml_serde::from_str(yaml).unwrap();
        let xa = entry.xa.as_ref().unwrap();
        assert_eq!(xa.file_number, 1);
        assert_eq!(yaml_serde::to_string(&entry).unwrap(), yaml);
    }

    #[test]
    fn xa_length_encoding_uses_numeric_units() {
        let yaml = "length_encoding: 2336\n";
        let value: EntryXa = yaml_serde::from_str(yaml).unwrap();
        assert_eq!(value.length_encoding, XaLengthEncoding::Mode2_2336);
        assert_eq!(yaml_serde::to_string(&value).unwrap(), yaml);

        let default: EntryXa = yaml_serde::from_str("length_encoding: 2048\n").unwrap();
        assert_eq!(default.length_encoding, XaLengthEncoding::Logical2048);
        assert_eq!(yaml_serde::to_string(&default).unwrap(), "{}\n");

        for invalid in ["mode2_2336\n", "2352\n"] {
            assert!(yaml_serde::from_str::<XaLengthEncoding>(invalid).is_err());
        }
    }

    #[test]
    fn legacy_interleaved_xa_shape_is_rejected() {
        for yaml in [
            "path: OLD.STR\nrecording_time: 1998-01-01T00:00:00+00:00\nxa:\n  form2: OLD.STR.XA\n",
            "path: OLD.STR\nrecording_time: 1998-01-01T00:00:00+00:00\nxa:\n  form1_subheader: {}\n",
        ] {
            assert!(yaml_serde::from_str::<Entry>(yaml).is_err());
        }
    }

    #[test]
    fn layout_sequence_interleaves_paths_and_physical_gaps() {
        let yaml = "- path: SYSTEM.CNF\n- gap: 13\n- path: WAD.WAD\n";
        let files: Vec<FileLayoutItem> = yaml_serde::from_str(yaml).unwrap();
        assert_eq!(yaml_serde::to_string(&files).unwrap(), yaml);
    }

    #[test]
    fn ordinary_file_source_is_an_optional_host_path() {
        let yaml = "- path: SYSTEM.CNF\n  source: SYSTEM.CNF.1\n";
        let files: Vec<FileLayoutItem> = yaml_serde::from_str(yaml).unwrap();
        let FileLayoutItem::Path(file) = &files[0] else {
            panic!("expected path item")
        };
        assert_eq!(file.path, "SYSTEM.CNF");
        assert_eq!(file.source.as_deref(), Some("SYSTEM.CNF.1"));
        assert_eq!(yaml_serde::to_string(&files).unwrap(), yaml);

        let legacy: Vec<FileLayoutItem> = yaml_serde::from_str("- path: SYSTEM.CNF\n").unwrap();
        let FileLayoutItem::Path(file) = &legacy[0] else {
            panic!("expected path item")
        };
        assert!(file.source.is_none());
    }

    #[test]
    fn layout_sequence_rejects_scalar_empty_and_ambiguous_items() {
        for yaml in [
            "- SYSTEM.CNF\n",
            "- {}\n",
            "- path: SYSTEM.CNF\n  gap: 13\n",
        ] {
            assert!(
                yaml_serde::from_str::<Vec<FileLayoutItem>>(yaml).is_err(),
                "unexpectedly accepted {yaml:?}"
            );
        }
    }

    #[test]
    fn all_xa_attribute_combinations_round_trip_as_named_flags() {
        for mask in 0_u16..32 {
            let expected = XaAttributes::from_bits(mask << 11);
            let yaml = yaml_serde::to_string(&expected).unwrap();
            let parsed: XaAttributes = yaml_serde::from_str(&yaml).unwrap();
            assert_eq!(parsed, expected, "failed YAML {yaml:?}");
        }

        let attributes = XaAttributes::from_bits(
            XaAttributes::MODE2_FORM1.bits()
                | XaAttributes::INTERLEAVED.bits()
                | XaAttributes::DIRECTORY.bits(),
        );
        assert_eq!(
            yaml_serde::to_string(&attributes).unwrap(),
            "- mode2_form1\n- interleaved\n- directory\n"
        );
    }

    #[test]
    fn xa_attributes_reject_duplicates_unknown_names_and_numeric_values() {
        for yaml in [
            "- interleaved\n- interleaved\n",
            "- unknown\n",
            "8192\n",
            "[8192]\n",
        ] {
            assert!(
                yaml_serde::from_str::<XaAttributes>(yaml).is_err(),
                "unexpectedly accepted {yaml:?}"
            );
        }
    }

    #[test]
    fn entry_references_are_explicit_and_removed_fields_are_rejected() {
        for (kind, extent, length) in [
            ("layout", 48_050, 362_496),
            ("record_only", 0, 61_922_688),
            ("external", 30_692, 0),
            ("directory", 0, 0),
        ] {
            let yaml = format!(
                "path: FILE.XA\nrecording_time: 1998-01-01T00:00:00+00:00\nreference:\n  kind: {kind}\n  extent: {extent}\n  length: {length}\n"
            );
            let entry: Entry = yaml_serde::from_str(&yaml).unwrap();
            assert_eq!(yaml_serde::to_string(&entry).unwrap(), yaml);
        }

        for removed in [
            "extent: 1\nlength: 2\n",
            "directory_reference:\n  extent: 0\n  length: 0\n",
            "unbacked: true\n",
        ] {
            let yaml =
                format!("path: FILE.XA\nrecording_time: 1998-01-01T00:00:00+00:00\n{removed}");
            assert!(yaml_serde::from_str::<Entry>(&yaml).is_err());
        }
    }

    #[test]
    fn metadata_and_path_table_subheaders_use_scalar_or_map_values() {
        let named: MetadataSubheader = yaml_serde::from_str("end_of_file_data\n").unwrap();
        assert_eq!(
            named,
            MetadataSubheader::Named(IsoMetadataSubheader::EndOfFileData)
        );
        let explicit_yaml = "file_number: 1\nsubmode:\n- data\n";
        let explicit: MetadataSubheader = yaml_serde::from_str(explicit_yaml).unwrap();
        assert_eq!(yaml_serde::to_string(&explicit).unwrap(), explicit_yaml);

        let path: PathTableSubheader = yaml_serde::from_str(explicit_yaml).unwrap();
        assert_eq!(yaml_serde::to_string(&path).unwrap(), explicit_yaml);
    }
}

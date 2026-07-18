use serde::{Deserialize, Serialize};

pub const FORMAT_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub format_version: u32,
    pub source: SourceInfo,
    pub track: Track,
    pub system_area: SystemArea,
    pub iso9660: Iso9660,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceInfo {
    pub sha1: String,
    pub sectors: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Track {
    pub mode: String,
    pub start_msf: String,
    pub raw_sector_size: u16,
    pub trailing_gap_sectors: u32,
    pub pvd_subheader: [u8; 4],
    pub metadata_subheader: [u8; 4],
    pub file_subheader: [u8; 4],
    pub file_end_submode: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SystemArea {
    pub path: String,
    pub source_sha1: String,
    pub source_length: u64,
    pub total_sectors: u8,
    pub form1_sectors: Form1Sectors,
    pub form1_subheader: [u8; 4],
    pub form2_subheader: [u8; 4],
    pub form2_edc: Form2Edc,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Form1Sectors {
    Auto(String),
    Count(u8),
}

impl Form1Sectors {
    pub fn resolve(&self, content_len: usize, total: u8) -> anyhow::Result<u8> {
        let needed = content_len.div_ceil(2048);
        let count = match self {
            Self::Auto(value) if value == "auto" => needed,
            Self::Auto(value) => anyhow::bail!("unknown form1_sectors value {value:?}"),
            Self::Count(count) => usize::from(*count),
        };
        anyhow::ensure!(
            count <= usize::from(total),
            "system content exceeds system area"
        );
        anyhow::ensure!(
            content_len <= count * 2048,
            "system content exceeds configured Form 1 sectors"
        );
        Ok(count as u8)
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Form2Edc {
    Computed,
    Zeroed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Iso9660 {
    pub primary_volume: PrimaryVolume,
    pub root: DirectoryMetadata,
    pub defaults: EntryDefaults,
    pub entries: Vec<Entry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrimaryVolume {
    pub system_identifier: String,
    pub volume_identifier: String,
    pub volume_set_identifier: String,
    pub publisher_identifier: String,
    pub data_preparer_identifier: String,
    pub application_identifier: String,
    pub copyright_file_identifier: String,
    pub abstract_file_identifier: String,
    pub bibliographic_file_identifier: String,
    pub volume_set_size: u16,
    pub volume_sequence_number: u16,
    pub logical_block_size: u16,
    pub creation_time_hex: String,
    pub modification_time_hex: String,
    pub expiration_time_hex: String,
    pub effective_time_hex: String,
    pub file_structure_version: u8,
    pub application_use_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryMetadata {
    pub recording_time_hex: String,
    pub flags: u8,
    pub file_unit_size: u8,
    pub interleave_gap_size: u8,
    pub volume_sequence_number: u16,
    pub system_use_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EntryDefaults {
    pub file_recording_time_hex: String,
    pub directory_recording_time_hex: String,
    pub file_system_use_hex: String,
    pub directory_system_use_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    pub path: String,
    pub kind: EntryKind,
    #[serde(default = "default_version")]
    pub version: u8,
    #[serde(default)]
    pub recording_time_hex: Option<String>,
    #[serde(default)]
    pub flags: u8,
    #[serde(default)]
    pub file_unit_size: u8,
    #[serde(default)]
    pub interleave_gap_size: u8,
    #[serde(default = "default_volume_sequence")]
    pub volume_sequence_number: u16,
    #[serde(default)]
    pub system_use_hex: Option<String>,
    #[serde(default)]
    pub data_order: Option<u32>,
    #[serde(default)]
    pub source_sha1: Option<String>,
    #[serde(default)]
    pub source_length: Option<u64>,
}

fn default_version() -> u8 {
    1
}

fn default_volume_sequence() -> u16 {
    1
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntryKind {
    File,
    Directory,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn form1_sector_count_supports_auto_and_explicit_layouts() {
        assert_eq!(
            Form1Sectors::Auto("auto".to_owned())
                .resolve(2049, 16)
                .unwrap(),
            2
        );
        assert_eq!(Form1Sectors::Count(12).resolve(1, 16).unwrap(), 12);
        assert!(Form1Sectors::Count(12).resolve(24_577, 16).is_err());
        assert!(
            Form1Sectors::Auto("auto".to_owned())
                .resolve(32_769, 16)
                .is_err()
        );
    }
}

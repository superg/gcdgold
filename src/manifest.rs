use std::collections::HashSet;
use std::fmt;

use anyhow::Context;
use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::raw_cd::{XaSubheader, XaSubmode};

pub const SYSTEM_AREA_SECTORS: usize = 16;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    #[serde(default, skip_serializing_if = "Track::is_default")]
    pub track: Track,
    pub system_area: SystemArea,
    pub iso9660: Iso9660,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Track {
    #[serde(default, skip_serializing_if = "TrackMode::is_default")]
    pub mode: TrackMode,
    #[serde(
        default = "default_start_msf",
        skip_serializing_if = "is_default_start_msf"
    )]
    pub start_msf: String,
    #[serde(
        default = "default_trailing_gap",
        skip_serializing_if = "is_default_trailing_gap"
    )]
    pub trailing_gap: u32,
    #[serde(
        default = "default_form2_edc",
        skip_serializing_if = "is_default_form2_edc"
    )]
    pub form2_edc: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub noncompliant_trailing_ecc: bool,
}

impl Default for Track {
    fn default() -> Self {
        Self {
            mode: TrackMode::default(),
            start_msf: default_start_msf(),
            trailing_gap: default_trailing_gap(),
            form2_edc: default_form2_edc(),
            noncompliant_trailing_ecc: false,
        }
    }
}

impl Track {
    fn is_default(&self) -> bool {
        self.mode.is_default()
            && is_default_start_msf(&self.start_msf)
            && is_default_trailing_gap(&self.trailing_gap)
            && is_default_form2_edc(&self.form2_edc)
            && !self.noncompliant_trailing_ecc
    }
}

#[derive(Serialize)]
struct ManifestWithDefaults<'a> {
    track: TrackWithDefaults<'a>,
    system_area: &'a SystemArea,
    iso9660: Iso9660WithDefaults<'a>,
}

#[derive(Serialize)]
struct TrackWithDefaults<'a> {
    mode: TrackMode,
    start_msf: &'a str,
    trailing_gap: u32,
    form2_edc: bool,
    noncompliant_trailing_ecc: bool,
}

#[derive(Serialize)]
struct Iso9660WithDefaults<'a> {
    primary_volume: PrimaryVolumeWithDefaults<'a>,
    entries: Vec<EntryWithDefaults<'a>>,
    files: &'a [FileLayoutItem],
}

#[derive(Serialize)]
struct EntryWithDefaults<'a> {
    path: &'a str,
    recording_time: &'a str,
    xa: EntryXaWithDefaults<'a>,
    #[serde(skip_serializing_if = "Option::is_none")]
    extent: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    length: Option<u32>,
}

#[derive(Serialize)]
struct EntryXaWithDefaults<'a> {
    group_id: u16,
    user_id: u16,
    attributes: XaAttributes,
    file_number: u8,
    form1_subheader: Option<XaSubheaderWithDefaults>,
    form2: Option<&'a str>,
}

#[derive(Serialize)]
struct XaSubheaderWithDefaults {
    file_number: u8,
    channel: u8,
    submode: XaSubmode,
    coding_info: u8,
}

impl From<XaSubheader> for XaSubheaderWithDefaults {
    fn from(subheader: XaSubheader) -> Self {
        Self {
            file_number: subheader.file_number,
            channel: subheader.channel,
            submode: subheader.submode,
            coding_info: subheader.coding_info,
        }
    }
}

#[derive(Serialize)]
struct PrimaryVolumeWithDefaults<'a> {
    system_identifier: &'a str,
    volume_identifier: &'a str,
    volume_set_identifier: &'a str,
    publisher_identifier: &'a str,
    data_preparer_identifier: &'a str,
    application_identifier: &'a str,
    copyright_file_identifier: &'a str,
    abstract_file_identifier: &'a str,
    bibliographic_file_identifier: &'a str,
    creation_time: Option<&'a str>,
    modification_time: Option<&'a str>,
    expiration_time: Option<&'a str>,
    effective_time: Option<&'a str>,
}

pub(crate) fn serialize_manifest(
    manifest: &Manifest,
    include_defaults: bool,
) -> anyhow::Result<String> {
    if include_defaults {
        let file_paths: HashSet<_> = manifest
            .iso9660
            .files
            .iter()
            .filter_map(FileLayoutItem::as_path)
            .collect();
        let entries = manifest
            .iso9660
            .entries
            .iter()
            .map(|entry| {
                let xa = entry.xa.as_ref();
                let attributes = xa.and_then(|value| value.attributes).unwrap_or_else(|| {
                    if file_paths.contains(entry.path.as_str()) {
                        XaAttributes::MODE2_FORM1
                    } else {
                        XaAttributes::from_bits(
                            XaAttributes::MODE2_FORM1.bits() | XaAttributes::DIRECTORY.bits(),
                        )
                    }
                });
                EntryWithDefaults {
                    path: &entry.path,
                    recording_time: &entry.recording_time,
                    xa: EntryXaWithDefaults {
                        group_id: xa.map_or(0, |value| value.group_id),
                        user_id: xa.map_or(0, |value| value.user_id),
                        attributes,
                        file_number: xa.map_or(0, |value| value.file_number),
                        form1_subheader: xa.and_then(|value| value.form1_subheader).map(Into::into),
                        form2: xa.and_then(|value| value.form2.as_deref()),
                    },
                    extent: entry.extent,
                    length: entry.length,
                }
            })
            .collect();
        yaml_serde::to_string(&ManifestWithDefaults {
            track: TrackWithDefaults {
                mode: manifest.track.mode,
                start_msf: &manifest.track.start_msf,
                trailing_gap: manifest.track.trailing_gap,
                form2_edc: manifest.track.form2_edc,
                noncompliant_trailing_ecc: manifest.track.noncompliant_trailing_ecc,
            },
            system_area: &manifest.system_area,
            iso9660: Iso9660WithDefaults {
                primary_volume: PrimaryVolumeWithDefaults {
                    system_identifier: &manifest.iso9660.primary_volume.system_identifier,
                    volume_identifier: &manifest.iso9660.primary_volume.volume_identifier,
                    volume_set_identifier: &manifest.iso9660.primary_volume.volume_set_identifier,
                    publisher_identifier: &manifest.iso9660.primary_volume.publisher_identifier,
                    data_preparer_identifier: &manifest
                        .iso9660
                        .primary_volume
                        .data_preparer_identifier,
                    application_identifier: &manifest.iso9660.primary_volume.application_identifier,
                    copyright_file_identifier: &manifest
                        .iso9660
                        .primary_volume
                        .copyright_file_identifier,
                    abstract_file_identifier: &manifest
                        .iso9660
                        .primary_volume
                        .abstract_file_identifier,
                    bibliographic_file_identifier: &manifest
                        .iso9660
                        .primary_volume
                        .bibliographic_file_identifier,
                    creation_time: manifest.iso9660.primary_volume.creation_time.as_deref(),
                    modification_time: manifest.iso9660.primary_volume.modification_time.as_deref(),
                    expiration_time: manifest.iso9660.primary_volume.expiration_time.as_deref(),
                    effective_time: manifest.iso9660.primary_volume.effective_time.as_deref(),
                },
                entries,
                files: &manifest.iso9660.files,
            },
        })
        .context("serializing manifest with defaults")
    } else {
        yaml_serde::to_string(manifest).context("serializing manifest")
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum TrackMode {
    Mode1,
    Mode2,
    #[default]
    Mode2Xa,
}

impl TrackMode {
    fn is_default(&self) -> bool {
        *self == Self::default()
    }
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

fn default_trailing_gap() -> u32 {
    150
}

fn is_default_trailing_gap(value: &u32) -> bool {
    *value == 150
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
    pub form1_sectors: Form1Sectors,
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
    pub entries: Vec<Entry>,
    pub files: Vec<FileLayoutItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum FileLayoutItem {
    Path(FilePathItem),
    Gap(FileGapItem),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FilePathItem {
    pub path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FileGapItem {
    pub gap: u32,
}

impl FileLayoutItem {
    pub fn path(path: impl Into<String>) -> Self {
        Self::Path(FilePathItem { path: path.into() })
    }

    pub const fn gap(sectors: u32) -> Self {
        Self::Gap(FileGapItem { gap: sectors })
    }

    pub fn as_path(&self) -> Option<&str> {
        match self {
            Self::Path(item) => Some(&item.path),
            Self::Gap(_) => None,
        }
    }

    pub const fn gap_sectors(&self) -> Option<u32> {
        match self {
            Self::Path(_) => None,
            Self::Gap(item) => Some(item.gap),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrimaryVolume {
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
    pub creation_time: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub modification_time: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expiration_time: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effective_time: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    pub path: String,
    pub recording_time: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub xa: Option<EntryXa>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extent: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub length: Option<u32>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct EntryXa {
    #[serde(skip_serializing_if = "is_zero_u16")]
    pub group_id: u16,
    #[serde(skip_serializing_if = "is_zero_u16")]
    pub user_id: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attributes: Option<XaAttributes>,
    #[serde(skip_serializing_if = "is_zero")]
    pub file_number: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub form1_subheader: Option<XaSubheader>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub form2: Option<String>,
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

#[cfg(test)]
mod tests {
    use super::*;

    fn track(mode: TrackMode, start_msf: &str) -> Track {
        Track {
            mode,
            start_msf: start_msf.to_owned(),
            trailing_gap: 150,
            form2_edc: true,
            noncompliant_trailing_ecc: false,
        }
    }

    #[test]
    fn track_defaults_are_omitted_and_restored() {
        let yaml = yaml_serde::to_string(&track(TrackMode::Mode2Xa, "00:02:00")).unwrap();
        assert!(!yaml.lines().any(|line| line.starts_with("mode:")));
        assert!(!yaml.lines().any(|line| line.starts_with("start_msf:")));
        assert!(!yaml.lines().any(|line| line.starts_with("trailing_gap:")));
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
        assert_eq!(parsed.trailing_gap, 150);
        assert!(parsed.form2_edc);
        assert!(!parsed.noncompliant_trailing_ecc);
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
    fn nondefault_trailing_gap_is_stored() {
        let mut track = track(TrackMode::Mode2Xa, "00:02:00");
        track.trailing_gap = 151;
        let yaml = yaml_serde::to_string(&track).unwrap();
        assert!(yaml.lines().any(|line| line == "trailing_gap: 151"));
        assert!(yaml_serde::from_str::<Track>("trailing_gap_sectors: 151\n").is_err());
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
        let yaml = "path: PETEXA0.STR\nrecording_time: 1998-01-01T00:00:00+00:00\nxa:\n  attributes:\n  - interleaved\n  file_number: 1\n  form2: PETEXA0.STR.XA\n";
        let entry: Entry = yaml_serde::from_str(yaml).unwrap();
        assert_eq!(yaml_serde::to_string(&entry).unwrap(), yaml);
    }

    #[test]
    fn mixed_xa_form1_subheader_round_trips_as_named_fields() {
        let yaml = "path: ANIMATIO.000\nrecording_time: 1995-06-25T15:56:08+09:00\nxa:\n  attributes:\n  - mode2_form1\n  - mode2_form2\n  file_number: 1\n  form1_subheader:\n    file_number: 1\n    channel: 1\n    submode:\n    - video\n    - realtime\n    coding_info: 128\n  form2: ANIMATIO.000.XA\n";
        let entry: Entry = yaml_serde::from_str(yaml).unwrap();
        assert_eq!(
            entry.xa.as_ref().unwrap().form1_subheader,
            Some([1, 1, 0x42, 0x80].into())
        );
        assert_eq!(yaml_serde::to_string(&entry).unwrap(), yaml);
    }

    #[test]
    fn files_sequence_interleaves_paths_and_physical_gaps() {
        let yaml = "- path: SYSTEM.CNF\n- gap: 13\n- path: WAD.WAD\n";
        let files: Vec<FileLayoutItem> = yaml_serde::from_str(yaml).unwrap();
        assert_eq!(yaml_serde::to_string(&files).unwrap(), yaml);
    }

    #[test]
    fn files_sequence_rejects_scalar_empty_and_ambiguous_items() {
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
}

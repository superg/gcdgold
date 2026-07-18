use std::fmt;

use anyhow::Context;
use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

pub const SYSTEM_AREA_SECTORS: usize = 16;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
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
        default = "default_trailing_gap_sectors",
        skip_serializing_if = "is_default_trailing_gap_sectors"
    )]
    pub trailing_gap_sectors: u32,
    #[serde(
        default = "default_form2_edc",
        skip_serializing_if = "is_default_form2_edc"
    )]
    pub form2_edc: bool,
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
    trailing_gap_sectors: u32,
    form2_edc: bool,
}

#[derive(Serialize)]
struct Iso9660WithDefaults<'a> {
    primary_volume: PrimaryVolumeWithDefaults<'a>,
    entries: &'a [Entry],
    files: &'a [String],
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
        yaml_serde::to_string(&ManifestWithDefaults {
            track: TrackWithDefaults {
                mode: manifest.track.mode,
                start_msf: &manifest.track.start_msf,
                trailing_gap_sectors: manifest.track.trailing_gap_sectors,
                form2_edc: manifest.track.form2_edc,
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
                entries: &manifest.iso9660.entries,
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

fn default_trailing_gap_sectors() -> u32 {
    150
}

fn is_default_trailing_gap_sectors(value: &u32) -> bool {
    *value == 150
}

fn default_form2_edc() -> bool {
    true
}

fn is_default_form2_edc(value: &bool) -> bool {
    *value
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
    pub files: Vec<String>,
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
}

#[cfg(test)]
mod tests {
    use super::*;

    fn track(mode: TrackMode, start_msf: &str) -> Track {
        Track {
            mode,
            start_msf: start_msf.to_owned(),
            trailing_gap_sectors: 150,
            form2_edc: true,
        }
    }

    #[test]
    fn track_defaults_are_omitted_and_restored() {
        let yaml = yaml_serde::to_string(&track(TrackMode::Mode2Xa, "00:02:00")).unwrap();
        assert!(!yaml.lines().any(|line| line.starts_with("mode:")));
        assert!(!yaml.lines().any(|line| line.starts_with("start_msf:")));
        assert!(
            !yaml
                .lines()
                .any(|line| line.starts_with("trailing_gap_sectors:"))
        );
        assert!(!yaml.lines().any(|line| line.starts_with("form2_edc:")));
        assert!(!yaml.contains("raw_sector_size"));

        let parsed: Track = yaml_serde::from_str(&yaml).unwrap();
        assert_eq!(parsed.mode, TrackMode::Mode2Xa);
        assert_eq!(parsed.start_msf, "00:02:00");
        assert_eq!(parsed.trailing_gap_sectors, 150);
        assert!(parsed.form2_edc);
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
        track.trailing_gap_sectors = 151;
        let yaml = yaml_serde::to_string(&track).unwrap();
        assert!(yaml.lines().any(|line| line == "trailing_gap_sectors: 151"));
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
}

use std::fmt;

use anyhow::{Context, Result, bail, ensure};
use ecmlib::{Decoder, Encoder, Optimizations, SectorType};
use serde::de;
use serde::ser::SerializeSeq;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

pub const RAW_SECTOR_SIZE: usize = 2352;
pub const LOGICAL_BLOCK_SIZE: usize = 2048;
pub const SYNC: [u8; 12] = [
    0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00,
];

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct XaSubheader {
    #[serde(skip_serializing_if = "is_zero")]
    pub file_number: u8,
    #[serde(skip_serializing_if = "is_zero")]
    pub channel: u8,
    #[serde(skip_serializing_if = "XaSubmode::is_empty")]
    pub submode: XaSubmode,
    #[serde(skip_serializing_if = "is_zero")]
    pub coding_info: u8,
}

impl XaSubheader {
    pub const fn with_submode(submode: XaSubmode) -> Self {
        Self {
            file_number: 0,
            channel: 0,
            submode,
            coding_info: 0,
        }
    }
}

impl From<[u8; 4]> for XaSubheader {
    fn from(bytes: [u8; 4]) -> Self {
        Self {
            file_number: bytes[0],
            channel: bytes[1],
            submode: XaSubmode::from_bits(bytes[2]),
            coding_info: bytes[3],
        }
    }
}

impl From<XaSubheader> for [u8; 4] {
    fn from(subheader: XaSubheader) -> Self {
        [
            subheader.file_number,
            subheader.channel,
            subheader.submode.bits(),
            subheader.coding_info,
        ]
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct XaSubmode(u8);

impl XaSubmode {
    pub const END_OF_RECORD: Self = Self(1 << 0);
    pub const VIDEO: Self = Self(1 << 1);
    pub const AUDIO: Self = Self(1 << 2);
    pub const DATA: Self = Self(1 << 3);
    pub const TRIGGER: Self = Self(1 << 4);
    pub const FORM2: Self = Self(1 << 5);
    pub const REALTIME: Self = Self(1 << 6);
    pub const END_OF_FILE: Self = Self(1 << 7);

    pub const fn from_bits(bits: u8) -> Self {
        Self(bits)
    }

    pub const fn bits(self) -> u8 {
        self.0
    }

    pub const fn contains(self, flag: XaSubmodeFlag) -> bool {
        self.0 & flag.bit() != 0
    }

    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.0 == 0
    }
}

impl Serialize for XaSubmode {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut sequence = serializer.serialize_seq(Some(self.0.count_ones() as usize))?;
        for flag in XaSubmodeFlag::ALL {
            if self.contains(flag) {
                sequence.serialize_element(&flag)?;
            }
        }
        sequence.end()
    }
}

impl<'de> Deserialize<'de> for XaSubmode {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let flags = Vec::<XaSubmodeFlag>::deserialize(deserializer)?;
        let mut bits = 0_u8;
        for flag in flags {
            let bit = flag.bit();
            if bits & bit != 0 {
                return Err(de::Error::custom(format_args!(
                    "duplicate XA submode flag {flag}"
                )));
            }
            bits |= bit;
        }
        Ok(Self(bits))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
#[serde(rename_all = "snake_case")]
pub enum XaSubmodeFlag {
    EndOfRecord,
    Video,
    Audio,
    Data,
    Trigger,
    Form2,
    Realtime,
    EndOfFile,
}

impl XaSubmodeFlag {
    const ALL: [Self; 8] = [
        Self::EndOfRecord,
        Self::Video,
        Self::Audio,
        Self::Data,
        Self::Trigger,
        Self::Form2,
        Self::Realtime,
        Self::EndOfFile,
    ];

    const fn bit(self) -> u8 {
        match self {
            Self::EndOfRecord => XaSubmode::END_OF_RECORD.bits(),
            Self::Video => XaSubmode::VIDEO.bits(),
            Self::Audio => XaSubmode::AUDIO.bits(),
            Self::Data => XaSubmode::DATA.bits(),
            Self::Trigger => XaSubmode::TRIGGER.bits(),
            Self::Form2 => XaSubmode::FORM2.bits(),
            Self::Realtime => XaSubmode::REALTIME.bits(),
            Self::EndOfFile => XaSubmode::END_OF_FILE.bits(),
        }
    }
}

impl fmt::Display for XaSubmodeFlag {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EndOfRecord => formatter.write_str("end_of_record"),
            Self::Video => formatter.write_str("video"),
            Self::Audio => formatter.write_str("audio"),
            Self::Data => formatter.write_str("data"),
            Self::Trigger => formatter.write_str("trigger"),
            Self::Form2 => formatter.write_str("form2"),
            Self::Realtime => formatter.write_str("realtime"),
            Self::EndOfFile => formatter.write_str("end_of_file"),
        }
    }
}

const fn is_zero(value: &u8) -> bool {
    *value == 0
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Form1,
    Form2,
    XaGap,
}

#[derive(Debug, Clone)]
pub struct ParsedSector {
    pub bytes: [u8; RAW_SECTOR_SIZE],
    pub kind: Kind,
    pub subheader: XaSubheader,
}

impl ParsedSector {
    pub fn logical_block(&self) -> &[u8] {
        &self.bytes[24..24 + LOGICAL_BLOCK_SIZE]
    }

    pub fn payload(&self) -> &[u8] {
        match self.kind {
            Kind::Form1 => &self.bytes[24..2072],
            Kind::Form2 => &self.bytes[24..2348],
            Kind::XaGap => &self.bytes[24..2072],
        }
    }
}

pub fn parse_image(bytes: &[u8]) -> Result<(u32, Vec<ParsedSector>)> {
    ensure!(
        bytes.len().is_multiple_of(RAW_SECTOR_SIZE),
        "raw image size is not a multiple of 2352 bytes"
    );
    ensure!(!bytes.is_empty(), "raw image is empty");
    let first = &bytes[..RAW_SECTOR_SIZE];
    let start_frame = msf_to_frame([first[12], first[13], first[14]])?;
    let detector = Encoder::new(Optimizations::all());
    let mut sectors = Vec::with_capacity(bytes.len() / RAW_SECTOR_SIZE);

    for (index, chunk) in bytes.chunks_exact(RAW_SECTOR_SIZE).enumerate() {
        ensure!(chunk[..12] == SYNC, "invalid sync at sector {index}");
        ensure!(chunk[15] == 2, "unsupported sector mode at sector {index}");
        let expected = frame_to_msf(start_frame + u32::try_from(index)?)?;
        ensure!(
            chunk[12..15] == expected,
            "non-monotonic MSF at sector {index}"
        );
        ensure!(
            chunk[16..20] == chunk[20..24],
            "mismatched XA subheader copies at sector {index}"
        );
        let detected = detector
            .detect_sector_type(chunk)
            .with_context(|| format!("detecting sector type at sector {index}"))?;
        let subheader_bytes: [u8; 4] = chunk[16..20].try_into()?;
        let subheader = XaSubheader::from(subheader_bytes);
        let kind = match detected {
            SectorType::Mode2Xa1 | SectorType::Mode2Xa1Gap => Kind::Form1,
            SectorType::Mode2Xa2 | SectorType::Mode2Xa2Gap => Kind::Form2,
            SectorType::Mode2Gap | SectorType::Mode2XaGap
                if subheader.submode.contains(XaSubmodeFlag::Form2) =>
            {
                Kind::Form2
            }
            SectorType::Mode2Gap | SectorType::Mode2XaGap => Kind::XaGap,
            other => bail!("unsupported or invalid sector type {other:?} at sector {index}"),
        };
        let mut sector = [0_u8; RAW_SECTOR_SIZE];
        sector.copy_from_slice(chunk);
        sectors.push(ParsedSector {
            bytes: sector,
            kind,
            subheader,
        });
    }
    Ok((start_frame, sectors))
}

pub struct SectorWriter {
    standard: Decoder,
    gap: Decoder,
}

impl SectorWriter {
    pub fn new() -> Self {
        Self {
            standard: Decoder::new(),
            gap: Decoder::new(),
        }
    }

    pub fn form1(&mut self, frame: u32, subheader: XaSubheader, data: &[u8]) -> Result<Vec<u8>> {
        ensure!(data.len() == 2048, "Form 1 payload must be 2048 bytes");
        let mut compact = Vec::with_capacity(2052);
        compact.extend_from_slice(&<[u8; 4]>::from(subheader));
        compact.extend_from_slice(data);
        self.standard
            .decode_sector(&compact, SectorType::Mode2Xa1, frame, Optimizations::all())
            .context("generating Form 1 sector")
    }

    pub fn form2(
        &mut self,
        frame: u32,
        subheader: XaSubheader,
        data: &[u8],
        computed_edc: bool,
    ) -> Result<Vec<u8>> {
        ensure!(data.len() == 2324, "Form 2 payload must be 2324 bytes");
        let mut compact = Vec::with_capacity(2332);
        compact.extend_from_slice(&<[u8; 4]>::from(subheader));
        compact.extend_from_slice(data);
        let mut optimizations = Optimizations::all();
        if !computed_edc {
            optimizations.remove(Optimizations::RemoveEDC);
            compact.extend_from_slice(&[0; 4]);
        }
        self.standard
            .decode_sector(&compact, SectorType::Mode2Xa2, frame, optimizations)
            .context("generating Form 2 sector")
    }

    pub fn xa_gap(&mut self, frame: u32, subheader: XaSubheader) -> Result<Vec<u8>> {
        let subheader = <[u8; 4]>::from(subheader);
        self.gap
            .decode_sector(
                &subheader,
                SectorType::Mode2XaGap,
                frame,
                Optimizations::all(),
            )
            .context("generating XA gap sector")
    }
}

pub fn msf_to_frame(msf: [u8; 3]) -> Result<u32> {
    let minute = from_bcd(msf[0])?;
    let second = from_bcd(msf[1])?;
    let frame = from_bcd(msf[2])?;
    ensure!(second < 60 && frame < 75, "invalid MSF value");
    Ok(u32::from(minute) * 60 * 75 + u32::from(second) * 75 + u32::from(frame))
}

pub fn frame_to_msf(value: u32) -> Result<[u8; 3]> {
    let minute = value / (60 * 75);
    ensure!(minute <= 99, "MSF exceeds two-digit BCD range");
    let second = value / 75 % 60;
    let frame = value % 75;
    Ok([
        to_bcd(minute as u8),
        to_bcd(second as u8),
        to_bcd(frame as u8),
    ])
}

pub fn format_msf(frame: u32) -> Result<String> {
    let value = frame_to_msf(frame)?;
    Ok(format!(
        "{:02x}:{:02x}:{:02x}",
        value[0], value[1], value[2]
    ))
}

pub fn parse_msf(value: &str) -> Result<u32> {
    let parts = value
        .split(':')
        .map(|part| u8::from_str_radix(part, 16).context("invalid MSF component"))
        .collect::<Result<Vec<_>>>()?;
    ensure!(parts.len() == 3, "MSF must have MM:SS:FF form");
    msf_to_frame([parts[0], parts[1], parts[2]])
}

fn from_bcd(value: u8) -> Result<u8> {
    let high = value >> 4;
    let low = value & 0x0f;
    ensure!(high <= 9 && low <= 9, "invalid BCD value {value:02x}");
    Ok(high * 10 + low)
}

const fn to_bcd(value: u8) -> u8 {
    ((value / 10) << 4) | (value % 10)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xa_subheader_maps_named_fields_to_exact_bytes() {
        let subheader = XaSubheader::from([7, 8, 0x89, 10]);
        assert_eq!(subheader.file_number, 7);
        assert_eq!(subheader.channel, 8);
        assert_eq!(subheader.submode.bits(), 0x89);
        assert_eq!(subheader.coding_info, 10);
        assert_eq!(<[u8; 4]>::from(subheader), [7, 8, 0x89, 10]);
    }

    #[test]
    fn all_xa_submode_bitmasks_round_trip_through_named_flags() {
        for bits in 0..=u8::MAX {
            let yaml = yaml_serde::to_string(&XaSubmode::from_bits(bits)).unwrap();
            let parsed: XaSubmode = yaml_serde::from_str(&yaml).unwrap();
            assert_eq!(parsed.bits(), bits);
        }
    }

    #[test]
    fn xa_submode_serializes_flags_in_bit_order() {
        let yaml = yaml_serde::to_string(&XaSubmode::from_bits(u8::MAX)).unwrap();
        assert_eq!(
            yaml.lines().collect::<Vec<_>>(),
            [
                "- end_of_record",
                "- video",
                "- audio",
                "- data",
                "- trigger",
                "- form2",
                "- realtime",
                "- end_of_file",
            ]
        );

        let reordered: XaSubmode =
            yaml_serde::from_str("- end_of_file\n- data\n- end_of_record\n").unwrap();
        let canonical = yaml_serde::to_string(&reordered).unwrap();
        assert_eq!(
            canonical.lines().collect::<Vec<_>>(),
            ["- end_of_record", "- data", "- end_of_file"]
        );
    }

    #[test]
    fn xa_submode_rejects_duplicates_unknown_names_and_numeric_values() {
        let duplicate = yaml_serde::from_str::<XaSubmode>("- data\n- data\n").unwrap_err();
        assert!(
            duplicate
                .to_string()
                .contains("duplicate XA submode flag data")
        );
        assert!(yaml_serde::from_str::<XaSubmode>("- unknown\n").is_err());
        assert!(yaml_serde::from_str::<XaSubmode>("8\n").is_err());
    }

    #[test]
    fn xa_subheader_rejects_legacy_byte_array() {
        assert!(yaml_serde::from_str::<XaSubheader>("- 0\n- 0\n- 8\n- 0\n").is_err());
    }

    #[test]
    fn msf_crosses_frame_and_second_boundaries() {
        assert_eq!(frame_to_msf(150).unwrap(), [0x00, 0x02, 0x00]);
        assert_eq!(frame_to_msf(224).unwrap(), [0x00, 0x02, 0x74]);
        assert_eq!(frame_to_msf(225).unwrap(), [0x00, 0x03, 0x00]);
        assert_eq!(msf_to_frame([0x01, 0x00, 0x00]).unwrap(), 4500);
    }

    #[test]
    fn generated_form2_zero_payload_has_nonzero_edc() {
        let mut writer = SectorWriter::new();
        let sector = writer
            .form2(162, [0, 0, 0x20, 0].into(), &[0; 2324], true)
            .unwrap();
        assert_eq!(&sector[2348..2352], &[0x3f, 0x13, 0xb0, 0xbe]);
    }

    #[test]
    fn completely_zeroed_mode2_tail_is_an_xa_gap() {
        let mut writer = SectorWriter::new();
        let raw = writer.xa_gap(150, XaSubheader::default()).unwrap();
        let (_, parsed) = parse_image(&raw).unwrap();
        assert_eq!(parsed[0].kind, Kind::XaGap);
    }

    #[test]
    fn zero_edc_form2_is_classified_from_the_form_bit() {
        let mut writer = SectorWriter::new();
        let raw = writer
            .form2(150, [0, 0, 0x20, 0].into(), &[0; 2324], false)
            .unwrap();
        let (_, parsed) = parse_image(&raw).unwrap();
        assert_eq!(parsed[0].kind, Kind::Form2);
    }
}

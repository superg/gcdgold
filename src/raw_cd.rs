use std::fmt;

use anyhow::{Context, Result, bail, ensure};
use crc::{CRC_32_CD_ROM_EDC, Crc};
use rayon::prelude::*;
use serde::de;
use serde::ser::SerializeSeq;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

pub const RAW_SECTOR_SIZE: usize = 2352;
pub const LOGICAL_BLOCK_SIZE: usize = 2048;
pub const MODE2_DATA_SIZE: usize = 2336;
const CD_ROM_EDC: Crc<u32> = Crc::<u32>::new(&CRC_32_CD_ROM_EDC);
const ECC_TABLES: EccTables = make_ecc_tables();
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
    Mode1,
    Mode1Gap,
    Form1,
    Form2,
    XaGap,
    RawZero,
}

#[derive(Debug, Clone)]
pub struct ParsedSector {
    pub bytes: [u8; RAW_SECTOR_SIZE],
    pub kind: Kind,
    pub subheader: XaSubheader,
    pub subheader_copy: XaSubheader,
    pub form2_edc_valid: bool,
    pub noncompliant_ecc: bool,
}

impl ParsedSector {
    pub fn logical_block(&self) -> &[u8] {
        match self.kind {
            Kind::Mode1 | Kind::Mode1Gap => &self.bytes[16..16 + LOGICAL_BLOCK_SIZE],
            Kind::Form1 | Kind::Form2 | Kind::XaGap | Kind::RawZero => {
                &self.bytes[24..24 + LOGICAL_BLOCK_SIZE]
            }
        }
    }

    pub fn payload(&self) -> &[u8] {
        match self.kind {
            Kind::Mode1 | Kind::Mode1Gap => &self.bytes[16..2064],
            Kind::Form1 => &self.bytes[24..2072],
            Kind::Form2 => &self.bytes[24..2348],
            Kind::XaGap => &self.bytes[24..2072],
            Kind::RawZero => &self.bytes[24..2072],
        }
    }
}

pub fn parse_image(bytes: &[u8]) -> Result<(u32, Vec<ParsedSector>)> {
    ensure!(
        bytes.len().is_multiple_of(RAW_SECTOR_SIZE),
        "raw image size is not a multiple of 2352 bytes"
    );
    ensure!(!bytes.is_empty(), "raw image is empty");
    let first_nonzero_sector = bytes
        .chunks_exact(RAW_SECTOR_SIZE)
        .position(|chunk| chunk.iter().any(|byte| *byte != 0))
        .context("raw image contains only all-zero sectors")?;
    let first_start = first_nonzero_sector * RAW_SECTOR_SIZE;
    let first = &bytes[first_start..first_start + RAW_SECTOR_SIZE];
    let track_mode = first[15];
    ensure!(
        matches!(track_mode, 1 | 2),
        "unsupported sector mode at sector {first_nonzero_sector}"
    );
    let first_frame = msf_to_frame([first[12], first[13], first[14]])?;
    let start_frame = first_frame
        .checked_sub(u32::try_from(first_nonzero_sector)?)
        .context("leading raw-zero sectors precede MSF 00:00:00")?;
    let last_nonzero_sector = bytes
        .chunks_exact(RAW_SECTOR_SIZE)
        .rposition(|chunk| chunk.iter().any(|byte| *byte != 0))
        .expect("validated first sector is nonzero");
    let classifications = bytes
        .par_chunks_exact(RAW_SECTOR_SIZE)
        .enumerate()
        .map(|(index, chunk)| {
            classify_sector(
                chunk,
                index,
                track_mode,
                start_frame,
                first_nonzero_sector,
                last_nonzero_sector,
            )
        })
        .collect::<Vec<_>>()
        .into_iter()
        .collect::<Result<Vec<_>>>()?;
    let sectors = bytes
        .par_chunks_exact(RAW_SECTOR_SIZE)
        .zip(classifications.into_par_iter())
        .map(|(chunk, classification)| {
            let mut sector = [0_u8; RAW_SECTOR_SIZE];
            sector.copy_from_slice(chunk);
            ParsedSector {
                bytes: sector,
                kind: classification.kind,
                subheader: classification.subheader,
                subheader_copy: classification.subheader_copy,
                form2_edc_valid: classification.form2_edc_valid,
                noncompliant_ecc: classification.noncompliant_ecc,
            }
        })
        .collect();
    Ok((start_frame, sectors))
}

#[derive(Clone, Copy)]
struct SectorClassification {
    kind: Kind,
    subheader: XaSubheader,
    subheader_copy: XaSubheader,
    form2_edc_valid: bool,
    noncompliant_ecc: bool,
}

fn classify_sector(
    chunk: &[u8],
    index: usize,
    track_mode: u8,
    start_frame: u32,
    first_nonzero_sector: usize,
    last_nonzero_sector: usize,
) -> Result<SectorClassification> {
    if chunk.iter().all(|byte| *byte == 0) {
        ensure!(
            index < first_nonzero_sector || index > last_nonzero_sector,
            "all-zero raw sectors are supported only as boundary runs"
        );
        return Ok(SectorClassification {
            kind: Kind::RawZero,
            subheader: XaSubheader::default(),
            subheader_copy: XaSubheader::default(),
            form2_edc_valid: false,
            noncompliant_ecc: false,
        });
    }
    ensure!(chunk[..12] == SYNC, "invalid sync at sector {index}");
    let sector_mode = chunk[15];
    ensure!(
        sector_mode == track_mode || (track_mode == 2 && sector_mode == 1),
        "mixed or unsupported sector mode at sector {index}"
    );
    let expected = frame_to_msf(start_frame + u32::try_from(index)?)?;
    ensure!(
        chunk[12..15] == expected,
        "non-monotonic MSF at sector {index}"
    );
    if sector_mode == 1 {
        ensure!(
            edc_matches(&chunk[..2064], &chunk[2064..2068]),
            "invalid Mode 1 EDC at sector {index}"
        );
        ensure!(
            ecc_matches(chunk, chunk[12..16].try_into()?),
            "invalid Mode 1 ECC at sector {index}"
        );
        let kind = if chunk[16..2064].iter().all(|byte| *byte == 0) {
            Kind::Mode1Gap
        } else {
            Kind::Mode1
        };
        ensure!(
            track_mode == 1 || kind == Kind::Mode1Gap,
            "non-gap Mode 1 sector in Mode 2 track at sector {index}"
        );
        return Ok(SectorClassification {
            kind,
            subheader: XaSubheader::default(),
            subheader_copy: XaSubheader::default(),
            form2_edc_valid: false,
            noncompliant_ecc: false,
        });
    }
    let subheader_bytes: [u8; 4] = chunk[16..20].try_into()?;
    let subheader = XaSubheader::from(subheader_bytes);
    let subheader_copy = XaSubheader::from(<[u8; 4]>::try_from(&chunk[20..24])?);
    let form2 = subheader.submode.contains(XaSubmodeFlag::Form2);
    let form2_edc_valid = form2 && edc_matches(&chunk[16..2348], &chunk[2348..2352]);
    let (kind, noncompliant_ecc) = if form2 {
        (Kind::Form2, false)
    } else if chunk[16..].iter().all(|byte| *byte == 0)
        || (chunk[16..20] == chunk[20..24] && chunk[24..].iter().all(|byte| *byte == 0))
    {
        (Kind::XaGap, false)
    } else if edc_matches(&chunk[16..2072], &chunk[2072..2076]) && ecc_matches(chunk, [0; 4]) {
        (Kind::Form1, false)
    } else if !edc_matches(&chunk[16..2348], &chunk[2348..2352])
        && recorded_header_ecc_matches(chunk)
    {
        (Kind::XaGap, true)
    } else {
        bail!("unsupported or invalid Mode 2 sector at sector {index}")
    };
    Ok(SectorClassification {
        kind,
        subheader,
        subheader_copy,
        form2_edc_valid,
        noncompliant_ecc,
    })
}

pub struct SectorWriter;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SectorProtection {
    None,
    Mode1,
    Mode2Form1,
    Mode2Form2 { computed_edc: bool },
    RecordedHeaderEcc,
}

impl SectorWriter {
    pub const fn new() -> Self {
        Self
    }

    pub fn mode1(&mut self, frame: u32, data: &[u8]) -> Result<Vec<u8>> {
        let mut sector = self.mode1_draft(frame, data)?;
        finalize_sector_protection(&mut sector, SectorProtection::Mode1)?;
        Ok(sector)
    }

    pub(crate) fn mode1_draft(&mut self, frame: u32, data: &[u8]) -> Result<Vec<u8>> {
        ensure!(
            data.len() == LOGICAL_BLOCK_SIZE,
            "Mode 1 payload must be 2048 bytes"
        );
        let mut sector = initialized_sector(frame, 1)?;
        sector[16..2064].copy_from_slice(data);
        Ok(sector)
    }

    pub fn form1(&mut self, frame: u32, subheader: XaSubheader, data: &[u8]) -> Result<Vec<u8>> {
        self.form1_with_subheaders(frame, subheader, subheader, data)
    }

    pub fn form1_with_subheaders(
        &mut self,
        frame: u32,
        subheader: XaSubheader,
        subheader_copy: XaSubheader,
        data: &[u8],
    ) -> Result<Vec<u8>> {
        let mut sector =
            self.form1_with_subheaders_draft(frame, subheader, subheader_copy, data)?;
        finalize_sector_protection(&mut sector, SectorProtection::Mode2Form1)?;
        Ok(sector)
    }

    pub(crate) fn form1_draft(
        &mut self,
        frame: u32,
        subheader: XaSubheader,
        data: &[u8],
    ) -> Result<Vec<u8>> {
        self.form1_with_subheaders_draft(frame, subheader, subheader, data)
    }

    pub(crate) fn form1_with_subheaders_draft(
        &mut self,
        frame: u32,
        subheader: XaSubheader,
        subheader_copy: XaSubheader,
        data: &[u8],
    ) -> Result<Vec<u8>> {
        ensure!(data.len() == 2048, "Form 1 payload must be 2048 bytes");
        let mut sector = initialized_sector(frame, 2)?;
        sector[16..20].copy_from_slice(&<[u8; 4]>::from(subheader));
        sector[20..24].copy_from_slice(&<[u8; 4]>::from(subheader_copy));
        sector[24..2072].copy_from_slice(data);
        Ok(sector)
    }

    pub fn form2(
        &mut self,
        frame: u32,
        subheader: XaSubheader,
        data: &[u8],
        computed_edc: bool,
    ) -> Result<Vec<u8>> {
        self.form2_with_subheaders(frame, subheader, subheader, data, computed_edc)
    }

    pub fn form2_with_subheaders(
        &mut self,
        frame: u32,
        subheader: XaSubheader,
        subheader_copy: XaSubheader,
        data: &[u8],
        computed_edc: bool,
    ) -> Result<Vec<u8>> {
        let mut sector =
            self.form2_with_subheaders_draft(frame, subheader, subheader_copy, data)?;
        finalize_sector_protection(&mut sector, SectorProtection::Mode2Form2 { computed_edc })?;
        Ok(sector)
    }

    pub(crate) fn form2_draft(
        &mut self,
        frame: u32,
        subheader: XaSubheader,
        data: &[u8],
    ) -> Result<Vec<u8>> {
        self.form2_with_subheaders_draft(frame, subheader, subheader, data)
    }

    pub(crate) fn form2_with_subheaders_draft(
        &mut self,
        frame: u32,
        subheader: XaSubheader,
        subheader_copy: XaSubheader,
        data: &[u8],
    ) -> Result<Vec<u8>> {
        ensure!(data.len() == 2324, "Form 2 payload must be 2324 bytes");
        let mut sector = initialized_sector(frame, 2)?;
        sector[16..20].copy_from_slice(&<[u8; 4]>::from(subheader));
        sector[20..24].copy_from_slice(&<[u8; 4]>::from(subheader_copy));
        sector[24..2348].copy_from_slice(data);
        Ok(sector)
    }

    pub fn xa_gap(&mut self, frame: u32, subheader: XaSubheader) -> Result<Vec<u8>> {
        let subheader = <[u8; 4]>::from(subheader);
        let mut sector = initialized_sector(frame, 2)?;
        sector[16..20].copy_from_slice(&subheader);
        sector[20..24].copy_from_slice(&subheader);
        Ok(sector)
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub fn xa_gap_with_recorded_header_ecc(
        &mut self,
        frame: u32,
        subheader: XaSubheader,
    ) -> Result<Vec<u8>> {
        let mut sector = self.xa_gap(frame, subheader)?;
        finalize_sector_protection(&mut sector, SectorProtection::RecordedHeaderEcc)?;
        Ok(sector)
    }
}

pub(crate) fn finalize_sector_protection(
    sector: &mut [u8],
    protection: SectorProtection,
) -> Result<()> {
    ensure!(
        sector.len() == RAW_SECTOR_SIZE,
        "raw sector must be 2352 bytes"
    );
    match protection {
        SectorProtection::None => {}
        SectorProtection::Mode1 => {
            ensure!(sector[15] == 1, "Mode 1 protection requires sector mode 1");
            let edc = generate_edc(&sector[..2064]).to_le_bytes();
            sector[2064..2068].copy_from_slice(&edc);
            write_ecc(sector, sector[12..16].try_into()?);
        }
        SectorProtection::Mode2Form1 => {
            ensure!(
                regenerate_mode2_protection(sector, true, false)? == Kind::Form1,
                "Form 1 protection requires a non-Form-2 subheader"
            );
        }
        SectorProtection::Mode2Form2 { computed_edc } => {
            ensure!(
                regenerate_mode2_protection(sector, computed_edc, false)? == Kind::Form2,
                "Form 2 protection requires a Form 2 subheader"
            );
        }
        SectorProtection::RecordedHeaderEcc => {
            ensure!(
                regenerate_mode2_protection(sector, false, true)? == Kind::XaGap,
                "recorded-header ECC requires a non-Form-2 subheader"
            );
        }
    }
    Ok(())
}

fn frame_header(frame: u32, mode: u8) -> Result<[u8; 4]> {
    let [minute, second, frame] = frame_to_msf(frame)?;
    Ok([minute, second, frame, mode])
}

fn initialized_sector(frame: u32, mode: u8) -> Result<Vec<u8>> {
    let mut sector = vec![0; RAW_SECTOR_SIZE];
    sector[..12].copy_from_slice(&SYNC);
    sector[12..16].copy_from_slice(&frame_header(frame, mode)?);
    Ok(sector)
}

fn recorded_header_ecc_matches(sector: &[u8]) -> bool {
    if sector.len() != RAW_SECTOR_SIZE || sector[16..2076].iter().any(|byte| *byte != 0) {
        return false;
    }
    ecc_matches(
        sector,
        sector[12..16].try_into().expect("four-byte CD header"),
    )
}

pub(crate) fn regenerate_mode2_protection(
    sector: &mut [u8],
    form2_edc: bool,
    recorded_header_ecc: bool,
) -> Result<Kind> {
    ensure!(
        sector.len() == RAW_SECTOR_SIZE,
        "raw sector must be 2352 bytes"
    );
    ensure!(
        sector[15] == 2,
        "unsupported patched sector mode {}",
        sector[15]
    );
    let primary = XaSubheader::from(<[u8; 4]>::try_from(&sector[16..20])?);
    if primary.submode.contains(XaSubmodeFlag::Form2) {
        let edc = if form2_edc {
            generate_edc(&sector[16..2348]).to_le_bytes()
        } else {
            [0; 4]
        };
        sector[2348..2352].copy_from_slice(&edc);
        return Ok(Kind::Form2);
    }

    if recorded_header_ecc {
        sector[2072..2076].fill(0);
        write_recorded_header_ecc(sector);
        return Ok(Kind::XaGap);
    }

    let edc = generate_edc(&sector[16..2072]).to_le_bytes();
    sector[2072..2076].copy_from_slice(&edc);
    write_standard_form1_ecc(sector);
    Ok(Kind::Form1)
}

fn generate_edc(data: &[u8]) -> u32 {
    CD_ROM_EDC.checksum(data)
}

fn edc_matches(data: &[u8], stored: &[u8]) -> bool {
    generate_edc(data).to_le_bytes() == stored
}

fn write_standard_form1_ecc(sector: &mut [u8]) {
    write_ecc(sector, [0; 4]);
}

fn write_recorded_header_ecc(sector: &mut [u8]) {
    debug_assert_eq!(sector.len(), RAW_SECTOR_SIZE);
    let address: [u8; 4] = sector[12..16].try_into().expect("four-byte CD header");
    write_ecc(sector, address);
}

fn write_ecc(sector: &mut [u8], address: [u8; 4]) {
    {
        let (data, parity) = sector.split_at_mut(2076);
        generate_ecc_p(
            &address,
            data[16..].try_into().expect("fixed-size P source region"),
            (&mut parity[..172])
                .try_into()
                .expect("fixed-size P parity region"),
        );
    }
    let (data, parity) = sector.split_at_mut(2248);
    generate_ecc_q(
        &address,
        data[16..].try_into().expect("fixed-size Q source region"),
        parity.try_into().expect("fixed-size Q parity region"),
    );
}

fn ecc_matches(sector: &[u8], address: [u8; 4]) -> bool {
    let mut p = [0_u8; 172];
    generate_ecc_p(
        &address,
        sector[16..2076]
            .try_into()
            .expect("fixed-size P source region"),
        &mut p,
    );
    if p != sector[2076..2248] {
        return false;
    }
    let mut q = [0_u8; 104];
    generate_ecc_q(
        &address,
        sector[16..2248]
            .try_into()
            .expect("fixed-size Q source region"),
        &mut q,
    );
    q == sector[2248..2352]
}

fn generate_ecc_p(address: &[u8; 4], data: &[u8; 2060], ecc: &mut [u8; 172]) {
    generate_ecc::<2060, 172, 86, 24, 2, 86>(address, data, ecc);
}

fn generate_ecc_q(address: &[u8; 4], data: &[u8; 2232], ecc: &mut [u8; 104]) {
    generate_ecc::<2232, 104, 52, 43, 86, 88>(address, data, ecc);
}

fn generate_ecc<
    const DATA_LEN: usize,
    const ECC_LEN: usize,
    const MAJOR_COUNT: usize,
    const MINOR_COUNT: usize,
    const MAJOR_MULT: usize,
    const MINOR_INC: usize,
>(
    address: &[u8; 4],
    data: &[u8; DATA_LEN],
    ecc: &mut [u8; ECC_LEN],
) {
    const ADDRESS_LEN: usize = 4;
    debug_assert_eq!(DATA_LEN + ADDRESS_LEN, MAJOR_COUNT * MINOR_COUNT);
    debug_assert_eq!(ECC_LEN, MAJOR_COUNT * 2);

    let size = MAJOR_COUNT * MINOR_COUNT;
    for major in 0..MAJOR_COUNT {
        let mut index = (major >> 1) * MAJOR_MULT + (major & 1);
        let mut ecc_a = 0_u8;
        let mut ecc_b = 0_u8;
        for _ in 0..MINOR_COUNT {
            let value = if index < ADDRESS_LEN {
                address[index]
            } else {
                data[index - ADDRESS_LEN]
            };
            index += MINOR_INC;
            if index >= size {
                index -= size;
            }
            ecc_b ^= value;
            ecc_a = ECC_TABLES.forward[usize::from(ecc_a ^ value)];
        }
        ecc_a = ECC_TABLES.backward[usize::from(ECC_TABLES.forward[usize::from(ecc_a)] ^ ecc_b)];
        ecc[major] = ecc_a;
        ecc[major + MAJOR_COUNT] = ecc_a ^ ecc_b;
    }
}

struct EccTables {
    forward: [u8; 256],
    backward: [u8; 256],
}

const fn make_ecc_tables() -> EccTables {
    let mut forward = [0_u8; 256];
    let mut backward = [0_u8; 256];
    let mut index = 0;
    while index < 256 {
        let next = ((index << 1) ^ if index & 0x80 != 0 { 0x11d } else { 0 }) & 0xff;
        forward[index] = next as u8;
        backward[index ^ next] = index as u8;
        index += 1;
    }
    EccTables { forward, backward }
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
        let (_, parsed) = parse_image(&sector).unwrap();
        assert!(parsed[0].form2_edc_valid);
    }

    #[test]
    fn canonical_mode1_sector_exposes_its_logical_block() {
        let payload = [0x5a; LOGICAL_BLOCK_SIZE];
        let raw = SectorWriter::new().mode1(150, &payload).unwrap();

        let (start_frame, parsed) = parse_image(&raw).unwrap();

        assert_eq!(start_frame, 150);
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].kind, Kind::Mode1);
        assert_eq!(parsed[0].logical_block(), payload);
        assert_eq!(parsed[0].payload(), payload);
    }

    #[test]
    fn canonical_zero_payload_mode1_sector_is_a_mode1_gap() {
        let raw = SectorWriter::new()
            .mode1(150, &[0; LOGICAL_BLOCK_SIZE])
            .unwrap();

        let (_, parsed) = parse_image(&raw).unwrap();

        assert_eq!(parsed[0].kind, Kind::Mode1Gap);
        assert!(parsed[0].payload().iter().all(|byte| *byte == 0));
    }

    #[test]
    fn terminal_all_zero_raw_sector_is_bounded() {
        let mut raw = SectorWriter::new()
            .form2(150, [0, 0, 0x20, 0].into(), &[0; 2324], true)
            .unwrap();
        raw.extend_from_slice(&[0; RAW_SECTOR_SIZE]);

        let (start_frame, parsed) = parse_image(&raw).unwrap();

        assert_eq!(start_frame, 150);
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[1].bytes, [0; RAW_SECTOR_SIZE]);
    }

    #[test]
    fn leading_all_zero_raw_run_backtracks_the_framed_start_msf() {
        let mut raw = vec![0; 2 * RAW_SECTOR_SIZE];
        raw.extend(
            SectorWriter::new()
                .form1(152, XaSubheader::with_submode(XaSubmode::DATA), &[7; 2048])
                .unwrap(),
        );

        let (start_frame, parsed) = parse_image(&raw).unwrap();

        assert_eq!(start_frame, 150);
        assert_eq!(parsed[0].kind, Kind::RawZero);
        assert_eq!(parsed[1].kind, Kind::RawZero);
        assert_eq!(parsed[2].kind, Kind::Form1);
    }

    #[test]
    fn parallel_parse_preserves_order_and_reports_the_first_error() {
        let mut writer = SectorWriter::new();
        let mut raw = Vec::new();
        for index in 0..8_u32 {
            raw.extend_from_slice(
                &writer
                    .mode1(150 + index, &[index as u8; LOGICAL_BLOCK_SIZE])
                    .unwrap(),
            );
        }
        let (_, parsed) = parse_image(&raw).unwrap();
        assert_eq!(
            parsed
                .iter()
                .map(|sector| sector.payload()[0])
                .collect::<Vec<_>>(),
            (0..8).collect::<Vec<_>>()
        );

        raw[2 * RAW_SECTOR_SIZE + 2076] ^= 1;
        raw[6 * RAW_SECTOR_SIZE + 2064] ^= 1;
        assert_eq!(
            parse_image(&raw).unwrap_err().to_string(),
            "invalid Mode 1 ECC at sector 2"
        );
    }

    #[test]
    fn parallel_parse_rejects_the_first_nonterminal_raw_zero_sector() {
        let mut writer = SectorWriter::new();
        let mut raw = writer
            .form2(150, [0, 0, 0x20, 0].into(), &[0; 2324], true)
            .unwrap();
        raw.extend_from_slice(&[0; RAW_SECTOR_SIZE]);
        raw.extend_from_slice(
            &writer
                .form2(152, [0, 0, 0x20, 0].into(), &[0; 2324], true)
                .unwrap(),
        );
        assert_eq!(
            parse_image(&raw).unwrap_err().to_string(),
            "all-zero raw sectors are supported only as boundary runs"
        );
    }

    #[test]
    fn completely_zeroed_mode2_tail_is_an_xa_gap() {
        let mut writer = SectorWriter::new();
        let raw = writer.xa_gap(150, XaSubheader::default()).unwrap();
        let (_, parsed) = parse_image(&raw).unwrap();
        assert_eq!(parsed[0].kind, Kind::XaGap);
        assert!(!parsed[0].noncompliant_ecc);
    }

    #[test]
    fn zero_edc_form2_is_classified_from_the_form_bit() {
        let mut writer = SectorWriter::new();
        let raw = writer
            .form2(150, [0, 0, 0x20, 0].into(), &[0; 2324], false)
            .unwrap();
        let (_, parsed) = parse_image(&raw).unwrap();
        assert_eq!(parsed[0].kind, Kind::Form2);
        assert!(!parsed[0].form2_edc_valid);
    }

    #[test]
    fn zero_edc_nonzero_form2_payload_is_classified_from_the_form_bit() {
        let raw = SectorWriter::new()
            .form2(1_114, [1, 2, 0x24, 3].into(), &[0x5a; 2324], false)
            .unwrap();

        let (_, sectors) = parse_image(&raw).unwrap();
        assert_eq!(sectors[0].kind, Kind::Form2);
        assert!(!sectors[0].form2_edc_valid);
        assert_eq!(&sectors[0].bytes[2348..2352], &[0; 4]);
        assert!(sectors[0].payload().iter().any(|byte| *byte != 0));
    }

    #[test]
    fn primary_subheader_classifies_sectors_when_the_duplicate_differs() {
        let mut writer = SectorWriter::new();
        let form2 = writer
            .form2_with_subheaders(
                13_486,
                [0x01, 0x03, 0xe2, 0x18].into(),
                [0x01, 0x19, 0xb2, 0xad].into(),
                &[0x5a; 2324],
                false,
            )
            .unwrap();
        let (_, sectors) = parse_image(&form2).unwrap();
        assert_eq!(sectors[0].kind, Kind::Form2);
        assert_eq!(sectors[0].subheader, [0x01, 0x03, 0xe2, 0x18].into());
        assert_eq!(sectors[0].subheader_copy, [0x01, 0x19, 0xb2, 0xad].into());
        assert!(!sectors[0].form2_edc_valid);

        let form1 = writer
            .form1_with_subheaders(
                13_487,
                [0x01, 0x0f, 0xd3, 0xeb].into(),
                [0x01, 0x0d, 0x9d, 0x23].into(),
                &[0xa5; LOGICAL_BLOCK_SIZE],
            )
            .unwrap();
        let (_, sectors) = parse_image(&form1).unwrap();
        assert_eq!(sectors[0].kind, Kind::Form1);
        assert_eq!(sectors[0].subheader, [0x01, 0x0f, 0xd3, 0xeb].into());
        assert_eq!(sectors[0].subheader_copy, [0x01, 0x0d, 0x9d, 0x23].into());
    }

    #[test]
    fn duplicate_subheader_overlay_precedes_form1_protection_generation() {
        let source = SectorWriter::new()
            .form1_with_subheaders(
                13_487,
                [0x01, 0x0f, 0xd3, 0xeb].into(),
                [0x01, 0x0d, 0x9d, 0x23].into(),
                &[0xa5; LOGICAL_BLOCK_SIZE],
            )
            .unwrap();
        let mut canonical = source.clone();
        canonical[20..24].copy_from_slice(&source[16..20]);
        regenerate_mode2_protection(&mut canonical, false, false).unwrap();
        assert_ne!(canonical, source);
        assert_eq!(canonical[16..20], canonical[20..24]);

        canonical[20..24].copy_from_slice(&source[20..24]);
        regenerate_mode2_protection(&mut canonical, false, false).unwrap();
        assert_eq!(canonical, source);
    }

    #[test]
    fn duplicate_subheader_overlay_precedes_zero_form2_edc_generation() {
        let source = SectorWriter::new()
            .form2_with_subheaders(
                13_486,
                [0x01, 0x03, 0xe2, 0x18].into(),
                [0x01, 0x19, 0xb2, 0xad].into(),
                &[0x5a; 2324],
                false,
            )
            .unwrap();
        let mut canonical = source.clone();
        canonical[20..24].copy_from_slice(&source[16..20]);
        regenerate_mode2_protection(&mut canonical, false, false).unwrap();
        assert_ne!(canonical, source);
        assert_eq!(&canonical[2348..2352], &[0; 4]);

        canonical[20..24].copy_from_slice(&source[20..24]);
        regenerate_mode2_protection(&mut canonical, false, false).unwrap();
        assert_eq!(canonical, source);
    }

    #[test]
    fn sector_writer_preserves_distinct_subheader_copies_before_protection() {
        let mut writer = SectorWriter::new();
        let primary: XaSubheader = [1, 2, 0x08, 4].into();
        let duplicate: XaSubheader = [5, 6, 0x28, 8].into();
        let form1 = writer
            .form1_with_subheaders(150, primary, duplicate, &[0x11; LOGICAL_BLOCK_SIZE])
            .unwrap();
        assert_eq!(&form1[16..20], &[1, 2, 0x08, 4]);
        assert_eq!(&form1[20..24], &[5, 6, 0x28, 8]);
        let (_, parsed) = parse_image(&form1).unwrap();
        assert_eq!(parsed[0].kind, Kind::Form1);
        assert_eq!(parsed[0].subheader_copy, duplicate);

        let primary: XaSubheader = [9, 10, 0x20, 12].into();
        let duplicate: XaSubheader = [13, 14, 0, 16].into();
        let form2 = writer
            .form2_with_subheaders(151, primary, duplicate, &[0x22; 2324], false)
            .unwrap();
        assert_eq!(&form2[16..20], &[9, 10, 0x20, 12]);
        assert_eq!(&form2[20..24], &[13, 14, 0, 16]);
        let (_, parsed) = parse_image(&form2).unwrap();
        assert_eq!(parsed[0].kind, Kind::Form2);
        assert_eq!(parsed[0].subheader_copy, duplicate);
    }

    #[test]
    fn final_xa_gap_accepts_ecc_calculated_with_the_recorded_header() {
        let frame = 81_860;
        let raw = SectorWriter::new()
            .xa_gap_with_recorded_header_ecc(frame, XaSubheader::default())
            .unwrap();

        let (parsed_frame, sectors) = parse_image(&raw).unwrap();
        assert_eq!(parsed_frame, frame);
        assert_eq!(sectors[0].kind, Kind::XaGap);
        assert!(sectors[0].noncompliant_ecc);

        let generated = SectorWriter::new()
            .xa_gap_with_recorded_header_ecc(frame, XaSubheader::default())
            .unwrap();
        assert_eq!(generated, raw);
    }

    #[test]
    fn native_sector_writer_matches_ecmlib_golden_vectors() {
        use sha1::{Digest, Sha1};

        let mut writer = SectorWriter::new();
        let sectors = [
            (
                "mode1",
                writer.mode1(150, &[0x5a; LOGICAL_BLOCK_SIZE]).unwrap(),
            ),
            (
                "form1_distinct",
                writer
                    .form1_with_subheaders(
                        151,
                        [1, 2, 0x08, 4].into(),
                        [5, 6, 0x08, 8].into(),
                        &[0x11; LOGICAL_BLOCK_SIZE],
                    )
                    .unwrap(),
            ),
            (
                "form2_computed",
                writer
                    .form2(152, [9, 10, 0x20, 12].into(), &[0x22; 2324], true)
                    .unwrap(),
            ),
            (
                "form2_zero",
                writer
                    .form2(153, [9, 10, 0x20, 12].into(), &[0x22; 2324], false)
                    .unwrap(),
            ),
            (
                "xa_gap",
                writer.xa_gap(154, XaSubheader::default()).unwrap(),
            ),
            (
                "recorded_header_gap",
                writer
                    .xa_gap_with_recorded_header_ecc(81_860, XaSubheader::default())
                    .unwrap(),
            ),
        ];
        let expected = [
            ("mode1", "0be5c2cdaef917dca3cb3c57cb612bf79abed8f6"),
            ("form1_distinct", "756938d5cd9f0a05700b8df3df13c8fbf59eb98a"),
            ("form2_computed", "2d379f2dc36c6f84bc31166b101245324e833523"),
            ("form2_zero", "6ee8e62a7d381f6ce955def30b83485a7ab6b130"),
            ("xa_gap", "f8f5ec8053c249225aa0d0a60471ae7af556cb34"),
            (
                "recorded_header_gap",
                "cc8062656b0c811d50169317518353adea92c7bd",
            ),
        ];
        for ((name, sector), (expected_name, expected_sha1)) in sectors.into_iter().zip(expected) {
            assert_eq!(name, expected_name);
            assert_eq!(hex::encode(Sha1::digest(sector)), expected_sha1, "{name}");
        }
    }

    #[test]
    fn edc_matches_the_cd_rom_catalog_check_value() {
        assert_eq!(generate_edc(b"123456789"), 0x6ec2_edc4);
    }

    #[test]
    fn ecc_tables_have_the_expected_inverse_relationship() {
        for index in 0..256 {
            let next = usize::from(ECC_TABLES.forward[index]);
            assert_eq!(usize::from(ECC_TABLES.backward[index ^ next]), index);
        }
    }

    #[test]
    fn mode1_reserved_bytes_are_preserved_while_protection_errors_are_rejected() {
        let mode1 = SectorWriter::new()
            .mode1(150, &[0x5a; LOGICAL_BLOCK_SIZE])
            .unwrap();
        let mut invalid_edc = mode1.clone();
        invalid_edc[2064] ^= 1;
        assert!(
            parse_image(&invalid_edc)
                .unwrap_err()
                .to_string()
                .contains("invalid Mode 1 EDC at sector 0")
        );
        let mut invalid_ecc = mode1.clone();
        invalid_ecc[2076] ^= 1;
        assert!(
            parse_image(&invalid_ecc)
                .unwrap_err()
                .to_string()
                .contains("invalid Mode 1 ECC at sector 0")
        );
        let mut reserved = mode1;
        reserved[2068] = 1;
        write_ecc(&mut reserved, frame_header(150, 1).unwrap());
        let parsed = parse_image(&reserved).unwrap().1;
        assert_eq!(parsed[0].bytes[2068..2076], [1, 0, 0, 0, 0, 0, 0, 0]);

        let form1 = SectorWriter::new()
            .form1(150, [0, 0, 0x08, 0].into(), &[0x5a; LOGICAL_BLOCK_SIZE])
            .unwrap();
        let mut invalid_edc = form1.clone();
        invalid_edc[2072] ^= 1;
        assert!(
            parse_image(&invalid_edc)
                .unwrap_err()
                .to_string()
                .contains("unsupported or invalid Mode 2 sector at sector 0")
        );
        let mut invalid_ecc = form1;
        invalid_ecc[2076] ^= 1;
        assert!(
            parse_image(&invalid_ecc)
                .unwrap_err()
                .to_string()
                .contains("unsupported or invalid Mode 2 sector at sector 0")
        );
    }

    #[test]
    fn mode2_track_can_contain_a_protected_zero_mode1_gap() {
        let mut writer = SectorWriter::new();
        let raw = [
            writer
                .form1(150, [0, 0, 0x08, 0].into(), &[1; LOGICAL_BLOCK_SIZE])
                .unwrap(),
            writer.mode1(151, &[0; LOGICAL_BLOCK_SIZE]).unwrap(),
            writer.xa_gap(152, XaSubheader::default()).unwrap(),
        ]
        .concat();
        let parsed = parse_image(&raw).unwrap().1;
        assert_eq!(parsed[1].kind, Kind::Mode1Gap);
    }
}

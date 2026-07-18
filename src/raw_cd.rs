use anyhow::{Context, Result, bail, ensure};
use ecmlib::{Decoder, Encoder, Optimizations, SectorType};

pub const RAW_SECTOR_SIZE: usize = 2352;
pub const LOGICAL_BLOCK_SIZE: usize = 2048;
pub const SYNC: [u8; 12] = [
    0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00,
];

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
    pub subheader: [u8; 4],
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
        let kind = match detected {
            SectorType::Mode2Xa1 | SectorType::Mode2Xa1Gap => Kind::Form1,
            SectorType::Mode2Xa2 | SectorType::Mode2Xa2Gap => Kind::Form2,
            SectorType::Mode2Gap | SectorType::Mode2XaGap if chunk[18] & 0x20 != 0 => Kind::Form2,
            SectorType::Mode2Gap | SectorType::Mode2XaGap => Kind::XaGap,
            other => bail!("unsupported or invalid sector type {other:?} at sector {index}"),
        };
        let mut sector = [0_u8; RAW_SECTOR_SIZE];
        sector.copy_from_slice(chunk);
        sectors.push(ParsedSector {
            bytes: sector,
            kind,
            subheader: chunk[16..20].try_into()?,
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

    pub fn form1(&mut self, frame: u32, subheader: [u8; 4], data: &[u8]) -> Result<Vec<u8>> {
        ensure!(data.len() == 2048, "Form 1 payload must be 2048 bytes");
        let mut compact = Vec::with_capacity(2052);
        compact.extend_from_slice(&subheader);
        compact.extend_from_slice(data);
        self.standard
            .decode_sector(&compact, SectorType::Mode2Xa1, frame, Optimizations::all())
            .context("generating Form 1 sector")
    }

    pub fn form2(
        &mut self,
        frame: u32,
        subheader: [u8; 4],
        data: &[u8],
        computed_edc: bool,
    ) -> Result<Vec<u8>> {
        ensure!(data.len() == 2324, "Form 2 payload must be 2324 bytes");
        let mut compact = Vec::with_capacity(2332);
        compact.extend_from_slice(&subheader);
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

    pub fn xa_gap(&mut self, frame: u32, subheader: [u8; 4]) -> Result<Vec<u8>> {
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
            .form2(162, [0, 0, 0x20, 0], &[0; 2324], true)
            .unwrap();
        assert_eq!(&sector[2348..2352], &[0x3f, 0x13, 0xb0, 0xbe]);
    }

    #[test]
    fn completely_zeroed_mode2_tail_is_an_xa_gap() {
        let mut writer = SectorWriter::new();
        let raw = writer.xa_gap(150, [0; 4]).unwrap();
        let (_, parsed) = parse_image(&raw).unwrap();
        assert_eq!(parsed[0].kind, Kind::XaGap);
    }

    #[test]
    fn zero_edc_form2_is_classified_from_the_form_bit() {
        let mut writer = SectorWriter::new();
        let raw = writer
            .form2(150, [0, 0, 0x20, 0], &[0; 2324], false)
            .unwrap();
        let (_, parsed) = parse_image(&raw).unwrap();
        assert_eq!(parsed[0].kind, Kind::Form2);
    }
}

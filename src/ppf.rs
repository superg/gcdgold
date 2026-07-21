use std::collections::BTreeSet;

use anyhow::{Result, ensure};

const PPF_MAGIC: &[u8; 5] = b"PPF20";
const PPF_ENCODING_METHOD: u8 = 1;
pub(crate) const BLOCK_CHECK_OFFSET: usize = 0x9320;
pub(crate) const BLOCK_CHECK_SIZE: usize = 1024;
pub(crate) const PPF_HEADER_SIZE: usize = 60 + BLOCK_CHECK_SIZE;
#[cfg_attr(not(test), allow(dead_code))]
const DESCRIPTION_TEXT: &[u8] = b"gcdgold pre-EDC/ECC mastering overlay";
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) const PPF_DESCRIPTION: [u8; 50] = make_description();

#[cfg_attr(not(test), allow(dead_code))]
const fn make_description() -> [u8; 50] {
    let mut description = [b' '; 50];
    let mut index = 0;
    while index < DESCRIPTION_TEXT.len() {
        description[index] = DESCRIPTION_TEXT[index];
        index += 1;
    }
    description
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PpfRecord {
    offset: u32,
    data: Vec<u8>,
}

impl PpfRecord {
    pub(crate) fn new(offset: u32, data: Vec<u8>) -> Result<Self> {
        ensure!(
            !data.is_empty() && data.len() <= usize::from(u8::MAX),
            "PPF2 record length must be between 1 and 255 bytes"
        );
        ensure!(
            u64::from(offset) + u64::try_from(data.len())? <= u64::from(u32::MAX),
            "PPF2 record exceeds the 32-bit target range"
        );
        Ok(Self { offset, data })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Ppf2 {
    target_size: u32,
    block_check: [u8; BLOCK_CHECK_SIZE],
    records: Vec<PpfRecord>,
}

impl Ppf2 {
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn new(target: &[u8], records: Vec<PpfRecord>) -> Result<Self> {
        let target_size = u32::try_from(target.len())?;
        ensure!(
            target.len() >= BLOCK_CHECK_OFFSET + BLOCK_CHECK_SIZE,
            "PPF2 target is too small for the standard block check"
        );
        validate_records(target_size, &records)?;
        Ok(Self {
            target_size,
            block_check: target[BLOCK_CHECK_OFFSET..BLOCK_CHECK_OFFSET + BLOCK_CHECK_SIZE]
                .try_into()?,
            records,
        })
    }

    pub(crate) fn from_bytes(bytes: &[u8]) -> Result<Self> {
        ensure!(
            bytes.len() >= PPF_HEADER_SIZE,
            "PPF2 file is shorter than its header"
        );
        ensure!(&bytes[..5] == PPF_MAGIC, "unsupported PPF magic");
        ensure!(
            bytes[5] == PPF_ENCODING_METHOD,
            "unsupported PPF2 encoding method {}",
            bytes[5]
        );
        let target_size = u32::from_le_bytes(bytes[56..60].try_into()?);
        ensure!(
            usize::try_from(target_size)? >= BLOCK_CHECK_OFFSET + BLOCK_CHECK_SIZE,
            "PPF2 target is too small for the standard block check"
        );
        let block_check = bytes[60..PPF_HEADER_SIZE].try_into()?;
        let mut records = Vec::new();
        let mut position = PPF_HEADER_SIZE;
        while position < bytes.len() {
            ensure!(bytes.len() - position >= 5, "truncated PPF2 record header");
            let offset = u32::from_le_bytes(bytes[position..position + 4].try_into()?);
            let length = usize::from(bytes[position + 4]);
            ensure!(length != 0, "PPF2 record has zero length");
            position += 5;
            ensure!(
                bytes.len() - position >= length,
                "truncated PPF2 record data"
            );
            records.push(PpfRecord::new(
                offset,
                bytes[position..position + length].to_vec(),
            )?);
            position += length;
        }
        validate_records(target_size, &records)?;
        Ok(Self {
            target_size,
            block_check,
            records,
        })
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn to_bytes(&self) -> Result<Vec<u8>> {
        validate_records(self.target_size, &self.records)?;
        let record_size = self
            .records
            .iter()
            .map(|record| 5 + record.data.len())
            .sum::<usize>();
        let mut bytes = Vec::with_capacity(PPF_HEADER_SIZE + record_size);
        bytes.extend_from_slice(PPF_MAGIC);
        bytes.push(PPF_ENCODING_METHOD);
        bytes.extend_from_slice(&PPF_DESCRIPTION);
        bytes.extend_from_slice(&self.target_size.to_le_bytes());
        bytes.extend_from_slice(&self.block_check);
        for record in &self.records {
            bytes.extend_from_slice(&record.offset.to_le_bytes());
            bytes.push(u8::try_from(record.data.len())?);
            bytes.extend_from_slice(&record.data);
        }
        Ok(bytes)
    }

    pub(crate) fn validate_target(&self, target: &[u8]) -> Result<()> {
        ensure!(
            target.len() == usize::try_from(self.target_size)?,
            "PPF2 target size does not match the canonical image"
        );
        ensure!(
            target[BLOCK_CHECK_OFFSET..BLOCK_CHECK_OFFSET + BLOCK_CHECK_SIZE] == self.block_check,
            "PPF2 block check does not match the canonical image"
        );
        Ok(())
    }

    pub(crate) fn apply(&self, target: &mut [u8], sector_size: usize) -> Result<BTreeSet<usize>> {
        ensure!(sector_size != 0, "PPF2 sector size must not be zero");
        self.validate_target(target)?;
        let mut touched = BTreeSet::new();
        for record in &self.records {
            let start = usize::try_from(record.offset)?;
            let end = start + record.data.len();
            target[start..end].copy_from_slice(&record.data);
            for sector in start / sector_size..=(end - 1) / sector_size {
                touched.insert(sector);
            }
        }
        Ok(touched)
    }

    #[cfg(test)]
    pub(crate) fn records(&self) -> &[PpfRecord] {
        &self.records
    }
}

fn validate_records(target_size: u32, records: &[PpfRecord]) -> Result<()> {
    for record in records {
        ensure!(
            u64::from(record.offset) + u64::try_from(record.data.len())? <= u64::from(target_size),
            "PPF2 record exceeds the target image"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target() -> Vec<u8> {
        (0..BLOCK_CHECK_OFFSET + BLOCK_CHECK_SIZE + 64)
            .map(|index| index as u8)
            .collect()
    }

    #[test]
    fn ppf2_uses_the_standard_header_and_target_only_records() {
        let target = target();
        let patch = Ppf2::new(
            &target,
            vec![
                PpfRecord::new(7, vec![0xaa, 0xbb]).unwrap(),
                PpfRecord::new(0x1234, vec![0xcc]).unwrap(),
            ],
        )
        .unwrap();
        let encoded = patch.to_bytes().unwrap();

        assert_eq!(&encoded[..5], b"PPF20");
        assert_eq!(encoded[5], 1);
        assert_eq!(&encoded[6..56], &PPF_DESCRIPTION);
        assert_eq!(
            u32::from_le_bytes(encoded[56..60].try_into().unwrap()),
            target.len() as u32
        );
        assert_eq!(
            &encoded[60..PPF_HEADER_SIZE],
            &target[BLOCK_CHECK_OFFSET..BLOCK_CHECK_OFFSET + BLOCK_CHECK_SIZE]
        );
        assert_eq!(
            &encoded[PPF_HEADER_SIZE..],
            &[7, 0, 0, 0, 2, 0xaa, 0xbb, 0x34, 0x12, 0, 0, 1, 0xcc]
        );

        let decoded = Ppf2::from_bytes(&encoded).unwrap();
        decoded.validate_target(&target).unwrap();
        assert_eq!(decoded.records(), patch.records());
    }

    #[test]
    fn ppf2_applies_overlapping_records_in_file_order() {
        let target = target();
        let patch = Ppf2::new(
            &target,
            vec![
                PpfRecord::new(10, vec![1, 2, 3]).unwrap(),
                PpfRecord::new(11, vec![8, 9]).unwrap(),
            ],
        )
        .unwrap();
        let mut output = target.clone();
        let touched = patch.apply(&mut output, 8).unwrap();

        assert_eq!(&output[10..13], &[1, 8, 9]);
        assert_eq!(touched.into_iter().collect::<Vec<_>>(), [1]);
    }

    #[test]
    fn ppf2_rejects_truncated_records_and_wrong_targets() {
        let target = target();
        let patch = Ppf2::new(&target, vec![PpfRecord::new(10, vec![1, 2, 3]).unwrap()]).unwrap();
        let mut encoded = patch.to_bytes().unwrap();
        encoded.pop();
        assert!(Ppf2::from_bytes(&encoded).is_err());

        let mut wrong_size = target.clone();
        wrong_size.push(0);
        assert!(patch.validate_target(&wrong_size).is_err());

        let mut wrong_block = target;
        wrong_block[BLOCK_CHECK_OFFSET] ^= 0xff;
        assert!(patch.validate_target(&wrong_block).is_err());
    }

    #[test]
    fn ppf2_rejects_zero_length_and_out_of_bounds_records() {
        assert!(PpfRecord::new(0, Vec::new()).is_err());
        assert!(PpfRecord::new(0, vec![0; 256]).is_err());

        let target = target();
        let patch = Ppf2::new(
            &target,
            vec![PpfRecord::new(target.len() as u32 - 1, vec![1, 2]).unwrap()],
        );
        assert!(patch.is_err());
    }
}

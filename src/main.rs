use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(version, about = "Extract and author CD-ROM data tracks")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

fn format_extraction_summary(report: &gcdgold::ExtractReport, manifest: &Path) -> String {
    format!(
        "Extraction complete\n  Sectors: {}\n  Source SHA-1: {}\n  Recovery warnings: {}\n  Manifest: {}",
        report.sectors,
        report.sha1,
        report.recovery_warnings.len(),
        manifest.display()
    )
}

fn format_build_summary(report: &gcdgold::BuildReport, image: &Path) -> String {
    format!(
        "Build complete\n  Sectors: {}\n  Image SHA-1: {}\n  SHA-1 warnings: {}\n  Image: {}",
        report.sectors,
        report.sha1,
        report.sha1_mismatches.len(),
        image.display()
    )
}

fn format_recovery_warning(warning: &gcdgold::RecoveryWarning) -> String {
    let location = warning
        .ranges
        .iter()
        .map(|range| {
            if range.first_lba == range.last_lba {
                format!("LBA {} ({})", range.first_lba, range.first_msf)
            } else {
                format!(
                    "LBAs {}-{} ({}-{})",
                    range.first_lba, range.last_lba, range.first_msf, range.last_msf
                )
            }
        })
        .collect::<Vec<_>>()
        .join(", ");
    let mut lines = vec![
        "Recovery warning".to_owned(),
        format!("  Category: {}", warning.category),
        format!("  Location: {location}"),
    ];
    if let Some(path) = &warning.path {
        lines.push(format!("  Path: {path}"));
    }
    lines.push(format!("  Details: {}", warning.description));
    lines.join("\n")
}

fn format_recovery_warnings(warnings: &[gcdgold::RecoveryWarning]) -> String {
    warnings
        .iter()
        .map(format_recovery_warning)
        .collect::<Vec<_>>()
        .join("\n\n")
}

fn format_sha1_warning(mismatch: &gcdgold::Sha1Mismatch) -> String {
    let target = match &mismatch.target {
        gcdgold::Sha1Target::Track => "track".to_owned(),
        gcdgold::Sha1Target::SystemArea { path } => format!("system area {path}"),
        gcdgold::Sha1Target::Asset { path } => format!("asset {path}"),
    };
    format!(
        "SHA-1 mismatch\n  Target: {target}\n  Expected: {}\n  Actual: {}",
        mismatch.expected, mismatch.actual
    )
}

fn format_sha1_warnings(mismatches: &[gcdgold::Sha1Mismatch]) -> String {
    mismatches
        .iter()
        .map(format_sha1_warning)
        .collect::<Vec<_>>()
        .join("\n\n")
}

fn has_track_sha1_mismatch(mismatches: &[gcdgold::Sha1Mismatch]) -> bool {
    mismatches
        .iter()
        .any(|mismatch| mismatch.target == gcdgold::Sha1Target::Track)
}

fn resolve_output_path(
    explicit: Option<PathBuf>,
    input: &Path,
    extension: &str,
    input_kind: &str,
) -> Result<PathBuf> {
    if let Some(explicit) = explicit {
        return Ok(explicit);
    }
    let file_name = input.file_name().with_context(|| {
        format!(
            "{input_kind} path {} has no file name for deriving the default output",
            input.display()
        )
    })?;
    Ok(PathBuf::from(file_name).with_extension(extension))
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Extract a CD-ROM data track into an editable project.
    Extract {
        #[arg(long)]
        image: PathBuf,
        #[arg(
            long,
            help = "Output manifest path (default: image filename with .yaml in the current directory)"
        )]
        manifest: Option<PathBuf>,
        #[arg(long, default_value = ".")]
        data_dir: PathBuf,
        #[arg(long)]
        overwrite: bool,
    },
    /// Author a CD-ROM data track from an editable project.
    Build {
        #[arg(long)]
        manifest: PathBuf,
        #[arg(
            long,
            help = "Output image path (default: manifest filename with .bin in the current directory)"
        )]
        image: Option<PathBuf>,
        #[arg(long, default_value = ".")]
        data_dir: PathBuf,
        #[arg(long)]
        overwrite: bool,
    },
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Extract {
            image,
            manifest,
            data_dir,
            overwrite,
        } => {
            let manifest = resolve_output_path(manifest, &image, "yaml", "image")?;
            let report = gcdgold::extract_with_options(
                &image,
                &manifest,
                &data_dir,
                gcdgold::ExtractOptions { overwrite },
            )?;
            let warnings = format_recovery_warnings(&report.recovery_warnings);
            if !warnings.is_empty() {
                eprintln!("{warnings}");
            }
            println!("{}", format_extraction_summary(&report, &manifest));
        }
        Command::Build {
            manifest,
            image,
            data_dir,
            overwrite,
        } => {
            let image = resolve_output_path(image, &manifest, "bin", "manifest")?;
            let report = gcdgold::build_with_options(
                &manifest,
                &image,
                &data_dir,
                gcdgold::BuildOptions { overwrite },
            )?;
            let warnings = format_sha1_warnings(&report.sha1_mismatches);
            if !warnings.is_empty() {
                eprintln!("{warnings}");
            }
            println!("{}", format_build_summary(&report, &image));
            if has_track_sha1_mismatch(&report.sha1_mismatches) {
                anyhow::bail!("built track SHA-1 does not match manifest track.sha1");
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn help_text_is_format_neutral() {
        let mut command = Cli::command();
        let top_level = command.render_long_help().to_string();
        assert!(top_level.contains("Extract and author CD-ROM data tracks"));
        assert!(top_level.contains("Extract a CD-ROM data track into an editable project"));
        assert!(top_level.contains("Author a CD-ROM data track from an editable project"));
        for narrow_term in ["MODE1", "MODE2", "/2352", "CD-ROM XA"] {
            assert!(!top_level.contains(narrow_term));
        }

        for name in ["extract", "build"] {
            let mut command = Cli::command();
            let subcommand = command.find_subcommand_mut(name).unwrap();
            let help = subcommand.render_long_help().to_string();
            for narrow_term in ["MODE1", "MODE2", "/2352", "CD-ROM XA"] {
                assert!(!help.contains(narrow_term));
            }
        }

        let mut command = Cli::command();
        let extract_help = command
            .find_subcommand_mut("extract")
            .unwrap()
            .render_long_help()
            .to_string();
        assert!(extract_help.contains("image filename with .yaml in the current directory"));

        let mut command = Cli::command();
        let build_help = command
            .find_subcommand_mut("build")
            .unwrap()
            .render_long_help()
            .to_string();
        assert!(build_help.contains("manifest filename with .bin in the current directory"));
    }

    #[test]
    fn implicit_outputs_use_only_the_input_filename_in_the_current_directory() {
        for (input, extension, kind, expected) in [
            ("/library/disc.bin", "yaml", "image", "disc.yaml"),
            ("library/disc.bin", "yaml", "image", "disc.yaml"),
            ("disc.bin", "yaml", "image", "disc.yaml"),
            (
                "/library/archive.disc.bin",
                "yaml",
                "image",
                "archive.disc.yaml",
            ),
            ("/projects/disc.yaml", "bin", "manifest", "disc.bin"),
            ("projects/disc.yaml", "bin", "manifest", "disc.bin"),
            ("disc.yaml", "bin", "manifest", "disc.bin"),
            (
                "/projects/archive.disc.yaml",
                "bin",
                "manifest",
                "archive.disc.bin",
            ),
        ] {
            assert_eq!(
                resolve_output_path(None, Path::new(input), extension, kind).unwrap(),
                PathBuf::from(expected)
            );
        }
    }

    #[test]
    fn explicit_outputs_are_unchanged_and_unusable_implicit_inputs_are_rejected() {
        let explicit = PathBuf::from("/custom/output.yaml");
        assert_eq!(
            resolve_output_path(Some(explicit.clone()), Path::new("/"), "yaml", "image").unwrap(),
            explicit
        );

        let error = resolve_output_path(None, Path::new("/"), "yaml", "image")
            .unwrap_err()
            .to_string();
        assert_eq!(
            error,
            "image path / has no file name for deriving the default output"
        );
    }

    #[test]
    fn overwrite_flag_is_accepted_by_both_commands() {
        let extract =
            Cli::try_parse_from(["gcdgold", "extract", "--image", "disc.bin", "--overwrite"])
                .unwrap();
        assert!(matches!(
            extract.command,
            Command::Extract {
                overwrite: true,
                ..
            }
        ));

        let build =
            Cli::try_parse_from(["gcdgold", "build", "--manifest", "disc.yaml", "--overwrite"])
                .unwrap();
        assert!(matches!(
            build.command,
            Command::Build {
                overwrite: true,
                ..
            }
        ));
    }

    #[test]
    fn removed_include_defaults_flag_is_rejected() {
        assert!(
            Cli::try_parse_from([
                "gcdgold",
                "extract",
                "--image",
                "disc.bin",
                "--include-defaults",
            ])
            .is_err()
        );
        assert!(
            Cli::try_parse_from([
                "gcdgold",
                "build",
                "--manifest",
                "disc.yaml",
                "--include-defaults",
            ])
            .is_err()
        );
    }

    #[test]
    fn removed_hash_and_patch_switches_are_rejected() {
        assert!(
            Cli::try_parse_from([
                "gcdgold",
                "extract",
                "--image",
                "disc.bin",
                "--manifest-only",
            ])
            .is_err()
        );
        assert!(
            Cli::try_parse_from([
                "gcdgold",
                "extract",
                "--image",
                "disc.bin",
                "--include-hashes",
            ])
            .is_err()
        );
        assert!(
            Cli::try_parse_from([
                "gcdgold",
                "build",
                "--manifest",
                "disc.yaml",
                "--no-patches",
            ])
            .is_err()
        );
    }

    #[test]
    fn success_summaries_are_multiline_and_include_output_paths() {
        let extract_report = gcdgold::ExtractReport {
            sectors: 248_051,
            sha1: "782c50827bf4cf8fe5530b64b188a2d43c75b0e0".to_owned(),
            recovery_warnings: Vec::new(),
        };
        let extraction = format_extraction_summary(
            &extract_report,
            Path::new("'98 Koushien - Koukou Yakyuu Simulation (Japan).yaml"),
        );
        assert_eq!(
            extraction,
            "Extraction complete\n  Sectors: 248051\n  Source SHA-1: 782c50827bf4cf8fe5530b64b188a2d43c75b0e0\n  Recovery warnings: 0\n  Manifest: '98 Koushien - Koukou Yakyuu Simulation (Japan).yaml"
        );

        let build_report = gcdgold::BuildReport {
            sectors: 248_051,
            sha1: "782c50827bf4cf8fe5530b64b188a2d43c75b0e0".to_owned(),
            sha1_mismatches: Vec::new(),
        };
        let build = format_build_summary(
            &build_report,
            Path::new("'98 Koushien - Koukou Yakyuu Simulation (Japan).bin"),
        );
        assert_eq!(
            build,
            "Build complete\n  Sectors: 248051\n  Image SHA-1: 782c50827bf4cf8fe5530b64b188a2d43c75b0e0\n  SHA-1 warnings: 0\n  Image: '98 Koushien - Koukou Yakyuu Simulation (Japan).bin"
        );
        assert!(!extraction.contains(';'));
        assert!(!build.contains(';'));
    }

    #[test]
    fn recovery_warnings_format_single_and_ranged_locations() {
        let single = gcdgold::RecoveryWarning {
            category: gcdgold::RecoveryCategory::MalformedSystemArea,
            ranges: vec![gcdgold::RecoveryRange {
                first_lba: -138,
                last_lba: -138,
                first_msf: "00:00:12".to_owned(),
                last_msf: "00:00:12".to_owned(),
            }],
            path: None,
            description: "recovered malformed framing".to_owned(),
        };
        assert_eq!(
            format_recovery_warning(&single),
            "Recovery warning\n  Category: malformed-system-area\n  Location: LBA -138 (00:00:12)\n  Details: recovered malformed framing"
        );

        let ranged = gcdgold::RecoveryWarning {
            category: gcdgold::RecoveryCategory::DirectoryBufferResidue,
            ranges: vec![gcdgold::RecoveryRange {
                first_lba: 24,
                last_lba: 26,
                first_msf: "00:02:24".to_owned(),
                last_msf: "00:02:26".to_owned(),
            }],
            path: Some("DATA/PLAYER'S FILE.BIN".to_owned()),
            description: "retained directory bytes".to_owned(),
        };
        assert_eq!(
            format_recovery_warning(&ranged),
            "Recovery warning\n  Category: directory-buffer-residue\n  Location: LBAs 24-26 (00:02:24-00:02:26)\n  Path: DATA/PLAYER'S FILE.BIN\n  Details: retained directory bytes"
        );

        let blocks = format_recovery_warnings(&[single, ranged]);
        assert_eq!(blocks.matches("\n\n").count(), 1);
        assert!(!blocks.contains(';'));
    }

    #[test]
    fn sha1_mismatch_blocks_name_every_target_and_both_hashes() {
        let expected = "1111111111111111111111111111111111111111";
        let actual = "2222222222222222222222222222222222222222";
        let targets = [
            (gcdgold::Sha1Target::Track, "track"),
            (
                gcdgold::Sha1Target::SystemArea {
                    path: "disc.system".to_owned(),
                },
                "system area disc.system",
            ),
            (
                gcdgold::Sha1Target::Asset {
                    path: "DATA/PLAYER'S FILE.BIN".to_owned(),
                },
                "asset DATA/PLAYER'S FILE.BIN",
            ),
        ];
        let mismatches = targets
            .into_iter()
            .map(|(target, _)| gcdgold::Sha1Mismatch {
                target,
                expected: expected.to_owned(),
                actual: actual.to_owned(),
            })
            .collect::<Vec<_>>();
        for (mismatch, target_text) in mismatches.iter().zip([
            "track",
            "system area disc.system",
            "asset DATA/PLAYER'S FILE.BIN",
        ]) {
            assert_eq!(
                format_sha1_warning(mismatch),
                format!(
                    "SHA-1 mismatch\n  Target: {target_text}\n  Expected: {expected}\n  Actual: {actual}"
                )
            );
        }
        let blocks = format_sha1_warnings(&mismatches);
        assert_eq!(blocks.matches("\n\n").count(), 2);
        assert!(!blocks.contains(';'));
    }

    #[test]
    fn only_track_sha1_mismatches_change_cli_success() {
        let asset = gcdgold::Sha1Mismatch {
            target: gcdgold::Sha1Target::Asset {
                path: "FILE.BIN".to_owned(),
            },
            expected: "1".repeat(40),
            actual: "2".repeat(40),
        };
        assert!(!has_track_sha1_mismatch(&[]));
        assert!(!has_track_sha1_mismatch(std::slice::from_ref(&asset)));

        let track = gcdgold::Sha1Mismatch {
            target: gcdgold::Sha1Target::Track,
            expected: "1".repeat(40),
            actual: "2".repeat(40),
        };
        assert!(has_track_sha1_mismatch(&[asset, track]));
    }
}

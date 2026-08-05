use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(version, about = "Extract and author CD-ROM data tracks")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

fn format_sha1_warning(mismatch: &gcdgold::Sha1Mismatch) -> String {
    let target = match &mismatch.target {
        gcdgold::Sha1Target::Track => "track".to_owned(),
        gcdgold::Sha1Target::SystemArea { path } => format!("system area {path}"),
        gcdgold::Sha1Target::Asset { path } => format!("asset {path}"),
    };
    format!(
        "warning: SHA-1 mismatch for {target}: expected {}, actual {}",
        mismatch.expected, mismatch.actual
    )
}

fn has_track_sha1_mismatch(mismatches: &[gcdgold::Sha1Mismatch]) -> bool {
    mismatches
        .iter()
        .any(|mismatch| mismatch.target == gcdgold::Sha1Target::Track)
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Extract a CD-ROM data track into an editable project.
    Extract {
        #[arg(long)]
        image: PathBuf,
        #[arg(long)]
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
        #[arg(long)]
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
            let manifest = manifest.unwrap_or_else(|| image.with_extension("yaml"));
            let report = gcdgold::extract_with_options(
                &image,
                &manifest,
                &data_dir,
                gcdgold::ExtractOptions { overwrite },
            )?;
            for warning in &report.recovery_warnings {
                let ranges = warning
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
                let path = warning
                    .path
                    .as_deref()
                    .map(|path| format!(" [{path}]"))
                    .unwrap_or_default();
                eprintln!(
                    "warning: {} at {}{}: {}",
                    warning.category, ranges, path, warning.description
                );
            }
            println!(
                "extracted {} sectors; source sha1 {}; recovery warnings {}; manifest {}",
                report.sectors,
                report.sha1,
                report.recovery_warnings.len(),
                manifest.display()
            );
        }
        Command::Build {
            manifest,
            image,
            data_dir,
            overwrite,
        } => {
            let image = image.unwrap_or_else(|| manifest.with_extension("bin"));
            let report = gcdgold::build_with_options(
                &manifest,
                &image,
                &data_dir,
                gcdgold::BuildOptions { overwrite },
            )?;
            for mismatch in &report.sha1_mismatches {
                eprintln!("{}", format_sha1_warning(mismatch));
            }
            println!(
                "built {} sectors; sha1 {}; hash warnings {}",
                report.sectors,
                report.sha1,
                report.sha1_mismatches.len()
            );
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
    fn sha1_mismatch_warning_names_the_asset_and_both_hashes() {
        let warning = format_sha1_warning(&gcdgold::Sha1Mismatch {
            target: gcdgold::Sha1Target::Asset {
                path: "FILE.BIN".to_owned(),
            },
            expected: "1111111111111111111111111111111111111111".to_owned(),
            actual: "2222222222222222222222222222222222222222".to_owned(),
        });
        assert_eq!(
            warning,
            "warning: SHA-1 mismatch for asset FILE.BIN: expected 1111111111111111111111111111111111111111, actual 2222222222222222222222222222222222222222"
        );
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

use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(version, about = "Extract and author raw CD-ROM XA data tracks")]
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

#[derive(Debug, Subcommand)]
enum Command {
    /// Extract a raw MODE2/2352 image into an editable project.
    Extract {
        #[arg(long)]
        image: PathBuf,
        #[arg(long)]
        manifest: Option<PathBuf>,
        #[arg(long, default_value = ".")]
        data_dir: PathBuf,
        #[arg(long)]
        manifest_only: bool,
        #[arg(long)]
        overwrite: bool,
        #[arg(long)]
        include_defaults: bool,
        #[arg(long)]
        include_hashes: bool,
    },
    /// Build a raw MODE2/2352 image from an editable project.
    Build {
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long)]
        image: Option<PathBuf>,
        #[arg(long, default_value = ".")]
        data_dir: PathBuf,
        #[arg(long)]
        overwrite: bool,
        #[arg(long)]
        no_patches: bool,
    },
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Extract {
            image,
            manifest,
            data_dir,
            manifest_only,
            overwrite,
            include_defaults,
            include_hashes,
        } => {
            let manifest = manifest.unwrap_or_else(|| image.with_extension("yaml"));
            let report = gcdgold::extract_with_options(
                &image,
                &manifest,
                &data_dir,
                gcdgold::ExtractOptions {
                    manifest_only,
                    overwrite,
                    include_defaults,
                    include_hashes,
                },
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
            no_patches,
        } => {
            let image = image.unwrap_or_else(|| manifest.with_extension("bin"));
            let report = gcdgold::build_with_options(
                &manifest,
                &image,
                &data_dir,
                gcdgold::BuildOptions {
                    overwrite,
                    apply_patches: !no_patches,
                },
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
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn include_defaults_flag_is_accepted_only_by_extract() {
        let extract = Cli::try_parse_from([
            "gcdgold",
            "extract",
            "--image",
            "disc.bin",
            "--include-defaults",
        ])
        .unwrap();
        assert!(matches!(
            extract.command,
            Command::Extract {
                include_defaults: true,
                ..
            }
        ));
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
    fn include_hashes_flag_is_accepted_only_by_extract() {
        let extract = Cli::try_parse_from([
            "gcdgold",
            "extract",
            "--image",
            "disc.bin",
            "--include-hashes",
        ])
        .unwrap();
        assert!(matches!(
            extract.command,
            Command::Extract {
                include_hashes: true,
                ..
            }
        ));
        assert!(
            Cli::try_parse_from([
                "gcdgold",
                "build",
                "--manifest",
                "disc.yaml",
                "--include-hashes",
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
    fn no_patches_flag_is_accepted_only_by_build() {
        let build = Cli::try_parse_from([
            "gcdgold",
            "build",
            "--manifest",
            "disc.yaml",
            "--no-patches",
        ])
        .unwrap();
        assert!(matches!(
            build.command,
            Command::Build {
                no_patches: true,
                ..
            }
        ));
        assert!(
            Cli::try_parse_from(["gcdgold", "extract", "--image", "disc.bin", "--no-patches",])
                .is_err()
        );
    }
}

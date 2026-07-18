use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(version, about = "Extract and author raw CD-ROM XA data tracks")]
struct Cli {
    #[command(subcommand)]
    command: Command,
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
                },
            )?;
            println!(
                "extracted {} sectors; source sha1 {}; manifest {}",
                report.sectors,
                report.sha1,
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
            let report = gcdgold::build(&manifest, &image, &data_dir, overwrite)?;
            println!("built {} sectors; sha1 {}", report.sectors, report.sha1);
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
}

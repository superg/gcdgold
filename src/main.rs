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
    },
    /// Build a raw MODE2/2352 image from an editable project.
    Build {
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long)]
        image: Option<PathBuf>,
        #[arg(long, default_value = ".")]
        data_dir: PathBuf,
    },
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Extract {
            image,
            manifest,
            data_dir,
            manifest_only,
        } => {
            let manifest = manifest.unwrap_or_else(|| image.with_extension("yaml"));
            let report = gcdgold::extract(&image, &manifest, &data_dir, manifest_only)?;
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
        } => {
            let image = image.unwrap_or_else(|| manifest.with_extension("bin"));
            let report = gcdgold::build(&manifest, &image, &data_dir)?;
            println!(
                "built {} sectors; sha1 {}; matches source: {}",
                report.sectors,
                report.sha1,
                if report.matches_source { "yes" } else { "no" }
            );
        }
    }
    Ok(())
}

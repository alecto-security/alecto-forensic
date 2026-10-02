use std::fs::File;
use std::path::PathBuf;

use clap::{Parser, Subcommand};

use crate::carve::{carve, Params};
use crate::error::{ForensicError, Result, EXIT_FAIL, EXIT_OK};
use crate::package::{extract, AcquisitionInput};
use crate::verify::verify_package;

#[derive(Parser)]
#[command(
    name = "alecto-forensic",
    version,
    about = "Read a disk image, never the disk. Write a package, never a bundle."
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Scan an image and report what would be extracted. Writes nothing.
    Detect {
        image: PathBuf,
        #[command(flatten)]
        params: ParamArgs,
        #[arg(long)]
        json: bool,
    },
    /// Extract recordings into a new package directory.
    Extract {
        image: PathBuf,
        #[arg(long)]
        out: PathBuf,
        /// JSON file with operator, authorization, write_blocker, acquired_at, image_sha256.
        #[arg(long, conflicts_with_all = ["operator", "authorization", "write_blocker"])]
        acquisition: Option<PathBuf>,
        #[arg(long)]
        operator: Option<String>,
        /// Reference to the owner's authority to read this disk.
        #[arg(long)]
        authorization: Option<String>,
        #[arg(long)]
        write_blocker: Option<String>,
        #[command(flatten)]
        params: ParamArgs,
        #[arg(long)]
        json: bool,
    },
    /// Check a package's hashes and index.
    VerifyPackage {
        package: PathBuf,
        #[arg(long)]
        json: bool,
    },
}

#[derive(clap::Args, Clone)]
pub struct ParamArgs {
    /// Join runs separated by at most this many bytes of other data.
    #[arg(long, default_value_t = Params::default().merge_gap)]
    pub merge_gap: u64,
    #[arg(long, default_value_t = Params::default().min_bytes)]
    pub min_bytes: u64,
    #[arg(long, default_value_t = Params::default().max_nal)]
    pub max_nal: usize,
}

impl From<&ParamArgs> for Params {
    fn from(a: &ParamArgs) -> Self {
        Params {
            merge_gap: a.merge_gap,
            min_bytes: a.min_bytes,
            max_nal: a.max_nal,
        }
    }
}

pub fn run() -> i32 {
    match execute(Cli::parse()) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("{e}");
            e.exit_code()
        }
    }
}

pub fn execute(cli: Cli) -> Result<i32> {
    match cli.command {
        Command::Detect { image, params, json } => {
            let carved = carve(File::open(&image)?, &Params::from(&params))?;
            if json {
                let streams: Vec<_> = carved
                    .streams
                    .iter()
                    .map(|s| serde_json::json!({"ranges": s.ranges, "bytes": s.bytes(), "nal_count": s.nal_count}))
                    .collect();
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "image_sha256": carved.image_sha256,
                        "image_bytes": carved.image_bytes,
                        "streams": streams,
                        "gaps": carved.gaps,
                    }))?
                );
            } else {
                println!("image    {} bytes, sha256 {}", carved.image_bytes, carved.image_sha256);
                println!("streams  {}", carved.streams.len());
                for (i, s) in carved.streams.iter().enumerate() {
                    println!(
                        "  #{:04} {} bytes, {} NALs, {} range(s), first at {}",
                        i + 1,
                        s.bytes(),
                        s.nal_count,
                        s.ranges.len(),
                        s.ranges[0].offset
                    );
                }
                println!("gaps     {}", carved.gaps.len());
            }
            Ok(EXIT_OK)
        }
        Command::Extract {
            image,
            out,
            acquisition,
            operator,
            authorization,
            write_blocker,
            params,
            json,
        } => {
            let input = match acquisition {
                Some(path) => serde_json::from_slice::<AcquisitionInput>(&std::fs::read(&path)?)
                    .map_err(|e| ForensicError::config(format!("{}: {e}", path.display())))?,
                None => AcquisitionInput {
                    operator: operator
                        .ok_or_else(|| ForensicError::config("--operator required"))?,
                    authorization: authorization
                        .ok_or_else(|| ForensicError::config("--authorization required"))?,
                    write_blocker,
                    acquired_at: None,
                    image_sha256: None,
                },
            };
            let summary = extract(&image, &out, &input, &Params::from(&params))?;
            if json {
                println!(
                    "{}",
                    serde_json::json!({
                        "streams": summary.streams,
                        "gaps": summary.gaps,
                        "image_sha256": summary.image_sha256,
                        "exit_code": summary.exit_code,
                    })
                );
            } else {
                println!("package  {}", out.display());
                println!("streams  {}", summary.streams);
                println!("gaps     {}", summary.gaps);
                println!("image    {}", summary.image_sha256);
            }
            Ok(summary.exit_code)
        }
        Command::VerifyPackage { package, json } => {
            let problems = verify_package(&package)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&problems)?);
            } else if problems.is_empty() {
                println!("package OK");
            } else {
                for p in &problems {
                    println!("{p}");
                }
            }
            Ok(if problems.is_empty() { EXIT_OK } else { EXIT_FAIL })
        }
    }
}

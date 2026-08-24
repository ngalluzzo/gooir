use std::{env, fs, path::PathBuf, process};

use buzz_surface_check::{
    CLI_LIFT_NAME, PROTOCOL_LIFT_NAME, RELAY_LIFT_NAME, analyze_documents, embedded_documents,
    render_details, render_human,
};

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let options = Options::parse(env::args().skip(1))?;
    if options.help {
        println!("{}", usage());
        return Ok(());
    }
    let documents = options.input.read()?;
    let report = analyze_documents(&documents.protocol, &documents.relay, &documents.cli)?;
    let output = if options.json {
        serde_json::to_string_pretty(&report)
            .map_err(|error| format!("failed to serialize analysis: {error}"))?
    } else if options.details {
        render_details(&report)?
    } else {
        render_human(&report)?
    };
    println!("{output}");
    Ok(())
}

struct Options {
    input: Input,
    json: bool,
    details: bool,
    help: bool,
}

impl Options {
    fn parse(arguments: impl Iterator<Item = String>) -> Result<Self, String> {
        let mut arguments = arguments.peekable();
        let mut json = false;
        let mut details = false;
        let mut help = false;
        let mut input_dir = None;
        let mut paths = Vec::new();

        while let Some(argument) = arguments.next() {
            match argument.as_str() {
                "--json" => json = true,
                "--details" => details = true,
                "--help" | "-h" => help = true,
                "--input-dir" => {
                    let directory = arguments.next().ok_or_else(|| {
                        "--input-dir requires a directory\n\n".to_owned() + &usage()
                    })?;
                    input_dir = Some(PathBuf::from(directory));
                }
                option if option.starts_with('-') => {
                    return Err(format!("unknown option {option}\n\n{}", usage()));
                }
                path => paths.push(PathBuf::from(path)),
            }
        }

        let input = match (input_dir, paths.as_slice()) {
            (None, []) => Input::Embedded,
            (Some(directory), []) => Input::Directory(directory),
            (None, [protocol, relay, cli]) => Input::Files {
                protocol: protocol.clone(),
                relay: relay.clone(),
                cli: cli.clone(),
            },
            _ => return Err(usage()),
        };

        if json && details {
            return Err("choose either --details or --json\n\n".to_owned() + &usage());
        }

        Ok(Self {
            input,
            json,
            details,
            help,
        })
    }
}

enum Input {
    Embedded,
    Directory(PathBuf),
    Files {
        protocol: PathBuf,
        relay: PathBuf,
        cli: PathBuf,
    },
}

impl Input {
    fn read(&self) -> Result<Documents, String> {
        match self {
            Self::Embedded => {
                let (protocol, relay, cli) = embedded_documents();
                Ok(Documents {
                    protocol: protocol.to_vec(),
                    relay: relay.to_vec(),
                    cli: cli.to_vec(),
                })
            }
            Self::Directory(directory) => Ok(Documents {
                protocol: read_document(&directory.join(PROTOCOL_LIFT_NAME))?,
                relay: read_document(&directory.join(RELAY_LIFT_NAME))?,
                cli: read_document(&directory.join(CLI_LIFT_NAME))?,
            }),
            Self::Files {
                protocol,
                relay,
                cli,
            } => Ok(Documents {
                protocol: read_document(protocol)?,
                relay: read_document(relay)?,
                cli: read_document(cli)?,
            }),
        }
    }
}

struct Documents {
    protocol: Vec<u8>,
    relay: Vec<u8>,
    cli: Vec<u8>,
}

fn read_document(path: &PathBuf) -> Result<Vec<u8>, String> {
    fs::read(path).map_err(|error| format!("failed to read {}: {error}", path.display()))
}

fn usage() -> String {
    "usage: buzz-surface-check [--details | --json] [--input-dir <directory>]\n       buzz-surface-check [--details | --json] <protocol-lift-json> <relay-lift-json> <cli-lift-json>\n\nWith no input paths, the command analyzes its embedded, reviewed Buzz desktop v0.5.18 lift documents.".to_owned()
}

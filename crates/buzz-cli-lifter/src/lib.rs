//! Native lifting for Buzz's Clap-derived command tree.
//!
//! The lifter starts at `Cli.command: Cmd` and recursively follows only enum
//! variants explicitly marked `#[command(subcommand)]`. Missing referenced
//! enums, conditional surfaces, external subcommands, flattening, or aliases it
//! cannot parse make coverage partial rather than silently proving absence.

use buzz_protocol_lifter::{SourceArtifact, SourceSpan};
use heck::{ToKebabCase, ToLowerCamelCase, ToShoutySnakeCase, ToSnakeCase, ToUpperCamelCase};
use proc_macro2::Span;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, fmt};
use syn::{
    Attribute, Expr, Fields, Item, ItemEnum, ItemStruct, Lit, Token, Type, spanned::Spanned,
};

pub const EXTRACTOR_PACKAGE: &str = "org.gooi.lifter.buzz_cli";
pub const EXTRACTOR_VERSION: &str = "0.1.0";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommandNodeKind {
    Group,
    Leaf,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CommandNode {
    pub path: Vec<String>,
    pub enum_symbol: String,
    pub variant_symbol: String,
    pub kind: CommandNodeKind,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub aliases: Vec<String>,
    pub declaration: SourceSpan,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeCompleteness {
    Exhaustive,
    Partial,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CliCoverage {
    pub extractor_package: String,
    pub extractor_version: String,
    pub mechanism: String,
    pub completeness: NativeCompleteness,
    pub included_artifacts: Vec<String>,
    pub unresolved: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CommandTreeLift {
    pub source: SourceArtifact,
    pub parser_struct: SourceSpan,
    pub command_field: SourceSpan,
    pub root_enum: String,
    pub commands: Vec<CommandNode>,
    pub coverage: CliCoverage,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LiftError {
    InvalidRust(String),
    MissingParserStruct,
    ParserDeriveMissing,
    MissingCommandField,
    InvalidCommandField,
    MissingRootEnum,
    RootSubcommandDeriveMissing,
    MissingSourceSpan { construct: String },
}

impl fmt::Display for LiftError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRust(error) => write!(formatter, "source is not valid Rust: {error}"),
            Self::MissingParserStruct => formatter.write_str("Cli parser struct was not found"),
            Self::ParserDeriveMissing => formatter.write_str("Cli does not derive Parser"),
            Self::MissingCommandField => formatter.write_str("Cli.command field was not found"),
            Self::InvalidCommandField => formatter.write_str(
                "Cli.command is not a direct #[command(subcommand)] field with a path type",
            ),
            Self::MissingRootEnum => formatter.write_str("root command enum was not found"),
            Self::RootSubcommandDeriveMissing => {
                formatter.write_str("root command enum does not derive Subcommand")
            }
            Self::MissingSourceSpan { construct } => {
                write!(formatter, "could not resolve source span for {construct}")
            }
        }
    }
}

impl std::error::Error for LiftError {}

pub fn lift_command_tree(
    source: &str,
    authority: impl Into<String>,
    artifact: impl Into<String>,
    revision: impl Into<String>,
) -> Result<CommandTreeLift, LiftError> {
    let file =
        syn::parse_file(source).map_err(|error| LiftError::InvalidRust(error.to_string()))?;
    let parser = find_struct(&file, "Cli").ok_or(LiftError::MissingParserStruct)?;
    if !derive_contains(&parser.attrs, "Parser") {
        return Err(LiftError::ParserDeriveMissing);
    }
    let command_field = parser
        .fields
        .iter()
        .find(|field| field.ident.as_ref().is_some_and(|ident| ident == "command"))
        .ok_or(LiftError::MissingCommandField)?;
    let command_attributes = command_attr(&command_field.attrs);
    let root_enum = type_symbol(&command_field.ty).ok_or(LiftError::InvalidCommandField)?;
    if !command_attributes.subcommand
        || command_attributes.external_subcommand
        || command_attributes.flatten
        || command_attributes.skip
    {
        return Err(LiftError::InvalidCommandField);
    }

    let enums = file
        .items
        .iter()
        .filter_map(|item| match item {
            Item::Enum(item) => Some((item.ident.to_string(), item)),
            _ => None,
        })
        .collect::<BTreeMap<_, _>>();
    let root = enums.get(&root_enum).ok_or(LiftError::MissingRootEnum)?;
    if !derive_contains(&root.attrs, "Subcommand") {
        return Err(LiftError::RootSubcommandDeriveMissing);
    }

    let mut commands = Vec::new();
    let mut unresolved = command_attributes
        .unresolved
        .into_iter()
        .map(|reason| format!("Cli.command: {reason}"))
        .collect::<Vec<_>>();
    let mut stack = Vec::new();
    visit_command_enum(
        source,
        root,
        &enums,
        &[],
        &mut stack,
        &mut commands,
        &mut unresolved,
    )?;

    let artifact = artifact.into();
    Ok(CommandTreeLift {
        source: SourceArtifact {
            authority: authority.into(),
            artifact: artifact.clone(),
            revision: revision.into(),
            sha256: sha256(source.as_bytes()),
        },
        parser_struct: source_span(source, parser.span(), "Cli parser struct")?,
        command_field: source_span(source, command_field.span(), "Cli.command field")?,
        root_enum,
        commands,
        coverage: CliCoverage {
            extractor_package: EXTRACTOR_PACKAGE.to_owned(),
            extractor_version: EXTRACTOR_VERSION.to_owned(),
            mechanism: "clap_derive_subcommand_tree".to_owned(),
            completeness: if unresolved.is_empty() {
                NativeCompleteness::Exhaustive
            } else {
                NativeCompleteness::Partial
            },
            included_artifacts: vec![artifact],
            unresolved,
        },
    })
}

fn visit_command_enum(
    source: &str,
    command_enum: &ItemEnum,
    enums: &BTreeMap<String, &ItemEnum>,
    prefix: &[String],
    stack: &mut Vec<String>,
    commands: &mut Vec<CommandNode>,
    unresolved: &mut Vec<String>,
) -> Result<(), LiftError> {
    let enum_symbol = command_enum.ident.to_string();
    if stack.contains(&enum_symbol) {
        unresolved.push(format!("recursive subcommand enum {enum_symbol}"));
        return Ok(());
    }
    if has_cfg(&command_enum.attrs) {
        unresolved.push(format!("conditional subcommand enum {enum_symbol}"));
    }
    if !derive_contains(&command_enum.attrs, "Subcommand") {
        unresolved.push(format!("{enum_symbol} does not derive Subcommand"));
    }
    let container_attributes = command_container_attr(&command_enum.attrs);
    unresolved.extend(
        container_attributes
            .unresolved
            .iter()
            .map(|reason| format!("{enum_symbol}: {reason}")),
    );
    stack.push(enum_symbol.clone());

    for variant in &command_enum.variants {
        let attributes = command_attr(&variant.attrs);
        if attributes.skip {
            continue;
        }
        let command_name = attributes.name.unwrap_or_else(|| {
            container_attributes
                .rename_all
                .unwrap_or(CasingStyle::Kebab)
                .apply(&variant.ident.to_string())
        });
        let mut path = prefix.to_vec();
        path.push(command_name);
        let kind = if attributes.subcommand {
            CommandNodeKind::Group
        } else {
            CommandNodeKind::Leaf
        };
        commands.push(CommandNode {
            path: path.clone(),
            enum_symbol: enum_symbol.clone(),
            variant_symbol: variant.ident.to_string(),
            kind,
            aliases: attributes.aliases,
            declaration: source_span(source, variant.span(), &variant.ident.to_string())?,
        });

        if has_cfg(&variant.attrs) {
            unresolved.push(format!("conditional command {}", path.join(" ")));
        }
        if attributes.external_subcommand || attributes.flatten {
            unresolved.push(format!("open command surface at {}", path.join(" ")));
        }
        unresolved.extend(
            attributes
                .unresolved
                .into_iter()
                .map(|reason| format!("{}: {reason}", path.join(" "))),
        );

        if attributes.subcommand {
            let nested_symbol = nested_enum_symbol(&variant.fields);
            match nested_symbol.and_then(|symbol| enums.get(&symbol).copied()) {
                Some(nested) => {
                    visit_command_enum(source, nested, enums, &path, stack, commands, unresolved)?;
                }
                None => unresolved.push(format!(
                    "{} references an unavailable subcommand enum",
                    path.join(" ")
                )),
            }
        }
    }
    stack.pop();
    Ok(())
}

fn find_struct<'a>(file: &'a syn::File, name: &str) -> Option<&'a ItemStruct> {
    file.items.iter().find_map(|item| match item {
        Item::Struct(item) if item.ident == name => Some(item),
        _ => None,
    })
}

fn derive_contains(attributes: &[Attribute], expected: &str) -> bool {
    attributes.iter().any(|attribute| {
        if !attribute.path().is_ident("derive") {
            return false;
        }
        let mut found = false;
        let _ = attribute.parse_nested_meta(|meta| {
            found |= meta
                .path
                .segments
                .last()
                .is_some_and(|segment| segment.ident == expected);
            Ok(())
        });
        found
    })
}

#[derive(Default)]
struct CommandAttributes {
    subcommand: bool,
    external_subcommand: bool,
    flatten: bool,
    skip: bool,
    name: Option<String>,
    aliases: Vec<String>,
    unresolved: Vec<String>,
}

fn command_attr(attributes: &[Attribute]) -> CommandAttributes {
    let mut result = CommandAttributes::default();
    for attribute in attributes {
        if !attribute.path().is_ident("command") {
            continue;
        }
        if let Err(error) = attribute.parse_nested_meta(|meta| {
            if meta.path.is_ident("subcommand") {
                result.subcommand = true;
            } else if meta.path.is_ident("external_subcommand") {
                result.external_subcommand = true;
            } else if meta.path.is_ident("flatten") {
                result.flatten = true;
            } else if meta.path.is_ident("skip") {
                if meta.input.is_empty() {
                    result.skip = true;
                } else {
                    if meta.input.peek(Token![=]) {
                        let _: Expr = meta.value()?.parse()?;
                    }
                    result
                        .unresolved
                        .push("unsupported skip attribute form".to_owned());
                }
            } else if meta.path.is_ident("name") {
                result.name = Some(meta.value()?.parse::<syn::LitStr>()?.value());
            } else if meta.path.is_ident("alias") || meta.path.is_ident("visible_alias") {
                result
                    .aliases
                    .push(meta.value()?.parse::<syn::LitStr>()?.value());
            } else if meta.path.is_ident("aliases") || meta.path.is_ident("visible_aliases") {
                let expression: Expr = meta.value()?.parse()?;
                let Expr::Array(array) = expression else {
                    result
                        .unresolved
                        .push("unsupported alias expression".to_owned());
                    return Ok(());
                };
                for element in array.elems {
                    match element {
                        Expr::Lit(literal) => match literal.lit {
                            Lit::Str(value) => result.aliases.push(value.value()),
                            _ => result
                                .unresolved
                                .push("non-string command alias".to_owned()),
                        },
                        _ => result
                            .unresolved
                            .push("non-literal command alias".to_owned()),
                    }
                }
            } else if meta.path.is_ident("after_help") || meta.path.is_ident("group") {
                // These affect help text or argument validation inside an
                // already identified command, not its path or aliases.
                let _: Expr = meta.value()?.parse()?;
            } else {
                let name = meta
                    .path
                    .segments
                    .last()
                    .map(|segment| segment.ident.to_string())
                    .unwrap_or_else(|| "unknown".to_owned());
                if meta.input.peek(Token![=]) {
                    let _: Expr = meta.value()?.parse()?;
                }
                result
                    .unresolved
                    .push(format!("unhandled command variant attribute {name}"));
            }
            Ok(())
        }) {
            result
                .unresolved
                .push(format!("unparsed command attribute: {error}"));
        }
    }
    result
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CasingStyle {
    Camel,
    Kebab,
    Pascal,
    ScreamingSnake,
    Snake,
    Lower,
    Upper,
    Verbatim,
}

impl CasingStyle {
    fn parse(value: &str) -> Option<Self> {
        match value.to_upper_camel_case().to_lowercase().as_str() {
            "camel" | "camelcase" => Some(Self::Camel),
            "kebab" | "kebabcase" => Some(Self::Kebab),
            "pascal" | "pascalcase" => Some(Self::Pascal),
            "screamingsnake" | "screamingsnakecase" => Some(Self::ScreamingSnake),
            "snake" | "snakecase" => Some(Self::Snake),
            "lower" | "lowercase" => Some(Self::Lower),
            "upper" | "uppercase" => Some(Self::Upper),
            "verbatim" | "verbatimcase" => Some(Self::Verbatim),
            _ => None,
        }
    }

    fn apply(self, symbol: &str) -> String {
        match self {
            Self::Camel => symbol.to_lower_camel_case(),
            Self::Kebab => symbol.to_kebab_case(),
            Self::Pascal => symbol.to_upper_camel_case(),
            Self::ScreamingSnake => symbol.to_shouty_snake_case(),
            Self::Snake => symbol.to_snake_case(),
            Self::Lower => symbol.to_snake_case().replace('_', ""),
            Self::Upper => symbol.to_shouty_snake_case().replace('_', ""),
            Self::Verbatim => symbol.to_owned(),
        }
    }
}

#[derive(Default)]
struct CommandContainerAttributes {
    rename_all: Option<CasingStyle>,
    unresolved: Vec<String>,
}

fn command_container_attr(attributes: &[Attribute]) -> CommandContainerAttributes {
    let mut result = CommandContainerAttributes::default();
    for attribute in attributes {
        if !attribute.path().is_ident("command") {
            continue;
        }
        if let Err(error) = attribute.parse_nested_meta(|meta| {
            if meta.path.is_ident("rename_all") {
                let value = meta.value()?.parse::<syn::LitStr>()?.value();
                match CasingStyle::parse(&value) {
                    Some(style) => result.rename_all = Some(style),
                    None => result
                        .unresolved
                        .push(format!("unsupported rename_all casing {value:?}")),
                }
            } else {
                let name = meta
                    .path
                    .segments
                    .last()
                    .map(|segment| segment.ident.to_string())
                    .unwrap_or_else(|| "unknown".to_owned());
                if meta.input.peek(Token![=]) {
                    let _: Expr = meta.value()?.parse()?;
                }
                result
                    .unresolved
                    .push(format!("unhandled command container attribute {name}"));
            }
            Ok(())
        }) {
            result
                .unresolved
                .push(format!("unparsed command container attribute: {error}"));
        }
    }
    result
}

fn has_cfg(attributes: &[Attribute]) -> bool {
    attributes
        .iter()
        .any(|attribute| attribute.path().is_ident("cfg") || attribute.path().is_ident("cfg_attr"))
}

fn type_symbol(ty: &Type) -> Option<String> {
    let Type::Path(path) = ty else { return None };
    path.path
        .segments
        .last()
        .map(|segment| segment.ident.to_string())
}

fn nested_enum_symbol(fields: &Fields) -> Option<String> {
    let Fields::Unnamed(fields) = fields else {
        return None;
    };
    if fields.unnamed.len() != 1 {
        return None;
    }
    type_symbol(&fields.unnamed.first()?.ty)
}

fn source_span(source: &str, span: Span, construct: &str) -> Result<SourceSpan, LiftError> {
    let start = span.start();
    let end = span.end();
    let byte_start = byte_offset(source, start.line, start.column).ok_or_else(|| {
        LiftError::MissingSourceSpan {
            construct: construct.to_owned(),
        }
    })?;
    let byte_end =
        byte_offset(source, end.line, end.column).ok_or_else(|| LiftError::MissingSourceSpan {
            construct: construct.to_owned(),
        })?;
    Ok(SourceSpan {
        byte_start: byte_start as u64,
        byte_end: byte_end as u64,
        line_start: start.line as u32,
        line_end: end.line as u32,
    })
}

fn byte_offset(source: &str, line: usize, column: usize) -> Option<usize> {
    let line_start = if line == 1 {
        0
    } else {
        source.match_indices('\n').nth(line.checked_sub(2)?)?.0 + 1
    };
    let line_text = source
        .get(line_start..)?
        .split_once('\n')
        .map_or_else(|| source.get(line_start..), |(line, _)| Some(line))?;
    let column_offset = line_text
        .char_indices()
        .nth(column)
        .map_or(line_text.len(), |(offset, _)| offset);
    Some(line_start + column_offset)
}

fn sha256(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(7 + digest.len() * 2);
    output.push_str("sha256:");
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

#[cfg(test)]
mod tests {
    use super::{CommandNodeKind, LiftError, NativeCompleteness, lift_command_tree};

    const FIXTURE: &str = r#"
#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    #[command(subcommand)]
    Messages(MessagesCmd),
    #[command(name = "set-profile")]
    SetProfile,
}

#[derive(Subcommand)]
enum MessagesCmd {
    Send,
    #[command(visible_alias = "read")]
    Get,
}
"#;

    #[test]
    fn recursively_lifts_the_closed_clap_command_tree() {
        let lift = lift_command_tree(FIXTURE, "fixture", "lib.rs", "revision")
            .expect("fixture command tree lifts");

        assert_eq!(lift.coverage.completeness, NativeCompleteness::Exhaustive);
        assert!(lift.commands.iter().any(|command| {
            command.path == ["messages"] && command.kind == CommandNodeKind::Group
        }));
        assert!(lift.commands.iter().any(|command| {
            command.path == ["messages", "send"] && command.kind == CommandNodeKind::Leaf
        }));
        assert!(lift.commands.iter().any(|command| {
            command.path == ["set-profile"] && command.kind == CommandNodeKind::Leaf
        }));
        assert!(
            lift.commands
                .iter()
                .any(|command| command.aliases == ["read"])
        );
    }

    #[test]
    fn external_subcommands_make_coverage_partial() {
        let source = FIXTURE.replace(
            "SetProfile,",
            "#[command(external_subcommand)]\n    External(Vec<String>),",
        );
        let lift = lift_command_tree(&source, "fixture", "lib.rs", "revision")
            .expect("open tree still lifts");

        assert_eq!(lift.coverage.completeness, NativeCompleteness::Partial);
        assert!(
            lift.coverage
                .unresolved
                .iter()
                .any(|reason| reason.contains("open command surface"))
        );
    }

    #[test]
    fn root_must_be_wired_as_a_clap_subcommand() {
        let source = FIXTURE.replace("#[command(subcommand)]\n    command", "command");
        let error = lift_command_tree(&source, "fixture", "lib.rs", "revision")
            .expect_err("unwired root must fail");

        assert_eq!(error, LiftError::InvalidCommandField);
    }

    #[test]
    fn enum_rename_all_uses_clap_casing_semantics() {
        let source = FIXTURE.replace(
            "#[derive(Subcommand)]\nenum Cmd",
            "#[derive(Subcommand)]\n#[command(rename_all = \"snake_case\")]\nenum Cmd",
        );
        let lift = lift_command_tree(&source, "fixture", "lib.rs", "revision")
            .expect("renamed command tree lifts");

        assert_eq!(lift.coverage.completeness, NativeCompleteness::Exhaustive);
        assert!(lift.commands.iter().any(|command| {
            command.path == ["set-profile"] && command.kind == CommandNodeKind::Leaf
        }));
        assert!(lift.commands.iter().any(|command| {
            command.path == ["messages"] && command.kind == CommandNodeKind::Group
        }));

        let source = source.replace(
            "#[command(name = \"set-profile\")]\n    SetProfile,",
            "SetProfile,",
        );
        let lift = lift_command_tree(&source, "fixture", "lib.rs", "revision")
            .expect("implicit renamed command tree lifts");
        assert!(lift.commands.iter().any(|command| {
            command.path == ["set_profile"] && command.kind == CommandNodeKind::Leaf
        }));
    }

    #[test]
    fn unhandled_enum_command_attribute_makes_coverage_partial() {
        let source = FIXTURE.replace(
            "#[derive(Subcommand)]\nenum Cmd",
            "#[derive(Subcommand)]\n#[command(disable_help_flag = true)]\nenum Cmd",
        );
        let lift = lift_command_tree(&source, "fixture", "lib.rs", "revision")
            .expect("tree with unhandled container attribute still lifts");

        assert_eq!(lift.coverage.completeness, NativeCompleteness::Partial);
        assert!(lift.coverage.unresolved.iter().any(|reason| {
            reason.contains("Cmd: unhandled command container attribute disable_help_flag")
        }));
    }

    #[test]
    fn skipped_variants_are_not_commands() {
        let source = FIXTURE.replace(
            "#[command(name = \"set-profile\")]\n    SetProfile,",
            "#[command(skip)]\n    SetProfile,",
        );
        let lift = lift_command_tree(&source, "fixture", "lib.rs", "revision")
            .expect("tree with a skipped variant still lifts");

        assert_eq!(lift.coverage.completeness, NativeCompleteness::Exhaustive);
        assert!(
            lift.commands
                .iter()
                .all(|command| command.variant_symbol != "SetProfile")
        );
    }

    #[test]
    fn unhandled_variant_invocation_attributes_make_coverage_partial() {
        let source = FIXTURE.replace(
            "#[command(name = \"set-profile\")]\n    SetProfile,",
            "#[command(long_flag = \"profile\")]\n    SetProfile,",
        );
        let lift = lift_command_tree(&source, "fixture", "lib.rs", "revision")
            .expect("tree with an unhandled invocation attribute still lifts");

        assert_eq!(lift.coverage.completeness, NativeCompleteness::Partial);
        assert!(lift.coverage.unresolved.iter().any(|reason| {
            reason.contains("set-profile: unhandled command variant attribute long_flag")
        }));
    }

    #[test]
    fn argument_groups_do_not_change_the_command_path_surface() {
        let source = FIXTURE.replace(
            "#[command(name = \"set-profile\")]",
            "#[command(name = \"set-profile\", group = clap::ArgGroup::new(\"edit\").required(true))]",
        );
        let lift = lift_command_tree(&source, "fixture", "lib.rs", "revision")
            .expect("path-neutral command metadata still lifts");

        assert_eq!(lift.coverage.completeness, NativeCompleteness::Exhaustive);
        assert!(
            lift.commands
                .iter()
                .any(|command| command.path == ["set-profile"])
        );
    }

    #[test]
    fn pinned_native_output_is_an_exhaustive_tree_without_a_job_command() {
        let lift: super::CommandTreeLift = serde_json::from_str(include_str!(
            "../../../fixtures/buzz/desktop-v0.5.18/job-cli.lift.json"
        ))
        .expect("pinned output matches the native schema");

        assert_eq!(
            lift.source.sha256,
            "sha256:a4a6829515e23851822ce5b1c3e7b341c32e2997b17b3b4f74f8aad994ab6310"
        );
        assert_eq!(lift.commands.len(), 138);
        assert_eq!(lift.coverage.completeness, NativeCompleteness::Exhaustive);
        assert!(lift.commands.iter().all(|command| {
            command.path.iter().chain(&command.aliases).all(|segment| {
                !segment.eq_ignore_ascii_case("job") && !segment.eq_ignore_ascii_case("jobs")
            })
        }));
    }
}

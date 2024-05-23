//! `rust-project.json` file format.
//!
//! This format is spiritually a serialization of [`base_db::CrateGraph`]. The
//! idea here is that people who do not use Cargo, can instead teach their build
//! system to generate `rust-project.json` which can be ingested by
//! rust-analyzer.
//!
//! This short file is a somewhat big conceptual piece of the architecture of
//! rust-analyzer, so it's worth elaborating on the underlying ideas and
//! motivation.
//!
//! For rust-analyzer to function, it needs some information about the project.
//! Specifically, it maintains an in-memory data structure which lists all the
//! crates (compilation units) and dependencies between them. This is necessary
//! a global singleton, as we do want, eg, find usages to always search across
//! the whole project, rather than just in the "current" crate.
//!
//! Normally, we get this "crate graph" by calling `cargo metadata
//! --message-format=json` for each cargo workspace and merging results. This
//! works for your typical cargo project, but breaks down for large folks who
//! have a monorepo with an infinite amount of Rust code which is built with bazel or
//! some such.
//!
//! To support this use case, we need to make _something_ configurable. To avoid
//! a [midlayer mistake](https://lwn.net/Articles/336262/), we allow configuring
//! the lowest possible layer. `ProjectJson` is essentially a hook to just set
//! that global singleton in-memory data structure. It is optimized for power,
//! not for convenience (you'd be using cargo anyway if you wanted nice things,
//! right? :)
//!
//! `rust-project.json` also isn't necessary a file. Architecturally, we support
//! any convenient way to specify this data, which today is:
//!
//! * file on disk
//! * a field in the config (ie, you can send a JSON request with the contents
//!   of rust-project.json to rust-analyzer, no need to write anything to disk)
//!
//! Another possible thing we don't do today, but which would be totally valid,
//! is to add an extension point to VS Code extension to register custom
//! project.
//!
//! In general, it is assumed that if you are going to use `rust-project.json`,
//! you'd write a fair bit of custom code gluing your build system to ra through
//! this JSON format. This logic can take form of a VS Code extension, or a
//! proxy process which injects data into "configure" LSP request, or maybe just
//! a simple build system rule to generate the file.
//!
//! In particular, the logic for lazily loading parts of the monorepo as the
//! user explores them belongs to that extension (it's totally valid to change
//! rust-project.json over time via configuration request!)

use base_db::{CrateDisplayName, CrateName};
use paths::{AbsPath, AbsPathBuf, Utf8PathBuf};
use rustc_hash::FxHashMap;
use serde::{de, Deserialize, Serialize};
use span::Edition;
use std::path::PathBuf;
use std::process::Command;

use crate::cfg::CfgFlag;
use crate::ManifestPath;
use crate::TargetKind;

/// Roots and crates that compose this Rust project.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectJson {
    /// e.g. `path/to/sysroot`
    pub(crate) sysroot: Option<AbsPathBuf>,
    /// e.g. `path/to/sysroot/lib/rustlib/src/rust`
    pub(crate) sysroot_src: Option<AbsPathBuf>,
    project_root: AbsPathBuf,
    manifest: Option<ManifestPath>,
    crates: Vec<Crate>,
}

/// A crate points to the root module of a crate and lists the dependencies of the crate. This is
/// useful in creating the crate graph.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Crate {
    pub display_name: Option<CrateDisplayName>,
    pub root_module: AbsPathBuf,
    pub(crate) edition: Edition,
    pub(crate) version: Option<String>,
    pub(crate) deps: Vec<Dep>,
    pub(crate) cfg: Vec<CfgFlag>,
    pub(crate) target: Option<String>,
    pub(crate) env: FxHashMap<String, String>,
    pub(crate) proc_macro_dylib_path: Option<AbsPathBuf>,
    pub(crate) is_workspace_member: bool,
    pub(crate) include: Vec<AbsPathBuf>,
    pub(crate) exclude: Vec<AbsPathBuf>,
    pub(crate) is_proc_macro: bool,
    pub(crate) repository: Option<String>,
    pub build_info: Option<BuildInfo>,
}

/// Additional metadata about a crate, used to configure runnables.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BuildInfo {
    /// The name associated with this crate, according to the custom
    /// build system being used.
    pub label: String,
    /// What kind of target is this crate? For example, we don't want
    /// to offer a 'run' button for library crates.
    pub target_kind: TargetKind,
    /// Configuration for shell commands, such as CLI invocations for
    /// a check build or a test run.
    pub shell_runnables: Vec<ShellRunnableArgs>,
}

impl ProjectJson {
    /// Create a new ProjectJson instance.
    ///
    /// # Arguments
    ///
    /// * `base` - The path to the workspace root (i.e. the folder containing `rust-project.json`)
    /// * `data` - The parsed contents of `rust-project.json`, or project json that's passed via
    ///            configuration.
    pub fn new(
        manifest: Option<ManifestPath>,
        base: &AbsPath,
        data: ProjectJsonData,
    ) -> ProjectJson {
        let absolutize_on_base = |p| base.absolutize(p);
        ProjectJson {
            sysroot: data.sysroot.map(absolutize_on_base),
            sysroot_src: data.sysroot_src.map(absolutize_on_base),
            project_root: base.to_path_buf(),
            manifest,
            crates: data
                .crates
                .into_iter()
                .map(|crate_data| {
                    let root_module = absolutize_on_base(crate_data.root_module);
                    let is_workspace_member = crate_data
                        .is_workspace_member
                        .unwrap_or_else(|| root_module.starts_with(base));
                    let (include, exclude) = match crate_data.source {
                        Some(src) => {
                            let absolutize = |dirs: Vec<Utf8PathBuf>| {
                                dirs.into_iter().map(absolutize_on_base).collect::<Vec<_>>()
                            };
                            (absolutize(src.include_dirs), absolutize(src.exclude_dirs))
                        }
                        None => (vec![root_module.parent().unwrap().to_path_buf()], Vec::new()),
                    };

                    let build_info = match crate_data.build_info {
                        Some(build_info) => Some(BuildInfo {
                            label: build_info.label,
                            target_kind: build_info.target_kind.into(),
                            shell_runnables: build_info.shell_runnables,
                        }),
                        None => None,
                    };

                    Crate {
                        display_name: crate_data
                            .display_name
                            .map(CrateDisplayName::from_canonical_name),
                        root_module,
                        edition: crate_data.edition.into(),
                        version: crate_data.version.as_ref().map(ToString::to_string),
                        deps: crate_data.deps,
                        cfg: crate_data.cfg,
                        target: crate_data.target,
                        env: crate_data.env,
                        proc_macro_dylib_path: crate_data
                            .proc_macro_dylib_path
                            .map(absolutize_on_base),
                        is_workspace_member,
                        include,
                        exclude,
                        is_proc_macro: crate_data.is_proc_macro,
                        repository: crate_data.repository,
                        build_info,
                    }
                })
                .collect(),
        }
    }

    /// Returns the number of crates in the project.
    pub fn n_crates(&self) -> usize {
        self.crates.len()
    }

    /// Returns an iterator over the crates in the project.
    pub fn crates(&self) -> impl Iterator<Item = (CrateArrayIdx, &Crate)> {
        self.crates.iter().enumerate().map(|(idx, krate)| (CrateArrayIdx(idx), krate))
    }

    /// Returns the path to the project's root folder.
    pub fn path(&self) -> &AbsPath {
        &self.project_root
    }

    /// Returns the path to the project's manifest or root folder, if no manifest exists.
    pub fn manifest_or_root(&self) -> &AbsPath {
        self.manifest.as_ref().map_or(&self.project_root, |manifest| manifest.as_ref())
    }

    pub fn crate_by_root(&self, root: &AbsPath) -> Option<&Crate> {
        self.crates
            .iter()
            .filter(|krate| krate.is_workspace_member)
            .find(|krate| krate.root_module == root)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ProjectJsonData {
    sysroot: Option<Utf8PathBuf>,
    sysroot_src: Option<Utf8PathBuf>,
    crates: Vec<CrateData>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct CrateData {
    display_name: Option<String>,
    root_module: Utf8PathBuf,
    edition: EditionData,
    #[serde(default)]
    version: Option<semver::Version>,
    deps: Vec<Dep>,
    #[serde(default)]
    cfg: Vec<CfgFlag>,
    target: Option<String>,
    #[serde(default)]
    env: FxHashMap<String, String>,
    proc_macro_dylib_path: Option<Utf8PathBuf>,
    is_workspace_member: Option<bool>,
    source: Option<CrateSource>,
    #[serde(default)]
    is_proc_macro: bool,
    #[serde(default)]
    repository: Option<String>,
    #[serde(default)]
    build_info: Option<BuildInfoData>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename = "edition")]
enum EditionData {
    #[serde(rename = "2015")]
    Edition2015,
    #[serde(rename = "2018")]
    Edition2018,
    #[serde(rename = "2021")]
    Edition2021,
    #[serde(rename = "2024")]
    Edition2024,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BuildInfoData {
    label: String,
    target_kind: TargetKindData,
    shell_runnables: Vec<ShellRunnableArgs>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ShellRunnableArgs {
    pub program: String,
    pub args: Vec<String>,
    pub cwd: PathBuf,
    pub kind: ShellRunnableKind,
}

impl ShellRunnableArgs {
    pub fn to_command(&self) -> Command {
        let mut cmd = Command::new(&self.program);
        cmd.args(&self.args).current_dir(&self.cwd);
        cmd
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum ShellRunnableKind {
    Flycheck,
    Check,
    Run,
    TestOne,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum TargetKindData {
    Bin,
    /// Any kind of Cargo lib crate-type (dylib, rlib, proc-macro, ...).
    Lib,
    Test,
}

impl From<TargetKindData> for TargetKind {
    fn from(value: TargetKindData) -> Self {
        match value {
            TargetKindData::Bin => TargetKind::Bin,
            TargetKindData::Lib => TargetKind::Lib { is_proc_macro: false },
            TargetKindData::Test => TargetKind::Test,
        }
    }
}

impl From<EditionData> for Edition {
    fn from(data: EditionData) -> Self {
        match data {
            EditionData::Edition2015 => Edition::Edition2015,
            EditionData::Edition2018 => Edition::Edition2018,
            EditionData::Edition2021 => Edition::Edition2021,
            EditionData::Edition2024 => Edition::Edition2024,
        }
    }
}

/// Identifies a crate by position in the crates array.
///
/// This will differ from `CrateId` when multiple `ProjectJson`
/// workspaces are loaded.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, Eq, PartialEq, Hash)]
#[serde(transparent)]
pub struct CrateArrayIdx(pub usize);

#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq)]
pub(crate) struct Dep {
    /// Identifies a crate by position in the crates array.
    #[serde(rename = "crate")]
    pub(crate) krate: CrateArrayIdx,
    #[serde(serialize_with = "serialize_crate_name")]
    #[serde(deserialize_with = "deserialize_crate_name")]
    pub(crate) name: CrateName,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct CrateSource {
    include_dirs: Vec<Utf8PathBuf>,
    exclude_dirs: Vec<Utf8PathBuf>,
}

fn deserialize_crate_name<'de, D>(de: D) -> std::result::Result<CrateName, D::Error>
where
    D: de::Deserializer<'de>,
{
    let name = String::deserialize(de)?;
    CrateName::new(&name).map_err(|err| de::Error::custom(format!("invalid crate name: {err:?}")))
}

fn serialize_crate_name<S>(name: &CrateName, se: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    se.serialize_str(name)
}

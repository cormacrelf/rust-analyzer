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
//!   of `rust-project.json` to rust-analyzer, no need to write anything to disk)
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
use cfg::CfgAtom;
use paths::{AbsPath, AbsPathBuf, Utf8PathBuf};
use rustc_hash::{FxHashMap, FxHashSet};
use serde::{de, Deserialize, Serialize};
use span::Edition;

use crate::{ManifestPath, TargetKind};

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
    /// Configuration for CLI commands.
    ///
    /// Examples include a check build or a test run.
    runnables: Vec<Runnable>,
}

impl ProjectJson {
    /// Create a new ProjectJson instance.
    ///
    /// # Arguments
    ///
    /// * `manifest` - The path to the `rust-project.json`.
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
            runnables: data.runnables.into_iter().map(Runnable::from).collect(),
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

                    let build = match crate_data.build {
                        Some(build) => Some(Build {
                            label: build.label,
                            build_file: build.build_file,
                            target_kind: build.target_kind.into(),
                        }),
                        None => None,
                    };

                    let cfg = crate_data
                        .cfg_groups
                        .iter()
                        .flat_map(|cfg_extend| {
                            let cfg_group = data.cfg_groups.get(cfg_extend);
                            match cfg_group {
                                Some(cfg_group) => cfg_group.0.iter().cloned(),
                                None => {
                                    tracing::error!(
                                        "Unknown cfg group `{cfg_extend}` in crate `{}`",
                                        crate_data.display_name.as_deref().unwrap_or("<unknown>"),
                                    );
                                    [].iter().cloned()
                                }
                            }
                        })
                        .chain(crate_data.cfg.0)
                        .collect();

                    Crate {
                        display_name: crate_data
                            .display_name
                            .as_deref()
                            .map(CrateDisplayName::from_canonical_name),
                        root_module,
                        edition: crate_data.edition.into(),
                        version: crate_data.version.as_ref().map(ToString::to_string),
                        deps: crate_data.deps,
                        cfg,
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
                        build,
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

    pub fn crate_by_root(&self, root: &AbsPath) -> Option<&Crate> {
        self.crates
            .iter()
            .filter(|krate| krate.is_workspace_member)
            .find(|krate| krate.root_module == root)
    }

    /// Returns the path to the project's manifest, if it exists.
    pub fn manifest(&self) -> Option<&ManifestPath> {
        self.manifest.as_ref()
    }

    pub fn crate_by_buildfile(&self, path: &AbsPath) -> Option<Build> {
        // this is fast enough for now, but it's unfortunate that this is O(crates).
        let path: &std::path::Path = path.as_ref();
        self.crates
            .iter()
            .filter(|krate| krate.is_workspace_member)
            .filter_map(|krate| krate.build.clone())
            .find(|build| build.build_file.as_std_path() == path)
    }

    /// Returns the path to the project's manifest or root folder, if no manifest exists.
    pub fn manifest_or_root(&self) -> &AbsPath {
        self.manifest.as_ref().map_or(&self.project_root, |manifest| manifest.as_ref())
    }

    /// Returns the path to the project's root folder.
    pub fn project_root(&self) -> &AbsPath {
        &self.project_root
    }

    pub fn runnables(&self) -> &[Runnable] {
        &self.runnables
    }

    pub fn runnable_template(&self, kind: RunnableKind) -> Option<&Runnable> {
        self.runnables().iter().find(|r| r.kind == kind)
    }
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
    pub(crate) cfg: Vec<CfgAtom>,
    pub(crate) target: Option<String>,
    pub(crate) env: FxHashMap<String, String>,
    pub(crate) proc_macro_dylib_path: Option<AbsPathBuf>,
    pub(crate) is_workspace_member: bool,
    pub(crate) include: Vec<AbsPathBuf>,
    pub(crate) exclude: Vec<AbsPathBuf>,
    pub(crate) is_proc_macro: bool,
    pub(crate) repository: Option<String>,
    pub build: Option<Build>,
}

/// Additional, build-specific data about a crate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Build {
    /// The name associated with this crate.
    ///
    /// This is determined by the build system that produced
    /// the `rust-project.json` in question. For instance, if buck were used,
    /// the label might be something like `//ide/rust/rust-analyzer:rust-analyzer`.
    ///
    /// Do not attempt to parse the contents of this string; it is a build system-specific
    /// identifier similar to [`Crate::display_name`].
    pub label: String,
    /// Path corresponding to the build system-specific file defining the crate.
    ///
    /// It is roughly analogous to [`ManifestPath`], but it should *not* be used with
    /// [`crate::ProjectManifest::from_manifest_file`], as the build file may not be
    /// be in the `rust-project.json`.
    pub build_file: Utf8PathBuf,
    /// The kind of target.
    ///
    /// Examples (non-exhaustively) include [`TargetKind::Bin`], [`TargetKind::Lib`],
    /// and [`TargetKind::Test`]. This information is used to determine what sort
    /// of runnable codelens to provide, if any.
    pub target_kind: TargetKind,
}

/// A template-like structure for describing runnables.
///
/// These are used for running and debugging binaries and tests without encoding
/// build system-specific knowledge into rust-analyzer.
///
/// # Example
///
/// Below is an example of a test runnable. `{label}` and `{test_id}`
/// are explained in [`Runnable::args`]'s documentation.
///
/// ```json
/// {
///     "program": "buck",
///     "args": [
///         "test",
///          "{label}",
///          "--",
///          "{test_id}",
///          "--print-passing-details"
///     ],
///     "cwd": "/home/user/repo-root/",
///     "kind": "testOne"
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Runnable {
    /// The program invoked by the runnable.
    ///
    /// For example, this might be `cargo`, `buck`, or `bazel`.
    pub program: String,
    /// The arguments passed to [`Runnable::program`].
    ///
    /// The args can contain two template strings: `{label}` and `{test_id}`.
    /// rust-analyzer will find and replace `{label}` with [`Build::label`] and
    /// `{test_id}` with the test name.
    pub args: Vec<String>,
    /// The current working directory of the runnable.
    pub cwd: Utf8PathBuf,
    pub kind: RunnableKind,
}

/// The kind of runnable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunnableKind {
    Check,

    /// Can run a binary.
    Run,

    /// Run a single test.
    TestOne,

    /// Template for checking a target, emitting rustc JSON diagnostics.
    /// May include {label} which will get the label from the `build` section of a crate.
    Flycheck,
}

#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq)]
pub struct ProjectJsonData {
    sysroot: Option<Utf8PathBuf>,
    sysroot_src: Option<Utf8PathBuf>,
    #[serde(default)]
    cfg_groups: FxHashMap<String, CfgList>,
    crates: Vec<CrateData>,
    #[serde(default)]
    runnables: Vec<RunnableData>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq, Default)]
#[serde(transparent)]
struct CfgList(#[serde(with = "cfg_")] Vec<CfgAtom>);

#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq)]
struct CrateData {
    display_name: Option<String>,
    root_module: Utf8PathBuf,
    edition: EditionData,
    #[serde(default)]
    version: Option<semver::Version>,
    deps: Vec<Dep>,
    #[serde(default)]
    cfg_groups: FxHashSet<String>,
    #[serde(default)]
    cfg: CfgList,
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
    build: Option<BuildData>,
}

mod cfg_ {
    use cfg::CfgAtom;
    use serde::{Deserialize, Serialize};

    pub(super) fn deserialize<'de, D>(deserializer: D) -> Result<Vec<CfgAtom>, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let cfg: Vec<String> = Vec::deserialize(deserializer)?;
        cfg.into_iter().map(|it| crate::parse_cfg(&it).map_err(serde::de::Error::custom)).collect()
    }
    pub(super) fn serialize<S>(cfg: &[CfgAtom], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        cfg.iter()
            .map(|cfg| match cfg {
                CfgAtom::Flag(flag) => flag.as_str().to_owned(),
                CfgAtom::KeyValue { key, value } => {
                    format!("{}=\"{}\"", key.as_str(), value.as_str())
                }
            })
            .collect::<Vec<String>>()
            .serialize(serializer)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq)]
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

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct BuildData {
    label: String,
    build_file: Utf8PathBuf,
    target_kind: TargetKindData,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunnableData {
    pub program: String,
    pub args: Vec<String>,
    pub cwd: Utf8PathBuf,
    pub kind: RunnableKindData,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum RunnableKindData {
    Flycheck,
    Check,
    Run,
    TestOne,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum TargetKindData {
    Bin,
    /// Any kind of Cargo lib crate-type (dylib, rlib, proc-macro, ...).
    Lib,
    Test,
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

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
struct CrateSource {
    include_dirs: Vec<Utf8PathBuf>,
    exclude_dirs: Vec<Utf8PathBuf>,
}

impl From<TargetKindData> for TargetKind {
    fn from(data: TargetKindData) -> Self {
        match data {
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

impl From<RunnableData> for Runnable {
    fn from(data: RunnableData) -> Self {
        Runnable { program: data.program, args: data.args, cwd: data.cwd, kind: data.kind.into() }
    }
}

impl From<RunnableKindData> for RunnableKind {
    fn from(data: RunnableKindData) -> Self {
        match data {
            RunnableKindData::Check => RunnableKind::Check,
            RunnableKindData::Run => RunnableKind::Run,
            RunnableKindData::TestOne => RunnableKind::TestOne,
            RunnableKindData::Flycheck => RunnableKind::Flycheck,
        }
    }
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

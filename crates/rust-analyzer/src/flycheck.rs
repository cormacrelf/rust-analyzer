//! Flycheck provides the functionality needed to run `cargo check` to provide
//! LSP diagnostics based on the output of the command.

use std::{fmt, io, process::Command, time::Duration};

use crossbeam_channel::{select_biased, unbounded, Receiver, Sender};
use paths::{AbsPath, AbsPathBuf, Utf8PathBuf};
use project_model::{project_json, TargetKind};
use rustc_hash::FxHashMap;
use serde::Deserialize;

pub(crate) use cargo_metadata::diagnostic::{
    Applicability, Diagnostic, DiagnosticCode, DiagnosticLevel, DiagnosticSpan,
};
use toolchain::Tool;

use crate::command::{CommandHandle, ParseFromLine};

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) enum InvocationStrategy {
    Once,
    #[default]
    PerWorkspace,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CargoOptions {
    pub(crate) target_triples: Vec<String>,
    pub(crate) all_targets: bool,
    pub(crate) no_default_features: bool,
    pub(crate) all_features: bool,
    pub(crate) features: Vec<String>,
    pub(crate) extra_args: Vec<String>,
    pub(crate) extra_test_bin_args: Vec<String>,
    pub(crate) extra_env: FxHashMap<String, String>,
    pub(crate) target_dir: Option<Utf8PathBuf>,
}

/// `--bin rust-analyzer`, `--example example-1`, `--bench microbenchmark`, `--test integrationtest2`
#[derive(Clone, Debug)]
pub(crate) enum BinTarget {
    /// --bin rust-analyzer
    Bin(String),
    /// --example example
    Example(String),
    /// -- bench microbenchmark
    Bench(String),
    /// --test integrationtest2
    Test(String),
}

impl BinTarget {
    pub(crate) fn from_target_kind(kind: TargetKind, name: impl Into<String>) -> Option<Self> {
        let name = name.into();
        Some(match kind {
            TargetKind::Bin => BinTarget::Bin(name),
            TargetKind::Example => BinTarget::Example(name),
            TargetKind::Bench => BinTarget::Bench(name),
            TargetKind::Test => BinTarget::Test(name),
            _ => return None,
        })
    }

    /// For e.g. this crate, we have `rust-analyzer` as the package name, and
    /// `rust-analyzer` as the binary target name. This is the latter, the
    /// binary target name.
    pub(crate) fn name(&self) -> &str {
        match self {
            BinTarget::Bin(it)
            | BinTarget::Example(it)
            | BinTarget::Bench(it)
            | BinTarget::Test(it) => it,
        }
    }

    #[allow(unused)]
    pub(crate) fn target_kind(&self) -> TargetKind {
        match self {
            BinTarget::Bin(_) => TargetKind::Bin,
            BinTarget::Example(_) => TargetKind::Example,
            BinTarget::Bench(_) => TargetKind::Bench,
            BinTarget::Test(_) => TargetKind::Test,
        }
    }

    pub(crate) fn append_cargo_arg<'a>(&self, cmd: &'a mut Command) -> &'a mut Command {
        match self {
            BinTarget::Bin(it) => cmd.arg("--bin").arg(it),
            BinTarget::Example(it) => cmd.arg("--example").arg(it),
            BinTarget::Bench(it) => cmd.arg("--bench").arg(it),
            BinTarget::Test(it) => cmd.arg("--test").arg(it),
        }
    }
}

impl CargoOptions {
    pub(crate) fn apply_on_command(&self, cmd: &mut Command) {
        for target in &self.target_triples {
            cmd.args(["--target", target.as_str()]);
        }
        if self.all_targets {
            cmd.arg("--all-targets");
        }
        if self.all_features {
            cmd.arg("--all-features");
        } else {
            if self.no_default_features {
                cmd.arg("--no-default-features");
            }
            if !self.features.is_empty() {
                cmd.arg("--features");
                cmd.arg(self.features.join(" "));
            }
        }
        if let Some(target_dir) = &self.target_dir {
            cmd.arg("--target-dir").arg(target_dir);
        }
        cmd.envs(&self.extra_env);
    }
}

/// The flycheck config from a rust-project.json file
#[derive(Debug, Default)]
pub(crate) struct FlycheckConfigJson {
    // XXX: unimplemented because not all that important> nobody
    // doing custom rust-project.json needs it most likely
    // pub workspace_template: Option<project_json::Runnable>,
    //
    /// The template with [project_json::RunnableKind::Flycheck]
    pub single_template: Option<project_json::Runnable>,
}

impl FlycheckConfigJson {
    pub(crate) fn any_configured(&self) -> bool {
        // self.workspace_template.is_some() ||
        self.single_template.is_some()
    }
}

/// The flycheck config from rust-analyzer's own configuration.
///
/// We rely on this when rust-project.json does not specify a flycheck runnable
///
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum FlycheckConfig {
    CargoCommand {
        command: String,
        options: CargoOptions,
        ansi_color_output: bool,
    },
    CustomCommand {
        command: String,
        args: Vec<String>,
        extra_env: FxHashMap<String, String>,
        invocation_strategy: InvocationStrategy,
    },
}

impl fmt::Display for FlycheckConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FlycheckConfig::CargoCommand { command, .. } => write!(f, "cargo {command}"),
            FlycheckConfig::CustomCommand { command, args, .. } => {
                write!(f, "{command} {}", args.join(" "))
            }
        }
    }
}

/// Flycheck wraps the shared state and communication machinery used for
/// running `cargo check` (or other compatible command) and providing
/// diagnostics based on the output.
/// The spawned thread is shut down when this struct is dropped.
#[derive(Debug)]
pub(crate) struct FlycheckHandle {
    // XXX: drop order is significant
    sender: Sender<StateChange>,
    _thread: stdx::thread::JoinHandle,
    id: usize,

    /// Bit hacky, but this lets us force the use of restart_for_package when the flycheck
    /// configuration does not support restart_workspace.
    cannot_run_workspace: bool,
}

impl FlycheckHandle {
    pub(crate) fn spawn(
        id: usize,
        sender: Sender<FlycheckMessage>,
        config: FlycheckConfig,
        config_json: FlycheckConfigJson,
        sysroot_root: Option<AbsPathBuf>,
        workspace_root: AbsPathBuf,
        manifest_path: Option<AbsPathBuf>,
    ) -> FlycheckHandle {
        let actor = FlycheckActor::new(
            id,
            sender,
            config,
            config_json,
            sysroot_root,
            workspace_root,
            manifest_path,
        );

        let cannot_run_workspace = actor.cannot_run_workspace();

        let (sender, receiver) = unbounded::<StateChange>();
        let thread = stdx::thread::Builder::new(stdx::thread::ThreadIntent::Worker)
            .name("Flycheck".to_owned())
            .spawn(move || actor.run(receiver))
            .expect("failed to spawn thread");
        FlycheckHandle { id, sender, _thread: thread, cannot_run_workspace }
    }

    /// Schedule a re-start of the cargo check worker to do a workspace wide check.
    pub(crate) fn restart_workspace(&self, saved_file: Option<AbsPathBuf>) {
        self.sender
            .send(StateChange::Restart { package: PackageToRestart::All, saved_file })
            .unwrap();
    }

    pub(crate) fn cannot_run_workspace(&self) -> bool {
        self.cannot_run_workspace
    }

    /// Schedule a re-start of the cargo check worker to do a package wide check.
    pub(crate) fn restart_for_package(&self, package: PackageSpecifier) {
        self.sender
            .send(StateChange::Restart {
                package: PackageToRestart::Package(package),
                saved_file: None,
            })
            .unwrap();
    }

    /// Stop this cargo check worker.
    pub(crate) fn cancel(&self) {
        self.sender.send(StateChange::Cancel).unwrap();
    }

    pub(crate) fn id(&self) -> usize {
        self.id
    }
}

pub(crate) enum FlycheckMessage {
    /// Request adding a diagnostic with fixes included to a file
    AddDiagnostic { id: usize, workspace_root: AbsPathBuf, diagnostic: Diagnostic },

    /// Request clearing all previous diagnostics
    ClearDiagnostics { id: usize },

    /// Request check progress notification to client
    Progress {
        /// Flycheck instance ID
        id: usize,
        progress: Progress,
    },
}

impl fmt::Debug for FlycheckMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FlycheckMessage::AddDiagnostic { id, workspace_root, diagnostic } => f
                .debug_struct("AddDiagnostic")
                .field("id", id)
                .field("workspace_root", workspace_root)
                .field("diagnostic_code", &diagnostic.code.as_ref().map(|it| &it.code))
                .finish(),
            FlycheckMessage::ClearDiagnostics { id } => {
                f.debug_struct("ClearDiagnostics").field("id", id).finish()
            }
            FlycheckMessage::Progress { id, progress } => {
                f.debug_struct("Progress").field("id", id).field("progress", progress).finish()
            }
        }
    }
}

#[derive(Debug)]
pub(crate) enum Progress {
    DidStart {
        /// The user sees this in VSCode, etc. May be a shortened version of the command we actually
        /// executed, otherwise it is way too long.
        user_facing_command: String,
    },
    DidCheckCrate(String),
    DidFinish(io::Result<()>),
    DidCancel,
    DidFailToRestart(String),
}

#[derive(Debug, Clone)]
enum PackageToRestart {
    All,
    // Either a cargo package or a $label in rust-project.check.overrideCommand
    Package(PackageSpecifier),
}

#[derive(Debug)]
enum FlycheckCommandOrigin {
    /// Regular cargo invocation
    Cargo,
    /// Configured via check_overrideCommand
    CheckOverrideCommand,
    /// From a runnable with [project_json::RunnableKind::Flycheck]
    ProjectJsonRunnable,
}

#[derive(Debug, Clone)]
pub(crate) enum PackageSpecifier {
    Cargo {
        /// The one in Cargo.toml, assumed to work with `cargo check -p {}` etc
        ///
        /// PackageData.name works.
        cargo_canonical_name: String,
        /// Ask cargo to build a specific --bin, --test, --bench
        bin_target: Option<BinTarget>,
    },
    BuildInfo {
        /// If a `build` field is present in rust-project.json, its label field
        label: String,
    },
}

enum StateChange {
    Restart { package: PackageToRestart, saved_file: Option<AbsPathBuf> },
    Cancel,
}

/// A [`FlycheckActor`] is a single check instance of a workspace.
struct FlycheckActor {
    /// The workspace id of this flycheck instance.
    id: usize,
    sender: Sender<FlycheckMessage>,
    config: FlycheckConfig,
    config_json: FlycheckConfigJson,
    /// If we are flychecking a cargo workspace, this will point to the workspace Cargo.toml
    manifest_path: Option<AbsPathBuf>,
    /// Either the workspace root of the workspace we are flychecking,
    /// or the project root of the project.
    root: AbsPathBuf,
    sysroot_root: Option<AbsPathBuf>,
    /// CargoHandle exists to wrap around the communication needed to be able to
    /// run `cargo check` without blocking. Currently the Rust standard library
    /// doesn't provide a way to read sub-process output without blocking, so we
    /// have to wrap sub-processes output handling in a thread and pass messages
    /// back over a channel.
    command_handle: Option<CommandHandle<CargoCheckMessage>>,
    /// The receiver side of the channel mentioned above.
    command_receiver: Option<Receiver<CargoCheckMessage>>,

    status: FlycheckStatus,
}

#[allow(clippy::large_enum_variant)]
enum Event {
    RequestStateChange(StateChange),
    CheckEvent(Option<CargoCheckMessage>),
}

#[derive(PartialEq)]
enum FlycheckStatus {
    Started,
    DiagnosticSent,
    Finished,
}

/// This is stable behaviour. Don't change.
const SAVED_FILE_PLACEHOLDER: &str = "$saved_file";
const LABEL_INLINE: &str = "{label}";

struct Substitutions<'a> {
    label: Option<&'a str>,
    saved_file: Option<&'a str>,
}

impl<'a> Substitutions<'a> {
    /// If you have a runnable, and it has {label} in it somewhere, treat it as a template that
    /// may be unsatisfied if you do not provide a label to substitute into it. Returns None in
    /// that situation. Otherwise performs the requested substitutions.
    ///
    fn substitute(self, template: &project_json::Runnable) -> Option<Command> {
        let mut cmd = Command::new(&template.program);
        let mut label_satisfied = self.label.is_none();
        let mut saved_file_satisfied = self.saved_file.is_none();
        for arg in &template.args {
            if let Some(ix) = arg.find(LABEL_INLINE) {
                if let Some(label) = self.label {
                    let mut arg = arg.to_string();
                    arg.replace_range(ix..ix + LABEL_INLINE.len(), label);
                    cmd.arg(arg);
                    label_satisfied = true;
                    continue;
                } else {
                    return None;
                }
            }
            if arg == SAVED_FILE_PLACEHOLDER {
                if let Some(saved_file) = self.saved_file {
                    cmd.arg(saved_file);
                    saved_file_satisfied = true;
                    continue;
                } else {
                    return None;
                }
            }
            cmd.arg(arg);
        }
        if label_satisfied && saved_file_satisfied {
            cmd.current_dir(&template.cwd);
            Some(cmd)
        } else {
            None
        }
    }
}

impl FlycheckActor {
    fn new(
        id: usize,
        sender: Sender<FlycheckMessage>,
        config: FlycheckConfig,
        config_json: FlycheckConfigJson,
        sysroot_root: Option<AbsPathBuf>,
        workspace_root: AbsPathBuf,
        manifest_path: Option<AbsPathBuf>,
    ) -> FlycheckActor {
        tracing::info!(%id, ?workspace_root, "Spawning flycheck");
        FlycheckActor {
            id,
            sender,
            config,
            config_json,
            sysroot_root,
            root: workspace_root,
            manifest_path,
            command_handle: None,
            command_receiver: None,
            status: FlycheckStatus::Finished,
        }
    }

    fn report_progress(&self, progress: Progress) {
        self.send(FlycheckMessage::Progress { id: self.id, progress });
    }

    fn next_event(&self, inbox: &Receiver<StateChange>) -> Option<Event> {
        let Some(command_receiver) = &self.command_receiver else {
            return inbox.recv().ok().map(Event::RequestStateChange);
        };

        // Biased to give restarts a preference so check outputs don't block a restart or stop
        select_biased! {
            recv(inbox) -> msg => msg.ok().map(Event::RequestStateChange),
            recv(command_receiver) -> msg => Some(Event::CheckEvent(msg.ok())),
        }
    }

    fn run(mut self, inbox: Receiver<StateChange>) {
        'event: while let Some(event) = self.next_event(&inbox) {
            match event {
                Event::RequestStateChange(StateChange::Cancel) => {
                    tracing::debug!(flycheck_id = self.id, "flycheck cancelled");
                    self.cancel_check_process();
                }
                Event::RequestStateChange(StateChange::Restart { package, saved_file }) => {
                    // Cancel the previously spawned process
                    self.cancel_check_process();
                    while let Ok(restart) = inbox.recv_timeout(Duration::from_millis(50)) {
                        // restart chained with a stop, so just cancel
                        if let StateChange::Cancel = restart {
                            continue 'event;
                        }
                    }

                    let Some((command, origin)) =
                        self.check_command(package.clone(), saved_file.as_deref())
                    else {
                        tracing::debug!(?package, "failed to build flycheck command");
                        continue;
                    };

                    let debug_command = format!("{command:?}");
                    let user_facing_command = match origin {
                        // Don't show all the --format=json-with-blah-blah args, just the simple
                        // version
                        FlycheckCommandOrigin::Cargo => self.config.to_string(),
                        // show them the full command but pretty printed. advanced user
                        FlycheckCommandOrigin::ProjectJsonRunnable
                        | FlycheckCommandOrigin::CheckOverrideCommand => display_command(
                            &command,
                            Some(std::path::Path::new(self.root.as_path())),
                        ),
                    };

                    tracing::debug!(?origin, ?command, "will restart flycheck");
                    let (sender, receiver) = unbounded();
                    match CommandHandle::spawn(command, sender) {
                        Ok(command_handle) => {
                            tracing::debug!(?origin, command = %debug_command, "did restart flycheck");
                            self.command_handle = Some(command_handle);
                            self.command_receiver = Some(receiver);
                            self.report_progress(Progress::DidStart { user_facing_command });
                            self.status = FlycheckStatus::Started;
                        }
                        Err(error) => {
                            self.report_progress(Progress::DidFailToRestart(format!(
                                "Failed to run the following command: {debug_command} origin={origin:?} error={error}"
                            )));
                            self.status = FlycheckStatus::Finished;
                        }
                    }
                }
                Event::CheckEvent(None) => {
                    tracing::debug!(flycheck_id = self.id, "flycheck finished");

                    // Watcher finished
                    let command_handle = self.command_handle.take().unwrap();
                    self.command_receiver.take();
                    let formatted_handle = format!("{command_handle:?}");

                    let res = command_handle.join();
                    if let Err(error) = &res {
                        tracing::error!(
                            "Flycheck failed to run the following command: {}, error={}",
                            formatted_handle,
                            error
                        );
                    }
                    if self.status == FlycheckStatus::Started {
                        self.send(FlycheckMessage::ClearDiagnostics { id: self.id });
                    }
                    self.report_progress(Progress::DidFinish(res));
                    self.status = FlycheckStatus::Finished;
                }
                Event::CheckEvent(Some(message)) => match message {
                    CargoCheckMessage::CompilerArtifact(msg) => {
                        tracing::trace!(
                            flycheck_id = self.id,
                            artifact = msg.target.name,
                            "artifact received"
                        );
                        self.report_progress(Progress::DidCheckCrate(msg.target.name));
                    }

                    CargoCheckMessage::Diagnostic(msg) => {
                        tracing::trace!(
                            flycheck_id = self.id,
                            message = msg.message,
                            "diagnostic received"
                        );
                        if self.status == FlycheckStatus::Started {
                            self.send(FlycheckMessage::ClearDiagnostics { id: self.id });
                        }
                        self.send(FlycheckMessage::AddDiagnostic {
                            id: self.id,
                            workspace_root: self.root.clone(),
                            diagnostic: msg,
                        });
                        self.status = FlycheckStatus::DiagnosticSent;
                    }
                },
            }
        }
        // If we rerun the thread, we need to discard the previous check results first
        self.cancel_check_process();
    }

    fn cancel_check_process(&mut self) {
        if let Some(command_handle) = self.command_handle.take() {
            tracing::debug!(
                command = ?command_handle,
                "did  cancel flycheck"
            );
            command_handle.cancel();
            self.command_receiver.take();
            self.report_progress(Progress::DidCancel);
            self.status = FlycheckStatus::Finished;
        }
    }

    fn explicit_check_command(
        &self,
        package: PackageToRestart,
        saved_file: Option<&AbsPath>,
    ) -> Option<Command> {
        match package {
            PackageToRestart::All => {
                // If the template doesn't contain {label}, then it works for restarting all.
                //
                // Might be nice to have: self.config_json.workspace_template.as_ref().map(|x| x.to_command())
                // But for now this works.
                //
                let template = self.config_json.single_template.as_ref()?;
                let subs = Substitutions {
                    label: None,
                    saved_file: saved_file.map(|x| x.as_str()),
                };
                subs.substitute(template)
            }
            PackageToRestart::Package(
                PackageSpecifier::BuildInfo { label }
                // Treat missing build_info as implicitly setting label = the cargo canonical name
                //
                // Not sure what to do about --bin etc with custom override commands.
                | PackageSpecifier::Cargo { cargo_canonical_name: label, bin_target: _ },
            ) => {
                let template = self.config_json.single_template.as_ref()?;
                let subs = Substitutions {
                    label: Some(&label),
                    saved_file: saved_file.map(|x| x.as_str()),
                };
                subs.substitute(template)
            }
        }
    }

    fn cannot_run_workspace(&self) -> bool {
        let fake_path = self.root.join("fake.rs");
        self.check_command(PackageToRestart::All, Some(&fake_path)).is_none()
    }

    /// Construct a `Command` object for checking the user's code. If the user
    /// has specified a custom command with placeholders that we cannot fill,
    /// return None.
    fn check_command(
        &self,
        package: PackageToRestart,
        saved_file: Option<&AbsPath>,
    ) -> Option<(Command, FlycheckCommandOrigin)> {
        match &self.config {
            FlycheckConfig::CargoCommand { command, options, ansi_color_output } => {
                // Only use the rust-project.json's flycheck config when no check_overrideCommand
                // is configured. In the other branch we will still do label substitution but on
                // the overrideCommand instead.
                if self.config_json.any_configured() {
                    // Completely handle according to rust-project.json.
                    // We don't consider this to be "using cargo" so we will not apply any of the
                    // CargoOptions to the command.
                    let cmd = self.explicit_check_command(package, saved_file)?;
                    return Some((cmd, FlycheckCommandOrigin::ProjectJsonRunnable));
                }

                let mut cmd = Command::new(Tool::Cargo.path());
                if let Some(sysroot_root) = &self.sysroot_root {
                    cmd.env("RUSTUP_TOOLCHAIN", AsRef::<std::path::Path>::as_ref(sysroot_root));
                }
                cmd.arg(command);
                cmd.current_dir(&self.root);

                match package {
                    PackageToRestart::Package(PackageSpecifier::Cargo {
                        cargo_canonical_name,
                        bin_target,
                    }) => {
                        cmd.arg("-p").arg(cargo_canonical_name);
                        if let Some(tgt) = bin_target {
                            tgt.append_cargo_arg(&mut cmd);
                        }
                    }
                    PackageToRestart::Package(PackageSpecifier::BuildInfo { label: _ }) => {
                        // No way to flycheck this single package. All we have is a build label.
                        // There's no way to really say whether this build label happens to be
                        // a cargo canonical name, so we won't try.
                        return None;
                    }
                    PackageToRestart::All => {
                        cmd.arg("--workspace");
                    }
                };

                cmd.arg(if *ansi_color_output {
                    "--message-format=json-diagnostic-rendered-ansi"
                } else {
                    "--message-format=json"
                });

                if let Some(manifest_path) = &self.manifest_path {
                    cmd.arg("--manifest-path");
                    cmd.arg(manifest_path);
                    if manifest_path.extension().map_or(false, |ext| ext == "rs") {
                        cmd.arg("-Zscript");
                    }
                }

                cmd.arg("--keep-going");

                options.apply_on_command(&mut cmd);
                cmd.args(&options.extra_args);
                Some((cmd, FlycheckCommandOrigin::Cargo))
            }
            FlycheckConfig::CustomCommand { command, args, extra_env, invocation_strategy } => {
                let mut cmd = Command::new(command);
                cmd.envs(extra_env);
                let root = match invocation_strategy {
                    InvocationStrategy::Once => self.root.as_path(),
                    InvocationStrategy::PerWorkspace => {
                        // FIXME: should run in the affected_workspace?
                        self.root.as_path()
                    }
                };

                let runnable = project_json::Runnable {
                    program: command.clone(),
                    cwd: Utf8PathBuf::new(),
                    args: args.clone(),
                    kind: project_json::RunnableKind::Flycheck,
                };

                let label = match &package {
                    PackageToRestart::All => None,
                    PackageToRestart::Package(PackageSpecifier::BuildInfo { label }) => {
                        Some(label.as_ref())
                    }
                    PackageToRestart::Package(PackageSpecifier::Cargo {
                        cargo_canonical_name,
                        bin_target: _,
                    }) => Some(cargo_canonical_name.as_ref()),
                };

                let subs = Substitutions { label, saved_file: saved_file.map(|x| x.as_str()) };
                let mut cmd = subs.substitute(&runnable)?;
                cmd.envs(extra_env);
                cmd.current_dir(root);

                Some((cmd, FlycheckCommandOrigin::CheckOverrideCommand))
            }
        }
    }

    #[track_caller]
    fn send(&self, check_task: FlycheckMessage) {
        self.sender.send(check_task).unwrap();
    }
}

#[allow(clippy::large_enum_variant)]
enum CargoCheckMessage {
    CompilerArtifact(cargo_metadata::Artifact),
    Diagnostic(Diagnostic),
}

impl ParseFromLine for CargoCheckMessage {
    fn from_line(line: &str, error: &mut String) -> Option<Self> {
        let mut deserializer = serde_json::Deserializer::from_str(line);
        deserializer.disable_recursion_limit();
        if let Ok(message) = JsonMessage::deserialize(&mut deserializer) {
            return match message {
                // Skip certain kinds of messages to only spend time on what's useful
                JsonMessage::Cargo(message) => match message {
                    cargo_metadata::Message::CompilerArtifact(artifact) if !artifact.fresh => {
                        Some(CargoCheckMessage::CompilerArtifact(artifact))
                    }
                    cargo_metadata::Message::CompilerMessage(msg) => {
                        Some(CargoCheckMessage::Diagnostic(msg.message))
                    }
                    _ => None,
                },
                JsonMessage::Rustc(message) => Some(CargoCheckMessage::Diagnostic(message)),
            };
        }

        error.push_str(line);
        error.push('\n');
        None
    }

    fn from_eof() -> Option<Self> {
        None
    }
}

#[derive(Deserialize)]
#[serde(untagged)]
enum JsonMessage {
    Cargo(cargo_metadata::Message),
    Rustc(Diagnostic),
}

/// Not good enough to execute in a shell, but good enough to show the user without all the noisy
/// quotes
fn display_command(c: &Command, implicit_cwd: Option<&std::path::Path>) -> String {
    let mut o = String::new();
    use std::fmt::Write;
    let lossy = std::ffi::OsStr::to_string_lossy;
    if let Some(dir) = c.get_current_dir() {
        if Some(dir) == implicit_cwd.map(std::path::Path::new) {
            // pass
        } else if dir.to_string_lossy().contains(" ") {
            write!(o, "cd {:?} && ", dir).unwrap();
        } else {
            write!(o, "cd {} && ", dir.display()).unwrap();
        }
    }
    for (env, val) in c.get_envs() {
        let (env, val) = (lossy(env), val.map(lossy).unwrap_or(std::borrow::Cow::Borrowed("")));
        if env.contains(" ") {
            write!(o, "\"{}={}\" ", env, val).unwrap();
        } else if val.contains(" ") {
            write!(o, "{}=\"{}\" ", env, val).unwrap();
        } else {
            write!(o, "{}={} ", env, val).unwrap();
        }
    }
    let prog = lossy(c.get_program());
    if prog.contains(" ") {
        write!(o, "{:?}", prog).unwrap();
    } else {
        write!(o, "{}", prog).unwrap();
    }
    for arg in c.get_args() {
        let arg = lossy(arg);
        if arg.contains(" ") {
            write!(o, " \"{}\"", arg).unwrap();
        } else {
            write!(o, " {}", arg).unwrap();
        }
    }
    o
}

#[test]
fn test_display_command() {
    use std::path::Path;
    let mut cmd = Command::new("command");
    assert_eq!(display_command(cmd.arg("--arg"), None), "command --arg");
    assert_eq!(display_command(cmd.arg("spaced arg"), None), "command --arg \"spaced arg\"");
    assert_eq!(
        display_command(cmd.env("ENVIRON", "yeah"), None),
        "ENVIRON=yeah command --arg \"spaced arg\""
    );
    assert_eq!(
        display_command(cmd.env("OTHER", "spaced env"), None),
        "ENVIRON=yeah OTHER=\"spaced env\" command --arg \"spaced arg\""
    );
    assert_eq!(
        display_command(cmd.current_dir("/tmp"), None),
        "cd /tmp && ENVIRON=yeah OTHER=\"spaced env\" command --arg \"spaced arg\""
    );
    assert_eq!(
        display_command(cmd.current_dir("/tmp and/thing"), None),
        "cd \"/tmp and/thing\" && ENVIRON=yeah OTHER=\"spaced env\" command --arg \"spaced arg\""
    );
    assert_eq!(
        display_command(cmd.current_dir("/tmp and/thing"), Some(Path::new("/tmp and/thing"))),
        "ENVIRON=yeah OTHER=\"spaced env\" command --arg \"spaced arg\""
    );
}

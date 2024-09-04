//! Flycheck provides the functionality needed to run `cargo check` to provide
//! LSP diagnostics based on the output of the command.

use std::{fmt, io, process::Command, time::Duration};

use crossbeam_channel::{select_biased, unbounded, Receiver, Sender};
use paths::{AbsPath, AbsPathBuf, Utf8PathBuf};
use project_model::project_json;
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

#[derive(Clone)]
pub(crate) enum Target {
    Bin(String),
    Example(String),
    Benchmark(String),
    Test(String),
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
        let (sender, receiver) = unbounded::<StateChange>();
        let thread = stdx::thread::Builder::new(stdx::thread::ThreadIntent::Worker)
            .name("Flycheck".to_owned())
            .spawn(move || actor.run(receiver))
            .expect("failed to spawn thread");
        FlycheckHandle { id, sender, _thread: thread }
    }

    /// Schedule a re-start of the cargo check worker to do a workspace wide check.
    pub(crate) fn restart_workspace(&self, saved_file: Option<AbsPathBuf>) {
        self.sender
            .send(StateChange::Restart { package: PackageToRestart::All, saved_file, target: None })
            .unwrap();
    }

    /// Schedule a re-start of the cargo check worker to do a package wide check.
    pub(crate) fn restart_for_package(&self, package: PackageSpecifier, target: Option<Target>) {
        self.sender
            .send(StateChange::Restart {
                package: PackageToRestart::Package(package),
                saved_file: None,
                target,
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
    DidStart,
    DidCheckCrate(String),
    DidFinish(io::Result<()>),
    DidCancel,
    DidFailToRestart(String),
}

enum PackageToRestart {
    All,
    // Either a cargo package or a $label in rust-project.check.overrideCommand
    Package(PackageSpecifier),
}

pub(crate) enum PackageSpecifier {
    Cargo {
        /// The one in Cargo.toml, assumed to work with `cargo check -p {}` etc
        cargo_canonical_name: String,
    },
    BuildInfo {
        /// If a `build` field is present in rust-project.json, its label field
        label: String,
    },
}

enum StateChange {
    Restart { package: PackageToRestart, saved_file: Option<AbsPathBuf>, target: Option<Target> },
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
                Event::RequestStateChange(StateChange::Restart { package, saved_file, target }) => {
                    // Cancel the previously spawned process
                    self.cancel_check_process();
                    while let Ok(restart) = inbox.recv_timeout(Duration::from_millis(50)) {
                        // restart chained with a stop, so just cancel
                        if let StateChange::Cancel = restart {
                            continue 'event;
                        }
                    }

                    let Some(command) = self.check_command(package, saved_file.as_deref(), target)
                    else {
                        continue;
                    };

                    let formatted_command = format!("{command:?}");

                    tracing::debug!(?command, "will restart flycheck");
                    let (sender, receiver) = unbounded();
                    match CommandHandle::spawn(command, sender) {
                        Ok(command_handle) => {
                            tracing::debug!(command = formatted_command, "did restart flycheck");
                            self.command_handle = Some(command_handle);
                            self.command_receiver = Some(receiver);
                            self.report_progress(Progress::DidStart);
                            self.status = FlycheckStatus::Started;
                        }
                        Err(error) => {
                            self.report_progress(Progress::DidFailToRestart(format!(
                                "Failed to run the following command: {formatted_command} error={error}"
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
                // self.config_json.workspace_template.as_ref().map(|x| x.to_command())
                None
            }
            PackageToRestart::Package(
                PackageSpecifier::BuildInfo { label }
                // Treat missing build_info as implicitly setting label = the cargo canonical name
                | PackageSpecifier::Cargo { cargo_canonical_name: label },
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

    /// Construct a `Command` object for checking the user's code. If the user
    /// has specified a custom command with placeholders that we cannot fill,
    /// return None.
    fn check_command(
        &self,
        package: PackageToRestart,
        saved_file: Option<&AbsPath>,
        target: Option<Target>,
    ) -> Option<Command> {
        match &self.config {
            FlycheckConfig::CargoCommand { command, options, ansi_color_output } => {
                // Only use the rust-project.json's flycheck config when no check_overrideCommand
                // is configured. In the other branch we will still do label substitution but on
                // the overrideCommand instead.
                if self.config_json.any_configured() {
                    // Completely handle according to rust-project.json.
                    // We don't consider this to be "using cargo" so we will not apply any of the
                    // CargoOptions to the command.
                    return self.explicit_check_command(package, saved_file);
                }

                let mut cmd = Command::new(Tool::Cargo.path());
                if let Some(sysroot_root) = &self.sysroot_root {
                    cmd.env("RUSTUP_TOOLCHAIN", AsRef::<std::path::Path>::as_ref(sysroot_root));
                }
                cmd.arg(command);
                cmd.current_dir(&self.root);

                match package {
                    PackageToRestart::Package(PackageSpecifier::Cargo { cargo_canonical_name }) => {
                        cmd.arg("-p").arg(cargo_canonical_name)
                    }
                    PackageToRestart::Package(PackageSpecifier::BuildInfo { label: _ }) => {
                        // No way to flycheck this single package. All we have is a build label.
                        // There's no way to really say whether this build label happens to be
                        // a cargo canonical name, so we won't try.
                        return None;
                    }
                    PackageToRestart::All => cmd.arg("--workspace"),
                };

                if let Some(tgt) = target {
                    match tgt {
                        Target::Bin(tgt) => cmd.arg("--bin").arg(tgt),
                        Target::Example(tgt) => cmd.arg("--example").arg(tgt),
                        Target::Test(tgt) => cmd.arg("--test").arg(tgt),
                        Target::Benchmark(tgt) => cmd.arg("--bench").arg(tgt),
                    };
                }

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
                Some(cmd)
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
                    PackageToRestart::Package(PackageSpecifier::Cargo { cargo_canonical_name }) => {
                        Some(cargo_canonical_name.as_ref())
                    }
                };

                let subs = Substitutions { label, saved_file: saved_file.map(|x| x.as_str()) };
                let mut cmd = subs.substitute(&runnable)?;
                cmd.envs(extra_env);
                cmd.current_dir(root);

                Some(cmd)
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

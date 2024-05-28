//! Flycheck provides the functionality needed to run `cargo check` or
//! another compatible command (f.x. clippy) in a background thread and provide
//! LSP diagnostics based on the output of the command.

// FIXME: This crate now handles running `cargo test` needed in the test explorer in
// addition to `cargo check`. Either split it into 3 crates (one for test, one for check
// and one common utilities) or change its name and docs to reflect the current state.

#![warn(rust_2018_idioms, unused_lifetimes)]

use std::{fmt, io, process::Command, time::Duration};

use crossbeam_channel::{never, select, unbounded, Receiver, Sender};
use paths::{AbsPath, AbsPathBuf, Utf8PathBuf};
use project_model::project_json;
use rustc_hash::FxHashMap;
use serde::Deserialize;

pub use cargo_metadata::diagnostic::{
    Applicability, Diagnostic, DiagnosticCode, DiagnosticLevel, DiagnosticSpan,
    DiagnosticSpanMacroExpansion,
};
use toolchain::Tool;

mod command;
mod test_runner;

use command::{CommandHandle, ParseFromLine};
pub use test_runner::{CargoTestHandle, CargoTestMessage, TestState};

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub enum InvocationStrategy {
    Once,
    #[default]
    PerWorkspace,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum InvocationLocation {
    Root(AbsPathBuf),
    #[default]
    Workspace,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CargoOptions {
    pub target_triples: Vec<String>,
    pub all_targets: bool,
    pub no_default_features: bool,
    pub all_features: bool,
    pub features: Vec<String>,
    pub extra_args: Vec<String>,
    pub extra_env: FxHashMap<String, String>,
    pub target_dir: Option<Utf8PathBuf>,
}

impl CargoOptions {
    fn apply_on_command(&self, cmd: &mut Command) {
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
pub struct FlycheckConfigJson {
    pub workspace_template: Option<project_json::ShellRunnableArgs>,
    pub single_template: Option<project_json::ShellRunnableArgs>,
}

impl FlycheckConfigJson {
    pub fn any_configured(&self) -> bool {
        self.workspace_template.is_some() || self.single_template.is_some()
    }
}

/// The flycheck config from rust-analyzer's own configuration.
///
/// We rely on this when rust-project.json does not specify flycheck/flycheckWorkspace commands.
///
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FlycheckConfig {
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
        invocation_location: InvocationLocation,
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
pub struct FlycheckHandle {
    // XXX: drop order is significant
    sender: Sender<StateChange>,
    _thread: stdx::thread::JoinHandle,
    id: usize,
}

impl FlycheckHandle {
    pub fn spawn(
        id: usize,
        sender: Box<dyn Fn(Message) + Send>,
        config_json: FlycheckConfigJson,
        config: FlycheckConfig,
        sysroot_root: Option<AbsPathBuf>,
        workspace_root: AbsPathBuf,
        manifest_path: Option<AbsPathBuf>,
    ) -> FlycheckHandle {
        let actor = FlycheckActor::new(
            id,
            sender,
            config_json,
            config,
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
    pub fn restart_workspace(&self, saved_file: Option<AbsPathBuf>) {
        self.sender
            .send(StateChange::Restart { package: PackageToRestart::All, saved_file })
            .unwrap();
    }

    /// Schedule a re-start of the cargo check worker to do a package wide check.
    pub fn restart_for_package(&self, package: PackageSpecifier) {
        self.sender
            .send(StateChange::Restart {
                package: PackageToRestart::Package(package),
                saved_file: None,
            })
            .unwrap();
    }

    /// Stop this cargo check worker.
    pub fn cancel(&self) {
        self.sender.send(StateChange::Cancel).unwrap();
    }

    pub fn id(&self) -> usize {
        self.id
    }
}

pub enum Message {
    /// Request adding a diagnostic with fixes included to a file
    AddDiagnostic { id: usize, workspace_root: AbsPathBuf, diagnostic: Diagnostic },

    /// Request check progress notification to client
    Progress {
        /// Flycheck instance ID
        id: usize,
        progress: Progress,
    },
}

impl fmt::Debug for Message {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Message::AddDiagnostic { id, workspace_root, diagnostic } => f
                .debug_struct("AddDiagnostic")
                .field("id", id)
                .field("workspace_root", workspace_root)
                .field("diagnostic_code", &diagnostic.code.as_ref().map(|it| &it.code))
                .finish(),
            Message::Progress { id, progress } => {
                f.debug_struct("Progress").field("id", id).field("progress", progress).finish()
            }
        }
    }
}

#[derive(Debug)]
pub enum Progress {
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

/// Describes how to run flycheck on a single package.
pub enum PackageSpecifier {
    /// Please just run cargo.
    Cargo {
        /// The one in Cargo.toml, assumed to work with `cargo check -p {}` etc
        cargo_canonical_name: String,
    },
    /// build_info.label in rust-project.json. Substituted into the flycheck runnable at the root of the json.
    BuildInfo {
        /// A build_info field is present in rust-project.json, and this is its label field
        label: String,
    },
    // build_info.shell_runnables specified a flycheck on the crate itself
    BuildInfoCustom {
        label: String,
        command: Command,
    },
}

const LABEL_INLINE: &str = "$$LABEL$$";

struct Substitutions<'a> {
    label: Option<&'a str>,
    saved_file: Option<&'a str>,
}

impl<'a> Substitutions<'a> {
    /// If you have a runnable, and it has $$LABEL$$ in it somewhere, treat it as a template that
    /// may be unsatisfied if you do not provide a label to substitute into it. Returns None in
    /// that sitution. Otherwise performs the requested substitutions.
    ///
    fn substitute(self, template: &project_json::ShellRunnableArgs) -> Option<Command> {
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
            if arg == "$saved_file" {
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

enum StateChange {
    Restart { package: PackageToRestart, saved_file: Option<AbsPathBuf> },
    Cancel,
}

/// A [`FlycheckActor`] is a single check instance of a workspace.
struct FlycheckActor {
    /// The workspace id of this flycheck instance.
    id: usize,
    sender: Box<dyn Fn(Message) + Send>,
    config_json: FlycheckConfigJson,
    config: FlycheckConfig,
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
}

enum Event {
    RequestStateChange(StateChange),
    CheckEvent(Option<CargoCheckMessage>),
}

impl FlycheckActor {
    fn new(
        id: usize,
        sender: Box<dyn Fn(Message) + Send>,
        config_json: FlycheckConfigJson,
        config: FlycheckConfig,
        sysroot_root: Option<AbsPathBuf>,
        workspace_root: AbsPathBuf,
        manifest_path: Option<AbsPathBuf>,
    ) -> FlycheckActor {
        tracing::info!(%id, ?workspace_root, "Spawning flycheck");
        FlycheckActor {
            id,
            sender,
            config_json,
            config,
            sysroot_root,
            root: workspace_root,
            manifest_path,
            command_handle: None,
            command_receiver: None,
        }
    }

    fn report_progress(&self, progress: Progress) {
        self.send(Message::Progress { id: self.id, progress });
    }

    fn next_event(&self, inbox: &Receiver<StateChange>) -> Option<Event> {
        if let Ok(msg) = inbox.try_recv() {
            // give restarts a preference so check outputs don't block a restart or stop
            return Some(Event::RequestStateChange(msg));
        }
        select! {
            recv(inbox) -> msg => msg.ok().map(Event::RequestStateChange),
            recv(self.command_receiver.as_ref().unwrap_or(&never())) -> msg => Some(Event::CheckEvent(msg.ok())),
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

                    let command = match self.check_command(package, saved_file.as_deref()) {
                        Some(c) => c,
                        None => continue,
                    };
                    let formatted_command = format!("{:?}", command);

                    tracing::debug!(?command, "will restart flycheck");
                    let (sender, receiver) = unbounded();
                    match CommandHandle::spawn(command, sender) {
                        Ok(command_handle) => {
                            tracing::debug!(command = formatted_command, "did restart flycheck");
                            self.command_handle = Some(command_handle);
                            self.command_receiver = Some(receiver);
                            self.report_progress(Progress::DidStart);
                        }
                        Err(error) => {
                            self.report_progress(Progress::DidFailToRestart(format!(
                                "Failed to run the following command: {} error={}",
                                formatted_command, error
                            )));
                        }
                    }
                }
                Event::CheckEvent(None) => {
                    tracing::debug!(flycheck_id = self.id, "flycheck finished");

                    // Watcher finished
                    let command_handle = self.command_handle.take().unwrap();
                    self.command_receiver.take();
                    let formatted_handle = format!("{:?}", command_handle);

                    let res = command_handle.join();
                    if let Err(error) = &res {
                        tracing::error!(
                            "Flycheck failed to run the following command: {}, error={}",
                            formatted_handle,
                            error
                        );
                    }
                    self.report_progress(Progress::DidFinish(res));
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
                        self.send(Message::AddDiagnostic {
                            id: self.id,
                            workspace_root: self.root.clone(),
                            diagnostic: msg,
                        });
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
            self.report_progress(Progress::DidCancel);
        }
    }

    fn explicit_check_command(
        &self,
        package: PackageToRestart,
        saved_file: Option<&AbsPath>,
    ) -> Option<Command> {
        match package {
            PackageToRestart::All => {
                self.config_json.workspace_template.as_ref().map(|x| x.to_command())
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
            PackageToRestart::Package(PackageSpecifier::BuildInfoCustom { command, label: _ }) => Some(command),
        }
    }

    /// Construct a `Command` object for checking the user's code. If the user
    /// has specified a custom command with placeholders that we cannot fill,
    /// return None.
    fn check_command(
        &self,
        package: PackageToRestart,
        saved_file: Option<&AbsPath>,
    ) -> Option<Command> {
        let (mut cmd, args) = match &self.config {
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
                    PackageToRestart::Package(PackageSpecifier::BuildInfoCustom {
                        command,
                        label: _,
                    }) => return Some(command),
                    PackageToRestart::Package(PackageSpecifier::BuildInfo { label: _ }) => {
                        // No way to flycheck this single package. All we have is a build label.
                        // There's no way to really say whether this build label happens to be
                        // a cargo canonical name, so we won't try.
                        return None;
                    }
                    PackageToRestart::Package(PackageSpecifier::Cargo {
                        cargo_canonical_name,
                        ..
                    }) => cmd.arg("-p").arg(cargo_canonical_name),
                    PackageToRestart::All => cmd.arg("--workspace"),
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

                options.apply_on_command(&mut cmd);
                (cmd, options.extra_args.clone())
            }
            FlycheckConfig::CustomCommand {
                command,
                args,
                extra_env,
                invocation_strategy,
                invocation_location,
            } => {
                let cwd = match invocation_location {
                    InvocationLocation::Workspace => {
                        match invocation_strategy {
                            InvocationStrategy::Once => self.root.clone(),
                            InvocationStrategy::PerWorkspace => {
                                // FIXME: cmd.current_dir(&affected_workspace);
                                self.root.clone()
                            }
                        }
                    }
                    InvocationLocation::Root(root) => root.clone(),
                };

                let template = project_json::ShellRunnableArgs {
                    program: command.clone(),
                    args: args.clone(),
                    cwd: cwd.into(),
                    kind: project_json::ShellRunnableKind::Flycheck,
                };
                let subs = Substitutions {
                    label: match &package {
                        PackageToRestart::All => None,
                        PackageToRestart::Package(PackageSpecifier::Cargo {
                            cargo_canonical_name: label,
                        })
                        | PackageToRestart::Package(PackageSpecifier::BuildInfo { label })
                        | PackageToRestart::Package(PackageSpecifier::BuildInfoCustom {
                            label,
                            command: _,
                        }) => Some(&label),
                    },
                    saved_file: saved_file.map(|x| x.as_str()),
                };
                let mut cmd = subs.substitute(&template)?;
                cmd.envs(extra_env);
                (cmd, vec![])
            }
        };

        cmd.args(args);
        Some(cmd)
    }

    fn send(&self, check_task: Message) {
        (self.sender)(check_task);
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

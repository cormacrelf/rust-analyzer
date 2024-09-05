//! This module is responsible for implementing handlers for Language Server
//! Protocol. This module specifically handles notifications.

use std::ops::{Deref, Not as _};

use ide::CrateId;
use itertools::Itertools;
use lsp_types::{
    CancelParams, DidChangeConfigurationParams, DidChangeTextDocumentParams,
    DidChangeWatchedFilesParams, DidChangeWorkspaceFoldersParams, DidCloseTextDocumentParams,
    DidOpenTextDocumentParams, DidSaveTextDocumentParams, WorkDoneProgressCancelParams,
};
use paths::Utf8PathBuf;
use project_model::project_json;
use triomphe::Arc;
use vfs::{AbsPathBuf, ChangeKind, VfsPath};

use crate::{
    config::{Config, ConfigChange},
    flycheck::{self, BinTarget},
    global_state::{FetchWorkspaceRequest, GlobalState},
    lsp::{from_proto, utils::apply_document_changes},
    lsp_ext::{self, RunFlycheckParams},
    mem_docs::DocumentData,
    reload,
    target_spec::TargetSpec,
};

pub(crate) fn handle_cancel(state: &mut GlobalState, params: CancelParams) -> anyhow::Result<()> {
    let id: lsp_server::RequestId = match params.id {
        lsp_types::NumberOrString::Number(id) => id.into(),
        lsp_types::NumberOrString::String(id) => id.into(),
    };
    state.cancel(id);
    Ok(())
}

pub(crate) fn handle_work_done_progress_cancel(
    state: &mut GlobalState,
    params: WorkDoneProgressCancelParams,
) -> anyhow::Result<()> {
    if let lsp_types::NumberOrString::String(s) = &params.token {
        if let Some(id) = s.strip_prefix("rust-analyzer/flycheck/") {
            if let Ok(id) = id.parse::<u32>() {
                if let Some(flycheck) = state.flycheck.get(id as usize) {
                    flycheck.cancel();
                }
            }
        }
    }

    // Just ignore this. It is OK to continue sending progress
    // notifications for this token, as the client can't know when
    // we accepted notification.
    Ok(())
}

pub(crate) fn handle_did_open_text_document(
    state: &mut GlobalState,
    params: DidOpenTextDocumentParams,
) -> anyhow::Result<()> {
    let _p = tracing::info_span!("handle_did_open_text_document").entered();

    if let Ok(path) = from_proto::vfs_path(&params.text_document.uri) {
        let already_exists = state
            .mem_docs
            .insert(
                path.clone(),
                DocumentData::new(
                    params.text_document.version,
                    params.text_document.text.clone().into_bytes(),
                ),
            )
            .is_err();
        if already_exists {
            tracing::error!("duplicate DidOpenTextDocument: {}", path);
        }

        tracing::info!("New file content set {:?}", params.text_document.text);
        state.vfs.write().0.set_file_contents(path, Some(params.text_document.text.into_bytes()));
        if state.config.discover_workspace_config().is_some() {
            tracing::debug!("queuing task");
            let _ = state
                .deferred_task_queue
                .sender
                .send(crate::main_loop::QueuedTask::CheckIfIndexed(params.text_document.uri));
        }
    }
    Ok(())
}

pub(crate) fn handle_did_change_text_document(
    state: &mut GlobalState,
    params: DidChangeTextDocumentParams,
) -> anyhow::Result<()> {
    let _p = tracing::info_span!("handle_did_change_text_document").entered();

    if let Ok(path) = from_proto::vfs_path(&params.text_document.uri) {
        let Some(DocumentData { version, data }) = state.mem_docs.get_mut(&path) else {
            tracing::error!(?path, "unexpected DidChangeTextDocument");
            return Ok(());
        };
        // The version passed in DidChangeTextDocument is the version after all edits are applied
        // so we should apply it before the vfs is notified.
        *version = params.text_document.version;

        let new_contents = apply_document_changes(
            state.config.negotiated_encoding(),
            std::str::from_utf8(data).unwrap(),
            params.content_changes,
        )
        .into_bytes();
        if *data != new_contents {
            data.clone_from(&new_contents);
            state.vfs.write().0.set_file_contents(path, Some(new_contents));
        }
    }
    Ok(())
}

pub(crate) fn handle_did_close_text_document(
    state: &mut GlobalState,
    params: DidCloseTextDocumentParams,
) -> anyhow::Result<()> {
    let _p = tracing::info_span!("handle_did_close_text_document").entered();

    if let Ok(path) = from_proto::vfs_path(&params.text_document.uri) {
        if state.mem_docs.remove(&path).is_err() {
            tracing::error!("orphan DidCloseTextDocument: {}", path);
        }

        if let Some(file_id) = state.vfs.read().0.file_id(&path) {
            state.diagnostics.clear_native_for(file_id);
        }

        state.semantic_tokens_cache.lock().remove(&params.text_document.uri);

        if let Some(path) = path.as_path() {
            state.loader.handle.invalidate(path.to_path_buf());
        }
    }
    Ok(())
}

pub(crate) fn handle_did_save_text_document(
    state: &mut GlobalState,
    params: DidSaveTextDocumentParams,
) -> anyhow::Result<()> {
    if let Ok(vfs_path) = from_proto::vfs_path(&params.text_document.uri) {
        let snap = state.snapshot();
        let file_id = snap.vfs_path_to_file_id(&vfs_path)?;
        let sr = snap.analysis.source_root_id(file_id)?;

        if state.config.script_rebuild_on_save(Some(sr)) && state.build_deps_changed {
            state.build_deps_changed = false;
            state
                .fetch_build_data_queue
                .request_op("build_deps_changed - save notification".to_owned(), ());
        }

        // Re-fetch workspaces if a workspace related file has changed
        if let Some(path) = vfs_path.as_path() {
            let additional_files = &state
                .config
                .discover_workspace_config()
                .map(|cfg| cfg.files_to_watch.iter().map(String::as_str).collect::<Vec<&str>>())
                .unwrap_or_default();

            // FIXME: We should move this check into a QueuedTask and do semantic resolution of
            // the files. There is only so much we can tell syntactically from the path.
            if reload::should_refresh_for_change(path, ChangeKind::Modify, additional_files) {
                state.fetch_workspaces_queue.request_op(
                    format!("workspace vfs file change saved {path}"),
                    FetchWorkspaceRequest {
                        path: Some(path.to_owned()),
                        force_crate_graph_reload: false,
                    },
                );
            } else if state.detached_files.contains(path) {
                state.fetch_workspaces_queue.request_op(
                    format!("detached file saved {path}"),
                    FetchWorkspaceRequest {
                        path: Some(path.to_owned()),
                        force_crate_graph_reload: false,
                    },
                );
            }
        }

        if !state.config.check_on_save(Some(sr)) || run_flycheck(state, vfs_path) {
            return Ok(());
        }
    } else if state.config.check_on_save(None) {
        // No specific flycheck was triggered, so let's trigger all of them.
        for flycheck in state.flycheck.iter() {
            flycheck.restart_workspace(None);
        }
    }

    Ok(())
}

pub(crate) fn handle_did_change_configuration(
    state: &mut GlobalState,
    _params: DidChangeConfigurationParams,
) -> anyhow::Result<()> {
    // As stated in https://github.com/microsoft/language-server-protocol/issues/676,
    // this notification's parameters should be ignored and the actual config queried separately.
    state.send_request::<lsp_types::request::WorkspaceConfiguration>(
        lsp_types::ConfigurationParams {
            items: vec![lsp_types::ConfigurationItem {
                scope_uri: None,
                section: Some("rust-analyzer".to_owned()),
            }],
        },
        |this, resp| {
            tracing::debug!("config update response: '{:?}", resp);
            let lsp_server::Response { error, result, .. } = resp;

            match (error, result) {
                (Some(err), _) => {
                    tracing::error!("failed to fetch the server settings: {:?}", err)
                }
                (None, Some(mut configs)) => {
                    if let Some(json) = configs.get_mut(0) {
                        let config = Config::clone(&*this.config);
                        let mut change = ConfigChange::default();
                        change.change_client_config(json.take());

                        let (config, e, _) = config.apply_change(change);
                        this.config_errors = e.is_empty().not().then_some(e);

                        // Client config changes neccesitates .update_config method to be called.
                        this.update_configuration(config);
                    }
                }
                (None, None) => {
                    tracing::error!("received empty server settings response from the client")
                }
            }
        },
    );

    Ok(())
}

pub(crate) fn handle_did_change_workspace_folders(
    state: &mut GlobalState,
    params: DidChangeWorkspaceFoldersParams,
) -> anyhow::Result<()> {
    let config = Arc::make_mut(&mut state.config);

    for workspace in params.event.removed {
        let Ok(path) = workspace.uri.to_file_path() else { continue };
        let Ok(path) = Utf8PathBuf::from_path_buf(path) else { continue };
        let Ok(path) = AbsPathBuf::try_from(path) else { continue };
        config.remove_workspace(&path);
    }

    let added = params
        .event
        .added
        .into_iter()
        .filter_map(|it| it.uri.to_file_path().ok())
        .filter_map(|it| Utf8PathBuf::from_path_buf(it).ok())
        .filter_map(|it| AbsPathBuf::try_from(it).ok());
    config.add_workspaces(added);

    if !config.has_linked_projects() && config.detached_files().is_empty() {
        config.rediscover_workspaces();

        let req = FetchWorkspaceRequest { path: None, force_crate_graph_reload: false };
        state.fetch_workspaces_queue.request_op("client workspaces changed".to_owned(), req);
    }

    Ok(())
}

pub(crate) fn handle_did_change_watched_files(
    state: &mut GlobalState,
    params: DidChangeWatchedFilesParams,
) -> anyhow::Result<()> {
    for change in params.changes.iter().unique_by(|&it| &it.uri) {
        if let Ok(path) = from_proto::abs_path(&change.uri) {
            state.loader.handle.invalidate(path);
        }
    }
    Ok(())
}

fn run_flycheck(state: &mut GlobalState, vfs_path: VfsPath) -> bool {
    let _p = tracing::info_span!("run_flycheck").entered();

    let file_id = state.vfs.read().0.file_id(&vfs_path);
    if let Some(file_id) = file_id {
        let world = state.snapshot();
        let source_root_id = world.analysis.source_root_id(file_id).ok();
        let mut updated = false;
        let task = move || -> std::result::Result<(), ide::Cancelled> {
            #[derive(Debug)]
            enum FlycheckScope {
                /// Cargo workspace but user edited a binary target. There should be no
                /// downstream crates. We let flycheck run only for the workspace that
                /// contains the crate.
                Binary { package_name: Option<String>, bin_target: BinTarget, crate_id: CrateId },
                /// Limit flycheck to crates actually containing the file_id, because the user does not want to
                /// flycheck with --workspace.
                NoDownstream,
                /// Run on any affected workspace
                Workspace,
            }

            let scope = TargetSpec::for_file(&world, file_id)?
                .map(|it| {
                    let tgt_kind = it.target_kind();
                    let (package_name, tgt_name, crate_id) = match it {
                        TargetSpec::Cargo(c) => (Some(c.package), c.target, c.crate_id),
                        TargetSpec::ProjectJson(p) => (None, p.label, p.crate_id),
                    };

                    if let Some(bin_target) = BinTarget::from_target_kind(tgt_kind, tgt_name) {
                        return FlycheckScope::Binary { package_name, bin_target, crate_id };
                    }
                    if !world.config.flycheck_workspace(source_root_id) {
                        FlycheckScope::NoDownstream
                    } else {
                        FlycheckScope::Workspace
                    }
                })
                // XXX: is this right?
                .unwrap_or(FlycheckScope::Workspace);

            tracing::debug!("flycheck scope: {:?}", scope);

            let crate_ids = match scope {
                FlycheckScope::Workspace => {
                    // Trigger flychecks for all workspaces that depend on the saved file
                    // i.e. have crates containing or depending on the saved file
                    world
                        .analysis
                        .crates_for(file_id)?
                        .into_iter()
                        // These are topologically sorted. So `id` is first.
                        .flat_map(|id| world.analysis.transitive_rev_deps(id))
                        // FIXME: If there are multiple crates_for(file_id), once you flatten
                        // multiple transitive_rev_deps, it's no longer guaranteed to be toposort.
                        .flatten()
                        .unique()
                        .collect::<Vec<_>>()
                }
                FlycheckScope::NoDownstream => {
                    // Trigger flychecks in all workspaces, but only for the exact crate that has
                    // this file, and not for any workspaces that don't have that file.
                    world.analysis.crates_for(file_id)?
                }
                // Trigger flychecks for the only crate which the target belongs to
                FlycheckScope::Binary { crate_id, .. } => {
                    vec![crate_id]
                }
            };

            let crate_root_paths: Vec<_> = crate_ids
                .iter()
                .filter_map(|&crate_id| {
                    world
                        .analysis
                        .crate_root(crate_id)
                        .map(|file_id| {
                            world.file_id_to_file_path(file_id).as_path().map(ToOwned::to_owned)
                        })
                        .transpose()
                })
                .collect::<ide::Cancellable<_>>()?;
            let crate_root_paths: Vec<_> = crate_root_paths.iter().map(Deref::deref).collect();

            // Find all workspaces that have at least one target containing the saved file
            let workspace_ids = world.workspaces.iter().enumerate().filter_map(|(idx, ws)| {
                let package = match &ws.kind {
                    project_model::ProjectWorkspaceKind::Cargo { cargo, .. }
                    | project_model::ProjectWorkspaceKind::DetachedFile {
                        cargo: Some((cargo, _, _)),
                        ..
                    } => {
                        // Iterate crate_root_paths first because it is in topological
                        // order^[1], and we can therefore find the actual crate your saved
                        // file was in rather than some random downstream dependency.
                        // Thus with `[check] workspace = false` we can flycheck the
                        // smallest number of crates (just A) instead of checking B and C
                        // in response to every file save in A.
                        //
                        // A <- B <- C
                        //
                        // [1]: But see FIXME above where we flatten.
                        crate_root_paths.iter().find_map(|root| {
                            let target = cargo.target_by_root(root)?;
                            let pkg = cargo[target].package;
                            let pkg_name = cargo[pkg].name.clone();
                            Some(flycheck::PackageSpecifier::Cargo {
                                // This is very hacky. But we are iterating through a lot of
                                // crates, many of which are reverse deps, and it doesn't make
                                // sense to attach --bin XXX to some random downstream dep in a
                                // different workspace.
                                bin_target: match &scope {
                                    FlycheckScope::Binary {
                                        package_name: bin_pkg_name,
                                        bin_target,
                                        ..
                                    } if bin_pkg_name.as_ref() == Some(&pkg_name)
                                        && bin_target.name() == cargo[target].name =>
                                    {
                                        Some(bin_target.clone())
                                    }
                                    _ => None,
                                },
                                cargo_canonical_name: pkg_name,
                            })
                        })
                    }
                    project_model::ProjectWorkspaceKind::Json(project) => {
                        let krate_flycheck = crate_root_paths.iter().find_map(|root| {
                            let krate = project.crate_by_root(root)?;
                            project_json_flycheck(project, krate)
                        });

                        // If there is no matching crate, returns None and doesn't hit this
                        // workspace in the loop below.
                        Some(krate_flycheck?)
                    }
                    project_model::ProjectWorkspaceKind::DetachedFile { .. } => return None,
                };
                Some((idx, package))
            });

            let saved_file = vfs_path.as_path().map(|p| p.to_owned());

            // Find and trigger corresponding flychecks
            for flycheck in world.flycheck.iter() {
                for (id, package) in workspace_ids.clone() {
                    if id == flycheck.id() {
                        updated = true;
                        match package.filter(|spec| {
                            // Any of these cases, and we can't flycheck the whole workspace.
                            !world.config.flycheck_workspace(source_root_id)
                                || flycheck.cannot_run_workspace()
                                    // No point flychecking the whole workspace when you edited a
                                    // main.rs. It cannot have dependencies.
                                || matches!(
                                    spec,
                                    flycheck::PackageSpecifier::Cargo { bin_target: Some(_), .. }
                                )
                        }) {
                            Some(spec) => flycheck.restart_for_package(spec),
                            None => flycheck.restart_workspace(saved_file.clone()),
                        }
                    }
                }
            }
            // No specific flycheck was triggered, so let's trigger all of them.
            if !updated {
                for flycheck in world.flycheck.iter() {
                    flycheck.restart_workspace(saved_file.clone());
                }
            }
            Ok(())
        };
        state.task_pool.handle.spawn_with_sender(stdx::thread::ThreadIntent::Worker, move |_| {
            if let Err(e) = std::panic::catch_unwind(task) {
                tracing::error!("flycheck task panicked: {e:?}")
            }
        });
        true
    } else {
        false
    }
}

pub(crate) fn handle_cancel_flycheck(state: &mut GlobalState, _: ()) -> anyhow::Result<()> {
    let _p = tracing::info_span!("handle_cancel_flycheck").entered();
    state.flycheck.iter().for_each(|flycheck| flycheck.cancel());
    Ok(())
}

pub(crate) fn handle_clear_flycheck(state: &mut GlobalState, _: ()) -> anyhow::Result<()> {
    let _p = tracing::info_span!("handle_clear_flycheck").entered();
    state.diagnostics.clear_check_all();
    Ok(())
}

pub(crate) fn handle_run_flycheck(
    state: &mut GlobalState,
    params: RunFlycheckParams,
) -> anyhow::Result<()> {
    let _p = tracing::info_span!("handle_run_flycheck").entered();
    if let Some(text_document) = params.text_document {
        if let Ok(vfs_path) = from_proto::vfs_path(&text_document.uri) {
            if run_flycheck(state, vfs_path) {
                return Ok(());
            }
        }
    }
    // No specific flycheck was triggered, so let's trigger all of them.
    for flycheck in state.flycheck.iter() {
        flycheck.restart_workspace(None);
    }
    Ok(())
}

pub(crate) fn handle_abort_run_test(state: &mut GlobalState, _: ()) -> anyhow::Result<()> {
    if state.test_run_session.take().is_some() {
        state.send_notification::<lsp_ext::EndRunTest>(());
    }
    Ok(())
}

fn project_json_flycheck(
    _project_json: &project_json::ProjectJson,
    krate: &project_json::Crate,
) -> Option<flycheck::PackageSpecifier> {
    if let Some(build_info) = krate.build.as_ref() {
        let label = build_info.label.clone();
        Some(flycheck::PackageSpecifier::BuildInfo { label })
    } else {
        // No build_info field, so assume this is built by cargo.
        let cargo_canonical_name =
            krate.display_name.as_ref().map(|x| x.canonical_name().to_owned())?.to_string();
        Some(flycheck::PackageSpecifier::Cargo {
            cargo_canonical_name,
            // In JSON world, can we even describe crates that are checkable with `cargo check --bin XXX`?
            bin_target: None,
        })
    }
}

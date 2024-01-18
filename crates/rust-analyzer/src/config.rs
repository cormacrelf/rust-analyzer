#![allow(dead_code)]
//! Config used by the language server.
//!
//! We currently get this config from `initialize` LSP request, which is not the
//! best way to do it, but was the simplest thing we could implement.
//!
//! Of particular interest is the `feature_flags` hash map: while other fields
//! configure the server itself, feature flags are passed into analysis, and
//! tweak things like automatic insertion of `()` in completions.

use std::{fmt, iter, ops::Not, path::PathBuf};

use cfg::{CfgAtom, CfgDiff};
use flycheck::FlycheckConfig;
use ide::{
    AssistConfig, CallableSnippets, CompletionConfig, DiagnosticsConfig, ExprFillDefaultMode,
    HighlightConfig, HighlightRelatedConfig, HoverConfig, HoverDocFormat, InlayFieldsToResolve,
    InlayHintsConfig, JoinLinesConfig, MemoryLayoutHoverConfig, MemoryLayoutHoverRenderKind,
    Snippet, SnippetScope,
};
use ide_db::{
    imports::insert_use::{ImportGranularity, InsertUseConfig, PrefixKind},
    SnippetCap,
};
use itertools::Itertools;
use la_arena::Arena;
use lsp_types::{ClientCapabilities, MarkupKind};
use project_model::{
    CargoConfig, CargoFeatures, ProjectJson, ProjectJsonData, ProjectManifest, RustLibSource,
};
use rustc_hash::{FxHashMap, FxHashSet};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::collections::BTreeMap;
use toml;
use vfs::{AbsPath, AbsPathBuf, FileId};

use crate::{
    caps::completion_item_edit_resolve,
    diagnostics::DiagnosticsMapConfig,
    line_index::PositionEncoding,
    lsp_ext::{self, negotiated_encoding, WorkspaceSymbolSearchKind, WorkspaceSymbolSearchScope},
};

mod patch_old_style;

// Conventions for configuration keys to preserve maximal extendability without breakage:
//  - Toggles (be it binary true/false or with more options in-between) should almost always suffix as `_enable`
//    This has the benefit of namespaces being extensible, and if the suffix doesn't fit later it can be changed without breakage.
//  - In general be wary of using the namespace of something verbatim, it prevents us from adding subkeys in the future
//  - Don't use abbreviations unless really necessary
//  - foo_command = overrides the subcommand, foo_overrideCommand allows full overwriting, extra args only applies for foo_command

// Defines the server-side configuration of the rust-analyzer. We generate
// *parts* of VS Code's `package.json` config from this. Run `cargo test` to
// re-generate that file.
//
// However, editor specific config, which the server doesn't know about, should
// be specified directly in `package.json`.
//
// To deprecate an option by replacing it with another name use `new_name | `old_name` so that we keep
// parsing the old name.
config_data! {
    global: struct GlobalConfigData {
        /// Whether to insert #[must_use] when generating `as_` methods
        /// for enum variants.
        assist_emitMustUse: bool               = false,
        /// Placeholder expression to use for missing expressions in assists.
        assist_expressionFillDefault: ExprFillDefaultDef              = ExprFillDefaultDef::Todo,

        /// Warm up caches on project load.
        cachePriming_enable: bool = true,
        /// How many worker threads to handle priming caches. The default `0` means to pick automatically.
        cachePriming_numThreads: ParallelCachePrimingNumThreads = 0u8,

        /// Automatically refresh project info via `cargo metadata` on
        /// `Cargo.toml` or `.cargo/config.toml` changes.
        cargo_autoreload: bool           = true,
        /// Run build scripts (`build.rs`) for more precise code analysis.
        cargo_buildScripts_enable: bool  = true,
        /// Specifies the working directory for running build scripts.
        /// - "workspace": run build scripts for a workspace in the workspace's root directory.
        ///   This is incompatible with `#rust-analyzer.cargo.buildScripts.invocationStrategy#` set to `once`.
        /// - "root": run build scripts in the project's root directory.
        /// This config only has an effect when `#rust-analyzer.cargo.buildScripts.overrideCommand#`
        /// is set.
        cargo_buildScripts_invocationLocation: InvocationLocation = InvocationLocation::Workspace,
        /// Specifies the invocation strategy to use when running the build scripts command.
        /// If `per_workspace` is set, the command will be executed for each workspace.
        /// If `once` is set, the command will be executed once.
        /// This config only has an effect when `#rust-analyzer.cargo.buildScripts.overrideCommand#`
        /// is set.
        cargo_buildScripts_invocationStrategy: InvocationStrategy = InvocationStrategy::PerWorkspace,
        /// Override the command rust-analyzer uses to run build scripts and
        /// build procedural macros. The command is required to output json
        /// and should therefore include `--message-format=json` or a similar
        /// option.
        ///
        /// If there are multiple linked projects/workspaces, this command is invoked for
        /// each of them, with the working directory being the workspace root
        /// (i.e., the folder containing the `Cargo.toml`). This can be overwritten
        /// by changing `#rust-analyzer.cargo.buildScripts.invocationStrategy#` and
        /// `#rust-analyzer.cargo.buildScripts.invocationLocation#`.
        ///
        /// By default, a cargo invocation will be constructed for the configured
        /// targets and features, with the following base command line:
        ///
        /// ```bash
        /// cargo check --quiet --workspace --message-format=json --all-targets
        /// ```
        /// .
        cargo_buildScripts_overrideCommand: Option<Vec<String>> = None,
        /// Use `RUSTC_WRAPPER=rust-analyzer` when running build scripts to
        /// avoid checking unnecessary things.
        cargo_buildScripts_useRustcWrapper: bool = true,
        /// List of cfg options to enable with the given values.
        cargo_cfgs: FxHashMap<String, String> = FxHashMap::default(),
        /// Extra arguments that are passed to every cargo invocation.
        cargo_extraArgs: Vec<String> = vec![],
        /// Extra environment variables that will be set when running cargo, rustc
        /// or other commands within the workspace. Useful for setting RUSTFLAGS.
        cargo_extraEnv: FxHashMap<String, String> = FxHashMap::default(),
        /// List of features to activate.
        ///
        /// Set this to `"all"` to pass `--all-features` to cargo.
        cargo_features: CargoFeaturesDef      = CargoFeaturesDef::Selected(vec![]),
        /// Whether to pass `--no-default-features` to cargo.
        cargo_noDefaultFeatures: bool    = false,
        /// Relative path to the sysroot, or "discover" to try to automatically find it via
        /// "rustc --print sysroot".
        ///
        /// Unsetting this disables sysroot loading.
        ///
        /// This option does not take effect until rust-analyzer is restarted.
        cargo_sysroot: Option<String>    = Some("discover".to_string()),
        /// Relative path to the sysroot library sources. If left unset, this will default to
        /// `{cargo.sysroot}/lib/rustlib/src/rust/library`.
        ///
        /// This option does not take effect until rust-analyzer is restarted.
        cargo_sysrootSrc: Option<String>    = None,
        /// Compilation target override (target triple).
        // FIXME(@poliorcetics): move to multiple targets here too, but this will need more work
        // than `checkOnSave_target`
        cargo_target: Option<String>     = None,
        /// Unsets the implicit `#[cfg(test)]` for the specified crates.
        cargo_unsetTest: Vec<String>     = @from_str: r#"["core"]"#,

        /// Run the check command for diagnostics on save.
        checkOnSave | checkOnSave_enable: bool                         = true,

        /// Check all targets and tests (`--all-targets`).
        check_allTargets | checkOnSave_allTargets: bool                  = true,
        /// Cargo command to use for `cargo check`.
        check_command | checkOnSave_command: String                      = "check".to_string(),
        /// Extra arguments for `cargo check`.
        check_extraArgs | checkOnSave_extraArgs: Vec<String>             = vec![],
        /// Extra environment variables that will be set when running `cargo check`.
        /// Extends `#rust-analyzer.cargo.extraEnv#`.
        check_extraEnv | checkOnSave_extraEnv: FxHashMap<String, String> = FxHashMap::default(),
        /// List of features to activate. Defaults to
        /// `#rust-analyzer.cargo.features#`.
        ///
        /// Set to `"all"` to pass `--all-features` to Cargo.
        check_features | checkOnSave_features: Option<CargoFeaturesDef>  = None,
        /// List of `cargo check` (or other command specified in `check.command`) diagnostics to ignore.
        ///
        /// For example for `cargo check`: `dead_code`, `unused_imports`, `unused_variables`,...
        check_ignore: FxHashSet<String> = FxHashSet::default(),
        /// Specifies the working directory for running checks.
        /// - "workspace": run checks for workspaces in the corresponding workspaces' root directories.
        // FIXME: Ideally we would support this in some way
        ///   This falls back to "root" if `#rust-analyzer.cargo.check.invocationStrategy#` is set to `once`.
        /// - "root": run checks in the project's root directory.
        /// This config only has an effect when `#rust-analyzer.cargo.check.overrideCommand#`
        /// is set.
        check_invocationLocation | checkOnSave_invocationLocation: InvocationLocation = InvocationLocation::Workspace,
        /// Specifies the invocation strategy to use when running the check command.
        /// If `per_workspace` is set, the command will be executed for each workspace.
        /// If `once` is set, the command will be executed once.
        /// This config only has an effect when `#rust-analyzer.cargo.check.overrideCommand#`
        /// is set.
        check_invocationStrategy | checkOnSave_invocationStrategy: InvocationStrategy = InvocationStrategy::PerWorkspace,
        /// Whether to pass `--no-default-features` to Cargo. Defaults to
        /// `#rust-analyzer.cargo.noDefaultFeatures#`.
        check_noDefaultFeatures | checkOnSave_noDefaultFeatures: Option<bool>         = None,
        /// Override the command rust-analyzer uses instead of `cargo check` for
        /// diagnostics on save. The command is required to output json and
        /// should therefore include `--message-format=json` or a similar option
        /// (if your client supports the `colorDiagnosticOutput` experimental
        /// capability, you can use `--message-format=json-diagnostic-rendered-ansi`).
        ///
        /// If you're changing this because you're using some tool wrapping
        /// Cargo, you might also want to change
        /// `#rust-analyzer.cargo.buildScripts.overrideCommand#`.
        ///
        /// If there are multiple linked projects/workspaces, this command is invoked for
        /// each of them, with the working directory being the workspace root
        /// (i.e., the folder containing the `Cargo.toml`). This can be overwritten
        /// by changing `#rust-analyzer.cargo.check.invocationStrategy#` and
        /// `#rust-analyzer.cargo.check.invocationLocation#`.
        ///
        /// An example command would be:
        ///
        /// ```bash
        /// cargo check --workspace --message-format=json --all-targets
        /// ```
        /// .
        check_overrideCommand | checkOnSave_overrideCommand: Option<Vec<String>>             = None,
        /// Check for specific targets. Defaults to `#rust-analyzer.cargo.target#` if empty.
        ///
        /// Can be a single target, e.g. `"x86_64-unknown-linux-gnu"` or a list of targets, e.g.
        /// `["aarch64-apple-darwin", "x86_64-apple-darwin"]`.
        ///
        /// Aliased as `"checkOnSave.targets"`.
        check_targets | checkOnSave_targets | checkOnSave_target: Option<CheckOnSaveTargets> = None,


        /// List of rust-analyzer diagnostics to disable.
        diagnostics_disabled: FxHashSet<String> = FxHashSet::default(),
        /// Whether to show native rust-analyzer diagnostics.
        diagnostics_enable: bool                = true,
        /// Whether to show experimental rust-analyzer diagnostics that might
        /// have more false positives than usual.
        diagnostics_experimental_enable: bool    = false,
        /// Map of prefixes to be substituted when parsing diagnostic file paths.
        /// This should be the reverse mapping of what is passed to `rustc` as `--remap-path-prefix`.
        diagnostics_remapPrefix: FxHashMap<String, String> = FxHashMap::default(),
        /// List of warnings that should be displayed with hint severity.
        ///
        /// The warnings will be indicated by faded text or three dots in code
        /// and will not show up in the `Problems Panel`.
        diagnostics_warningsAsHint: Vec<String> = vec![],
        /// List of warnings that should be displayed with info severity.
        ///
        /// The warnings will be indicated by a blue squiggly underline in code
        /// and a blue icon in the `Problems Panel`.
        diagnostics_warningsAsInfo: Vec<String> = vec![],
        /// These directories will be ignored by rust-analyzer. They are
        /// relative to the workspace root, and globs are not supported. You may
        /// also need to add the folders to Code's `files.watcherExclude`.
        files_excludeDirs: Vec<PathBuf> = vec![],
        /// Controls file watching implementation.
        files_watcher: FilesWatcherDef = FilesWatcherDef::Client,


        /// Enables the experimental support for interpreting tests.
        interpret_tests: bool                                      = false,



        /// Whether to show `Debug` lens. Only applies when
        /// `#rust-analyzer.lens.enable#` is set.
        lens_debug_enable: bool            = true,
       /// Whether to show CodeLens in Rust files.
        lens_enable: bool           = true,
        /// Internal config: use custom client-side commands even when the
        /// client doesn't set the corresponding capability.
        lens_forceCustomCommands: bool = true,
        /// Whether to show `Implementations` lens. Only applies when
        /// `#rust-analyzer.lens.enable#` is set.
        lens_implementations_enable: bool  = true,
        /// Where to render annotations.
        lens_location: AnnotationLocation = AnnotationLocation::AboveName,
        /// Whether to show `References` lens for Struct, Enum, and Union.
        /// Only applies when `#rust-analyzer.lens.enable#` is set.
        lens_references_adt_enable: bool = false,
        /// Whether to show `References` lens for Enum Variants.
        /// Only applies when `#rust-analyzer.lens.enable#` is set.
        lens_references_enumVariant_enable: bool = false,
        /// Whether to show `Method References` lens. Only applies when
        /// `#rust-analyzer.lens.enable#` is set.
        lens_references_method_enable: bool = false,
        /// Whether to show `References` lens for Trait.
        /// Only applies when `#rust-analyzer.lens.enable#` is set.
        lens_references_trait_enable: bool = false,
        /// Whether to show `Run` lens. Only applies when
        /// `#rust-analyzer.lens.enable#` is set.
        lens_run_enable: bool              = true,

        /// Disable project auto-discovery in favor of explicitly specified set
        /// of projects.
        ///
        /// Elements must be paths pointing to `Cargo.toml`,
        /// `rust-project.json`, or JSON objects in `rust-project.json` format.
        linkedProjects: Vec<ManifestOrProjectJson> = vec![],

        /// Number of syntax trees rust-analyzer keeps in memory. Defaults to 128.
        lru_capacity: Option<usize>                 = None,
        /// Sets the LRU capacity of the specified queries.
        lru_query_capacities: FxHashMap<Box<str>, usize> = FxHashMap::default(),

        /// Whether to show `can't find Cargo.toml` error message.
        notifications_cargoTomlNotFound: bool      = true,

        /// How many worker threads in the main loop. The default `null` means to pick automatically.
        numThreads: Option<usize> = None,

        /// Expand attribute macros. Requires `#rust-analyzer.procMacro.enable#` to be set.
        procMacro_attributes_enable: bool = true,
        /// Enable support for procedural macros, implies `#rust-analyzer.cargo.buildScripts.enable#`.
        procMacro_enable: bool                     = true,
        /// These proc-macros will be ignored when trying to expand them.
        ///
        /// This config takes a map of crate names with the exported proc-macro names to ignore as values.
        procMacro_ignored: FxHashMap<Box<str>, Box<[Box<str>]>>          = FxHashMap::default(),
        /// Internal config, path to proc-macro server executable.
        procMacro_server: Option<PathBuf>          = None,

        /// Exclude imports from find-all-references.
        references_excludeImports: bool = false,

        /// Command to be executed instead of 'cargo' for runnables.
        runnables_command: Option<String> = None,
        /// Additional arguments to be passed to cargo for runnables such as
        /// tests or binaries. For example, it may be `--release`.
        runnables_extraArgs: Vec<String>   = vec![],

        /// Optional path to a rust-analyzer specific target directory.
        /// This prevents rust-analyzer's `cargo check` from locking the `Cargo.lock`
        /// at the expense of duplicating build artifacts.
        ///
        /// Set to `true` to use a subdirectory of the existing target directory or
        /// set to a path relative to the workspace to use that path.
        rust_analyzerTargetDir: Option<TargetDirectory> = None,

        /// Path to the Cargo.toml of the rust compiler workspace, for usage in rustc_private
        /// projects, or "discover" to try to automatically find it if the `rustc-dev` component
        /// is installed.
        ///
        /// Any project which uses rust-analyzer with the rustcPrivate
        /// crates must set `[package.metadata.rust-analyzer] rustc_private=true` to use it.
        ///
        /// This option does not take effect until rust-analyzer is restarted.
        rustc_source: Option<String> = None,

        /// Additional arguments to `rustfmt`.
        rustfmt_extraArgs: Vec<String>               = vec![],
        /// Advanced option, fully override the command rust-analyzer uses for
        /// formatting. This should be the equivalent of `rustfmt` here, and
        /// not that of `cargo fmt`. The file contents will be passed on the
        /// standard input and the formatted result will be read from the
        /// standard output.
        rustfmt_overrideCommand: Option<Vec<String>> = None,
        /// Enables the use of rustfmt's unstable range formatting command for the
        /// `textDocument/rangeFormatting` request. The rustfmt option is unstable and only
        /// available on a nightly build.
        rustfmt_rangeFormatting_enable: bool = false,


        /// Show full signature of the callable. Only shows parameters if disabled.
        signatureInfo_detail: SignatureDetail                           = SignatureDetail::Full,
        /// Show documentation.
        signatureInfo_documentation_enable: bool                       = true,

        /// Whether to insert closing angle brackets when typing an opening angle bracket of a generic argument list.
        typing_autoClosingAngleBrackets_enable: bool = false,

        /// Workspace symbol search kind.
        workspace_symbol_search_kind: WorkspaceSymbolSearchKindDef = WorkspaceSymbolSearchKindDef::OnlyTypes,
        /// Limits the number of items returned from a workspace symbol search (Defaults to 128).
        /// Some clients like vs-code issue new searches on result filtering and don't require all results to be returned in the initial search.
        /// Other clients requires all results upfront and might require a higher limit.
        workspace_symbol_search_limit: usize = 128,
        /// Workspace symbol search scope.
        workspace_symbol_search_scope: WorkspaceSymbolSearchScopeDef = WorkspaceSymbolSearchScopeDef::Workspace,
    }
}

config_data! {
    local: struct LocalConfigData {
        /// Toggles the additional completions that automatically add imports when completed.
        /// Note that your client must specify the `additionalTextEdits` LSP client capability to truly have this feature enabled.
        completion_autoimport_enable: bool       = true,
        /// Toggles the additional completions that automatically show method calls and field accesses
        /// with `self` prefixed to them when inside a method.
        completion_autoself_enable: bool        = true,
        /// Whether to add parenthesis and argument snippets when completing function.
        completion_callable_snippets: CallableCompletionDef  = CallableCompletionDef::FillArguments,
        /// Whether to show full function/method signatures in completion docs.
        completion_fullFunctionSignatures_enable: bool = false,
        /// Maximum number of completions to return. If `None`, the limit is infinite.
        completion_limit: Option<usize> = None,
        /// Whether to show postfix snippets like `dbg`, `if`, `not`, etc.
        completion_postfix_enable: bool         = true,
        /// Enables completions of private items and fields that are defined in the current workspace even if they are not visible at the current position.
        completion_privateEditable_enable: bool = false,
        /// Custom completion snippets.
        // NOTE: we use BTreeMap for deterministic serialization ordering
        completion_snippets_custom: BTreeMap<String, SnippetDef> = @from_str: r#"{
            "Arc::new": {
                "postfix": "arc",
                "body": "Arc::new(${receiver})",
                "requires": "std::sync::Arc",
                "description": "Put the expression into an `Arc`",
                "scope": "expr"
            },
            "Rc::new": {
                "postfix": "rc",
                "body": "Rc::new(${receiver})",
                "requires": "std::rc::Rc",
                "description": "Put the expression into an `Rc`",
                "scope": "expr"
            },
            "Box::pin": {
                "postfix": "pinbox",
                "body": "Box::pin(${receiver})",
                "requires": "std::boxed::Box",
                "description": "Put the expression into a pinned `Box`",
                "scope": "expr"
            },
            "Ok": {
                "postfix": "ok",
                "body": "Ok(${receiver})",
                "description": "Wrap the expression in a `Result::Ok`",
                "scope": "expr"
            },
            "Err": {
                "postfix": "err",
                "body": "Err(${receiver})",
                "description": "Wrap the expression in a `Result::Err`",
                "scope": "expr"
            },
            "Some": {
                "postfix": "some",
                "body": "Some(${receiver})",
                "description": "Wrap the expression in an `Option::Some`",
                "scope": "expr"
            }
        }"#,

        /// Enables highlighting of related references while the cursor is on `break`, `loop`, `while`, or `for` keywords.
        highlightRelated_breakPoints_enable: bool = true,
        /// Enables highlighting of all captures of a closure while the cursor is on the `|` or move keyword of a closure.
        highlightRelated_closureCaptures_enable: bool = true,
        /// Enables highlighting of all exit points while the cursor is on any `return`, `?`, `fn`, or return type arrow (`->`).
        highlightRelated_exitPoints_enable: bool = true,
        /// Enables highlighting of related references while the cursor is on any identifier.
        highlightRelated_references_enable: bool = true,
        /// Enables highlighting of all break points for a loop or block context while the cursor is on any `async` or `await` keywords.
        highlightRelated_yieldPoints_enable: bool = true,

        /// Whether to show `Debug` action. Only applies when
        /// `#rust-analyzer.hover.actions.enable#` is set.
        hover_actions_debug_enable: bool           = true,
        /// Whether to show HoverActions in Rust files.
        hover_actions_enable: bool          = true,
        /// Whether to show `Go to Type Definition` action. Only applies when
        /// `#rust-analyzer.hover.actions.enable#` is set.
        hover_actions_gotoTypeDef_enable: bool     = true,
        /// Whether to show `Implementations` action. Only applies when
        /// `#rust-analyzer.hover.actions.enable#` is set.
        hover_actions_implementations_enable: bool = true,
        /// Whether to show `References` action. Only applies when
        /// `#rust-analyzer.hover.actions.enable#` is set.
        hover_actions_references_enable: bool      = false,
        /// Whether to show `Run` action. Only applies when
        /// `#rust-analyzer.hover.actions.enable#` is set.
        hover_actions_run_enable: bool             = true,

        /// Whether to show documentation on hover.
        hover_documentation_enable: bool           = true,
        /// Whether to show keyword hover popups. Only applies when
        /// `#rust-analyzer.hover.documentation.enable#` is set.
        hover_documentation_keywords_enable: bool  = true,
        /// Use markdown syntax for links on hover.
        hover_links_enable: bool = true,
        /// How to render the align information in a memory layout hover.
        hover_memoryLayout_alignment: Option<MemoryLayoutHoverRenderKindDef> = Some(MemoryLayoutHoverRenderKindDef::Hexadecimal),
        /// Whether to show memory layout data on hover.
        hover_memoryLayout_enable: bool = true,
        /// How to render the niche information in a memory layout hover.
        hover_memoryLayout_niches: Option<bool> = Some(false),
        /// How to render the offset information in a memory layout hover.
        hover_memoryLayout_offset: Option<MemoryLayoutHoverRenderKindDef> = Some(MemoryLayoutHoverRenderKindDef::Hexadecimal),
        /// How to render the size information in a memory layout hover.
        hover_memoryLayout_size: Option<MemoryLayoutHoverRenderKindDef> = Some(MemoryLayoutHoverRenderKindDef::Both),

        /// Whether to enforce the import granularity setting for all files. If set to false rust-analyzer will try to keep import styles consistent per file.
        imports_granularity_enforce: bool              = false,
        /// How imports should be grouped into use statements.
        imports_granularity_group: ImportGranularityDef  = ImportGranularityDef::Crate,
        /// Group inserted imports by the https://rust-analyzer.github.io/manual.html#auto-import[following order]. Groups are separated by newlines.
        imports_group_enable: bool                           = true,
        /// Whether to allow import insertion to merge new imports into single path glob imports like `use std::fmt::*;`.
        imports_merge_glob: bool           = true,
        /// Prefer to unconditionally use imports of the core and alloc crate, over the std crate.
        imports_prefer_no_std: bool                     = false,
        /// The path structure for newly inserted paths to use.
        imports_prefix: ImportPrefixDef               = ImportPrefixDef::Plain,


        /// Whether to show inlay type hints for binding modes.
        inlayHints_bindingModeHints_enable: bool                   = false,
        /// Whether to show inlay type hints for method chains.
        inlayHints_chainingHints_enable: bool                      = true,
        /// Whether to show inlay hints after a closing `}` to indicate what item it belongs to.
        inlayHints_closingBraceHints_enable: bool                  = true,
        /// Minimum number of lines required before the `}` until the hint is shown (set to 0 or 1
        /// to always show them).
        inlayHints_closingBraceHints_minLines: usize               = 25,
        /// Whether to show inlay hints for closure captures.
        inlayHints_closureCaptureHints_enable: bool                          = false,
        /// Whether to show inlay type hints for return types of closures.
        inlayHints_closureReturnTypeHints_enable: ClosureReturnTypeHintsDef  = ClosureReturnTypeHintsDef::Never,
        /// Closure notation in type and chaining inlay hints.
        inlayHints_closureStyle: ClosureStyle                                = ClosureStyle::ImplFn,
        /// Whether to show enum variant discriminant hints.
        inlayHints_discriminantHints_enable: DiscriminantHintsDef            = DiscriminantHintsDef::Never,
        /// Whether to show inlay hints for type adjustments.
        inlayHints_expressionAdjustmentHints_enable: AdjustmentHintsDef = AdjustmentHintsDef::Never,
        /// Whether to hide inlay hints for type adjustments outside of `unsafe` blocks.
        inlayHints_expressionAdjustmentHints_hideOutsideUnsafe: bool = false,
        /// Whether to show inlay hints as postfix ops (`.*` instead of `*`, etc).
        inlayHints_expressionAdjustmentHints_mode: AdjustmentHintsModeDef = AdjustmentHintsModeDef::Prefix,
        /// Whether to show inlay type hints for elided lifetimes in function signatures.
        inlayHints_lifetimeElisionHints_enable: LifetimeElisionDef = LifetimeElisionDef::Never,
        /// Whether to prefer using parameter names as the name for elided lifetime hints if possible.
        inlayHints_lifetimeElisionHints_useParameterNames: bool    = false,
        /// Maximum length for inlay hints. Set to null to have an unlimited length.
        inlayHints_maxLength: Option<usize>                        = Some(25),
        /// Whether to show function parameter name inlay hints at the call
        /// site.
        inlayHints_parameterHints_enable: bool                     = true,
        /// Whether to show inlay hints for compiler inserted reborrows.
        /// This setting is deprecated in favor of #rust-analyzer.inlayHints.expressionAdjustmentHints.enable#.
        inlayHints_reborrowHints_enable: ReborrowHintsDef          = ReborrowHintsDef::Never,
        /// Whether to render leading colons for type hints, and trailing colons for parameter hints.
        inlayHints_renderColons: bool                              = true,
        /// Whether to show inlay type hints for variables.
        inlayHints_typeHints_enable: bool                          = true,
        /// Whether to hide inlay type hints for `let` statements that initialize to a closure.
        /// Only applies to closures with blocks, same as `#rust-analyzer.inlayHints.closureReturnTypeHints.enable#`.
        inlayHints_typeHints_hideClosureInitialization: bool       = false,
        /// Whether to hide inlay type hints for constructors.
        inlayHints_typeHints_hideNamedConstructor: bool            = false,


        /// Join lines merges consecutive declaration and initialization of an assignment.
        joinLines_joinAssignments: bool = true,
        /// Join lines inserts else between consecutive ifs.
        joinLines_joinElseIf: bool = true,
        /// Join lines removes trailing commas.
        joinLines_removeTrailingComma: bool = true,
        /// Join lines unwraps trivial blocks.
        joinLines_unwrapTrivialBlock: bool = true,

        /// Inject additional highlighting into doc comments.
        ///
        /// When enabled, rust-analyzer will highlight rust source in doc comments as well as intra
        /// doc links.
        semanticHighlighting_doc_comment_inject_enable: bool = true,
        /// Whether the server is allowed to emit non-standard tokens and modifiers.
        semanticHighlighting_nonStandardTokens: bool = true,
        /// Use semantic tokens for operators.
        ///
        /// When disabled, rust-analyzer will emit semantic tokens only for operator tokens when
        /// they are tagged with modifiers.
        semanticHighlighting_operator_enable: bool = true,
        /// Use specialized semantic tokens for operators.
        ///
        /// When enabled, rust-analyzer will emit special token types for operator tokens instead
        /// of the generic `operator` token type.
        semanticHighlighting_operator_specialization_enable: bool = false,
        /// Use semantic tokens for punctuation.
        ///
        /// When disabled, rust-analyzer will emit semantic tokens only for punctuation tokens when
        /// they are tagged with modifiers or have a special role.
        semanticHighlighting_punctuation_enable: bool = false,
        /// When enabled, rust-analyzer will emit a punctuation semantic token for the `!` of macro
        /// calls.
        semanticHighlighting_punctuation_separate_macro_bang: bool = false,
        /// Use specialized semantic tokens for punctuation.
        ///
        /// When enabled, rust-analyzer will emit special token types for punctuation tokens instead
        /// of the generic `punctuation` token type.
        semanticHighlighting_punctuation_specialization_enable: bool = false,
        /// Use semantic tokens for strings.
        ///
        /// In some editors (e.g. vscode) semantic tokens override other highlighting grammars.
        /// By disabling semantic tokens for strings, other grammars can be used to highlight
        /// their contents.
        semanticHighlighting_strings_enable: bool = true,
    }
}

config_data! {
    client: struct ClientConfigData {}
}

impl Default for ConfigData {
    fn default() -> Self {
        ConfigData::from_json(serde_json::Value::Null, &mut Vec::new())
    }
}

#[derive(Debug, Clone)]
struct RootLocalConfigData(LocalConfigData);
#[derive(Debug, Clone)]
struct RootGlobalConfigData(GlobalConfigData);
#[derive(Debug, Clone)]
struct RootClientConfigData(ClientConfigData);

#[derive(Debug, Clone)]
struct RootConfigData {
    local: RootLocalConfigData,
    global: RootGlobalConfigData,
    client: RootClientConfigData,
}

impl Default for RootConfigData {
    fn default() -> Self {
        RootConfigData {
            local: RootLocalConfigData(LocalConfigData::from_json(
                &mut serde_json::Value::Null,
                &mut Vec::new(),
            )),
            global: RootGlobalConfigData(GlobalConfigData::from_json(
                &mut serde_json::Value::Null,
                &mut Vec::new(),
            )),
            client: RootClientConfigData(ClientConfigData::from_json(
                &mut serde_json::Value::Null,
                &mut Vec::new(),
            )),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Config {
    discovered_projects: Vec<ProjectManifest>,
    /// The workspace roots as registered by the LSP client
    workspace_roots: Vec<AbsPathBuf>,
    caps: lsp_types::ClientCapabilities,
    root_path: AbsPathBuf,
    root_config: RootConfigData,
    config_arena: Arena<ConfigData>,
    detached_files: Vec<AbsPathBuf>,
    snippets: Vec<Snippet>,
    is_visual_studio_code: bool,
}

macro_rules! try_ {
    ($expr:expr) => {
        || -> _ { Some($expr) }()
    };
}
macro_rules! try_or {
    ($expr:expr, $or:expr) => {
        try_!($expr).unwrap_or($or)
    };
}

macro_rules! try_or_def {
    ($expr:expr) => {
        try_!($expr).unwrap_or_default()
    };
}

#[derive(Debug, Clone)]
pub struct LocalConfigView<'a> {
    local: &'a LocalConfigData,
    global: &'a RootGlobalConfigData,
    client: &'a RootClientConfigData,
    caps: &'a lsp_types::ClientCapabilities,
    snippets: &'a Vec<Snippet>,
}

impl<'a> LocalConfigView<'a> {
    pub fn assist(&self) -> AssistConfig {
        AssistConfig {
            snippet_cap: SnippetCap::new(self.experimental("snippetTextEdit")),
            allowed: None,
            insert_use: self.insert_use_config(),
            prefer_no_std: self.local.imports_prefer_no_std,
            assist_emit_must_use: self.global.0.assist_emitMustUse,
        }
    }

    pub fn completion(&self) -> CompletionConfig {
        CompletionConfig {
            enable_postfix_completions: self.local.completion_postfix_enable,
            enable_imports_on_the_fly: self.local.completion_autoimport_enable
                && completion_item_edit_resolve(&self.caps),
            enable_self_on_the_fly: self.local.completion_autoself_enable,
            enable_private_editable: self.local.completion_privateEditable_enable,
            full_function_signatures: self.local.completion_fullFunctionSignatures_enable,
            callable: match self.local.completion_callable_snippets {
                CallableCompletionDef::FillArguments => Some(CallableSnippets::FillArguments),
                CallableCompletionDef::AddParentheses => Some(CallableSnippets::AddParentheses),
                CallableCompletionDef::None => None,
            },
            insert_use: self.insert_use_config(),
            prefer_no_std: self.local.imports_prefer_no_std,
            snippet_cap: SnippetCap::new(try_or_def!(
                self.caps
                    .text_document
                    .as_ref()?
                    .completion
                    .as_ref()?
                    .completion_item
                    .as_ref()?
                    .snippet_support?
            )),
            snippets: self.snippets.clone().to_vec(),
            limit: self.local.completion_limit,
        }
    }

    pub fn diagnostics(&self) -> DiagnosticsConfig {
        DiagnosticsConfig {
            enabled: self.global.0.diagnostics_enable,
            proc_attr_macros_enabled: self.expand_proc_attr_macros(),
            proc_macros_enabled: self.global.0.procMacro_enable,
            disable_experimental: !self.global.0.diagnostics_experimental_enable,
            disabled: self.global.0.diagnostics_disabled.clone(),
            expr_fill_default: match self.global.0.assist_expressionFillDefault {
                ExprFillDefaultDef::Todo => ExprFillDefaultMode::Todo,
                ExprFillDefaultDef::Default => ExprFillDefaultMode::Default,
            },
            insert_use: self.insert_use_config(),
            prefer_no_std: self.local.imports_prefer_no_std,
        }
    }
    pub fn expand_proc_attr_macros(&self) -> bool {
        self.global.0.procMacro_enable && self.global.0.procMacro_attributes_enable
    }

    fn experimental(&self, index: &'static str) -> bool {
        try_or_def!(self.caps.experimental.as_ref()?.get(index)?.as_bool()?)
    }

    pub fn highlight_related(&self) -> HighlightRelatedConfig {
        HighlightRelatedConfig {
            references: self.local.highlightRelated_references_enable,
            break_points: self.local.highlightRelated_breakPoints_enable,
            exit_points: self.local.highlightRelated_exitPoints_enable,
            yield_points: self.local.highlightRelated_yieldPoints_enable,
            closure_captures: self.local.highlightRelated_closureCaptures_enable,
        }
    }

    pub fn hover_actions(&self) -> HoverActionsConfig {
        let enable = self.experimental("hoverActions") && self.local.hover_actions_enable;
        HoverActionsConfig {
            implementations: enable && self.local.hover_actions_implementations_enable,
            references: enable && self.local.hover_actions_references_enable,
            run: enable && self.local.hover_actions_run_enable,
            debug: enable && self.local.hover_actions_debug_enable,
            goto_type_def: enable && self.local.hover_actions_gotoTypeDef_enable,
        }
    }

    pub fn hover(&self) -> HoverConfig {
        let mem_kind = |kind| match kind {
            MemoryLayoutHoverRenderKindDef::Both => MemoryLayoutHoverRenderKind::Both,
            MemoryLayoutHoverRenderKindDef::Decimal => MemoryLayoutHoverRenderKind::Decimal,
            MemoryLayoutHoverRenderKindDef::Hexadecimal => MemoryLayoutHoverRenderKind::Hexadecimal,
        };
        HoverConfig {
            links_in_hover: self.local.hover_links_enable,
            memory_layout: self.local.hover_memoryLayout_enable.then_some(
                MemoryLayoutHoverConfig {
                    size: self.local.hover_memoryLayout_size.map(mem_kind),
                    offset: self.local.hover_memoryLayout_offset.map(mem_kind),
                    alignment: self.local.hover_memoryLayout_alignment.map(mem_kind),
                    niches: self.local.hover_memoryLayout_niches.unwrap_or_default(),
                },
            ),
            documentation: self.local.hover_documentation_enable,
            format: {
                let is_markdown = try_or_def!(self
                    .caps
                    .text_document
                    .as_ref()?
                    .hover
                    .as_ref()?
                    .content_format
                    .as_ref()?
                    .as_slice())
                .contains(&MarkupKind::Markdown);
                if is_markdown {
                    HoverDocFormat::Markdown
                } else {
                    HoverDocFormat::PlainText
                }
            },
            keywords: self.local.hover_documentation_keywords_enable,
        }
    }

    pub fn inlay_hints(&self) -> InlayHintsConfig {
        let client_capability_fields = self
            .caps
            .text_document
            .as_ref()
            .and_then(|text| text.inlay_hint.as_ref())
            .and_then(|inlay_hint_caps| inlay_hint_caps.resolve_support.as_ref())
            .map(|inlay_resolve| inlay_resolve.properties.iter())
            .into_iter()
            .flatten()
            .cloned()
            .collect::<FxHashSet<_>>();

        InlayHintsConfig {
            render_colons: self.local.inlayHints_renderColons,
            type_hints: self.local.inlayHints_typeHints_enable,
            parameter_hints: self.local.inlayHints_parameterHints_enable,
            chaining_hints: self.local.inlayHints_chainingHints_enable,
            discriminant_hints: match self.local.inlayHints_discriminantHints_enable {
                DiscriminantHintsDef::Always => ide::DiscriminantHints::Always,
                DiscriminantHintsDef::Never => ide::DiscriminantHints::Never,
                DiscriminantHintsDef::Fieldless => ide::DiscriminantHints::Fieldless,
            },
            closure_return_type_hints: match self.local.inlayHints_closureReturnTypeHints_enable {
                ClosureReturnTypeHintsDef::Always => ide::ClosureReturnTypeHints::Always,
                ClosureReturnTypeHintsDef::Never => ide::ClosureReturnTypeHints::Never,
                ClosureReturnTypeHintsDef::WithBlock => ide::ClosureReturnTypeHints::WithBlock,
            },
            lifetime_elision_hints: match self.local.inlayHints_lifetimeElisionHints_enable {
                LifetimeElisionDef::Always => ide::LifetimeElisionHints::Always,
                LifetimeElisionDef::Never => ide::LifetimeElisionHints::Never,
                LifetimeElisionDef::SkipTrivial => ide::LifetimeElisionHints::SkipTrivial,
            },
            hide_named_constructor_hints: self.local.inlayHints_typeHints_hideNamedConstructor,
            hide_closure_initialization_hints: self
                .local
                .inlayHints_typeHints_hideClosureInitialization,
            closure_style: match self.local.inlayHints_closureStyle {
                ClosureStyle::ImplFn => hir::ClosureStyle::ImplFn,
                ClosureStyle::RustAnalyzer => hir::ClosureStyle::RANotation,
                ClosureStyle::WithId => hir::ClosureStyle::ClosureWithId,
                ClosureStyle::Hide => hir::ClosureStyle::Hide,
            },
            closure_capture_hints: self.local.inlayHints_closureCaptureHints_enable,
            adjustment_hints: match self.local.inlayHints_expressionAdjustmentHints_enable {
                AdjustmentHintsDef::Always => ide::AdjustmentHints::Always,
                AdjustmentHintsDef::Never => match self.local.inlayHints_reborrowHints_enable {
                    ReborrowHintsDef::Always | ReborrowHintsDef::Mutable => {
                        ide::AdjustmentHints::ReborrowOnly
                    }
                    ReborrowHintsDef::Never => ide::AdjustmentHints::Never,
                },
                AdjustmentHintsDef::Reborrow => ide::AdjustmentHints::ReborrowOnly,
            },
            adjustment_hints_mode: match self.local.inlayHints_expressionAdjustmentHints_mode {
                AdjustmentHintsModeDef::Prefix => ide::AdjustmentHintsMode::Prefix,
                AdjustmentHintsModeDef::Postfix => ide::AdjustmentHintsMode::Postfix,
                AdjustmentHintsModeDef::PreferPrefix => ide::AdjustmentHintsMode::PreferPrefix,
                AdjustmentHintsModeDef::PreferPostfix => ide::AdjustmentHintsMode::PreferPostfix,
            },
            adjustment_hints_hide_outside_unsafe: self
                .local
                .inlayHints_expressionAdjustmentHints_hideOutsideUnsafe,
            binding_mode_hints: self.local.inlayHints_bindingModeHints_enable,
            param_names_for_lifetime_elision_hints: self
                .local
                .inlayHints_lifetimeElisionHints_useParameterNames,
            max_length: self.local.inlayHints_maxLength,
            closing_brace_hints_min_lines: if self.local.inlayHints_closingBraceHints_enable {
                Some(self.local.inlayHints_closingBraceHints_minLines)
            } else {
                None
            },
            fields_to_resolve: InlayFieldsToResolve {
                resolve_text_edits: client_capability_fields.contains("textEdits"),
                resolve_hint_tooltip: client_capability_fields.contains("tooltip"),
                resolve_label_tooltip: client_capability_fields.contains("label.tooltip"),
                resolve_label_location: client_capability_fields.contains("label.location"),
                resolve_label_command: client_capability_fields.contains("label.command"),
            },
        }
    }

    fn insert_use_config(&self) -> InsertUseConfig {
        InsertUseConfig {
            granularity: match self.local.imports_granularity_group {
                ImportGranularityDef::Preserve => ImportGranularity::Preserve,
                ImportGranularityDef::Item => ImportGranularity::Item,
                ImportGranularityDef::Crate => ImportGranularity::Crate,
                ImportGranularityDef::Module => ImportGranularity::Module,
            },
            enforce_granularity: self.local.imports_granularity_enforce,
            prefix_kind: match self.local.imports_prefix {
                ImportPrefixDef::Plain => PrefixKind::Plain,
                ImportPrefixDef::ByCrate => PrefixKind::ByCrate,
                ImportPrefixDef::BySelf => PrefixKind::BySelf,
            },
            group: self.local.imports_group_enable,
            skip_glob_imports: !self.local.imports_merge_glob,
        }
    }

    pub fn join_lines(&self) -> JoinLinesConfig {
        JoinLinesConfig {
            join_else_if: self.local.joinLines_joinElseIf,
            remove_trailing_comma: self.local.joinLines_removeTrailingComma,
            unwrap_trivial_blocks: self.local.joinLines_unwrapTrivialBlock,
            join_assignments: self.local.joinLines_joinAssignments,
        }
    }

    pub fn highlighting_non_standard_tokens(&self) -> bool {
        self.local.semanticHighlighting_nonStandardTokens
    }

    pub fn highlighting_config(&self) -> HighlightConfig {
        HighlightConfig {
            strings: self.local.semanticHighlighting_strings_enable,
            punctuation: self.local.semanticHighlighting_punctuation_enable,
            specialize_punctuation: self
                .local
                .semanticHighlighting_punctuation_specialization_enable,
            macro_bang: self.local.semanticHighlighting_punctuation_separate_macro_bang,
            operator: self.local.semanticHighlighting_operator_enable,
            specialize_operator: self.local.semanticHighlighting_operator_specialization_enable,
            inject_doc_comment: self.local.semanticHighlighting_doc_comment_inject_enable,
            syntactic_name_ref_highlighting: false,
        }
    }
}

type ParallelCachePrimingNumThreads = u8;

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum LinkedProject {
    ProjectManifest(ProjectManifest),
    InlineJsonProject(ProjectJson),
}

impl From<ProjectManifest> for LinkedProject {
    fn from(v: ProjectManifest) -> Self {
        LinkedProject::ProjectManifest(v)
    }
}

impl From<ProjectJson> for LinkedProject {
    fn from(v: ProjectJson) -> Self {
        LinkedProject::InlineJsonProject(v)
    }
}

pub struct CallInfoConfig {
    pub params_only: bool,
    pub docs: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LensConfig {
    // runnables
    pub run: bool,
    pub debug: bool,
    pub interpret: bool,

    // implementations
    pub implementations: bool,

    // references
    pub method_refs: bool,
    pub refs_adt: bool,   // for Struct, Enum, Union and Trait
    pub refs_trait: bool, // for Struct, Enum, Union and Trait
    pub enum_variant_refs: bool,

    // annotations
    pub location: AnnotationLocation,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnnotationLocation {
    AboveName,
    AboveWholeItem,
}

impl From<AnnotationLocation> for ide::AnnotationLocation {
    fn from(location: AnnotationLocation) -> Self {
        match location {
            AnnotationLocation::AboveName => ide::AnnotationLocation::AboveName,
            AnnotationLocation::AboveWholeItem => ide::AnnotationLocation::AboveWholeItem,
        }
    }
}

impl LensConfig {
    pub fn any(&self) -> bool {
        self.run
            || self.debug
            || self.implementations
            || self.method_refs
            || self.refs_adt
            || self.refs_trait
            || self.enum_variant_refs
    }

    pub fn none(&self) -> bool {
        !self.any()
    }

    pub fn runnable(&self) -> bool {
        self.run || self.debug
    }

    pub fn references(&self) -> bool {
        self.method_refs || self.refs_adt || self.refs_trait || self.enum_variant_refs
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HoverActionsConfig {
    pub implementations: bool,
    pub references: bool,
    pub run: bool,
    pub debug: bool,
    pub goto_type_def: bool,
}

impl HoverActionsConfig {
    pub const NO_ACTIONS: Self = Self {
        implementations: false,
        references: false,
        run: false,
        debug: false,
        goto_type_def: false,
    };

    pub fn any(&self) -> bool {
        self.implementations || self.references || self.runnable() || self.goto_type_def
    }

    pub fn none(&self) -> bool {
        !self.any()
    }

    pub fn runnable(&self) -> bool {
        self.run || self.debug
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct FilesConfig {
    pub watcher: FilesWatcher,
    pub exclude: Vec<AbsPathBuf>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum FilesWatcher {
    Client,
    Server,
}

#[derive(Debug, Clone, PartialEq)]
pub struct NotificationsConfig {
    pub cargo_toml_not_found: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub enum RustfmtConfig {
    Rustfmt { extra_args: Vec<String>, enable_range_formatting: bool },
    CustomCommand { command: String, args: Vec<String> },
}

/// Configuration for runnable items, such as `main` function or tests.
#[derive(Debug, Clone, PartialEq)]
pub struct RunnablesConfig {
    /// Custom command to be executed instead of `cargo` for runnables.
    pub override_cargo: Option<String>,
    /// Additional arguments for the `cargo`, e.g. `--release`.
    pub cargo_extra_args: Vec<String>,
}

/// Configuration for workspace symbol search requests.
#[derive(Debug, Clone, PartialEq)]
pub struct WorkspaceSymbolConfig {
    /// In what scope should the symbol be searched in.
    pub search_scope: WorkspaceSymbolSearchScope,
    /// What kind of symbol is being searched for.
    pub search_kind: WorkspaceSymbolSearchKind,
    /// How many items are returned at most.
    pub search_limit: usize,
}

pub struct ClientCommandsConfig {
    pub run_single: bool,
    pub debug_single: bool,
    pub show_reference: bool,
    pub goto_location: bool,
    pub trigger_parameter_hints: bool,
}

#[derive(Debug)]
pub struct ConfigError {
    errors: Vec<(String, serde_json::Error)>,
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let errors = self.errors.iter().format_with("\n", |(key, e), f| {
            f(key)?;
            f(&": ")?;
            f(e)
        });
        write!(
            f,
            "invalid config value{}:\n{}",
            if self.errors.len() == 1 { "" } else { "s" },
            errors
        )
    }
}

impl std::error::Error for ConfigError {}

impl Config {
    pub fn new(
        root_path: AbsPathBuf,
        caps: ClientCapabilities,
        workspace_roots: Vec<AbsPathBuf>,
        is_visual_studio_code: bool,
    ) -> Self {
        let root_config = RootConfigData::default();
        let config_arena = Arena::new();

        Config {
            caps,
            root_config,
            detached_files: Vec::new(),
            discovered_projects: Vec::new(),
            root_path,
            snippets: Default::default(),
            workspace_roots,
            is_visual_studio_code,
            config_arena,
        }
    }

    /// Returns a `LocalConfigView` that points to the root config.
    /// This is a compromise for cases where we do not have enough data
    /// to point to a specific local view and we still need to have one
    /// because we need to query fields that are essentially global.
    pub fn localize_to_root_view(&self) -> LocalConfigView<'_> {
        LocalConfigView {
            local: &self.root_config.local.0,
            global: &self.root_config.global,
            client: &self.root_config.client,
            caps: &self.caps,
            snippets: &self.snippets,
        }
    }

    pub fn localize_by_file_id(&self, file_id: FileId) -> LocalConfigView<'_> {
        // FIXME : Plain wrong
        LocalConfigView {
            local: &self.root_config.local.0,
            global: &self.root_config.global,
            client: &self.root_config.client,
            caps: &self.caps,
            snippets: &self.snippets,
        }
    }

    pub fn expand_proc_attr_macros(&self) -> bool {
        self.root_config.global.0.procMacro_enable
            && self.root_config.global.0.procMacro_attributes_enable
    }

    pub fn rediscover_workspaces(&mut self) {
        let discovered = ProjectManifest::discover_all(&self.workspace_roots);
        tracing::info!("discovered projects: {:?}", discovered);
        if discovered.is_empty() {
            tracing::error!("failed to find any projects in {:?}", &self.workspace_roots);
        }
        self.discovered_projects = discovered;
    }

    pub fn remove_workspace(&mut self, path: &AbsPath) {
        if let Some(position) = self.workspace_roots.iter().position(|it| it == path) {
            self.workspace_roots.remove(position);
        }
    }

    pub fn add_workspaces(&mut self, paths: impl Iterator<Item = AbsPathBuf>) {
        self.workspace_roots.extend(paths);
    }

    pub fn update(&mut self, mut json: serde_json::Value) -> Result<(), ConfigError> {
        tracing::info!("updating config from JSON: {:#}", json);
        if json.is_null() || json.as_object().map_or(false, |it| it.is_empty()) {
            return Ok(());
        }
        let mut errors = Vec::new();
        self.detached_files =
            get_field::<Vec<PathBuf>>(&mut json, &mut errors, "detachedFiles", None, vec![])
                .into_iter()
                .map(AbsPathBuf::assert)
                .collect();
        patch_old_style::patch_json_for_outdated_configs(&mut json);
        self.root_config.global =
            RootGlobalConfigData(GlobalConfigData::from_json(&mut json, &mut errors));
        tracing::debug!("deserialized config data: {:#?}", self.root_config.global);
        self.snippets.clear();
        for (name, def) in self.root_config.local.0.completion_snippets_custom.iter() {
            if def.prefix.is_empty() && def.postfix.is_empty() {
                continue;
            }
            let scope = match def.scope {
                SnippetScopeDef::Expr => SnippetScope::Expr,
                SnippetScopeDef::Type => SnippetScope::Type,
                SnippetScopeDef::Item => SnippetScope::Item,
            };
            match Snippet::new(
                &def.prefix,
                &def.postfix,
                &def.body,
                def.description.as_ref().unwrap_or(name),
                &def.requires,
                scope,
            ) {
                Some(snippet) => self.snippets.push(snippet),
                None => errors.push((
                    format!("snippet {name} is invalid"),
                    <serde_json::Error as serde::de::Error>::custom(
                        "snippet path is invalid or triggers are missing",
                    ),
                )),
            }
        }

        self.validate(&mut errors);

        if errors.is_empty() {
            Ok(())
        } else {
            Err(ConfigError { errors })
        }
    }

    fn validate(&self, error_sink: &mut Vec<(String, serde_json::Error)>) {
        use serde::de::Error;
        if self.root_config.global.0.check_command.is_empty() {
            error_sink.push((
                "/check/command".to_string(),
                serde_json::Error::custom("expected a non-empty string"),
            ));
        }
    }

    pub fn json_schema() -> serde_json::Value {
        ConfigData::json_schema()
    }

    pub fn root_path(&self) -> &AbsPathBuf {
        &self.root_path
    }

    pub fn caps(&self) -> &lsp_types::ClientCapabilities {
        &self.caps
    }

    pub fn detached_files(&self) -> &[AbsPathBuf] {
        &self.detached_files
    }
}

impl Config {
    pub fn has_linked_projects(&self) -> bool {
        !self.root_config.global.0.linkedProjects.is_empty()
    }
    pub fn linked_projects(&self) -> Vec<LinkedProject> {
        match self.root_config.global.0.linkedProjects.as_slice() {
            [] => {
                let exclude_dirs: Vec<_> = self
                    .root_config
                    .global
                    .0
                    .files_excludeDirs
                    .iter()
                    .map(|p| self.root_path.join(p))
                    .collect();
                self.discovered_projects
                    .iter()
                    .filter(
                        |(ProjectManifest::ProjectJson(path)
                         | ProjectManifest::CargoToml(path))| {
                            !exclude_dirs.iter().any(|p| path.starts_with(p))
                        },
                    )
                    .cloned()
                    .map(LinkedProject::from)
                    .collect()
            }
            linked_projects => linked_projects
                .iter()
                .filter_map(|linked_project| match linked_project {
                    ManifestOrProjectJson::Manifest(it) => {
                        let path = self.root_path.join(it);
                        ProjectManifest::from_manifest_file(path)
                            .map_err(|e| tracing::error!("failed to load linked project: {}", e))
                            .ok()
                            .map(Into::into)
                    }
                    ManifestOrProjectJson::ProjectJson(it) => {
                        Some(ProjectJson::new(&self.root_path, it.clone()).into())
                    }
                })
                .collect(),
        }
    }

    pub fn add_linked_projects(&mut self, linked_projects: Vec<ProjectJsonData>) {
        let mut linked_projects = linked_projects
            .into_iter()
            .map(ManifestOrProjectJson::ProjectJson)
            .collect::<Vec<ManifestOrProjectJson>>();

        self.root_config.global.0.linkedProjects.append(&mut linked_projects);
    }

    pub fn did_save_text_document_dynamic_registration(&self) -> bool {
        let caps = try_or_def!(self.caps.text_document.as_ref()?.synchronization.clone()?);
        caps.did_save == Some(true) && caps.dynamic_registration == Some(true)
    }

    pub fn did_change_watched_files_dynamic_registration(&self) -> bool {
        try_or_def!(
            self.caps.workspace.as_ref()?.did_change_watched_files.as_ref()?.dynamic_registration?
        )
    }

    pub fn prefill_caches(&self) -> bool {
        self.root_config.global.0.cachePriming_enable
    }

    pub fn location_link(&self) -> bool {
        try_or_def!(self.caps.text_document.as_ref()?.definition?.link_support?)
    }

    pub fn line_folding_only(&self) -> bool {
        try_or_def!(self.caps.text_document.as_ref()?.folding_range.as_ref()?.line_folding_only?)
    }

    pub fn hierarchical_symbols(&self) -> bool {
        try_or_def!(
            self.caps
                .text_document
                .as_ref()?
                .document_symbol
                .as_ref()?
                .hierarchical_document_symbol_support?
        )
    }

    pub fn code_action_literals(&self) -> bool {
        try_!(self
            .caps
            .text_document
            .as_ref()?
            .code_action
            .as_ref()?
            .code_action_literal_support
            .as_ref()?)
        .is_some()
    }

    pub fn work_done_progress(&self) -> bool {
        try_or_def!(self.caps.window.as_ref()?.work_done_progress?)
    }

    pub fn will_rename(&self) -> bool {
        try_or_def!(self.caps.workspace.as_ref()?.file_operations.as_ref()?.will_rename?)
    }

    pub fn change_annotation_support(&self) -> bool {
        try_!(self
            .caps
            .workspace
            .as_ref()?
            .workspace_edit
            .as_ref()?
            .change_annotation_support
            .as_ref()?)
        .is_some()
    }

    pub fn code_action_resolve(&self) -> bool {
        try_or_def!(self
            .caps
            .text_document
            .as_ref()?
            .code_action
            .as_ref()?
            .resolve_support
            .as_ref()?
            .properties
            .as_slice())
        .iter()
        .any(|it| it == "edit")
    }

    pub fn signature_help_label_offsets(&self) -> bool {
        try_or_def!(
            self.caps
                .text_document
                .as_ref()?
                .signature_help
                .as_ref()?
                .signature_information
                .as_ref()?
                .parameter_information
                .as_ref()?
                .label_offset_support?
        )
    }

    pub fn completion_label_details_support(&self) -> bool {
        try_!(self
            .caps
            .text_document
            .as_ref()?
            .completion
            .as_ref()?
            .completion_item
            .as_ref()?
            .label_details_support
            .as_ref()?)
        .is_some()
    }

    pub fn semantics_tokens_augments_syntax_tokens(&self) -> bool {
        try_!(self.caps.text_document.as_ref()?.semantic_tokens.as_ref()?.augments_syntax_tokens?)
            .unwrap_or(false)
    }

    pub fn position_encoding(&self) -> PositionEncoding {
        negotiated_encoding(&self.caps)
    }

    fn experimental(&self, index: &'static str) -> bool {
        try_or_def!(self.caps.experimental.as_ref()?.get(index)?.as_bool()?)
    }

    pub fn code_action_group(&self) -> bool {
        self.experimental("codeActionGroup")
    }

    pub fn local_docs(&self) -> bool {
        self.experimental("localDocs")
    }

    pub fn open_server_logs(&self) -> bool {
        self.experimental("openServerLogs")
    }

    pub fn server_status_notification(&self) -> bool {
        self.experimental("serverStatusNotification")
    }

    /// Whether the client supports colored output for full diagnostics from `checkOnSave`.
    pub fn color_diagnostic_output(&self) -> bool {
        self.experimental("colorDiagnosticOutput")
    }

    pub fn publish_diagnostics(&self) -> bool {
        self.root_config.global.0.diagnostics_enable
    }

    pub fn diagnostics_map(&self) -> DiagnosticsMapConfig {
        DiagnosticsMapConfig {
            remap_prefix: self.root_config.global.0.diagnostics_remapPrefix.clone(),
            warnings_as_info: self.root_config.global.0.diagnostics_warningsAsInfo.clone(),
            warnings_as_hint: self.root_config.global.0.diagnostics_warningsAsHint.clone(),
            check_ignore: self.root_config.global.0.check_ignore.clone(),
        }
    }

    pub fn extra_args(&self) -> &Vec<String> {
        &self.root_config.global.0.cargo_extraArgs
    }

    pub fn extra_env(&self) -> &FxHashMap<String, String> {
        &self.root_config.global.0.cargo_extraEnv
    }

    pub fn check_extra_args(&self) -> Vec<String> {
        let mut extra_args = self.extra_args().clone();
        extra_args.extend_from_slice(&self.root_config.global.0.check_extraArgs);
        extra_args
    }

    pub fn check_extra_env(&self) -> FxHashMap<String, String> {
        let mut extra_env = self.root_config.global.0.cargo_extraEnv.clone();
        extra_env.extend(self.root_config.global.0.check_extraEnv.clone());
        extra_env
    }

    pub fn lru_parse_query_capacity(&self) -> Option<usize> {
        self.root_config.global.0.lru_capacity
    }

    pub fn lru_query_capacities(&self) -> Option<&FxHashMap<Box<str>, usize>> {
        self.root_config
            .global
            .0
            .lru_query_capacities
            .is_empty()
            .not()
            .then(|| &self.root_config.global.0.lru_query_capacities)
    }

    pub fn proc_macro_srv(&self) -> Option<AbsPathBuf> {
        let path = self.root_config.global.0.procMacro_server.clone()?;
        Some(AbsPathBuf::try_from(path).unwrap_or_else(|path| self.root_path.join(&path)))
    }

    pub fn dummy_replacements(&self) -> &FxHashMap<Box<str>, Box<[Box<str>]>> {
        &self.root_config.global.0.procMacro_ignored
    }

    pub fn expand_proc_macros(&self) -> bool {
        self.root_config.global.0.procMacro_enable
    }

    pub fn files(&self) -> FilesConfig {
        FilesConfig {
            watcher: match self.root_config.global.0.files_watcher {
                FilesWatcherDef::Client if self.did_change_watched_files_dynamic_registration() => {
                    FilesWatcher::Client
                }
                _ => FilesWatcher::Server,
            },
            exclude: self
                .root_config
                .global
                .0
                .files_excludeDirs
                .iter()
                .map(|it| self.root_path.join(it))
                .collect(),
        }
    }

    pub fn notifications(&self) -> NotificationsConfig {
        NotificationsConfig {
            cargo_toml_not_found: self.root_config.global.0.notifications_cargoTomlNotFound,
        }
    }

    pub fn cargo_autoreload(&self) -> bool {
        self.root_config.global.0.cargo_autoreload
    }

    pub fn run_build_scripts(&self) -> bool {
        self.root_config.global.0.cargo_buildScripts_enable
            || self.root_config.global.0.procMacro_enable
    }

    pub fn cargo(&self) -> CargoConfig {
        let rustc_source = self.root_config.global.0.rustc_source.as_ref().map(|rustc_src| {
            if rustc_src == "discover" {
                RustLibSource::Discover
            } else {
                RustLibSource::Path(self.root_path.join(rustc_src))
            }
        });
        let sysroot = self.root_config.global.0.cargo_sysroot.as_ref().map(|sysroot| {
            if sysroot == "discover" {
                RustLibSource::Discover
            } else {
                RustLibSource::Path(self.root_path.join(sysroot))
            }
        });
        let sysroot_src = self
            .root_config
            .global
            .0
            .cargo_sysrootSrc
            .as_ref()
            .map(|sysroot| self.root_path.join(sysroot));

        CargoConfig {
            features: match &self.root_config.global.0.cargo_features {
                CargoFeaturesDef::All => CargoFeatures::All,
                CargoFeaturesDef::Selected(features) => CargoFeatures::Selected {
                    features: features.clone(),
                    no_default_features: self.root_config.global.0.cargo_noDefaultFeatures,
                },
            },
            target: self.root_config.global.0.cargo_target.clone(),
            sysroot,
            sysroot_src,
            rustc_source,
            cfg_overrides: project_model::CfgOverrides {
                global: CfgDiff::new(
                    self.root_config
                        .global
                        .0
                        .cargo_cfgs
                        .iter()
                        .map(|(key, val)| {
                            if val.is_empty() {
                                CfgAtom::Flag(key.into())
                            } else {
                                CfgAtom::KeyValue { key: key.into(), value: val.into() }
                            }
                        })
                        .collect(),
                    vec![],
                )
                .unwrap(),
                selective: self
                    .root_config
                    .global
                    .0
                    .cargo_unsetTest
                    .iter()
                    .map(|it| {
                        (
                            it.clone(),
                            CfgDiff::new(vec![], vec![CfgAtom::Flag("test".into())]).unwrap(),
                        )
                    })
                    .collect(),
            },
            wrap_rustc_in_build_scripts: self
                .root_config
                .global
                .0
                .cargo_buildScripts_useRustcWrapper,
            invocation_strategy: match self
                .root_config
                .global
                .0
                .cargo_buildScripts_invocationStrategy
            {
                InvocationStrategy::Once => project_model::InvocationStrategy::Once,
                InvocationStrategy::PerWorkspace => project_model::InvocationStrategy::PerWorkspace,
            },
            invocation_location: match self
                .root_config
                .global
                .0
                .cargo_buildScripts_invocationLocation
            {
                InvocationLocation::Root => {
                    project_model::InvocationLocation::Root(self.root_path.clone())
                }
                InvocationLocation::Workspace => project_model::InvocationLocation::Workspace,
            },
            run_build_script_command: self
                .root_config
                .global
                .0
                .cargo_buildScripts_overrideCommand
                .clone(),
            extra_args: self.root_config.global.0.cargo_extraArgs.clone(),
            extra_env: self.root_config.global.0.cargo_extraEnv.clone(),
            target_dir: self.target_dir_from_config(),
        }
    }

    pub fn rustfmt(&self) -> RustfmtConfig {
        match &self.root_config.global.0.rustfmt_overrideCommand {
            Some(args) if !args.is_empty() => {
                let mut args = args.clone();
                let command = args.remove(0);
                RustfmtConfig::CustomCommand { command, args }
            }
            Some(_) | None => RustfmtConfig::Rustfmt {
                extra_args: self.root_config.global.0.rustfmt_extraArgs.clone(),
                enable_range_formatting: self.root_config.global.0.rustfmt_rangeFormatting_enable,
            },
        }
    }

    pub fn flycheck(&self) -> FlycheckConfig {
        match &self.root_config.global.0.check_overrideCommand {
            Some(args) if !args.is_empty() => {
                let mut args = args.clone();
                let command = args.remove(0);
                FlycheckConfig::CustomCommand {
                    command,
                    args,
                    extra_env: self.check_extra_env(),
                    invocation_strategy: match self.root_config.global.0.check_invocationStrategy {
                        InvocationStrategy::Once => flycheck::InvocationStrategy::Once,
                        InvocationStrategy::PerWorkspace => {
                            flycheck::InvocationStrategy::PerWorkspace
                        }
                    },
                    invocation_location: match self.root_config.global.0.check_invocationLocation {
                        InvocationLocation::Root => {
                            flycheck::InvocationLocation::Root(self.root_path.clone())
                        }
                        InvocationLocation::Workspace => flycheck::InvocationLocation::Workspace,
                    },
                }
            }
            Some(_) | None => FlycheckConfig::CargoCommand {
                command: self.root_config.global.0.check_command.clone(),
                target_triples: self
                    .root_config
                    .global
                    .0
                    .check_targets
                    .clone()
                    .and_then(|targets| match &targets.0[..] {
                        [] => None,
                        targets => Some(targets.into()),
                    })
                    .unwrap_or_else(|| {
                        self.root_config.global.0.cargo_target.clone().into_iter().collect()
                    }),
                all_targets: self.root_config.global.0.check_allTargets,
                no_default_features: self
                    .root_config
                    .global
                    .0
                    .check_noDefaultFeatures
                    .unwrap_or(self.root_config.global.0.cargo_noDefaultFeatures),
                all_features: matches!(
                    self.root_config
                        .global
                        .0
                        .check_features
                        .as_ref()
                        .unwrap_or(&self.root_config.global.0.cargo_features),
                    CargoFeaturesDef::All
                ),
                features: match self
                    .root_config
                    .global
                    .0
                    .check_features
                    .clone()
                    .unwrap_or_else(|| self.root_config.global.0.cargo_features.clone())
                {
                    CargoFeaturesDef::All => vec![],
                    CargoFeaturesDef::Selected(it) => it,
                },
                extra_args: self.check_extra_args(),
                extra_env: self.check_extra_env(),
                ansi_color_output: self.color_diagnostic_output(),
                target_dir: self.target_dir_from_config(),
            },
        }
    }

    fn target_dir_from_config(&self) -> Option<PathBuf> {
        self.root_config.global.0.rust_analyzerTargetDir.as_ref().and_then(|target_dir| {
            match target_dir {
                TargetDirectory::UseSubdirectory(yes) if *yes => {
                    Some(PathBuf::from("target/rust-analyzer"))
                }
                TargetDirectory::UseSubdirectory(_) => None,
                TargetDirectory::Directory(dir) => Some(dir.clone()),
            }
        })
    }

    pub fn check_on_save(&self) -> bool {
        self.root_config.global.0.checkOnSave
    }

    pub fn runnables(&self) -> RunnablesConfig {
        RunnablesConfig {
            override_cargo: self.root_config.global.0.runnables_command.clone(),
            cargo_extra_args: self.root_config.global.0.runnables_extraArgs.clone(),
        }
    }

    pub fn find_all_refs_exclude_imports(&self) -> bool {
        self.root_config.global.0.references_excludeImports
    }

    pub fn snippet_cap(&self) -> bool {
        self.experimental("snippetTextEdit")
    }

    pub fn call_info(&self) -> CallInfoConfig {
        CallInfoConfig {
            params_only: matches!(
                self.root_config.global.0.signatureInfo_detail,
                SignatureDetail::Parameters
            ),
            docs: self.root_config.global.0.signatureInfo_documentation_enable,
        }
    }

    pub fn lens(&self) -> LensConfig {
        LensConfig {
            run: self.root_config.global.0.lens_enable && self.root_config.global.0.lens_run_enable,
            debug: self.root_config.global.0.lens_enable
                && self.root_config.global.0.lens_debug_enable,
            interpret: self.root_config.global.0.lens_enable
                && self.root_config.global.0.lens_run_enable
                && self.root_config.global.0.interpret_tests,
            implementations: self.root_config.global.0.lens_enable
                && self.root_config.global.0.lens_implementations_enable,
            method_refs: self.root_config.global.0.lens_enable
                && self.root_config.global.0.lens_references_method_enable,
            refs_adt: self.root_config.global.0.lens_enable
                && self.root_config.global.0.lens_references_adt_enable,
            refs_trait: self.root_config.global.0.lens_enable
                && self.root_config.global.0.lens_references_trait_enable,
            enum_variant_refs: self.root_config.global.0.lens_enable
                && self.root_config.global.0.lens_references_enumVariant_enable,
            location: self.root_config.global.0.lens_location,
        }
    }

    pub fn workspace_symbol(&self) -> WorkspaceSymbolConfig {
        WorkspaceSymbolConfig {
            search_scope: match self.root_config.global.0.workspace_symbol_search_scope {
                WorkspaceSymbolSearchScopeDef::Workspace => WorkspaceSymbolSearchScope::Workspace,
                WorkspaceSymbolSearchScopeDef::WorkspaceAndDependencies => {
                    WorkspaceSymbolSearchScope::WorkspaceAndDependencies
                }
            },
            search_kind: match self.root_config.global.0.workspace_symbol_search_kind {
                WorkspaceSymbolSearchKindDef::OnlyTypes => WorkspaceSymbolSearchKind::OnlyTypes,
                WorkspaceSymbolSearchKindDef::AllSymbols => WorkspaceSymbolSearchKind::AllSymbols,
            },
            search_limit: self.root_config.global.0.workspace_symbol_search_limit,
        }
    }

    pub fn semantic_tokens_refresh(&self) -> bool {
        try_or_def!(self.caps.workspace.as_ref()?.semantic_tokens.as_ref()?.refresh_support?)
    }

    pub fn code_lens_refresh(&self) -> bool {
        try_or_def!(self.caps.workspace.as_ref()?.code_lens.as_ref()?.refresh_support?)
    }

    pub fn inlay_hints_refresh(&self) -> bool {
        try_or_def!(self.caps.workspace.as_ref()?.inlay_hint.as_ref()?.refresh_support?)
    }

    pub fn insert_replace_support(&self) -> bool {
        try_or_def!(
            self.caps
                .text_document
                .as_ref()?
                .completion
                .as_ref()?
                .completion_item
                .as_ref()?
                .insert_replace_support?
        )
    }

    pub fn client_commands(&self) -> ClientCommandsConfig {
        let commands =
            try_or!(self.caps.experimental.as_ref()?.get("commands")?, &serde_json::Value::Null);
        let commands: Option<lsp_ext::ClientCommandOptions> =
            serde_json::from_value(commands.clone()).ok();
        let force = commands.is_none() && self.root_config.global.0.lens_forceCustomCommands;
        let commands = commands.map(|it| it.commands).unwrap_or_default();

        let get = |name: &str| commands.iter().any(|it| it == name) || force;

        ClientCommandsConfig {
            run_single: get("rust-analyzer.runSingle"),
            debug_single: get("rust-analyzer.debugSingle"),
            show_reference: get("rust-analyzer.showReferences"),
            goto_location: get("rust-analyzer.gotoLocation"),
            trigger_parameter_hints: get("editor.action.triggerParameterHints"),
        }
    }

    pub fn prime_caches_num_threads(&self) -> u8 {
        match self.root_config.global.0.cachePriming_numThreads {
            0 => num_cpus::get_physical().try_into().unwrap_or(u8::MAX),
            n => n,
        }
    }

    pub fn main_loop_num_threads(&self) -> usize {
        self.root_config
            .global
            .0
            .numThreads
            .unwrap_or(num_cpus::get_physical().try_into().unwrap_or(1))
    }

    pub fn typing_autoclose_angle(&self) -> bool {
        self.root_config.global.0.typing_autoClosingAngleBrackets_enable
    }

    // FIXME: VSCode seems to work wrong sometimes, see https://github.com/microsoft/vscode/issues/193124
    // hence, distinguish it for now.
    pub fn is_visual_studio_code(&self) -> bool {
        self.is_visual_studio_code
    }
}
// Deserialization definitions

macro_rules! create_bool_or_string_serde {
    ($ident:ident<$bool:literal, $string:literal>) => {
        mod $ident {
            pub(super) fn deserialize<'de, D>(d: D) -> Result<(), D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                struct V;
                impl<'de> serde::de::Visitor<'de> for V {
                    type Value = ();

                    fn expecting(
                        &self,
                        formatter: &mut std::fmt::Formatter<'_>,
                    ) -> std::fmt::Result {
                        formatter.write_str(concat!(
                            stringify!($bool),
                            " or \"",
                            stringify!($string),
                            "\""
                        ))
                    }

                    fn visit_bool<E>(self, v: bool) -> Result<Self::Value, E>
                    where
                        E: serde::de::Error,
                    {
                        match v {
                            $bool => Ok(()),
                            _ => Err(serde::de::Error::invalid_value(
                                serde::de::Unexpected::Bool(v),
                                &self,
                            )),
                        }
                    }

                    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
                    where
                        E: serde::de::Error,
                    {
                        match v {
                            $string => Ok(()),
                            _ => Err(serde::de::Error::invalid_value(
                                serde::de::Unexpected::Str(v),
                                &self,
                            )),
                        }
                    }

                    fn visit_enum<A>(self, a: A) -> Result<Self::Value, A::Error>
                    where
                        A: serde::de::EnumAccess<'de>,
                    {
                        use serde::de::VariantAccess;
                        let (variant, va) = a.variant::<&'de str>()?;
                        va.unit_variant()?;
                        match variant {
                            $string => Ok(()),
                            _ => Err(serde::de::Error::invalid_value(
                                serde::de::Unexpected::Str(variant),
                                &self,
                            )),
                        }
                    }
                }
                d.deserialize_any(V)
            }

            pub(super) fn serialize<S>(serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                serializer.serialize_str($string)
            }
        }
    };
}
create_bool_or_string_serde!(true_or_always<true, "always">);
create_bool_or_string_serde!(false_or_never<false, "never">);

macro_rules! named_unit_variant {
    ($variant:ident) => {
        pub(super) mod $variant {
            pub(in super::super) fn deserialize<'de, D>(deserializer: D) -> Result<(), D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                struct V;
                impl<'de> serde::de::Visitor<'de> for V {
                    type Value = ();
                    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                        f.write_str(concat!("\"", stringify!($variant), "\""))
                    }
                    fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Self::Value, E> {
                        if value == stringify!($variant) {
                            Ok(())
                        } else {
                            Err(E::invalid_value(serde::de::Unexpected::Str(value), &self))
                        }
                    }
                }
                deserializer.deserialize_str(V)
            }
            pub(in super::super) fn serialize<S>(serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                serializer.serialize_str(stringify!($variant))
            }
        }
    };
}

mod unit_v {
    named_unit_variant!(all);
    named_unit_variant!(skip_trivial);
    named_unit_variant!(mutable);
    named_unit_variant!(reborrow);
    named_unit_variant!(fieldless);
    named_unit_variant!(with_block);
    named_unit_variant!(decimal);
    named_unit_variant!(hexadecimal);
    named_unit_variant!(both);
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq)]
#[serde(rename_all = "snake_case")]
enum SnippetScopeDef {
    Expr,
    Item,
    Type,
}

impl Default for SnippetScopeDef {
    fn default() -> Self {
        SnippetScopeDef::Expr
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq)]
#[serde(default)]
struct SnippetDef {
    #[serde(with = "single_or_array")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    prefix: Vec<String>,

    #[serde(with = "single_or_array")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    postfix: Vec<String>,

    #[serde(with = "single_or_array")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    body: Vec<String>,

    #[serde(with = "single_or_array")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    requires: Vec<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,

    scope: SnippetScopeDef,
}

mod single_or_array {
    use serde::{Deserialize, Serialize};

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct SingleOrVec;

        impl<'de> serde::de::Visitor<'de> for SingleOrVec {
            type Value = Vec<String>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("string or array of strings")
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(vec![value.to_owned()])
            }

            fn visit_seq<A>(self, seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                Deserialize::deserialize(serde::de::value::SeqAccessDeserializer::new(seq))
            }
        }

        deserializer.deserialize_any(SingleOrVec)
    }

    pub fn serialize<S>(vec: &Vec<String>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match &vec[..] {
            // []  case is handled by skip_serializing_if
            [single] => serializer.serialize_str(&single),
            slice => slice.serialize(serializer),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(untagged)]
enum ManifestOrProjectJson {
    Manifest(PathBuf),
    ProjectJson(ProjectJsonData),
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "snake_case")]
enum ExprFillDefaultDef {
    Todo,
    Default,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "snake_case")]
enum ImportGranularityDef {
    Preserve,
    Item,
    Crate,
    Module,
}

#[derive(Serialize, Deserialize, Debug, Copy, Clone, PartialEq)]
#[serde(rename_all = "snake_case")]
enum CallableCompletionDef {
    FillArguments,
    AddParentheses,
    None,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(untagged)]
enum CargoFeaturesDef {
    #[serde(with = "unit_v::all")]
    All,
    Selected(Vec<String>),
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "snake_case")]
enum InvocationStrategy {
    Once,
    PerWorkspace,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
struct CheckOnSaveTargets(#[serde(with = "single_or_array")] Vec<String>);

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "snake_case")]
enum InvocationLocation {
    Root,
    Workspace,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(untagged)]
enum LifetimeElisionDef {
    #[serde(with = "true_or_always")]
    Always,
    #[serde(with = "false_or_never")]
    Never,
    #[serde(with = "unit_v::skip_trivial")]
    SkipTrivial,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(untagged)]
enum ClosureReturnTypeHintsDef {
    #[serde(with = "true_or_always")]
    Always,
    #[serde(with = "false_or_never")]
    Never,
    #[serde(with = "unit_v::with_block")]
    WithBlock,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "snake_case")]
enum ClosureStyle {
    ImplFn,
    RustAnalyzer,
    WithId,
    Hide,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(untagged)]
enum ReborrowHintsDef {
    #[serde(with = "true_or_always")]
    Always,
    #[serde(with = "false_or_never")]
    Never,
    #[serde(with = "unit_v::mutable")]
    Mutable,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(untagged)]
enum AdjustmentHintsDef {
    #[serde(with = "true_or_always")]
    Always,
    #[serde(with = "false_or_never")]
    Never,
    #[serde(with = "unit_v::reborrow")]
    Reborrow,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(untagged)]
enum DiscriminantHintsDef {
    #[serde(with = "true_or_always")]
    Always,
    #[serde(with = "false_or_never")]
    Never,
    #[serde(with = "unit_v::fieldless")]
    Fieldless,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "snake_case")]
enum AdjustmentHintsModeDef {
    Prefix,
    Postfix,
    PreferPrefix,
    PreferPostfix,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "snake_case")]
enum FilesWatcherDef {
    Client,
    Notify,
    Server,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "snake_case")]
enum ImportPrefixDef {
    Plain,
    #[serde(alias = "self")]
    BySelf,
    #[serde(alias = "crate")]
    ByCrate,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "snake_case")]
enum WorkspaceSymbolSearchScopeDef {
    Workspace,
    WorkspaceAndDependencies,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "snake_case")]
enum SignatureDetail {
    Full,
    Parameters,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "snake_case")]
enum WorkspaceSymbolSearchKindDef {
    OnlyTypes,
    AllSymbols,
}

#[derive(Serialize, Deserialize, Debug, Copy, Clone, PartialEq)]
#[serde(rename_all = "snake_case")]
#[serde(untagged)]
enum MemoryLayoutHoverRenderKindDef {
    #[serde(with = "unit_v::decimal")]
    Decimal,
    #[serde(with = "unit_v::hexadecimal")]
    Hexadecimal,
    #[serde(with = "unit_v::both")]
    Both,
}

#[test]
fn untagged_option_hover_render_kind() {
    let hex = MemoryLayoutHoverRenderKindDef::Hexadecimal;

    let ser = serde_json::to_string(&Some(hex)).unwrap();
    assert_eq!(&ser, "\"hexadecimal\"");

    let opt: Option<_> = serde_json::from_str("\"hexadecimal\"").unwrap();
    assert_eq!(opt, Some(hex));
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "snake_case")]
#[serde(untagged)]
pub enum TargetDirectory {
    UseSubdirectory(bool),
    Directory(PathBuf),
}

macro_rules! _default_val {
    (@from_str: $s:literal, $ty:ty) => {{
        let default_: $ty = serde_json::from_str(&$s).unwrap();
        default_
    }};
    ($default:expr, $ty:ty) => {{
        let default_: $ty = $default;
        default_
    }};
}

macro_rules! _default_str {
    (@from_str: $s:literal, $_ty:ty) => {
        $s.to_string()
    };
    ($default:expr, $ty:ty) => {{
        let val = default_val!($default, $ty);
        serde_json::to_string_pretty(&val).unwrap()
    }};
}

macro_rules! _config_data {
    // modname is for the tests
    ($modname:ident: struct $name:ident {
        $(
            $(#[doc=$doc:literal])*
            $field:ident $(| $alias:ident)*: $ty:ty = $(@$marker:ident: )? $default:expr,
        )*
    }) => {
        #[allow(non_snake_case)]
        #[derive(Debug, Clone, Serialize)]
        struct $name { $($field: $ty,)* }
        impl $name {
            #[allow(unused)]
            fn from_json(json: &mut serde_json::Value, error_sink: &mut Vec<(String, serde_json::Error)>) -> $name {
                $name {$(
                    $field: get_field(
                        json,
                        error_sink,
                        stringify!($field),
                        None$(.or(Some(stringify!($alias))))*,
                        default_val!($(@$marker:)? $default, $ty),
                    ),
                )*}
            }

            #[allow(unused)]
            fn from_toml(toml: &mut toml::Table , error_sink: &mut Vec<(String, toml::de::Error)>) -> $name {
                $name {$(
                    $field: get_field_toml::<$ty>(
                        toml,
                        error_sink,
                        stringify!($field),
                        None$(.or(Some(stringify!($alias))))*,
                        default_val!($(@$marker:)? $default, $ty),
                    ),
                )*}
            }

            fn schema_fields(sink: &mut Vec<SchemaField>) {
                sink.extend_from_slice(&[
                    $({
                        let field = stringify!($field);
                        let ty = stringify!($ty);
                        let default = default_str!($(@$marker:)? $default, $ty);

                        (field, ty, &[$($doc),*], default)
                    },)*
                ])
            }
        }

        mod $modname {
            use super::*;
            #[test]
            fn fields_are_sorted() {
                let field_names: &'static [&'static str] = &[$(stringify!($field)),*];
                field_names.windows(2).for_each(|w| assert!(w[0] <= w[1], "{} <= {} does not hold", w[0], w[1]));
            }

            #[test]
            fn roundtrip() {
                $({
                    let field = stringify!($field);
                    let default_val = default_val!($(@$marker:)? $default, $ty);
                    let default_str = default_str!($(@$marker:)? $default, $ty);

                    let from_str_val = serde_json::from_str::<$ty>(&default_str).unwrap();
                    assert!(
                        default_val == from_str_val,
                        "{field}: parsing default value from a string:\n{default_str}\n...to:{from_str_val:?}\n...was not the same as the provided value: {default_val:?}",
                    );
                    let as_str = serde_json::to_string_pretty(&default_val).unwrap();
                    assert!(
                        as_str == default_str,
                        "{field}: converting default value to a string:\n{as_str}\n...was not the same as the provided string: {default_str}",
                    );
                })*
            }
        }
    };
}
use _config_data as config_data;
use _default_str as default_str;
use _default_val as default_val;

#[derive(Debug, Clone, Serialize)]
struct ConfigData {
    #[serde(flatten)]
    global: GlobalConfigData,
    #[serde(flatten)]
    local: LocalConfigData,
    #[serde(flatten)]
    client: ClientConfigData,
}

impl ConfigData {
    fn from_json(
        mut json: serde_json::Value,
        error_sink: &mut Vec<(String, serde_json::Error)>,
    ) -> ConfigData {
        ConfigData {
            global: GlobalConfigData::from_json(&mut json, error_sink),
            local: LocalConfigData::from_json(&mut json, error_sink),
            client: ClientConfigData::from_json(&mut json, error_sink),
        }
    }

    fn from_toml(
        mut toml: toml::Table,
        error_sink: &mut Vec<(String, toml::de::Error)>,
    ) -> ConfigData {
        ConfigData {
            global: GlobalConfigData::from_toml(&mut toml, error_sink),
            local: LocalConfigData::from_toml(&mut toml, error_sink),
            client: ClientConfigData::from_toml(&mut toml, error_sink),
        }
    }

    fn schema_fields() -> Vec<SchemaField> {
        let mut fields = Vec::new();
        GlobalConfigData::schema_fields(&mut fields);
        LocalConfigData::schema_fields(&mut fields);
        ClientConfigData::schema_fields(&mut fields);
        // HACK: sort the fields, so the diffs on the generated docs/schema are smaller
        fields.sort_by_key(|&(x, ..)| x);
        fields
    }

    fn json_schema() -> serde_json::Value {
        schema(&Self::schema_fields())
    }

    #[cfg(test)]
    fn manual() -> String {
        manual(&Self::schema_fields())
    }
}

fn get_field_toml<T: DeserializeOwned>(
    val: &toml::Table,
    error_sink: &mut Vec<(String, toml::de::Error)>,
    field: &'static str,
    alias: Option<&'static str>,
    default: T,
) -> T {
    alias
        .into_iter()
        .chain(iter::once(field))
        .filter_map(move |field| {
            let subkeys = field.split('_');
            let mut v = val;
            for subkey in subkeys {
                if let Some(val) = v.get(subkey) {
                    if let Some(map) = val.as_table() {
                        v = map;
                    } else {
                        return Some(toml::Value::try_into(val.clone()).map_err(|e| (e, v)));
                    }
                } else {
                    return None;
                }
            }
            None
        })
        .find(Result::is_ok)
        .and_then(|res| match res {
            Ok(it) => Some(it),
            Err((e, pointer)) => {
                error_sink.push((pointer.to_string(), e));
                None
            }
        })
        .unwrap_or(default)
}

fn get_field<T: DeserializeOwned>(
    json: &mut serde_json::Value,
    error_sink: &mut Vec<(String, serde_json::Error)>,
    field: &'static str,
    alias: Option<&'static str>,
    default: T,
) -> T {
    // XXX: check alias first, to work around the VS Code where it pre-fills the
    // defaults instead of sending an empty object.
    alias
        .into_iter()
        .chain(iter::once(field))
        .filter_map(move |field| {
            let mut pointer = field.replace('_', "/");
            pointer.insert(0, '/');
            json.pointer_mut(&pointer)
                .map(|it| serde_json::from_value(it.take()).map_err(|e| (e, pointer)))
        })
        .find(Result::is_ok)
        .and_then(|res| match res {
            Ok(it) => Some(it),
            Err((e, pointer)) => {
                tracing::warn!("Failed to deserialize config field at {}: {:?}", pointer, e);
                error_sink.push((pointer, e));
                None
            }
        })
        .unwrap_or(default)
}

type SchemaField = (&'static str, &'static str, &'static [&'static str], String);

fn schema(fields: &[SchemaField]) -> serde_json::Value {
    let map = fields
        .iter()
        .map(|(field, ty, doc, default)| {
            let name = field.replace('_', ".");
            let name = format!("rust-analyzer.{name}");
            let props = field_props(field, ty, doc, default);
            (name, props)
        })
        .collect::<serde_json::Map<_, _>>();
    map.into()
}

fn field_props(field: &str, ty: &str, doc: &[&str], default: &str) -> serde_json::Value {
    let doc = doc_comment_to_string(doc);
    let doc = doc.trim_end_matches('\n');
    assert!(
        doc.ends_with('.') && doc.starts_with(char::is_uppercase),
        "bad docs for {field}: {doc:?}"
    );
    let default = default.parse::<serde_json::Value>().unwrap();

    let mut map = serde_json::Map::default();
    macro_rules! set {
        ($($key:literal: $value:tt),*$(,)?) => {{$(
            map.insert($key.into(), serde_json::json!($value));
        )*}};
    }
    set!("markdownDescription": doc);
    set!("default": default);

    match ty {
        "bool" => set!("type": "boolean"),
        "usize" => set!("type": "integer", "minimum": 0),
        "String" => set!("type": "string"),
        "Vec<String>" => set! {
            "type": "array",
            "items": { "type": "string" },
        },
        "Vec<PathBuf>" => set! {
            "type": "array",
            "items": { "type": "string" },
        },
        "FxHashSet<String>" => set! {
            "type": "array",
            "items": { "type": "string" },
            "uniqueItems": true,
        },
        "FxHashMap<Box<str>, Box<[Box<str>]>>" => set! {
            "type": "object",
        },
        "BTreeMap<String, SnippetDef>" => set! {
            "type": "object",
        },
        "FxHashMap<String, String>" => set! {
            "type": "object",
        },
        "FxHashMap<Box<str>, usize>" => set! {
            "type": "object",
        },
        "Option<usize>" => set! {
            "type": ["null", "integer"],
            "minimum": 0,
        },
        "Option<String>" => set! {
            "type": ["null", "string"],
        },
        "Option<PathBuf>" => set! {
            "type": ["null", "string"],
        },
        "Option<bool>" => set! {
            "type": ["null", "boolean"],
        },
        "Option<Vec<String>>" => set! {
            "type": ["null", "array"],
            "items": { "type": "string" },
        },
        "ExprFillDefaultDef" => set! {
            "type": "string",
            "enum": ["todo", "default"],
            "enumDescriptions": [
                "Fill missing expressions with the `todo` macro",
                "Fill missing expressions with reasonable defaults, `new` or `default` constructors."
            ],
        },
        "ImportGranularityDef" => set! {
            "type": "string",
            "enum": ["preserve", "crate", "module", "item"],
            "enumDescriptions": [
                "Do not change the granularity of any imports and preserve the original structure written by the developer.",
                "Merge imports from the same crate into a single use statement. Conversely, imports from different crates are split into separate statements.",
                "Merge imports from the same module into a single use statement. Conversely, imports from different modules are split into separate statements.",
                "Flatten imports so that each has its own use statement."
            ],
        },
        "ImportPrefixDef" => set! {
            "type": "string",
            "enum": [
                "plain",
                "self",
                "crate"
            ],
            "enumDescriptions": [
                "Insert import paths relative to the current module, using up to one `super` prefix if the parent module contains the requested item.",
                "Insert import paths relative to the current module, using up to one `super` prefix if the parent module contains the requested item. Prefixes `self` in front of the path if it starts with a module.",
                "Force import paths to be absolute by always starting them with `crate` or the extern crate name they come from."
            ],
        },
        "Vec<ManifestOrProjectJson>" => set! {
            "type": "array",
            "items": { "type": ["string", "object"] },
        },
        "WorkspaceSymbolSearchScopeDef" => set! {
            "type": "string",
            "enum": ["workspace", "workspace_and_dependencies"],
            "enumDescriptions": [
                "Search in current workspace only.",
                "Search in current workspace and dependencies."
            ],
        },
        "WorkspaceSymbolSearchKindDef" => set! {
            "type": "string",
            "enum": ["only_types", "all_symbols"],
            "enumDescriptions": [
                "Search for types only.",
                "Search for all symbols kinds."
            ],
        },
        "ParallelCachePrimingNumThreads" => set! {
            "type": "number",
            "minimum": 0,
            "maximum": 255
        },
        "LifetimeElisionDef" => set! {
            "type": "string",
            "enum": [
                "always",
                "never",
                "skip_trivial"
            ],
            "enumDescriptions": [
                "Always show lifetime elision hints.",
                "Never show lifetime elision hints.",
                "Only show lifetime elision hints if a return type is involved."
            ]
        },
        "ClosureReturnTypeHintsDef" => set! {
            "type": "string",
            "enum": [
                "always",
                "never",
                "with_block"
            ],
            "enumDescriptions": [
                "Always show type hints for return types of closures.",
                "Never show type hints for return types of closures.",
                "Only show type hints for return types of closures with blocks."
            ]
        },
        "ReborrowHintsDef" => set! {
            "type": "string",
            "enum": [
                "always",
                "never",
                "mutable"
            ],
            "enumDescriptions": [
                "Always show reborrow hints.",
                "Never show reborrow hints.",
                "Only show mutable reborrow hints."
            ]
        },
        "AdjustmentHintsDef" => set! {
            "type": "string",
            "enum": [
                "always",
                "never",
                "reborrow"
            ],
            "enumDescriptions": [
                "Always show all adjustment hints.",
                "Never show adjustment hints.",
                "Only show auto borrow and dereference adjustment hints."
            ]
        },
        "DiscriminantHintsDef" => set! {
            "type": "string",
            "enum": [
                "always",
                "never",
                "fieldless"
            ],
            "enumDescriptions": [
                "Always show all discriminant hints.",
                "Never show discriminant hints.",
                "Only show discriminant hints on fieldless enum variants."
            ]
        },
        "AdjustmentHintsModeDef" => set! {
            "type": "string",
            "enum": [
                "prefix",
                "postfix",
                "prefer_prefix",
                "prefer_postfix",
            ],
            "enumDescriptions": [
                "Always show adjustment hints as prefix (`*expr`).",
                "Always show adjustment hints as postfix (`expr.*`).",
                "Show prefix or postfix depending on which uses less parenthesis, preferring prefix.",
                "Show prefix or postfix depending on which uses less parenthesis, preferring postfix.",
            ]
        },
        "CargoFeaturesDef" => set! {
            "anyOf": [
                {
                    "type": "string",
                    "enum": [
                        "all"
                    ],
                    "enumDescriptions": [
                        "Pass `--all-features` to cargo",
                    ]
                },
                {
                    "type": "array",
                    "items": { "type": "string" }
                }
            ],
        },
        "Option<CargoFeaturesDef>" => set! {
            "anyOf": [
                {
                    "type": "string",
                    "enum": [
                        "all"
                    ],
                    "enumDescriptions": [
                        "Pass `--all-features` to cargo",
                    ]
                },
                {
                    "type": "array",
                    "items": { "type": "string" }
                },
                { "type": "null" }
            ],
        },
        "CallableCompletionDef" => set! {
            "type": "string",
            "enum": [
                "fill_arguments",
                "add_parentheses",
                "none",
            ],
            "enumDescriptions": [
                "Add call parentheses and pre-fill arguments.",
                "Add call parentheses.",
                "Do no snippet completions for callables."
            ]
        },
        "SignatureDetail" => set! {
            "type": "string",
            "enum": ["full", "parameters"],
            "enumDescriptions": [
                "Show the entire signature.",
                "Show only the parameters."
            ],
        },
        "FilesWatcherDef" => set! {
            "type": "string",
            "enum": ["client", "server"],
            "enumDescriptions": [
                "Use the client (editor) to watch files for changes",
                "Use server-side file watching",
            ],
        },
        "AnnotationLocation" => set! {
            "type": "string",
            "enum": ["above_name", "above_whole_item"],
            "enumDescriptions": [
                "Render annotations above the name of the item.",
                "Render annotations above the whole item, including documentation comments and attributes."
            ],
        },
        "InvocationStrategy" => set! {
            "type": "string",
            "enum": ["per_workspace", "once"],
            "enumDescriptions": [
                "The command will be executed for each workspace.",
                "The command will be executed once."
            ],
        },
        "InvocationLocation" => set! {
            "type": "string",
            "enum": ["workspace", "root"],
            "enumDescriptions": [
                "The command will be executed in the corresponding workspace root.",
                "The command will be executed in the project root."
            ],
        },
        "Option<CheckOnSaveTargets>" => set! {
            "anyOf": [
                {
                    "type": "null"
                },
                {
                    "type": "string",
                },
                {
                    "type": "array",
                    "items": { "type": "string" }
                },
            ],
        },
        "ClosureStyle" => set! {
            "type": "string",
            "enum": ["impl_fn", "rust_analyzer", "with_id", "hide"],
            "enumDescriptions": [
                "`impl_fn`: `impl FnMut(i32, u64) -> i8`",
                "`rust_analyzer`: `|i32, u64| -> i8`",
                "`with_id`: `{closure#14352}`, where that id is the unique number of the closure in r-a internals",
                "`hide`: Shows `...` for every closure type",
            ],
        },
        "Option<MemoryLayoutHoverRenderKindDef>" => set! {
            "anyOf": [
                {
                    "type": "null"
                },
                {
                    "type": "string",
                    "enum": ["both", "decimal", "hexadecimal", ],
                    "enumDescriptions": [
                        "Render as 12 (0xC)",
                        "Render as 12",
                        "Render as 0xC"
                    ],
                },
            ],
        },
        "Option<TargetDirectory>" => set! {
            "anyOf": [
                {
                    "type": "null"
                },
                {
                    "type": "boolean"
                },
                {
                    "type": "string"
                },
            ],
        },
        _ => panic!("missing entry for {ty}: {default}"),
    }

    map.into()
}

#[cfg(test)]
fn manual(fields: &[SchemaField]) -> String {
    fields
        .iter()
        .map(|(field, _ty, doc, default)| {
            let name = format!("rust-analyzer.{}", field.replace('_', "."));
            let doc = doc_comment_to_string(doc);
            if default.contains('\n') {
                format!(
                    r#"[[{name}]]{name}::
+
--
Default:
----
{default}
----
{doc}
--
"#
                )
            } else {
                format!("[[{name}]]{name} (default: `{default}`)::\n+\n--\n{doc}--\n")
            }
        })
        .collect::<String>()
}

fn doc_comment_to_string(doc: &[&str]) -> String {
    doc.iter().map(|it| it.strip_prefix(' ').unwrap_or(it)).map(|it| format!("{it}\n")).collect()
}

#[cfg(test)]
mod tests {
    use std::fs;

    use test_utils::{ensure_file_contents, project_root};

    use super::*;

    #[test]
    fn generate_package_json_config() {
        let s = Config::json_schema();
        let schema = format!("{s:#}");
        let mut schema = schema
            .trim_start_matches('{')
            .trim_end_matches('}')
            .replace("  ", "    ")
            .replace('\n', "\n            ")
            .trim_start_matches('\n')
            .trim_end()
            .to_string();
        schema.push_str(",\n");

        // Transform the asciidoc form link to markdown style.
        //
        // https://link[text] => [text](https://link)
        let url_matches = schema.match_indices("https://");
        let mut url_offsets = url_matches.map(|(idx, _)| idx).collect::<Vec<usize>>();
        url_offsets.reverse();
        for idx in url_offsets {
            let link = &schema[idx..];
            // matching on whitespace to ignore normal links
            if let Some(link_end) = link.find(|c| c == ' ' || c == '[') {
                if link.chars().nth(link_end) == Some('[') {
                    if let Some(link_text_end) = link.find(']') {
                        let link_text = link[link_end..(link_text_end + 1)].to_string();

                        schema.replace_range((idx + link_end)..(idx + link_text_end + 1), "");
                        schema.insert(idx, '(');
                        schema.insert(idx + link_end + 1, ')');
                        schema.insert_str(idx, &link_text);
                    }
                }
            }
        }

        let package_json_path = project_root().join("editors/code/package.json");
        let mut package_json = fs::read_to_string(&package_json_path).unwrap();

        let start_marker = "                \"$generated-start\": {},\n";
        let end_marker = "                \"$generated-end\": {}\n";

        let start = package_json.find(start_marker).unwrap() + start_marker.len();
        let end = package_json.find(end_marker).unwrap();

        let p = remove_ws(&package_json[start..end]);
        let s = remove_ws(&schema);
        if !p.contains(&s) {
            package_json.replace_range(start..end, &schema);
            ensure_file_contents(&package_json_path, &package_json)
        }
    }

    #[test]
    fn generate_config_documentation() {
        let docs_path = project_root().join("docs/user/generated_config.adoc");
        let expected = ConfigData::manual();
        ensure_file_contents(&docs_path, &expected);
    }

    fn remove_ws(text: &str) -> String {
        text.replace(char::is_whitespace, "")
    }

    #[test]
    fn proc_macro_srv_null() {
        let mut config = Config::new(
            AbsPathBuf::try_from(project_root()).unwrap(),
            Default::default(),
            vec![],
            false,
        );
        config
            .update(serde_json::json!({
                "procMacro_server": null,
            }))
            .unwrap();
        assert_eq!(config.proc_macro_srv(), None);
    }

    #[test]
    fn proc_macro_srv_abs() {
        let mut config = Config::new(
            AbsPathBuf::try_from(project_root()).unwrap(),
            Default::default(),
            vec![],
            false,
        );
        config
            .update(serde_json::json!({
                "procMacro": {"server": project_root().display().to_string()}
            }))
            .unwrap();
        assert_eq!(config.proc_macro_srv(), Some(AbsPathBuf::try_from(project_root()).unwrap()));
    }

    #[test]
    fn proc_macro_srv_rel() {
        let mut config = Config::new(
            AbsPathBuf::try_from(project_root()).unwrap(),
            Default::default(),
            vec![],
            false,
        );
        config
            .update(serde_json::json!({
                "procMacro": {"server": "./server"}
            }))
            .unwrap();
        assert_eq!(
            config.proc_macro_srv(),
            Some(AbsPathBuf::try_from(project_root().join("./server")).unwrap())
        );
    }

    #[test]
    fn cargo_target_dir_unset() {
        let mut config = Config::new(
            AbsPathBuf::try_from(project_root()).unwrap(),
            Default::default(),
            vec![],
            false,
        );
        config
            .update(serde_json::json!({
                "rust": { "analyzerTargetDir": null }
            }))
            .unwrap();
        assert_eq!(config.root_config.global.0.rust_analyzerTargetDir, None);
        assert!(
            matches!(config.flycheck(), FlycheckConfig::CargoCommand { target_dir, .. } if target_dir == None)
        );
    }

    #[test]
    fn cargo_target_dir_subdir() {
        let mut config = Config::new(
            AbsPathBuf::try_from(project_root()).unwrap(),
            Default::default(),
            vec![],
            false,
        );
        config
            .update(serde_json::json!({
                "rust": { "analyzerTargetDir": true }
            }))
            .unwrap();
        assert_eq!(
            config.root_config.global.0.rust_analyzerTargetDir,
            Some(TargetDirectory::UseSubdirectory(true))
        );
        assert!(
            matches!(config.flycheck(), FlycheckConfig::CargoCommand { target_dir, .. } if target_dir == Some(PathBuf::from("target/rust-analyzer")))
        );
    }

    #[test]
    fn cargo_target_dir_relative_dir() {
        let mut config = Config::new(
            AbsPathBuf::try_from(project_root()).unwrap(),
            Default::default(),
            vec![],
            false,
        );
        config
            .update(serde_json::json!({
                "rust": { "analyzerTargetDir": "other_folder" }
            }))
            .unwrap();
        assert_eq!(
            config.root_config.global.0.rust_analyzerTargetDir,
            Some(TargetDirectory::Directory(PathBuf::from("other_folder")))
        );
        assert!(
            matches!(config.flycheck(), FlycheckConfig::CargoCommand { target_dir, .. } if target_dir == Some(PathBuf::from("other_folder")))
        );
    }
}

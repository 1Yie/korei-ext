//! Bridge ownership.
//!
//! An unprepared workspace has one Serena server, keyed by its root. Prepared
//! execution installs a session registry and keeps one server per private project
//! and fixed linked-root authorization. Additive contexts reuse the original
//! lease and report its narrower coverage; revocation waits for owner cleanup.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex, OnceLock};

use tokio::sync::Mutex;

use super::bridge::{BridgeFactory, McpBridge, SerenaBridge, SerenaLaunch, SerenaToolInfo};
use super::catalog::SerenaToolCatalog;
use agent_capabilities::{RootAccess, SandboxCtx, WorkspaceCtx};
use agent_tool::{ToolContext, ToolError};

/// A bridge plus the catalog fetched from it — one unit, because a catalog
/// only describes the server it came from.
struct Live {
    bridge: Arc<dyn McpBridge>,
    catalog: SerenaToolCatalog,
}

struct WorkspaceSlot {
    /// `None` until first use, and again after the bridge dies. Held across
    /// the spawn so concurrent callers wait for one server instead of racing
    /// to start several.
    live: Mutex<Option<Live>>,
    effective_grants: StdMutex<Option<Arc<agent_sandbox::EffectiveOsGrants>>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SerenaStatus {
    Stopped,
    Running,
    CleanupPending,
}

impl WorkspaceSlot {
    fn cleanup_pending(&self) -> bool {
        self.effective_grants
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .is_some_and(|grants| !grants.is_quiescent())
    }

    async fn status(&self) -> SerenaStatus {
        match self.live.lock().await.as_ref() {
            None if self.cleanup_pending() => SerenaStatus::CleanupPending,
            None => SerenaStatus::Stopped,
            Some(live) if live.bridge.is_healthy() => SerenaStatus::Running,
            Some(_) => SerenaStatus::CleanupPending,
        }
    }

    async fn stop(&self) -> Result<(), ToolError> {
        let mut live = self.live.lock().await;
        if let Some(entry) = live.as_ref() {
            entry.bridge.shutdown().await?;
        }
        if self.cleanup_pending() {
            return Err(ToolError::Failed(
                "Serena owner cleanup is unconfirmed; its original OS grants remain active".into(),
            ));
        }
        live.take();
        self.effective_grants
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();
        Ok(())
    }
}

pub struct SerenaManager {
    factory: Arc<dyn BridgeFactory>,
    slots: StdMutex<HashMap<PathBuf, Arc<WorkspaceSlot>>>,
    /// Spawns observed — test/diagnostic counter, and the thing that would
    /// have caught a shared bridge across workspaces.
    spawns: std::sync::atomic::AtomicUsize,
}

impl SerenaManager {
    pub fn new(factory: Arc<dyn BridgeFactory>) -> Self {
        Self {
            factory,
            slots: StdMutex::new(HashMap::new()),
            spawns: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    pub fn spawn_count(&self) -> usize {
        self.spawns.load(std::sync::atomic::Ordering::Relaxed)
    }

    pub async fn status(&self, root: &Path) -> SerenaStatus {
        let slot = self
            .slots
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&normalize_root(root))
            .cloned();
        match slot {
            Some(slot) => slot.status().await,
            None => SerenaStatus::Stopped,
        }
    }

    pub async fn stop(&self, root: &Path) -> Result<(), ToolError> {
        let slot = self
            .slots
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&normalize_root(root))
            .cloned();
        if let Some(slot) = slot {
            slot.stop().await?;
        }
        Ok(())
    }

    fn slot(&self, root: &Path) -> Arc<WorkspaceSlot> {
        let mut slots = self.slots.lock().unwrap_or_else(|e| e.into_inner());
        slots
            .entry(root.to_path_buf())
            .or_insert_with(|| {
                Arc::new(WorkspaceSlot {
                    live: Mutex::new(None),
                    effective_grants: StdMutex::new(None),
                })
            })
            .clone()
    }

    /// A healthy bridge for `root`, spawning or restarting as needed.
    pub async fn bridge(&self, root: &Path) -> Result<Arc<dyn McpBridge>, ToolError> {
        let root = normalize_root(root);
        let slot = self.slot(&root);
        let live = self.ensure_live(&slot, &root).await?;
        Ok(live.as_ref().expect("ensure_live").bridge.clone())
    }

    /// The cached `tools/list` for `root` (one request per live bridge).
    pub async fn catalog(&self, root: &Path) -> Result<Vec<SerenaToolInfo>, ToolError> {
        let root = normalize_root(root);
        let slot = self.slot(&root);
        let mut live = self.ensure_live(&slot, &root).await?;
        let entry = live.as_mut().expect("ensure_live");
        let Live { bridge, catalog } = entry;
        let bridge = bridge.clone();
        let tools = catalog.tools(bridge.as_ref()).await?;
        Ok(tools.to_vec())
    }

    /// Render the catalog for the model (see [`SerenaToolCatalog::render`]).
    pub async fn render_catalog(
        &self,
        root: &Path,
        detail: Option<&str>,
    ) -> Result<String, ToolError> {
        let root = normalize_root(root);
        let slot = self.slot(&root);
        let mut live = self.ensure_live(&slot, &root).await?;
        let entry = live.as_mut().expect("ensure_live");
        let Live { bridge, catalog } = entry;
        let bridge = bridge.clone();
        catalog.tools(bridge.as_ref()).await?;
        Ok(catalog.render(detail))
    }

    /// Hold the slot lock and make sure it holds a *healthy* bridge, spawning
    /// one if it is empty or the previous child died.
    ///
    /// The guard is returned, not the bridge: the spawn happens under the lock
    /// so concurrent callers wait for one server instead of racing to start
    /// several, and the caller keeps exclusivity while it talks to the bridge.
    async fn ensure_live<'a>(
        &self,
        slot: &'a WorkspaceSlot,
        root: &Path,
    ) -> Result<tokio::sync::MutexGuard<'a, Option<Live>>, ToolError> {
        ensure_slot(slot, &self.spawns, || self.factory.spawn(root)).await
    }

    /// Forget this workspace's bridge. Called when a call failed in a way that
    /// says the child is gone, so the *next* call restarts instead of writing
    /// into a dead pipe forever.
    pub async fn invalidate(&self, root: &Path) {
        let root = normalize_root(root);
        let slot = self.slot(&root);
        slot.live.lock().await.take();
    }
}

async fn ensure_slot<'a, F, Fut>(
    slot: &'a WorkspaceSlot,
    spawns: &AtomicUsize,
    spawn: F,
) -> Result<tokio::sync::MutexGuard<'a, Option<Live>>, ToolError>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Result<Arc<dyn McpBridge>, ToolError>>,
{
    let mut live = slot.live.lock().await;
    if live
        .as_ref()
        .map(|entry| !entry.bridge.is_healthy())
        .unwrap_or(false)
    {
        if let Some(entry) = live.as_ref() {
            entry.bridge.shutdown().await?;
        }
        if slot.cleanup_pending() {
            return Err(ToolError::Failed(
                "Serena owner cleanup is unconfirmed; refusing to replace its lease".into(),
            ));
        }
        live.take();
    }
    if live.is_none() {
        if slot.cleanup_pending() {
            return Err(ToolError::Failed(
                "Serena startup cleanup is unconfirmed; its original OS grants remain active"
                    .into(),
            ));
        }
        live.replace(Live {
            bridge: spawn().await?,
            catalog: SerenaToolCatalog::default(),
        });
        spawns.fetch_add(1, Ordering::Relaxed);
    }
    Ok(live)
}

#[derive(Clone, PartialEq, Eq, Hash)]
struct ViewKey {
    project: PathBuf,
    auth: Vec<(PathBuf, RootAccess)>,
    root_count: usize,
}

#[cfg(test)]
type SpawnHook = Arc<
    dyn Fn(&Path, &[(PathBuf, RootAccess)]) -> Result<Arc<dyn McpBridge>, ToolError> + Send + Sync,
>;

/// Servers for one prepared session. The host installs one registry per session;
/// delegated children inherit the same slot.
pub struct SerenaRegistry {
    launch: SerenaLaunch,
    child_env: Vec<(String, String)>,
    slots: StdMutex<HashMap<ViewKey, Arc<WorkspaceSlot>>>,
    spawns: AtomicUsize,
    #[cfg(test)]
    hook: Option<SpawnHook>,
}

/// Host-installed registry for this context and its delegated children.
pub struct SerenaRegistrySlot(pub Arc<SerenaRegistry>);

impl SerenaRegistry {
    pub fn new(launch: SerenaLaunch) -> Self {
        Self::with_env(launch, Vec::new())
    }

    pub fn with_env(launch: SerenaLaunch, child_env: Vec<(String, String)>) -> Self {
        Self {
            launch,
            child_env,
            slots: StdMutex::new(HashMap::new()),
            spawns: AtomicUsize::new(0),
            #[cfg(test)]
            hook: None,
        }
    }

    #[cfg(test)]
    pub fn hooked(hook: SpawnHook) -> Self {
        let mut registry = Self::new(SerenaLaunch::from_env());
        registry.hook = Some(hook);
        registry
    }

    pub fn spawn_count(&self) -> usize {
        self.spawns.load(Ordering::Relaxed)
    }

    pub async fn status<C: WorkspaceCtx>(&self, ctx: &C) -> Result<SerenaStatus, ToolError> {
        let mut status = SerenaStatus::Stopped;
        for slot in self.project_slots(&project_path(ctx)?) {
            match slot.status().await {
                SerenaStatus::CleanupPending => return Ok(SerenaStatus::CleanupPending),
                SerenaStatus::Running => status = SerenaStatus::Running,
                SerenaStatus::Stopped => {}
            }
        }
        Ok(status)
    }

    pub async fn stop<C: WorkspaceCtx>(&self, ctx: &C) -> Result<(), ToolError> {
        let mut failure = None;
        for slot in self.project_slots(&project_path(ctx)?) {
            if let Err(error) = slot.stop().await {
                failure.get_or_insert(error);
            }
        }
        match failure {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    fn project_slots(&self, project: &Path) -> Vec<Arc<WorkspaceSlot>> {
        self.slots
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .filter(|(key, _)| key.project == project)
            .map(|(_, slot)| slot.clone())
            .collect()
    }

    pub async fn bridge<C>(&self, ctx: &C) -> Result<Arc<dyn McpBridge>, ToolError>
    where
        C: SandboxCtx + WorkspaceCtx,
    {
        let current = view_key(ctx)?;
        let key = self.select_key(&current).await?;
        let slot = self.slot(&key);
        let project = project_path(ctx)?;
        let live = ensure_slot(&slot, &self.spawns, || async {
            if key != current {
                return Err(ToolError::Failed("retained Serena coverage has stopped; call again to start with the current authorization".into()));
            }
            self.open(ctx, &project, &slot).await
        }).await?;
        Ok(live.as_ref().expect("ensure_slot").bridge.clone())
    }

    pub async fn render_catalog<C>(
        &self,
        ctx: &C,
        detail: Option<&str>,
    ) -> Result<String, ToolError>
    where
        C: SandboxCtx + WorkspaceCtx,
    {
        let current = view_key(ctx)?;
        let key = self.select_key(&current).await?;
        let slot = self.slot(&key);
        let project = project_path(ctx)?;
        let mut live = ensure_slot(&slot, &self.spawns, || async {
            if key != current {
                return Err(ToolError::Failed("retained Serena coverage has stopped; call again to start with the current authorization".into()));
            }
            self.open(ctx, &project, &slot).await
        }).await?;
        let entry = live.as_mut().expect("ensure_slot");
        let bridge = entry.bridge.clone();
        entry.catalog.tools(bridge.as_ref()).await?;
        let mut rendered = entry.catalog.render(detail);
        if let Some(notice) = coverage_notice(&key, &current) {
            rendered.push_str(&format!("\n\n{notice}"));
        }
        Ok(rendered)
    }

    /// Confirm cleanup for every retained owner of this private project.
    pub async fn invalidate<C: WorkspaceCtx>(&self, ctx: &C) -> Result<(), ToolError> {
        self.stop(ctx).await
    }

    /// Includes owners recorded before the stdio handshake completes.
    pub fn effective_grants_for_project(
        &self,
        project: &Path,
    ) -> Vec<Arc<agent_sandbox::EffectiveOsGrants>> {
        self.project_slots(project)
            .into_iter()
            .filter_map(|slot| {
                slot.effective_grants
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .clone()
            })
            .filter(|grants| !grants.is_quiescent())
            .collect()
    }

    pub fn effective_grants<C: WorkspaceCtx>(
        &self,
        ctx: &C,
    ) -> Result<Vec<Arc<agent_sandbox::EffectiveOsGrants>>, ToolError> {
        Ok(self.effective_grants_for_project(&project_path(ctx)?))
    }

    pub async fn coverage_notice<C: WorkspaceCtx>(
        &self,
        ctx: &C,
    ) -> Result<Option<String>, ToolError> {
        let current = view_key(ctx)?;
        let slots: Vec<_> = self
            .slots
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .filter(|(key, _)| key.project == current.project)
            .map(|(key, slot)| (key.clone(), slot.clone()))
            .collect();
        for (key, slot) in slots {
            if slot
                .live
                .lock()
                .await
                .as_ref()
                .is_some_and(|live| live.bridge.is_healthy())
            {
                if let Some(notice) = coverage_notice(&key, &current) {
                    return Ok(Some(notice));
                }
            }
        }
        Ok(None)
    }

    fn slot(&self, key: &ViewKey) -> Arc<WorkspaceSlot> {
        let mut slots = self.slots.lock().unwrap_or_else(|error| error.into_inner());
        slots
            .entry(key.clone())
            .or_insert_with(|| {
                Arc::new(WorkspaceSlot {
                    live: Mutex::new(None),
                    effective_grants: StdMutex::new(None),
                })
            })
            .clone()
    }

    async fn select_key(&self, current: &ViewKey) -> Result<ViewKey, ToolError> {
        let stale: Vec<_> = self
            .slots
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .iter()
            .filter(|(key, _)| key.project == current.project && *key != current)
            .map(|(key, slot)| (key.clone(), slot.clone()))
            .collect();
        let mut retained = None;
        for (key, slot) in stale {
            if is_addition(&key, current) {
                let healthy = slot
                    .live
                    .lock()
                    .await
                    .as_ref()
                    .is_some_and(|live| live.bridge.is_healthy());
                if healthy {
                    retained = Some(key);
                    continue;
                }
            }
            slot.stop().await?;
            self.slots
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .remove(&key);
        }
        Ok(retained.unwrap_or_else(|| current.clone()))
    }

    async fn open<C>(
        &self,
        ctx: &C,
        project: &Path,
        slot: &WorkspaceSlot,
    ) -> Result<Arc<dyn McpBridge>, ToolError>
    where
        C: SandboxCtx + WorkspaceCtx,
    {
        #[cfg(test)]
        if let Some(hook) = &self.hook {
            return hook(project, &authorization(ctx));
        }
        let lease = ctx
            .workspace_lease()
            .ok_or_else(|| ToolError::Failed("prepared serena has no execution lease".into()))?;
        let (program, args) = self.launch.resolve(project);
        let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
        let mut cfg = agent_sandbox::SandboxConfig {
            workspace_dir: ctx.root()?.to_path_buf(),
            allow_network: false,
            ..agent_sandbox::SandboxConfig::default()
        };
        cfg.env_vars.extend(self.child_env.iter().cloned());
        let child = ctx.spawn_process(&cfg, &program, &arg_refs)?;
        *slot
            .effective_grants
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = child.effective_grants();
        let bridge = SerenaBridge::from_managed(project, program, child, Some(lease)).await?;
        Ok(bridge)
    }
}

fn authorization<C: WorkspaceCtx>(ctx: &C) -> Vec<(PathBuf, RootAccess)> {
    let mut auth: Vec<_> = ctx
        .linked_roots()
        .iter()
        .map(|root| (root.path.clone(), root.access))
        .collect();
    auth.sort_by(|left, right| {
        left.0
            .cmp(&right.0)
            .then_with(|| left.1.as_str().cmp(right.1.as_str()))
    });
    auth.dedup();
    auth
}

fn view_key<C: WorkspaceCtx>(ctx: &C) -> Result<ViewKey, ToolError> {
    Ok(ViewKey {
        project: project_path(ctx)?,
        auth: authorization(ctx),
        root_count: ctx
            .workspace_lease()
            .ok_or_else(|| ToolError::Failed("prepared serena has no execution lease".into()))?
            .roots()
            .count(),
    })
}

fn is_addition(original: &ViewKey, current: &ViewKey) -> bool {
    original.project == current.project
        && original.root_count <= current.root_count
        && original.auth.iter().all(|(path, access)| {
            current.auth.iter().any(|(next_path, next_access)| {
                path == next_path
                    && (access == next_access
                        || (*access == RootAccess::Read && *next_access == RootAccess::ReadWrite))
            })
        })
}

fn coverage_notice(original: &ViewKey, current: &ViewKey) -> Option<String> {
    if original == current || !is_addition(original, current) {
        return None;
    }
    let auth = original
        .auth
        .iter()
        .map(|(path, access)| format!("{} ({})", path.display(), access.as_str()))
        .collect::<Vec<_>>()
        .join(", ");
    Some(format!(
        "Serena coverage: this server retains its original authorization [{}] and original lease root count {} (current context: {}). Its coverage does not include newly added roots or permissions. Use serena_stop, then call again to start with the current authorization.",
        auth, original.root_count, current.root_count
    ))
}

fn project_path<C: WorkspaceCtx>(ctx: &C) -> Result<PathBuf, ToolError> {
    let lease = ctx
        .workspace_lease()
        .ok_or_else(|| ToolError::Failed("prepared serena has no execution lease".into()))?;
    let (id, relative) = lease
        .map_source(ctx.root()?)
        .map_err(|error| ToolError::Failed(error.to_string()))?;
    Ok(lease
        .working_root(id)
        .map_err(|error| ToolError::Failed(error.to_string()))?
        .join(relative))
}

/// The prepared session's registry. A missing slot refuses the call.
pub fn registry<C: ToolContext>(ctx: &C) -> Result<Arc<SerenaRegistry>, ToolError> {
    ctx.service::<SerenaRegistrySlot>()
        .map(|slot| slot.0.clone())
        .ok_or_else(|| {
            ToolError::Failed("prepared serena requires a session serena registry".into())
        })
}

/// Install a fresh per-session registry, shared with delegated children.
pub fn install_registry<C: ToolContext>(ctx: &mut C) -> Arc<SerenaRegistry> {
    let registry = Arc::new(SerenaRegistry::new(SerenaLaunch::from_env()));
    ctx.extensions_mut()
        .insert_shared(Arc::new(SerenaRegistrySlot(registry.clone())));
    registry
}

/// Canonical key for the slot map: `ToolCtx` roots are already canonical, but
/// a trailing-slash or symlinked duplicate must not get its own server.
fn normalize_root(root: &Path) -> PathBuf {
    std::fs::canonicalize(root).unwrap_or_else(|_| root.to_path_buf())
}

/// One manager per unprepared workspace root, process-wide.
///
/// Prepared execution is not stored here. A session [`SerenaRegistry`] owns
/// those servers and keys them by private project and authorization, so two views
/// of one workspace cannot share an index. `invalidate` and `shutdown` release
/// an unprepared server when its workspace closes.
pub fn manager_for(root: &Path) -> Arc<SerenaManager> {
    let managers = managers_map();
    let mut managers = managers.lock().unwrap_or_else(|e| e.into_inner());
    managers
        .entry(normalize_root(root))
        .or_insert_with(|| Arc::new(SerenaManager::new(Arc::new(UvxSerenaFactory))))
        .clone()
}

/// Drop the manager (and with it the server) for a workspace that is closing.
pub fn shutdown(root: &Path) {
    let mut managers = managers_map().lock().unwrap_or_else(|e| e.into_inner());
    managers.remove(&normalize_root(root));
}

/// The one process-wide map. `manager_for` and `shutdown` must agree on it —
/// two separate `OnceLock`s would mean `shutdown` silently drops nothing.
fn managers_map() -> &'static StdMutex<HashMap<PathBuf, Arc<SerenaManager>>> {
    static MANAGERS: OnceLock<StdMutex<HashMap<PathBuf, Arc<SerenaManager>>>> = OnceLock::new();
    MANAGERS.get_or_init(|| StdMutex::new(HashMap::new()))
}

/// The real spawner: `uvx --from <source> serena start-mcp-server …`.
pub struct UvxSerenaFactory;

#[async_trait::async_trait]
impl BridgeFactory for UvxSerenaFactory {
    async fn spawn(&self, root: &Path) -> Result<Arc<dyn McpBridge>, ToolError> {
        let bridge = SerenaBridge::spawn(root).await?;
        Ok(bridge as Arc<dyn McpBridge>)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    /// Records which root it was asked for, so "two workspaces" is observable,
    /// plus the last bridge it handed out so a test can kill it.
    #[derive(Default)]
    struct FakeFactory {
        roots: StdMutex<Vec<PathBuf>>,
        lists: Arc<AtomicUsize>,
        last: StdMutex<Option<Arc<FakeBridge>>>,
    }

    struct FakeBridge {
        healthy: AtomicBool,
        lists: Arc<AtomicUsize>,
        stop_error: AtomicBool,
    }

    #[async_trait::async_trait]
    impl McpBridge for FakeBridge {
        async fn shutdown(&self) -> Result<(), ToolError> {
            self.healthy.store(false, Ordering::Release);
            if self.stop_error.load(Ordering::Acquire) {
                return Err(ToolError::Failed("cleanup unconfirmed".into()));
            }
            Ok(())
        }

        async fn call(&self, tool: &str, _args: Value) -> Result<String, ToolError> {
            if !self.is_healthy() {
                return Err(ToolError::Failed("fake bridge is gone".into()));
            }
            Ok(format!("called {tool}"))
        }
        async fn list_tools(&self) -> Result<Vec<SerenaToolInfo>, ToolError> {
            self.lists.fetch_add(1, Ordering::Relaxed);
            Ok(vec![SerenaToolInfo {
                name: "find_symbol".into(),
                description: Some("find".into()),
                input_schema: Some(json!({"type":"object"})),
            }])
        }
        fn is_healthy(&self) -> bool {
            self.healthy.load(Ordering::Relaxed)
        }
        async fn diagnostics(&self) -> String {
            String::new()
        }
    }

    #[async_trait::async_trait]
    impl BridgeFactory for FakeFactory {
        async fn spawn(&self, root: &Path) -> Result<Arc<dyn McpBridge>, ToolError> {
            self.roots.lock().unwrap().push(root.to_path_buf());
            let bridge = Arc::new(FakeBridge {
                healthy: AtomicBool::new(true),
                lists: self.lists.clone(),
                stop_error: AtomicBool::new(false),
            });
            *self.last.lock().unwrap() = Some(bridge.clone());
            Ok(bridge)
        }
    }

    /// The regression test for the shared-bridge bug: two workspaces must
    /// never share one server. A single cached `OnceCell` spawns once and
    /// every later workspace silently talks to the first one's project.
    #[tokio::test]
    async fn each_workspace_gets_its_own_bridge() {
        let factory = Arc::new(FakeFactory::default());
        let mgr = SerenaManager::new(factory.clone());
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("project-a");
        let b = dir.path().join("project-b");
        std::fs::create_dir_all(&a).unwrap();
        std::fs::create_dir_all(&b).unwrap();

        let _ = mgr.bridge(&a).await.unwrap();
        let _ = mgr.bridge(&a).await.unwrap();
        let _ = mgr.bridge(&b).await.unwrap();

        let roots = factory.roots.lock().unwrap().clone();
        assert_eq!(
            mgr.spawn_count(),
            2,
            "one server per workspace, not per call"
        );
        assert!(roots[0].ends_with("project-a"), "{roots:?}");
        assert!(
            roots[1].ends_with("project-b"),
            "workspace B reused A's bridge: {roots:?}"
        );
    }

    #[tokio::test]
    async fn status_and_stop_preserve_failed_cleanup_without_spawning() {
        let factory = Arc::new(FakeFactory::default());
        let manager = SerenaManager::new(factory.clone());
        let root = tempfile::tempdir().unwrap();
        assert_eq!(manager.status(root.path()).await, SerenaStatus::Stopped);
        manager.stop(root.path()).await.unwrap();
        assert_eq!(manager.spawn_count(), 0);
        let bridge = manager.bridge(root.path()).await.unwrap();
        let retained = factory.last.lock().unwrap().as_ref().unwrap().clone();
        assert_eq!(manager.status(root.path()).await, SerenaStatus::Running);
        retained.stop_error.store(true, Ordering::Release);
        assert!(manager.stop(root.path()).await.is_err());
        assert_eq!(
            manager.status(root.path()).await,
            SerenaStatus::CleanupPending
        );
        assert!(manager.bridge(root.path()).await.is_err());
        assert_eq!(manager.spawn_count(), 1);
        retained.stop_error.store(false, Ordering::Release);
        manager.stop(root.path()).await.unwrap();
        manager.stop(root.path()).await.unwrap();
        assert_eq!(manager.status(root.path()).await, SerenaStatus::Stopped);
        assert_eq!(manager.spawn_count(), 1);
        assert!(!bridge.is_healthy());
        let replacement = manager.bridge(root.path()).await.unwrap();
        assert!(!Arc::ptr_eq(&bridge, &replacement));
        assert_eq!(manager.spawn_count(), 2);
    }

    /// A dead child must be replaced on the next call — the old code cached
    /// the handle forever and kept writing into a closed pipe.
    #[tokio::test]
    async fn dead_bridge_is_replaced_on_the_next_call() {
        let factory = Arc::new(FakeFactory::default());
        let mgr = SerenaManager::new(factory.clone());
        let dir = tempfile::tempdir().unwrap();

        let first = mgr.bridge(dir.path()).await.unwrap();
        assert!(first.is_healthy());
        // The child exits (the reader task flips this in the real bridge).
        factory
            .last
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .healthy
            .store(false, Ordering::Relaxed);

        let second = mgr.bridge(dir.path()).await.unwrap();
        assert_eq!(mgr.spawn_count(), 2, "a dead child must be respawned");
        assert!(
            second.is_healthy(),
            "the manager handed out the dead bridge again"
        );

        // Explicit invalidation (what the tool does when a call failed on a
        // child that had already died) also forces a restart.
        mgr.invalidate(dir.path()).await;
        let _ = mgr.bridge(dir.path()).await.unwrap();
        assert_eq!(mgr.spawn_count(), 3);
    }

    /// `tools/list` costs one round trip per bridge, not one per call.
    #[tokio::test]
    async fn catalog_is_fetched_once_per_bridge() {
        let factory = Arc::new(FakeFactory::default());
        let mgr = SerenaManager::new(factory.clone());
        let dir = tempfile::tempdir().unwrap();

        mgr.bridge(dir.path()).await.unwrap();
        mgr.catalog(dir.path()).await.unwrap();
        mgr.catalog(dir.path()).await.unwrap();
        let rendered = mgr.render_catalog(dir.path(), None).await.unwrap();

        assert_eq!(mgr.spawn_count(), 1, "catalog reads must not respawn");
        assert_eq!(
            factory.lists.load(Ordering::Relaxed),
            1,
            "tools/list must be fetched once per bridge, not per call"
        );
        assert!(rendered.contains("find_symbol"), "{rendered}");

        // …and a restart refetches it (the catalog belongs to one server).
        mgr.invalidate(dir.path()).await;
        mgr.render_catalog(dir.path(), None).await.unwrap();
        assert_eq!(factory.lists.load(Ordering::Relaxed), 2);
    }

    /// The process-wide registry is keyed by the **workspace root**: two
    /// workspaces get two managers (and so two servers), one workspace gets
    /// one, and `shutdown` releases it. This is the property the old
    /// process-wide `OnceCell<Option<Arc<SerenaBridge>>>` broke — there, the
    /// second workspace silently talked to the first one's project.
    #[tokio::test]
    async fn registry_is_keyed_by_workspace_root() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("ws-a");
        let b = dir.path().join("ws-b");
        std::fs::create_dir_all(&a).unwrap();
        std::fs::create_dir_all(&b).unwrap();

        let ma = manager_for(&a);
        assert!(
            Arc::ptr_eq(&ma, &manager_for(&a)),
            "same root must reuse one manager"
        );
        assert!(
            Arc::ptr_eq(&ma, &manager_for(&a.join("."))),
            "a non-normalized path must not get its own server"
        );

        let mb = manager_for(&b);
        assert!(
            !Arc::ptr_eq(&ma, &mb),
            "two workspaces shared one manager — the isolation bug"
        );

        shutdown(&a);
        assert!(
            !Arc::ptr_eq(&ma, &manager_for(&a)),
            "shutdown must drop the entry"
        );
        shutdown(&a);
        shutdown(&b);
    }

    /// Concurrent first calls must not each start a server.
    #[tokio::test]
    async fn concurrent_first_calls_share_one_spawn() {
        let factory = Arc::new(FakeFactory::default());
        let mgr = Arc::new(SerenaManager::new(factory.clone()));
        let dir = tempfile::tempdir().unwrap();

        let mut set = tokio::task::JoinSet::new();
        for _ in 0..8 {
            let mgr = mgr.clone();
            let root = dir.path().to_path_buf();
            set.spawn(async move { mgr.bridge(&root).await.map(|_| ()) });
        }
        while let Some(r) = set.join_next().await {
            r.unwrap().unwrap();
        }
        assert_eq!(
            mgr.spawn_count(),
            1,
            "thundering herd spawned extra servers"
        );
    }

    #[cfg(unix)]
    mod prepared {
        use super::{
            registry, Arc, AtomicBool, AtomicUsize, FakeBridge, McpBridge, Ordering, PathBuf,
            SerenaRegistry, SerenaRegistrySlot, SerenaStatus, SerenaToolInfo, StdMutex, ToolError,
            Value,
        };
        use serde_json::json;
        use std::os::unix::fs::PermissionsExt;

        use agent_capabilities::{LinkedRoot, LinkedRoots, RootAccess, WorkspaceCtx};
        use agent_sandbox::snapshot::{SnapshotBudget, SnapshotPreference, WorkspaceSnapshot};
        use agent_tool::ToolContext;

        #[derive(Default)]
        struct Ctx(agent_tool::Extensions);

        impl ToolContext for Ctx {
            fn extensions(&self) -> &agent_tool::Extensions {
                &self.0
            }

            fn extensions_mut(&mut self) -> &mut agent_tool::Extensions {
                &mut self.0
            }
        }

        struct Probe {
            healthy: Arc<AtomicBool>,
            dropped: Arc<AtomicBool>,
        }

        impl Probe {
            fn healthy() -> Self {
                Self {
                    healthy: Arc::new(AtomicBool::new(true)),
                    dropped: Arc::new(AtomicBool::new(false)),
                }
            }
        }

        impl Drop for Probe {
            fn drop(&mut self) {
                self.dropped.store(true, Ordering::Release);
            }
        }

        #[async_trait::async_trait]
        impl McpBridge for Probe {
            async fn shutdown(&self) -> Result<(), ToolError> {
                self.healthy.store(false, Ordering::Release);
                Ok(())
            }

            async fn call(&self, _tool: &str, _args: Value) -> Result<String, ToolError> {
                Ok("ok".into())
            }

            async fn list_tools(&self) -> Result<Vec<SerenaToolInfo>, ToolError> {
                Ok(Vec::new())
            }

            fn is_healthy(&self) -> bool {
                self.healthy.load(Ordering::Acquire)
            }

            async fn diagnostics(&self) -> String {
                String::new()
            }
        }

        fn prepared_ctx() -> (tempfile::TempDir, WorkspaceSnapshot, Ctx) {
            let temp = tempfile::tempdir().unwrap();
            let base = temp.path().canonicalize().unwrap();
            let source = base.join("source");
            let storage = base.join("storage");
            std::fs::create_dir(&source).unwrap();
            std::fs::create_dir(&storage).unwrap();
            std::fs::set_permissions(&storage, std::fs::Permissions::from_mode(0o700)).unwrap();
            std::fs::write(source.join("original"), "unchanged").unwrap();
            let snapshot = WorkspaceSnapshot::prepare(
                &[source.clone()],
                &storage,
                SnapshotBudget {
                    max_bytes: 1024 * 1024,
                    max_entries: 64,
                    max_depth: 8,
                },
                SnapshotPreference::PrivateCopy,
            )
            .unwrap();
            let mut ctx = Ctx::default().with_workspace(source);
            ctx.install_workspace_lease(snapshot.lease().unwrap())
                .unwrap();
            (temp, snapshot, ctx)
        }

        fn bind(ctx: &mut Ctx, registry: Arc<SerenaRegistry>) {
            ctx.extensions_mut()
                .insert_shared(Arc::new(SerenaRegistrySlot(registry)));
        }

        #[tokio::test]
        async fn control_tools_do_not_start_servers_and_stop_only_their_view() {
            let registry = Arc::new(SerenaRegistry::hooked(Arc::new(|_, _| {
                Ok(Arc::new(Probe::healthy()))
            })));
            let (_dir, _snapshot, mut ctx) = prepared_ctx();
            let (_other_dir, _other_snapshot, mut other) = prepared_ctx();
            bind(&mut ctx, registry.clone());
            bind(&mut other, registry.clone());
            let roots = Arc::new(LinkedRoots::default());
            ctx.install_linked_roots(roots.clone());
            let ctx = Arc::new(ctx);
            let spec = crate::tool::spec::<Ctx>();
            let status = (spec.exec)(json!({"tool":"serena_status"}), ctx.clone())
                .await
                .unwrap();
            assert_eq!(status.content, "serena: stopped");
            (spec.exec)(json!({"tool":"serena_stop"}), ctx.clone())
                .await
                .unwrap();
            assert_eq!(registry.spawn_count(), 0);
            let bridge = registry.bridge(&*ctx).await.unwrap();
            let other_bridge = registry.bridge(&other).await.unwrap();
            roots.set(vec![LinkedRoot {
                path: ctx.root().unwrap().join("linked"),
                access: RootAccess::Read,
            }]);
            let status = (spec.exec)(json!({"tool":"serena_status"}), ctx.clone())
                .await
                .unwrap();
            assert_eq!(status.content, "serena: running");
            (spec.exec)(json!({"tool":"serena_stop"}), ctx.clone())
                .await
                .unwrap();
            assert!(!bridge.is_healthy());
            assert!(other_bridge.is_healthy());
            assert_eq!(registry.status(&*ctx).await.unwrap(), SerenaStatus::Stopped);
            assert_eq!(registry.spawn_count(), 2);
        }

        #[tokio::test]
        async fn separate_views_use_private_projects_and_do_not_share_a_server() {
            let seen = Arc::new(StdMutex::new(Vec::<PathBuf>::new()));
            let record = seen.clone();
            let registry = Arc::new(SerenaRegistry::hooked(Arc::new(move |project, _| {
                record
                    .lock()
                    .unwrap_or_else(|error| error.into_inner())
                    .push(project.to_path_buf());
                Ok(Arc::new(Probe::healthy()))
            })));
            let (_first_dir, first_snapshot, mut first) = prepared_ctx();
            let (_second_dir, _second_snapshot, mut second) = prepared_ctx();
            bind(&mut first, registry.clone());
            bind(&mut second, registry.clone());
            let first_bridge = registry.bridge(&first).await.unwrap();
            let again = registry.bridge(&first).await.unwrap();
            assert!(Arc::ptr_eq(&first_bridge, &again));
            let mut next_turn = Ctx::default().with_workspace(first.root().unwrap().to_owned());
            next_turn
                .install_workspace_lease(first_snapshot.lease().unwrap())
                .unwrap();
            bind(&mut next_turn, registry.clone());
            let next_bridge = registry.bridge(&next_turn).await.unwrap();
            assert!(Arc::ptr_eq(&first_bridge, &next_bridge));
            let second_bridge = registry.bridge(&second).await.unwrap();
            assert!(!Arc::ptr_eq(&first_bridge, &second_bridge));
            assert_eq!(registry.spawn_count(), 2);
            let seen = seen.lock().unwrap();
            assert_eq!(seen.len(), 2);
            assert_ne!(seen[0], seen[1]);
            for (ctx, project) in [(&first, &seen[0]), (&second, &seen[1])] {
                let source = ctx.root().unwrap();
                assert_ne!(project, source);
                let lease = ctx.workspace_lease().unwrap();
                let (id, relative) = lease.map_source(source).unwrap();
                assert_eq!(project, &lease.working_root(id).unwrap().join(relative));
            }
        }

        #[tokio::test]
        async fn added_authorization_reuses_original_coverage_and_revocation_stops_it() {
            let dropped = Arc::new(AtomicBool::new(false));
            let flag = dropped.clone();
            let registry = Arc::new(SerenaRegistry::hooked(Arc::new(move |_, _| {
                Ok(Arc::new(Probe {
                    healthy: Arc::new(AtomicBool::new(true)),
                    dropped: flag.clone(),
                }))
            })));
            let (_dir, _snapshot, mut ctx) = prepared_ctx();
            let roots = Arc::new(LinkedRoots::default());
            ctx.install_linked_roots(roots.clone());
            bind(&mut ctx, registry.clone());
            let linked = ctx.root().unwrap().join("linked");
            roots.set(vec![LinkedRoot {
                path: linked.clone(),
                access: RootAccess::ReadWrite,
            }]);
            let original = registry.bridge(&ctx).await.unwrap();
            roots.set(vec![
                LinkedRoot {
                    path: linked.clone(),
                    access: RootAccess::ReadWrite,
                },
                LinkedRoot {
                    path: ctx.root().unwrap().join("added"),
                    access: RootAccess::Read,
                },
            ]);
            let reused = registry.bridge(&ctx).await.unwrap();
            assert!(Arc::ptr_eq(&original, &reused));
            assert!(!dropped.load(Ordering::Acquire));
            assert_eq!(registry.spawn_count(), 1);
            let catalog = registry.render_catalog(&ctx, None).await.unwrap();
            assert!(catalog.contains("original authorization ["));
            assert!(catalog.contains(&linked.display().to_string()));
            assert!(catalog.contains("original lease root count 1"));
            let spec = crate::tool::spec::<Ctx>();
            let ctx = Arc::new(ctx);
            let result = (spec.exec)(json!({"tool":"find_symbol"}), ctx.clone())
                .await
                .unwrap();
            assert!(result.content.contains("serena_stop"));
            roots.set(vec![LinkedRoot {
                path: linked,
                access: RootAccess::Read,
            }]);
            let replacement = registry.bridge(&*ctx).await.unwrap();
            assert!(!original.is_healthy());
            assert!(!Arc::ptr_eq(&original, &replacement));
            assert_eq!(registry.spawn_count(), 2);
            drop(reused);
            drop(original);
            assert!(dropped.load(Ordering::Acquire));
        }

        #[tokio::test]
        async fn changed_authorization_keeps_failed_cleanup_reachable() {
            let bridge = Arc::new(FakeBridge {
                healthy: AtomicBool::new(true),
                lists: Arc::new(AtomicUsize::new(0)),
                stop_error: AtomicBool::new(true),
            });
            let registry = Arc::new(SerenaRegistry::hooked({
                let bridge = bridge.clone();
                Arc::new(move |_, _| Ok(bridge.clone()))
            }));
            let (_dir, _snapshot, mut ctx) = prepared_ctx();
            let roots = Arc::new(LinkedRoots::default());
            ctx.install_linked_roots(roots.clone());
            bind(&mut ctx, registry.clone());
            roots.set(vec![LinkedRoot {
                path: ctx.root().unwrap().join("linked"),
                access: RootAccess::ReadWrite,
            }]);
            registry.bridge(&ctx).await.unwrap();
            roots.set(vec![LinkedRoot {
                path: ctx.root().unwrap().join("linked"),
                access: RootAccess::Read,
            }]);
            assert!(registry.bridge(&ctx).await.is_err());
            assert_eq!(registry.spawn_count(), 1);
            assert_eq!(
                registry.status(&ctx).await.unwrap(),
                SerenaStatus::CleanupPending
            );
            bridge.stop_error.store(false, Ordering::Release);
            registry.stop(&ctx).await.unwrap();
            assert_eq!(registry.status(&ctx).await.unwrap(), SerenaStatus::Stopped);
        }

        #[tokio::test]
        async fn dead_view_bridge_is_replaced() {
            let healthy = Arc::new(AtomicBool::new(true));
            let dropped = Arc::new(AtomicBool::new(false));
            let registry = Arc::new(SerenaRegistry::hooked({
                let healthy = healthy.clone();
                let dropped = dropped.clone();
                Arc::new(move |_, _| {
                    Ok(Arc::new(Probe {
                        healthy: healthy.clone(),
                        dropped: dropped.clone(),
                    }))
                })
            }));
            let (_dir, _snapshot, mut ctx) = prepared_ctx();
            bind(&mut ctx, registry.clone());
            drop(registry.bridge(&ctx).await.unwrap());
            healthy.store(false, Ordering::Release);
            let _replacement = registry.bridge(&ctx).await.unwrap();
            assert!(dropped.load(Ordering::Acquire));
            assert_eq!(registry.spawn_count(), 2);
        }

        #[tokio::test]
        async fn concurrent_view_calls_share_one_spawn() {
            let registry = Arc::new(SerenaRegistry::hooked(Arc::new(|_, _| {
                Ok(Arc::new(Probe::healthy()))
            })));
            let (_dir, _snapshot, mut ctx) = prepared_ctx();
            bind(&mut ctx, registry.clone());
            let ctx = Arc::new(ctx);
            let mut set = tokio::task::JoinSet::new();
            for _ in 0..8 {
                let registry = registry.clone();
                let ctx = ctx.clone();
                set.spawn(async move { registry.bridge(&*ctx).await.map(|_| ()) });
            }
            while let Some(result) = set.join_next().await {
                result.unwrap().unwrap();
            }
            assert_eq!(registry.spawn_count(), 1);
        }

        #[tokio::test]
        async fn prepared_context_without_a_registry_is_refused() {
            let (_dir, _snapshot, ctx) = prepared_ctx();
            let Err(error) = registry(&ctx) else {
                panic!("prepared context must refuse without a registry");
            };
            assert!(
                error.to_string().contains("session serena registry"),
                "{error}"
            );
        }

        #[cfg(target_os = "macos")]
        #[tokio::test]
        async fn isolated_registry_reuses_stdio_and_releases_the_lease() {
            use std::time::Duration;

            use super::{Path, SerenaLaunch};
            use agent_capabilities::SandboxCtx;
            use serde_json::json;

            use agent_sandbox::spawn::{
                spawn_isolated, ExecutionKind, IsolatedSpawn, MemoryEnforcement, SandboxedChild,
            };
            use agent_sandbox::{
                CommandOutput, SandboxBackend, SandboxCapabilities, SandboxConfig, SandboxTier,
            };

            struct LeasedBackend;

            #[async_trait::async_trait]
            impl SandboxBackend for LeasedBackend {
                fn id(&self) -> &'static str {
                    "leased-test"
                }

                fn tier(&self) -> SandboxTier {
                    SandboxTier::L2
                }

                fn capabilities(&self) -> SandboxCapabilities {
                    SandboxCapabilities {
                        filesystem: true,
                        network: true,
                        snapshots: true,
                    }
                }

                async fn run_command(
                    &self,
                    _: &str,
                    _: &[&str],
                    _: &SandboxConfig,
                ) -> anyhow::Result<CommandOutput> {
                    anyhow::bail!("ordinary command execution must not be used")
                }

                fn wrap_spawn(
                    &self,
                    _: &SandboxConfig,
                    _: &str,
                    _: &[&str],
                ) -> Option<tokio::process::Command> {
                    panic!("ordinary process wrapping must not be used")
                }

                fn spawn_leased(
                    &self,
                    lease: Arc<agent_sandbox::snapshot::SnapshotLease>,
                    cfg: &SandboxConfig,
                    cmd: &str,
                    args: &[&str],
                ) -> anyhow::Result<SandboxedChild> {
                    let executable = std::fs::canonicalize(cmd)?;
                    let request = IsolatedSpawn {
                        executable: executable.clone(),
                        linux_launcher: None,
                        linux_cgroup_parent: None,
                        args: args.iter().map(std::ffi::OsString::from).collect(),
                        root: Some(lease.map_source(&cfg.workspace_dir)?.0),
                        kind: ExecutionKind::Tool,
                        read_only: vec![executable, "/usr/lib".into(), "/System/Library".into()],
                        deny_read: Vec::new(),
                        deny_write: Vec::new(),
                        env: Vec::new(),
                        max_memory_bytes: 128 * 1024 * 1024,
                        max_processes: 1,
                        memory_enforcement: MemoryEnforcement::MonitoredRss,
                        tool_policy: Some(cfg.clone()),
                    };
                    spawn_isolated(lease, &request)
                }
            }

            for explicit_stop in [false, true] {
                let (_dir, mut snapshot, mut ctx) = prepared_ctx();
                ctx.install_sandbox(Arc::new(LeasedBackend));
                let program = std::env::current_exe().unwrap();
                let registry = Arc::new(SerenaRegistry::with_env(
                    SerenaLaunch {
                        program: Some(program.display().to_string()),
                        source: String::new(),
                        modes: Vec::new(),
                        argv_override: Some(vec![
                            "--exact".into(),
                            "bridge::tests::stub_mcp_server".into(),
                            "--nocapture".into(),
                            "--quiet".into(),
                        ]),
                    },
                    vec![
                        ("AGENT_SERENA_STUB".into(), "write-on-call".into()),
                        ("RUST_TEST_THREADS".into(), "1".into()),
                    ],
                ));
                bind(&mut ctx, registry.clone());
                let source = ctx.root().unwrap().to_path_buf();
                let ctx = Arc::new(ctx);
                let bridge = tokio::time::timeout(Duration::from_secs(10), registry.bridge(&*ctx))
                    .await
                    .expect("isolated MCP handshake must complete")
                    .unwrap();
                assert_eq!(
                    bridge.call("find_symbol", json!({})).await.unwrap(),
                    "stub-ok"
                );
                let added = source.parent().unwrap().join("added");
                std::fs::create_dir(&added).unwrap();
                let grants = snapshot.effective_grants();
                assert_eq!(grants.len(), 1);
                snapshot
                    .append_roots_checked(&[added.clone()], |source, working| {
                        for grant in &grants {
                            grant.check_root_addition(source, working)?;
                        }
                        Ok(())
                    })
                    .unwrap();
                assert!(ctx.workspace_lease().unwrap().map_source(&added).is_err());
                let mut next_turn = Ctx::default().with_workspace(source.clone());
                next_turn.install_sandbox(Arc::new(LeasedBackend));
                let linked = Arc::new(LinkedRoots::default());
                linked.set(vec![LinkedRoot {
                    path: added,
                    access: RootAccess::ReadWrite,
                }]);
                next_turn.install_linked_roots(linked);
                next_turn
                    .install_workspace_lease(snapshot.lease().unwrap())
                    .unwrap();
                bind(&mut next_turn, registry.clone());
                let again = registry.bridge(&next_turn).await.unwrap();
                assert!(Arc::ptr_eq(&bridge, &again));
                assert!(Arc::ptr_eq(
                    &grants[0],
                    &registry.effective_grants(&next_turn).unwrap()[0],
                ));
                let catalog = registry.render_catalog(&next_turn, None).await.unwrap();
                assert!(catalog.contains("original lease root count 1 (current context: 2)"));
                assert_eq!(
                    again.call("find_symbol", json!({})).await.unwrap(),
                    "stub-ok"
                );
                assert_eq!(registry.spawn_count(), 1);
                assert!(
                    snapshot.seal().is_err(),
                    "live registry must occupy the lease"
                );
                if explicit_stop {
                    registry.stop(&next_turn).await.unwrap();
                    registry.stop(&next_turn).await.unwrap();
                    assert_eq!(
                        registry.status(&next_turn).await.unwrap(),
                        SerenaStatus::Stopped
                    );
                    assert!(!bridge.is_healthy());
                    let restarted = registry.bridge(&next_turn).await.unwrap();
                    assert!(!Arc::ptr_eq(&bridge, &restarted));
                    assert_eq!(registry.spawn_count(), 2);
                    assert_eq!(
                        restarted.call("find_symbol", json!({})).await.unwrap(),
                        "stub-ok"
                    );
                    registry.stop(&next_turn).await.unwrap();
                    drop(next_turn);
                    drop(ctx);
                    snapshot
                        .seal()
                        .expect("confirmed stop must release every process and stdio lease");
                } else {
                    drop(bridge);
                    drop(again);
                    drop(next_turn);
                    drop(ctx);
                    drop(registry);
                    tokio::time::timeout(Duration::from_secs(10), async {
                        while snapshot.seal().is_err() {
                            tokio::time::sleep(Duration::from_millis(10)).await;
                        }
                    })
                    .await
                    .expect("dropping the registry must release the real lease");
                }
                assert!(grants[0].is_quiescent());
                let changes = snapshot.diff().unwrap();
                assert_eq!(changes.len(), 1);
                assert_eq!(changes[0].path, Path::new("private-effect"));
                assert!(!source.join("private-effect").exists());
                assert_eq!(
                    std::fs::read_to_string(source.join("original")).unwrap(),
                    "unchanged"
                );
            }
        }
    }
}

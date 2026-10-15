//! Bridge ownership: one Serena server per workspace, spawned lazily and
//! replaced when it dies.
//!
//! Serena indexes the `--project` it was started with, so a bridge is valid only
//! for its own workspace — handing it to another silently runs `find_symbol` /
//! `replace_symbol_body` against the wrong tree. It is not per session either:
//! sessions in one workspace share one server and one index.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex as StdMutex, OnceLock};

use tokio::sync::Mutex;

use super::bridge::{BridgeFactory, McpBridge, SerenaBridge, SerenaToolInfo};
use super::catalog::SerenaToolCatalog;
use agent_tool::ToolError;

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

    fn slot(&self, root: &Path) -> Arc<WorkspaceSlot> {
        let mut slots = self.slots.lock().unwrap_or_else(|e| e.into_inner());
        slots
            .entry(root.to_path_buf())
            .or_insert_with(|| {
                Arc::new(WorkspaceSlot {
                    live: Mutex::new(None),
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
        let mut live = slot.live.lock().await;
        if live
            .as_ref()
            .map(|l| !l.bridge.is_healthy())
            .unwrap_or(false)
        {
            // The child died: drop the handle (kill_on_drop reaps it) so the
            // next call starts a fresh server over a fresh index.
            live.take();
        }
        if live.is_none() {
            let bridge = self.factory.spawn(root).await?;
            self.spawns
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            live.replace(Live {
                bridge,
                catalog: SerenaToolCatalog::default(),
            });
        }
        Ok(live)
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

/// Canonical key for the slot map: `ToolCtx` roots are already canonical, but
/// a trailing-slash or symlinked duplicate must not get its own server.
fn normalize_root(root: &Path) -> PathBuf {
    std::fs::canonicalize(root).unwrap_or_else(|_| root.to_path_buf())
}

/// One manager per workspace root, process-wide.
///
/// Process-wide *because* the key is the workspace: a registry keyed by
/// something weaker (a single slot, a session) is exactly the bug this module
/// exists to prevent. Entries are tiny; the child processes they own are the
/// intended cost of "a parked workspace keeps its turn" — `invalidate` and
/// `shutdown` are the release valves.
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
    }

    #[async_trait::async_trait]
    impl McpBridge for FakeBridge {
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
}

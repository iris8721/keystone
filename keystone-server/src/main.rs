//! keystone-server entry point: pick the entitlement backend, load the
//! rest of the configuration from the environment, serve.

use std::process::exit;
use std::sync::Arc;

use keystone_server::entitlement::dev_seed_source;
use keystone_server::runtime::ServerConfig;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    // Entitlement backend selection, in precedence order:
    //   1. KEYSTONE_ACCOUNTS set → the file must exist; a configured
    //      path that isn't there is a misconfiguration (bad mount,
    //      wrong env), not a reason to fall back to dev accounts.
    //   2. KEYSTONE_ACCOUNTS unset but ./accounts.json exists → the
    //      file-backed backend.
    //   3. KEYSTONE_DEV_SEED=1 → the stub, dev only.
    //   4. Neither → refuse to start. A server that can authenticate
    //      no one authorizes no one; running it anyway would only hide
    //      the misconfiguration.
    let accounts_env = std::env::var_os("KEYSTONE_ACCOUNTS").map(std::path::PathBuf::from);
    let accounts_path = accounts_env
        .clone()
        .unwrap_or_else(|| std::path::PathBuf::from("accounts.json"));
    let dev_seed = std::env::var("KEYSTONE_DEV_SEED").as_deref() == Ok("1");
    let entitlements: Arc<dyn keystone_core::EntitlementSource> = if accounts_env.is_some()
        && !accounts_path.exists()
    {
        tracing::error!(
            path = %accounts_path.display(),
            "KEYSTONE_ACCOUNTS points at a file that does not exist — refusing to start"
        );
        exit(1);
    } else if accounts_path.exists() {
        tracing::info!(path = %accounts_path.display(), "entitlement backend: local accounts file");
        Arc::new(keystone_server::accounts::LocalAccounts::open(
            accounts_path,
        ))
    } else if let Some(stub) = dev_seed_source(dev_seed) {
        tracing::warn!("KEYSTONE_DEV_SEED=1 — stub entitlement backend with dev accounts active");
        stub
    } else {
        tracing::error!(
            "no accounts file (KEYSTONE_ACCOUNTS / ./accounts.json) and \
                 KEYSTONE_DEV_SEED is not set — refusing to start"
        );
        exit(1);
    };

    let served = async { ServerConfig::from_env()?.serve(entitlements).await }.await;
    if let Err(msg) = served {
        eprintln!("{msg}");
        exit(1);
    }
}

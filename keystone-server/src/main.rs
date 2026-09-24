//! keystone-server binary: configuration from `KEYSTONE_*`, serve until
//! Ctrl-C or SIGTERM.

use std::process::ExitCode;

use keystone_server::config::entitlements_from_env;
use keystone_server::{ServerConfig, ServerError, serve};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!("{e}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<(), ServerError> {
    let config = ServerConfig::from_env()?;
    let entitlements = entitlements_from_env()?;
    let (builder, listeners) = config.into_parts(entitlements)?;
    let state = builder.build().await?;
    tracing::info!(
        public = %listeners.public_addr(),
        admin = ?listeners.admin_addr(),
        "keystone-server listening"
    );
    serve(state, listeners, shutdown_signal()).await?;
    tracing::info!("keystone-server stopped");
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(e) = tokio::signal::ctrl_c().await {
            tracing::error!("Ctrl-C handler failed: {e}");
            std::future::pending::<()>().await;
        }
    };
    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(e) => {
                tracing::error!("SIGTERM handler failed: {e}");
                std::future::pending::<()>().await;
            }
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        () = ctrl_c => {}
        () = terminate => {}
    }
    tracing::info!("shutdown requested");
}

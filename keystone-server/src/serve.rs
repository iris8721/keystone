//! Serving the routers: listeners, TLS, the sweep timer, and graceful
//! shutdown.

use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use axum::Router;
use axum_server::Handle;
use axum_server::tls_rustls::RustlsConfig;

use crate::error::ServerError;
use crate::routes::{admin_router, public_router};
use crate::state::AppState;
use crate::tls::PeerCertAcceptor;

/// How often [`serve`] sweeps expired state.
pub const SWEEP_INTERVAL: Duration = Duration::from_secs(30);
/// How long in-flight connections get to finish after shutdown is requested.
pub const DRAIN_TIMEOUT: Duration = Duration::from_secs(10);

/// Bound listeners plus the TLS config both share (`None` for plain HTTP).
pub struct Listeners {
    public: std::net::TcpListener,
    public_addr: SocketAddr,
    admin: Option<(std::net::TcpListener, SocketAddr)>,
    tls: Option<RustlsConfig>,
}

impl Listeners {
    /// Wrap already-bound listeners. The admin listener, when present,
    /// serves only the admin router.
    pub fn from_std(
        public: std::net::TcpListener,
        admin: Option<std::net::TcpListener>,
        tls: Option<RustlsConfig>,
    ) -> io::Result<Self> {
        let public_addr = public.local_addr()?;
        let admin = admin
            .map(|l| l.local_addr().map(|addr| (l, addr)))
            .transpose()?;
        Ok(Self {
            public,
            public_addr,
            admin,
            tls,
        })
    }

    /// Where the public router listens.
    pub fn public_addr(&self) -> SocketAddr {
        self.public_addr
    }

    /// Where the admin router listens, if it is served.
    pub fn admin_addr(&self) -> Option<SocketAddr> {
        self.admin.as_ref().map(|(_, addr)| *addr)
    }
}

impl std::fmt::Debug for Listeners {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Listeners")
            .field("public", &self.public_addr)
            .field("admin", &self.admin_addr())
            .field("tls", &self.tls.is_some())
            .finish()
    }
}

/// Serve the public router (and the admin router, when it has a listener)
/// until `shutdown` resolves, then stop accepting and drain connections for
/// up to [`DRAIN_TIMEOUT`]. Expired state is swept every [`SWEEP_INTERVAL`].
/// Returns early with [`ServerError::Serve`] if either listener fails.
pub async fn serve(
    state: AppState,
    listeners: Listeners,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> Result<(), ServerError> {
    let public_handle = Handle::new();
    let admin_handle = Handle::new();
    let trigger = tokio::spawn({
        let handles = [public_handle.clone(), admin_handle.clone()];
        async move {
            shutdown.await;
            for handle in handles {
                handle.graceful_shutdown(Some(DRAIN_TIMEOUT));
            }
        }
    });
    let sweeper = tokio::spawn(sweep_loop(state.clone()));

    let tls = listeners.tls;
    let public = run(
        listeners.public,
        tls.clone(),
        public_router(state.clone()),
        public_handle,
    );
    let result = match listeners.admin {
        Some((listener, _)) => {
            let admin = run(listener, tls, admin_router(state), admin_handle);
            tokio::try_join!(public, admin).map(|_| ())
        }
        None => public.await,
    };
    trigger.abort();
    sweeper.abort();
    result.map_err(ServerError::Serve)
}

async fn run(
    listener: std::net::TcpListener,
    tls: Option<RustlsConfig>,
    router: Router,
    handle: Handle,
) -> io::Result<()> {
    let service = router.into_make_service_with_connect_info::<SocketAddr>();
    let server = axum_server::from_tcp(listener).handle(handle);
    match tls {
        Some(config) => {
            server
                .acceptor(PeerCertAcceptor::new(config))
                .serve(service)
                .await
        }
        None => server.serve(service).await,
    }
}

async fn sweep_loop(state: AppState) {
    let mut timer = tokio::time::interval(SWEEP_INTERVAL);
    timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        timer.tick().await;
        match state.sweep().await {
            Ok(0) => {}
            Ok(dropped) => tracing::debug!(dropped, "swept expired sessions"),
            Err(e) => tracing::warn!("sweep failed: {e}"),
        }
    }
}

//! Windows Service Control Manager integration.

use std::{ffi::OsString, path::PathBuf, sync::OnceLock, time::Duration};
use tokio::sync::watch;
use windows_service::{
    define_windows_service,
    service::{
        ServiceAccess, ServiceControl, ServiceControlAccept, ServiceErrorControl, ServiceExitCode,
        ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType,
    },
    service_control_handler::{self, ServiceControlHandlerResult},
    service_dispatcher,
    service_manager::{ServiceManager, ServiceManagerAccess},
};

const NAME: &str = "TervanoAgent";
static CONFIG_PATH: OnceLock<PathBuf> = OnceLock::new();

pub fn install(config: &std::path::Path) -> anyhow::Result<()> {
    let mgr = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CREATE_SERVICE)?;
    let info = ServiceInfo {
        name: NAME.into(),
        display_name: "Tervano Agent".into(),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: std::env::current_exe()?,
        launch_arguments: vec![
            "service".into(),
            "run".into(),
            config.as_os_str().to_owned(),
        ],
        dependencies: vec![],
        account_name: None, // LocalSystem
        account_password: None,
    };
    let svc = mgr.create_service(&info, ServiceAccess::CHANGE_CONFIG)?;
    svc.set_description(
        "Tervano endpoint management agent. Reports device state to Tervano Server.",
    )?;
    println!("installed service {NAME} (config: {})", config.display());
    Ok(())
}

pub fn uninstall() -> anyhow::Result<()> {
    let mgr = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let svc = mgr.open_service(
        NAME,
        ServiceAccess::DELETE | ServiceAccess::STOP | ServiceAccess::QUERY_STATUS,
    )?;
    if svc.query_status()?.current_state != ServiceState::Stopped {
        let _ = svc.stop();
    }
    svc.delete()?;
    println!("service {NAME} marked for deletion");
    Ok(())
}

pub fn run_as_service(config: PathBuf) -> anyhow::Result<()> {
    CONFIG_PATH.set(config).ok();
    service_dispatcher::start(NAME, ffi_service_main)?;
    Ok(())
}

define_windows_service!(ffi_service_main, service_main);

fn service_main(_args: Vec<OsString>) {
    if let Err(e) = service_body() {
        tracing::error!("service failed: {e:#}");
    }
}

fn service_body() -> anyhow::Result<()> {
    let cfg = crate::Config::load(CONFIG_PATH.get().expect("set before dispatch"))?;
    std::fs::create_dir_all(&cfg.state_dir)?;
    // shortcut: single unrotated log file; rotation/Event Log sink is T-216.
    let log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(cfg.state_dir.join("agent.log"))?;
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .with_ansi(false)
        .with_writer(std::sync::Mutex::new(log))
        .init();

    let (tx, rx) = watch::channel(false);
    let handler = move |ctrl| match ctrl {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            let _ = tx.send(true);
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    };
    let status = service_control_handler::register(NAME, handler)?;
    let set = |state, accept| {
        status.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: state,
            controls_accepted: accept,
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::from_secs(5),
            process_id: None,
        })
    };
    set(
        ServiceState::Running,
        ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
    )?;
    let result = tokio::runtime::Runtime::new()?.block_on(crate::run(cfg, rx));
    if let Err(e) = &result {
        tracing::error!("agent stopped with error: {e:#}");
    }
    set(ServiceState::Stopped, ServiceControlAccept::empty())?;
    result
}

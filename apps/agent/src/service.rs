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
    register_event_source()?;
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
    // Best effort: the event source key is only cosmetic once the service is gone.
    let _ = std::process::Command::new(system32("reg.exe"))
        .args(["delete", EVENT_SOURCE_KEY, "/f"])
        .output();
    println!("service {NAME} marked for deletion");
    Ok(())
}

const EVENT_SOURCE_KEY: &str =
    r"HKLM\SYSTEM\CurrentControlSet\Services\EventLog\Application\TervanoAgent";

fn system32(exe: &str) -> PathBuf {
    let root = std::env::var_os("SystemRoot").unwrap_or_else(|| r"C:\Windows".into());
    PathBuf::from(root).join("System32").join(exe)
}

/// Registers the event source with EventCreate.exe as message file, whose message table renders
/// any string we report verbatim, so Event Viewer shows our text instead of "description not found".
fn register_event_source() -> anyhow::Result<()> {
    use crate::reg::{HKEY_LOCAL_MACHINE, Key, View};
    let key = Key::create(
        HKEY_LOCAL_MACHINE,
        &EVENT_SOURCE_KEY["HKLM\\".len()..],
        View::Native,
    )
    .map_err(|e| anyhow::anyhow!("registering event source: {}", crate::reg::error_text(e)))?;
    let wide = |s: &str| -> Vec<u8> {
        s.encode_utf16()
            .chain(std::iter::once(0))
            .flat_map(u16::to_le_bytes)
            .collect()
    };
    key.set_raw(
        "EventMessageFile",
        2,
        &wide(r"%SystemRoot%\System32\EventCreate.exe"),
    )
    .and_then(|()| key.set_raw("TypesSupported", 4, &7u32.to_le_bytes()))
    .map_err(|e| anyhow::anyhow!("registering event source: {}", crate::reg::error_text(e)))
}

pub fn run_as_service(config: PathBuf) -> anyhow::Result<()> {
    CONFIG_PATH.set(config).ok();
    service_dispatcher::start(NAME, ffi_service_main)?;
    Ok(())
}

define_windows_service!(ffi_service_main, service_main);

fn service_main(_args: Vec<OsString>) {
    if let Err(e) = service_body() {
        // The file logger may not exist yet (bad config, unwritable state dir), so always also
        // record the failure where an administrator will look for it.
        crate::logfile::event_log_error(&format!("Tervano Agent service failed: {e:#}"));
        tracing::error!("service failed: {e:#}");
    }
}

fn service_body() -> anyhow::Result<()> {
    let cfg = crate::Config::load(CONFIG_PATH.get().expect("set before dispatch"))?;
    std::fs::create_dir_all(&cfg.state_dir)?;
    crate::secure::restrict_dir(&cfg.state_dir)?;
    // At most 5 x 10 MiB of logs: agent.log plus agent.log.1 … agent.log.4.
    let log =
        crate::logfile::RotatingLog::open(cfg.state_dir.join("agent.log"), 10 * 1024 * 1024, 5)?;
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
    if let Ok(crate::Exit::Updated) = result {
        // shortcut: the SCM starts the new executable only through its recovery actions (restart on
        // failure), which `service install` does not configure yet (T-212); without them the
        // service stays stopped after an update.
        tracing::info!("stopping with an error so service recovery starts the updated agent");
        status.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: ServiceState::Stopped,
            controls_accepted: ServiceControlAccept::empty(),
            exit_code: ServiceExitCode::ServiceSpecific(1),
            checkpoint: 0,
            wait_hint: Duration::from_secs(5),
            process_id: None,
        })?;
        return Ok(());
    }
    set(ServiceState::Stopped, ServiceControlAccept::empty())?;
    result.map(|_| ())
}

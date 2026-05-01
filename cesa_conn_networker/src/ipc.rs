use std::{
    io::{Read, Write},
    sync::Arc,
};
/*
TODO:
make types for diffrent ipc actions
IPC client
IPC daemon
IPC for windows
*/
use std::fmt;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::SocketAddr;
use std::{
    fs::{Permissions, read_dir, read_to_string, remove_file, set_permissions},
    path::Path,
    process::id,
};
use tokio::select;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::RwLock,
};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info};

#[derive(Debug, PartialEq)]
#[repr(u8)]
pub enum ActionType {
    Default = 0x00,
    UpdateAuthPassword = 0x01,
    UpdateDataPassword = 0x02,
}

impl ActionType {
    /// Converts a raw u8 wire byte into an ActionType variant.
    ///
    /// Returns None for unknown values rather than panicking — the caller decides
    /// whether to fall back to Default or reject the packet entirely.
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x00 => Some(Self::Default),
            0x01 => Some(Self::UpdateAuthPassword),
            0x02 => Some(Self::UpdateDataPassword),
            _ => None,
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum IpcErrors {
    UIDNotFound,
    FailedToRead,
    FailedToGetUID,
    FailedToFetchSocketPath,
    FailedToReadprocessDirectory,
    FailedToFilterMap,
    FailedToFechProcesses,
    FailedToGetSelfName,
    FailedToReadProcessName,
    FailedToCheckIfProcessExists,
    FailedToRemoveFile,
    FailedToBindSocket,
    FailedToSetPermissions,
    DaemonAlreadyRunning,
    FailedToCheckIfRunning,
    FailedToConnectToPipe,
    FailedToCheckStreamState,
    NotWritable,
    FailedToWriteToStream,
    PipeNotCreated,
    FailedToCreateSecurePipe,
    FailedToAcceptConnection,
    FailedToReadDataFromStream,
    ConfirmationByteNotReceived,
    FailedToRecvData,
}

impl fmt::Display for IpcErrors {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            Self::UIDNotFound => "UID not found in /proc/self/status",
            Self::FailedToRead => "failed to read /proc/self/status",
            Self::FailedToGetUID => "failed to get UID for socket path",
            Self::FailedToFetchSocketPath => "failed to fetch socket path",
            Self::FailedToReadprocessDirectory => "failed to read process directory",
            Self::FailedToFilterMap => "failed to filter map",
            Self::FailedToFechProcesses => "failed to fetch processes",
            Self::FailedToGetSelfName => "failed to get name from our own process",
            Self::FailedToReadProcessName => "failed to fetch process name",
            Self::FailedToCheckIfProcessExists => "failed to check if process exists",
            Self::FailedToRemoveFile => "failed to remove file",
            Self::FailedToBindSocket => "failed to bind socket",
            Self::FailedToSetPermissions => "failed to set permissions",
            Self::DaemonAlreadyRunning => "daemon is already running",
            Self::FailedToCheckIfRunning => "failed to check if daemon is running",
            Self::FailedToConnectToPipe => "failed to connect to the pipe",
            Self::FailedToCheckStreamState => "failed to check stream state",
            Self::NotWritable => "stream is not writable",
            Self::FailedToWriteToStream => "failed to write data to stream",
            Self::PipeNotCreated => "secure pipe is not created yet",
            Self::FailedToCreateSecurePipe => "failed to create secure pipe",
            Self::FailedToAcceptConnection => "failed to accept ipc connection",
            Self::FailedToReadDataFromStream => "failed to read data from ipc stream",
            Self::ConfirmationByteNotReceived => "confirmation byte not received",
            Self::FailedToRecvData => "failed to get data from client",
        };
        write!(f, "{}", msg)
    }
}

#[cfg(unix)]
fn getuid() -> Result<u32, IpcErrors> {
    std::fs::read_to_string("/proc/self/status")
        .map_err(|_| IpcErrors::FailedToRead)?
        .lines()
        .find(|l| l.starts_with("Uid:"))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|uid| uid.parse().ok())
        .ok_or_else(|| IpcErrors::UIDNotFound)
}

#[cfg(unix)]
fn socket_path() -> Result<String, IpcErrors> {
    let uid = getuid().map_err(|_| IpcErrors::FailedToGetUID)?;
    Ok(format!("/run/user/{}/cesa_conn.sock", uid))
}

#[cfg(unix)]
pub fn get_self_name() -> Result<String, IpcErrors> {
    Ok(read_to_string("/proc/self/comm")
        .map_err(|_| IpcErrors::FailedToGetSelfName)?
        .trim()
        .to_string())
}

#[cfg(unix)]
pub fn get_processes() -> Result<Vec<String>, IpcErrors> {
    let process_dir = read_dir("/proc/").map_err(|_| IpcErrors::FailedToReadprocessDirectory)?;

    let processes: Vec<String> = process_dir
        .filter_map(|e| e.ok())
        .filter_map(|e| {
            let name = e.file_name().to_str()?.to_string();
            name.parse::<u32>().ok()?;
            Some(name)
        })
        .filter(|e| *e != id().to_string())
        .collect();

    Ok(processes)
}

#[cfg(unix)]
pub fn get_process_name(pid: String) -> Result<String, IpcErrors> {
    Ok(read_to_string(format!("/proc/{}/comm", pid))
        .map_err(|_| IpcErrors::FailedToReadProcessName)?
        .trim()
        .to_string())
}

#[cfg(unix)]
pub fn process_exists(name: String) -> Result<bool, IpcErrors> {
    let processes = get_processes().map_err(|_| {
        error!("Failed to fetch processes");
        IpcErrors::FailedToFechProcesses
    })?;

    Ok(processes.iter().any(|pid| {
        get_process_name(pid.to_string())
            .map(|n| n == name)
            .unwrap_or(false)
    }))
}

#[cfg(unix)]
pub fn is_running() -> Result<bool, IpcErrors> {
    let path = socket_path().map_err(|_| IpcErrors::FailedToFetchSocketPath)?;

    let proc_name = get_self_name().map_err(|_| IpcErrors::FailedToGetSelfName)?;

    let process_exists =
        process_exists(proc_name).map_err(|_| IpcErrors::FailedToCheckIfProcessExists)?;

    if Path::new(&path).exists() {
        if process_exists {
            return Ok(true);
        }
    }
    Ok(false)
}

#[cfg(unix)]
use tokio::net::UnixListener;
pub fn create_secure_pipe() -> Result<UnixListener, IpcErrors> {
    let path = socket_path().map_err(|_| IpcErrors::FailedToFetchSocketPath)?;

    let is_daemon_running = is_running().map_err(|_| IpcErrors::FailedToCheckIfRunning)?;

    if !is_daemon_running {
        if Path::new(&path).exists() {
            remove_file(&path).map_err(|_| IpcErrors::FailedToRemoveFile)?;
        }
    } else {
        return Err(IpcErrors::DaemonAlreadyRunning);
    }

    let socket = UnixListener::bind(&path).map_err(|_| IpcErrors::FailedToBindSocket)?;

    set_permissions(&path, Permissions::from_mode(0o600))
        .map_err(|_| IpcErrors::FailedToSetPermissions)?;

    Ok(socket)
}

#[cfg(unix)]
pub async fn ipc_recv(
    a_key: Arc<RwLock<[u8; 32]>>,
    d_key: Arc<RwLock<[u8; 32]>>,
    trusted_addrs: Arc<RwLock<SocketAddr>>,
    incoming_connection: (tokio::net::UnixStream, tokio::net::unix::SocketAddr),
) -> Result<(), IpcErrors> {
    let (mut stream, _addr) = incoming_connection;

    let mut size_buffer = [0u8; 8];
    stream
        .read_exact(&mut size_buffer)
        .await
        .map_err(|_| IpcErrors::FailedToReadDataFromStream)?;

    let confirmation_byte = [1u8];

    stream
        .write_all(&confirmation_byte)
        .await
        .map_err(|_| IpcErrors::FailedToWriteToStream)?;

    let size = u64::from_le_bytes(size_buffer);
    let mut buffer = vec![0u8; size as usize];

    stream
        .read_exact(&mut buffer)
        .await
        .map_err(|_| IpcErrors::FailedToReadDataFromStream)?;

    // TODO : HANDLE KEYS CHANGES, DATA SYNCING WITH UI, DATA PASSING TO CONTROLLER IN cesa_conn_system if ac tion type doesnt match
    match ActionType::from_u8(buffer[0]) {
        _ => {}
    }

    Ok(())
}

#[cfg(unix)]
pub async fn ipc_daemon(
    a_key: Arc<RwLock<[u8; 32]>>,
    d_key: Arc<RwLock<[u8; 32]>>,
    trusted_addrs: Arc<RwLock<SocketAddr>>,
    cancellation_token: CancellationToken,
) -> Result<(), IpcErrors> {
    let socket = create_secure_pipe().map_err(|_| IpcErrors::FailedToCreateSecurePipe)?;
    loop {
        let cancellation_token_clone = cancellation_token.clone();
        let (a_key_clone, d_key_clone) = (a_key.clone(), d_key.clone());
        let trusted_addrs_clone = trusted_addrs.clone();

        let incoming_connection = select! {
            _ = cancellation_token.cancelled() => {
                info!("IPC daemon shutting down");
                return Ok(());
            }
            result = socket.accept() => {
                result.map_err(|_| IpcErrors::FailedToAcceptConnection)?
            }
        };

        tokio::spawn(async move {
            select! {
                _ = cancellation_token_clone.cancelled() => {
                    info!("cancellation token fired mid-handler, dropping ipc_recv task");
                }
                result = ipc_recv(a_key_clone, d_key_clone, trusted_addrs_clone, incoming_connection) => {
                    match result {
                        Ok(()) => debug!("ipc_recv completed successfully"),
                        Err(e) => error!(error = %e, "ipc_recv returned an error"),
                    }
                }
            }
        });
    }
}

#[cfg(unix)]
use std::os::unix::net::UnixStream;
pub fn ipc_send(action_type: ActionType, data: &[u8]) -> Result<(), IpcErrors> {
    let path = socket_path().map_err(|_| IpcErrors::FailedToFetchSocketPath)?;

    if !Path::new(&path).exists() {
        return Err(IpcErrors::PipeNotCreated);
    }

    let mut stream = UnixStream::connect(path).map_err(|_| IpcErrors::FailedToConnectToPipe)?;
    let mut final_data = Vec::with_capacity(data.len() + 1);

    final_data.push(action_type as u8);
    final_data.extend_from_slice(&data);

    let len = u64::to_le_bytes(final_data.len() as u64);

    stream
        .write_all(&len)
        .map_err(|_| IpcErrors::FailedToWriteToStream)?;

    let mut buffer = [0u8];

    stream
        .read_exact(&mut buffer)
        .map_err(|_| IpcErrors::FailedToReadDataFromStream)?;

    if buffer.is_empty() {
        return Err(IpcErrors::FailedToReadDataFromStream);
    }

    if buffer[0] == 0x00 {
        return Err(IpcErrors::ConfirmationByteNotReceived);
    }

    stream
        .write_all(&final_data)
        .map_err(|_| IpcErrors::FailedToWriteToStream)?;

    Ok(())
}

#[cfg(target_os = "windows")]
pub fn create_secure_pipe() -> Result<(), IpcErrors> {
    Ok(())
}

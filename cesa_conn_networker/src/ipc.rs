/*
TODO:
IPC daemon
*/

use std::fmt;
#[cfg(unix)]
use std::{
    fs::{read_dir, read_to_string, remove_file},
    path::Path,
    process::id,
};
use tracing::{debug, error};

#[derive(Debug, PartialEq)]
pub enum IcpErrors {
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
}

impl fmt::Display for IcpErrors {
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
        };
        write!(f, "{}", msg)
    }
}

#[cfg(unix)]
fn getuid() -> Result<u32, IcpErrors> {
    std::fs::read_to_string("/proc/self/status")
        .map_err(|_| IcpErrors::FailedToRead)?
        .lines()
        .find(|l| l.starts_with("Uid:"))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|uid| uid.parse().ok())
        .ok_or_else(|| IcpErrors::UIDNotFound)
}

#[cfg(unix)]
fn socket_path() -> Result<String, IcpErrors> {
    let uid = getuid().map_err(|_| IcpErrors::FailedToGetUID)?;
    Ok(format!("/run/user/{}/cesa_conn.sock", uid))
}

#[cfg(unix)]
pub fn get_self_name() -> Result<String, IcpErrors> {
    Ok(read_to_string("/proc/self/comm").map_err(|_| IcpErrors::FailedToGetSelfName)?)
}

#[cfg(unix)]
pub fn get_processes() -> Result<Vec<String>, IcpErrors> {
    let process_dir = read_dir("/proc/").map_err(|_| IcpErrors::FailedToReadprocessDirectory)?;

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
pub fn get_process_name(pid: String) -> Result<String, IcpErrors> {
    Ok(read_to_string(format!("/proc/{}/comm", pid))
        .map_err(|_| IcpErrors::FailedToReadProcessName)?
        .trim()
        .to_string())
}

#[cfg(unix)]
pub fn process_exists(name: String) -> Result<bool, IcpErrors> {
    let processes = get_processes().map_err(|_| {
        error!("Failed to fetch processes");
        IcpErrors::FailedToFechProcesses
    })?;

    Ok(processes.iter().any(|pid| {
        get_process_name(pid.to_string())
            .map(|n| n == name)
            .unwrap_or(false)
    }))
}

#[cfg(unix)]
use tokio::net::UnixListener;
pub fn create_secure_pipe() -> Result<(), IcpErrors> {
    let path = socket_path().map_err(|_| IcpErrors::FailedToFetchSocketPath)?;

    let proc_name = get_self_name().map_err(|_| IcpErrors::FailedToGetSelfName)?;

    let process_exists =
        process_exists(proc_name).map_err(|_| IcpErrors::FailedToCheckIfProcessExists)?;

    if Path::new(&path).exists() {
        if !process_exists {
            remove_file(path).map_err(|_| IcpErrors::FailedToRemoveFile)?;
        }
    }

    Ok(())
}

#[cfg(target_os = "windows")]
pub fn create_secure_pipe() -> Result<(), IcpErrors> {
    Ok(())
}

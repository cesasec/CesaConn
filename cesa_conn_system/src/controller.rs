#[derive(Debug, PartialEq)]
pub enum ControllerErrors {
    FailedToReadFromStream,
}

// impl fmt::Display for ControllerErrors {
//     fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
//         match self {
//             TcpNetworkerErrors::FailedToReadFromStream => write!(f, "failed to read from stream"),
//         }
//     }
// }

pub async fn handle_ipc_signal() -> Result<(), ControllerErrors> {
    Ok(())
}

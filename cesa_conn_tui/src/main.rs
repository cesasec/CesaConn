use cesa_conn_tui::{ipc_client, App};

fn main() -> std::io::Result<()> {
    let mut terminal = ratatui::init();
    let mut app = App::new();

    match ipc_client::connect() {
        Ok((event_rx, cmd_tx)) => {
            app.connect_channels(event_rx, cmd_tx);
        }
        Err(e) => {
            app.push_log(format!("[WARN] {e}"));
            app.push_log("[WARN] Running without daemon — commands will have no effect.");
        }
    }

    let result = cesa_conn_tui::run(&mut terminal, &mut app);
    ratatui::restore();
    result
}

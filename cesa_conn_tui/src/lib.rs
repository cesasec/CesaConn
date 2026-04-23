//! CesaConn terminal UI.
//!
//! This crate is both a library (exposing `App` and `run` for the daemon to
//! spawn) and a standalone binary that connects to an already-running daemon
//! via `ipc_client::connect()`.
//!
//! # Event model
//! The TUI polls for daemon events (`DaemonEvent`) and keyboard input in a
//! tight 50 ms loop.  All daemon state changes arrive through the `event_rx`
//! channel and are applied to `App` before the next frame is drawn.

pub mod ipc_client;

use std::{
    io,
    sync::mpsc::{Receiver, Sender, TryRecvError},
    time::Duration,
};

use cesa_conn_ipc::{ConfigKey, DaemonEvent, TuiCommand};
use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use ratatui::{
    layout::{Alignment, Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Clear, List, ListItem, ListState, Paragraph, Tabs},
    Frame,
};

// ── Data types ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum DeviceStatus {
    Connected,
    Connecting,
    Disconnected,
}

#[derive(Debug, Clone)]
pub struct Device {
    pub addr: String,
    pub status: DeviceStatus,
}

#[derive(Debug, Clone, PartialEq)]
pub enum SettingKind {
    Secret { configured: bool },
    Bool(bool),
    Text,
}

#[derive(Debug, Clone)]
pub struct Setting {
    pub label: &'static str,
    pub kind: SettingKind,
    /// Current value — used for Text settings; empty for Secret.
    pub value: String,
    /// If Some, enabling this Bool shows a security warning with this message.
    pub warn_message: Option<&'static str>,
}

impl Setting {
    fn display_value(&self) -> (&str, Color) {
        match &self.kind {
            SettingKind::Secret { configured: true } => ("[configured]", Color::Green),
            SettingKind::Secret { configured: false } => ("[not configured]", Color::DarkGray),
            SettingKind::Bool(true) => ("on", Color::Green),
            SettingKind::Bool(false) => ("off", Color::DarkGray),
            SettingKind::Text => {
                if self.value.is_empty() {
                    ("[not set]", Color::DarkGray)
                } else {
                    (self.value.as_str(), Color::Cyan)
                }
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum Tab {
    Devices,
    Settings,
    Logs,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum SettingsSection {
    Basic,
    Advanced,
}

#[derive(Debug, Clone, PartialEq)]
enum ActivePopup {
    None,
    AddDevice,
    EditSetting,
    SecurityWarning { section: SettingsSection, idx: usize },
}

// ── App state ─────────────────────────────────────────────────────────────────

pub struct App {
    active_tab: Tab,

    pub devices: Vec<Device>,
    device_list_state: ListState,

    pub settings_basic: Vec<Setting>,
    pub settings_advanced: Vec<Setting>,
    settings_section: SettingsSection,
    settings_selected: usize,

    pub logs: Vec<String>,
    log_scroll: u16,
    log_follow: bool,

    active_popup: ActivePopup,
    input_buf: String,

    // IPC channels — None when running without a daemon.
    cmd_tx: Option<Sender<TuiCommand>>,
    event_rx: Option<Receiver<DaemonEvent>>,
    pub daemon_connected: bool,

    pub should_quit: bool,
}

impl App {
    pub fn new() -> Self {
        let mut device_list_state = ListState::default();
        device_list_state.select(Some(0));

        Self {
            active_tab: Tab::Devices,
            devices: Vec::new(),
            device_list_state,
            settings_basic: vec![
                Setting {
                    label: "Auth key",
                    kind: SettingKind::Secret { configured: false },
                    value: String::new(),
                    warn_message: None,
                },
                Setting {
                    label: "Data key",
                    kind: SettingKind::Secret { configured: false },
                    value: String::new(),
                    warn_message: None,
                },
                Setting {
                    label: "Key persistence",
                    kind: SettingKind::Bool(false),
                    value: String::new(),
                    warn_message: Some(
                        "Keys will be stored in the system keyring.\n\
                         Persistent keys are reused across sessions,\n\
                         which reduces forward secrecy.",
                    ),
                },
                Setting {
                    label: "Auto-connect",
                    kind: SettingKind::Bool(false),
                    value: String::new(),
                    warn_message: None,
                },
                Setting {
                    label: "UDP discovery",
                    kind: SettingKind::Bool(true),
                    value: String::new(),
                    warn_message: None,
                },
            ],
            settings_advanced: vec![
                Setting {
                    label: "Listen address",
                    kind: SettingKind::Text,
                    value: "0.0.0.0".into(),
                    warn_message: None,
                },
                Setting {
                    label: "Listen port",
                    kind: SettingKind::Text,
                    value: "3232".into(),
                    warn_message: None,
                },
                Setting {
                    label: "UDP broadcast duration (s)",
                    kind: SettingKind::Text,
                    value: "3".into(),
                    warn_message: None,
                },
            ],
            settings_section: SettingsSection::Basic,
            settings_selected: 0,
            logs: Vec::new(),
            log_scroll: 0,
            log_follow: true,
            active_popup: ActivePopup::None,
            input_buf: String::new(),
            cmd_tx: None,
            event_rx: None,
            daemon_connected: false,
            should_quit: false,
        }
    }

    /// Attach IPC channels produced by `ipc_client::connect()`.
    ///
    /// Must be called before `run()`. If not called, the TUI still renders
    /// but all commands are silently dropped and no events are received.
    pub fn connect_channels(
        &mut self,
        event_rx: Receiver<DaemonEvent>,
        cmd_tx: Sender<TuiCommand>,
    ) {
        self.event_rx = Some(event_rx);
        self.cmd_tx = Some(cmd_tx);
        self.daemon_connected = true;
    }

    pub fn push_log(&mut self, msg: impl Into<String>) {
        self.logs.push(msg.into());
    }

    fn send_command(&self, cmd: TuiCommand) {
        if let Some(tx) = &self.cmd_tx {
            let _ = tx.send(cmd);
        }
    }

    /// Drain all pending daemon events. Called once per frame before drawing.
    ///
    /// Uses a `loop` + `try_recv` rather than collecting into a `Vec` first
    /// because `try_recv` returns `TryRecvError::Disconnected` immediately when
    /// the daemon socket thread exits, letting us update `daemon_connected`
    /// without an extra allocation.
    fn drain_daemon_events(&mut self) {
        loop {
            let result = match self.event_rx.as_ref() {
                Some(rx) => rx.try_recv(),
                None => return,
            };
            match result {
                Ok(event) => self.handle_daemon_event(event),
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    self.daemon_connected = false;
                    self.event_rx = None;
                    self.push_log("[WARN] Lost connection to daemon");
                    break;
                }
            }
        }
    }

    fn handle_daemon_event(&mut self, event: DaemonEvent) {
        match event {
            DaemonEvent::DeviceConnected { addr } => {
                let s = addr.to_string();
                if let Some(d) = self.devices.iter_mut().find(|d| d.addr == s) {
                    d.status = DeviceStatus::Connected;
                } else {
                    self.devices
                        .push(Device { addr: s, status: DeviceStatus::Connected });
                }
            }
            DaemonEvent::DeviceConnecting { addr } => {
                let s = addr.to_string();
                if let Some(d) = self.devices.iter_mut().find(|d| d.addr == s) {
                    d.status = DeviceStatus::Connecting;
                }
            }
            DaemonEvent::DeviceDisconnected { addr } => {
                let s = addr.to_string();
                if let Some(d) = self.devices.iter_mut().find(|d| d.addr == s) {
                    d.status = DeviceStatus::Disconnected;
                }
            }
            DaemonEvent::KeyConfigured { is_auth } => {
                let label = if is_auth { "Auth key" } else { "Data key" };
                if let Some(s) = self.settings_basic.iter_mut().find(|s| s.label == label) {
                    s.kind = SettingKind::Secret { configured: true };
                }
            }
            DaemonEvent::Log { message } => self.push_log(message),
        }
    }

    fn active_settings(&self) -> &Vec<Setting> {
        match self.settings_section {
            SettingsSection::Basic => &self.settings_basic,
            SettingsSection::Advanced => &self.settings_advanced,
        }
    }

    fn active_settings_mut(&mut self) -> &mut Vec<Setting> {
        match self.settings_section {
            SettingsSection::Basic => &mut self.settings_basic,
            SettingsSection::Advanced => &mut self.settings_advanced,
        }
    }

    fn next_tab(&mut self) {
        self.active_tab = match self.active_tab {
            Tab::Devices => Tab::Settings,
            Tab::Settings => Tab::Logs,
            Tab::Logs => Tab::Devices,
        };
    }

    fn prev_tab(&mut self) {
        self.active_tab = match self.active_tab {
            Tab::Devices => Tab::Logs,
            Tab::Settings => Tab::Devices,
            Tab::Logs => Tab::Settings,
        };
    }

    fn switch_settings_section(&mut self, section: SettingsSection) {
        self.settings_section = section;
        self.settings_selected = 0;
    }

    fn next_device(&mut self) {
        if self.devices.is_empty() {
            return;
        }
        let i = self
            .device_list_state
            .selected()
            .map(|i| (i + 1) % self.devices.len())
            .unwrap_or(0);
        self.device_list_state.select(Some(i));
    }

    fn prev_device(&mut self) {
        if self.devices.is_empty() {
            return;
        }
        let i = self
            .device_list_state
            .selected()
            .map(|i| if i == 0 { self.devices.len() - 1 } else { i - 1 })
            .unwrap_or(0);
        self.device_list_state.select(Some(i));
    }

    fn selected_device(&self) -> Option<&Device> {
        self.device_list_state
            .selected()
            .and_then(|i| self.devices.get(i))
    }

    fn next_setting(&mut self) {
        let len = self.active_settings().len();
        if len > 0 {
            self.settings_selected = (self.settings_selected + 1) % len;
        }
    }

    fn prev_setting(&mut self) {
        let len = self.active_settings().len();
        if len > 0 {
            self.settings_selected =
                self.settings_selected.checked_sub(1).unwrap_or(len - 1);
        }
    }
}

// ── Input handling ────────────────────────────────────────────────────────────

fn handle_input(app: &mut App) -> io::Result<()> {
    let Event::Key(key) = event::read()? else {
        return Ok(());
    };
    if key.kind != KeyEventKind::Press {
        return Ok(());
    }

    if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
        app.should_quit = true;
        return Ok(());
    }

    let popup = app.active_popup.clone();
    match popup {
        ActivePopup::AddDevice => {
            handle_add_device_input(app, key.code);
            return Ok(());
        }
        ActivePopup::EditSetting => {
            handle_edit_setting_input(app, key.code);
            return Ok(());
        }
        ActivePopup::SecurityWarning { section, idx } => {
            handle_security_warning_input(app, key.code, section, idx);
            return Ok(());
        }
        ActivePopup::None => {}
    }

    match key.code {
        KeyCode::Char('q') => app.should_quit = true,
        KeyCode::Tab => app.next_tab(),
        KeyCode::BackTab => app.prev_tab(),
        _ => {}
    }

    match app.active_tab {
        Tab::Devices => match key.code {
            KeyCode::Up | KeyCode::Char('k') => app.prev_device(),
            KeyCode::Down | KeyCode::Char('j') => app.next_device(),
            KeyCode::Char('n') => app.active_popup = ActivePopup::AddDevice,
            KeyCode::Char('d') => {
                let addr_str = app
                    .device_list_state
                    .selected()
                    .and_then(|i| app.devices.get(i))
                    .map(|d| d.addr.clone());
                if let Some(addr_str) = addr_str {
                    if let Ok(addr) = addr_str.parse() {
                        app.send_command(TuiCommand::Disconnect { addr });
                    }
                    let i = app.device_list_state.selected().unwrap();
                    if let Some(dev) = app.devices.get_mut(i) {
                        dev.status = DeviceStatus::Disconnected;
                    }
                    app.push_log(format!("[ INFO] Disconnected from {}", addr_str));
                }
            }
            _ => {}
        },
        Tab::Settings => match key.code {
            KeyCode::Up | KeyCode::Char('k') => app.prev_setting(),
            KeyCode::Down | KeyCode::Char('j') => app.next_setting(),
            KeyCode::Left | KeyCode::Char('h') => {
                app.switch_settings_section(SettingsSection::Basic)
            }
            KeyCode::Right | KeyCode::Char('l') => {
                app.switch_settings_section(SettingsSection::Advanced)
            }
            KeyCode::Enter => handle_settings_enter(app),
            _ => {}
        },
        Tab::Logs => match key.code {
            KeyCode::Up | KeyCode::Char('k') => {
                app.log_follow = false;
                app.log_scroll = app.log_scroll.saturating_sub(1);
            }
            KeyCode::Down | KeyCode::Char('j') => {
                app.log_scroll += 1;
            }
            KeyCode::Char('f') => {
                app.log_follow = !app.log_follow;
            }
            _ => {}
        },
    }

    Ok(())
}

fn handle_settings_enter(app: &mut App) {
    let section = app.settings_section;
    let idx = app.settings_selected;

    let (is_bool, currently_on, has_warning) = app
        .active_settings()
        .get(idx)
        .map(|s| match &s.kind {
            SettingKind::Bool(v) => (true, *v, s.warn_message.is_some()),
            _ => (false, false, false),
        })
        .unwrap_or_default();

    if is_bool {
        if !currently_on && has_warning {
            app.active_popup = ActivePopup::SecurityWarning { section, idx };
        } else if let Some(s) = app.active_settings_mut().get_mut(idx) {
            if let SettingKind::Bool(ref mut v) = s.kind {
                *v = !*v;
            }
        }
    } else {
        app.input_buf.clear();
        app.active_popup = ActivePopup::EditSetting;
    }
}

fn handle_add_device_input(app: &mut App, code: KeyCode) {
    match code {
        KeyCode::Esc => {
            app.active_popup = ActivePopup::None;
            app.input_buf.clear();
        }
        KeyCode::Enter => {
            let addr_str = app.input_buf.trim().to_string();
            if !addr_str.is_empty() {
                match addr_str.parse() {
                    Ok(addr) => {
                        app.send_command(TuiCommand::Connect { addr });
                        app.devices.push(Device {
                            addr: addr_str,
                            status: DeviceStatus::Connecting,
                        });
                    }
                    Err(_) => {
                        app.push_log(format!("[ WARN] Invalid address: {}", addr_str));
                    }
                }
            }
            app.active_popup = ActivePopup::None;
            app.input_buf.clear();
        }
        KeyCode::Backspace => {
            app.input_buf.pop();
        }
        KeyCode::Char(c) => app.input_buf.push(c),
        _ => {}
    }
}

fn handle_edit_setting_input(app: &mut App, code: KeyCode) {
    match code {
        KeyCode::Esc => {
            app.active_popup = ActivePopup::None;
            app.input_buf.clear();
        }
        KeyCode::Enter => {
            let new_value = app.input_buf.trim().to_string();
            if !new_value.is_empty() {
                apply_setting_edit(app, new_value);
            }
            app.active_popup = ActivePopup::None;
            app.input_buf.clear();
        }
        KeyCode::Backspace => {
            app.input_buf.pop();
        }
        KeyCode::Char(c) => app.input_buf.push(c),
        _ => {}
    }
}

fn apply_setting_edit(app: &mut App, new_value: String) {
    let idx = app.settings_selected;

    let (is_secret, is_text, label) = app
        .active_settings()
        .get(idx)
        .map(|s| (
            matches!(s.kind, SettingKind::Secret { .. }),
            s.kind == SettingKind::Text,
            s.label,
        ))
        .unwrap_or_default();

    if is_secret {
        let cmd = if label == "Auth key" {
            TuiCommand::SetAuthKey { passphrase: new_value }
        } else {
            TuiCommand::SetDataKey { passphrase: new_value }
        };
        app.send_command(cmd);
        if let Some(s) = app.active_settings_mut().get_mut(idx) {
            s.kind = SettingKind::Secret { configured: true };
        }
    } else if is_text {
        let config_key = match label {
            "Listen address" => ConfigKey::ListenAddress,
            "Listen port" => ConfigKey::ListenPort,
            _ => ConfigKey::UdpBroadcastDuration,
        };
        app.send_command(TuiCommand::SetConfig {
            key: config_key,
            value: new_value.clone(),
        });
        if let Some(s) = app.active_settings_mut().get_mut(idx) {
            s.value = new_value;
        }
    }
}

fn handle_security_warning_input(
    app: &mut App,
    code: KeyCode,
    section: SettingsSection,
    idx: usize,
) {
    match code {
        KeyCode::Char('y') | KeyCode::Char('Y') => {
            let settings = match section {
                SettingsSection::Basic => &mut app.settings_basic,
                SettingsSection::Advanced => &mut app.settings_advanced,
            };
            if let Some(s) = settings.get_mut(idx) {
                if let SettingKind::Bool(ref mut v) = s.kind {
                    *v = true;
                }
            }
            app.active_popup = ActivePopup::None;
        }
        KeyCode::Esc | KeyCode::Char('n') | KeyCode::Char('N') => {
            app.active_popup = ActivePopup::None;
        }
        _ => {}
    }
}

// ── Rendering ─────────────────────────────────────────────────────────────────

fn ui(frame: &mut Frame, app: &mut App) {
    let area = frame.area();

    let [header, content, statusbar] = Layout::vertical([
        Constraint::Length(3),
        Constraint::Min(0),
        Constraint::Length(1),
    ])
    .areas(area);

    render_header(frame, header, app);
    render_content(frame, content, app);
    render_statusbar(frame, statusbar, app);

    match app.active_popup.clone() {
        ActivePopup::AddDevice => render_add_popup(frame, area, app),
        ActivePopup::EditSetting => render_edit_setting_popup(frame, area, app),
        ActivePopup::SecurityWarning { section, idx } => {
            render_security_warning_popup(frame, area, section, idx, app)
        }
        ActivePopup::None => {}
    }
}

fn render_header(frame: &mut Frame, area: Rect, app: &App) {
    let tabs = Tabs::new(["  Devices  ", "  Settings  ", "  Logs  "])
        .block(
            Block::bordered()
                .title(" CesaConn ")
                .title_alignment(Alignment::Center)
                .border_type(BorderType::Rounded),
        )
        .select(match app.active_tab {
            Tab::Devices => 0,
            Tab::Settings => 1,
            Tab::Logs => 2,
        })
        .style(Style::default().fg(Color::DarkGray))
        .highlight_style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        );

    frame.render_widget(tabs, area);
}

fn render_content(frame: &mut Frame, area: Rect, app: &mut App) {
    match app.active_tab {
        Tab::Devices => render_devices(frame, area, app),
        Tab::Settings => render_settings(frame, area, app),
        Tab::Logs => render_logs(frame, area, app),
    }
}

fn render_devices(frame: &mut Frame, area: Rect, app: &mut App) {
    let [list_area, detail_area] =
        Layout::horizontal([Constraint::Percentage(40), Constraint::Percentage(60)])
            .areas(area);

    let items: Vec<ListItem> = app
        .devices
        .iter()
        .map(|d| {
            let (icon, color) = match d.status {
                DeviceStatus::Connected => ("● ", Color::Green),
                DeviceStatus::Connecting => ("◌ ", Color::Yellow),
                DeviceStatus::Disconnected => ("○ ", Color::DarkGray),
            };
            ListItem::new(Line::from(vec![
                Span::styled(icon, Style::default().fg(color)),
                Span::raw(d.addr.as_str()),
            ]))
        })
        .collect();

    let list = List::new(items)
        .block(
            Block::bordered()
                .title(" Devices ")
                .border_type(BorderType::Rounded),
        )
        .highlight_style(
            Style::default()
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("▶ ");

    frame.render_stateful_widget(list, list_area, &mut app.device_list_state);

    let detail_lines = match app.selected_device() {
        None => vec![Line::from(Span::styled(
            "  No devices",
            Style::default().fg(Color::DarkGray),
        ))],
        Some(dev) => {
            let (status_str, status_color) = match dev.status {
                DeviceStatus::Connected => ("Connected", Color::Green),
                DeviceStatus::Connecting => ("Connecting...", Color::Yellow),
                DeviceStatus::Disconnected => ("Disconnected", Color::DarkGray),
            };
            vec![
                Line::from(""),
                Line::from(vec![
                    Span::styled("  Address : ", Style::default().fg(Color::DarkGray)),
                    Span::styled(dev.addr.as_str(), Style::default().fg(Color::Cyan)),
                ]),
                Line::from(vec![
                    Span::styled("  Status  : ", Style::default().fg(Color::DarkGray)),
                    Span::styled(status_str, Style::default().fg(status_color)),
                ]),
                Line::from(""),
                Line::from(Span::styled(
                    "  n: add device    d: disconnect",
                    Style::default().fg(Color::DarkGray),
                )),
            ]
        }
    };

    frame.render_widget(
        Paragraph::new(detail_lines).block(
            Block::bordered()
                .title(" Details ")
                .border_type(BorderType::Rounded),
        ),
        detail_area,
    );
}

fn render_settings(frame: &mut Frame, area: Rect, app: &App) {
    let outer_block = Block::bordered()
        .title(" Settings ")
        .border_type(BorderType::Rounded);
    let inner = outer_block.inner(area);
    frame.render_widget(outer_block, area);

    let [section_area, list_area] =
        Layout::vertical([Constraint::Length(2), Constraint::Min(0)]).areas(inner);

    let section_tabs = Tabs::new(["  Basic  ", "  Advanced  "])
        .select(match app.settings_section {
            SettingsSection::Basic => 0,
            SettingsSection::Advanced => 1,
        })
        .style(Style::default().fg(Color::DarkGray))
        .highlight_style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        );
    frame.render_widget(section_tabs, section_area);

    const LABEL_WIDTH: usize = 30;
    let settings = app.active_settings();
    let items: Vec<ListItem> = settings
        .iter()
        .enumerate()
        .map(|(i, s)| {
            let selected = i == app.settings_selected;
            let label_style = if selected {
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::Reset)
            };
            let (val_str, val_color) = s.display_value();
            let label = format!("  {:<LABEL_WIDTH$}", s.label);
            ListItem::new(Line::from(vec![
                Span::styled(label, label_style),
                Span::styled(val_str, Style::default().fg(val_color)),
            ]))
        })
        .collect();

    let mut list_state = ListState::default();
    list_state.select(Some(app.settings_selected));

    frame.render_stateful_widget(
        List::new(items)
            .highlight_style(Style::default().bg(Color::DarkGray))
            .highlight_symbol("▶ "),
        list_area,
        &mut list_state,
    );
}

fn render_logs(frame: &mut Frame, area: Rect, app: &mut App) {
    let inner_height = area.height.saturating_sub(2) as usize;

    if app.log_follow {
        app.log_scroll = app.logs.len().saturating_sub(inner_height) as u16;
    }

    let lines: Vec<Line> = app
        .logs
        .iter()
        .map(|entry| {
            let color = if entry.contains("ERROR") {
                Color::Red
            } else if entry.contains("WARN") {
                Color::Yellow
            } else if entry.contains("DEBUG") {
                Color::DarkGray
            } else {
                Color::Reset
            };
            Line::from(Span::styled(entry.as_str(), Style::default().fg(color)))
        })
        .collect();

    let title = if app.log_follow { " Logs [follow] " } else { " Logs " };

    frame.render_widget(
        Paragraph::new(lines)
            .block(
                Block::bordered()
                    .title(title)
                    .border_type(BorderType::Rounded),
            )
            .scroll((app.log_scroll, 0)),
        area,
    );
}

fn render_statusbar(frame: &mut Frame, area: Rect, app: &App) {
    let help = match app.active_tab {
        Tab::Devices => " q:Quit  Tab:Switch  ↑↓:Navigate  n:Add  d:Disconnect ",
        Tab::Settings => " q:Quit  Tab:Switch  ←→:Section  ↑↓:Navigate  Enter:Edit ",
        Tab::Logs => " q:Quit  Tab:Switch  ↑↓:Scroll  f:Follow ",
    };

    let connected_devices = app
        .devices
        .iter()
        .filter(|d| d.status == DeviceStatus::Connected)
        .count();

    let (daemon_indicator, daemon_color) = if app.daemon_connected {
        ("● daemon", Color::Green)
    } else {
        ("○ daemon", Color::DarkGray)
    };

    let devices_str = format!(" {} connected ", connected_devices);

    let daemon_str = format!(" {}  {}", daemon_indicator, devices_str.trim());

    let [help_area, right_area] = Layout::horizontal([
        Constraint::Min(0),
        Constraint::Length(daemon_str.len() as u16 + 1),
    ])
    .areas(area);

    frame.render_widget(
        Paragraph::new(help).style(Style::default().fg(Color::DarkGray)),
        help_area,
    );
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(
                format!(" {}", daemon_indicator),
                Style::default().fg(daemon_color),
            ),
            Span::styled(
                format!("  {} connected ", connected_devices),
                Style::default().fg(Color::Green),
            ),
        ]))
        .alignment(Alignment::Right),
        right_area,
    );
}

fn render_add_popup(frame: &mut Frame, area: Rect, app: &App) {
    let w = 52u16.min(area.width);
    let h = 5u16.min(area.height);
    let popup = Rect::new(
        area.x + (area.width - w) / 2,
        area.y + (area.height - h) / 2,
        w,
        h,
    );

    frame.render_widget(Clear, popup);
    frame.render_widget(
        Paragraph::new(format!(" {}", app.input_buf)).block(
            Block::bordered()
                .title(" Add Device — IP:port ")
                .title_alignment(Alignment::Center)
                .border_type(BorderType::Double)
                .style(Style::default().fg(Color::Cyan)),
        ),
        popup,
    );

    frame.set_cursor_position((
        popup.x + 2 + app.input_buf.len() as u16,
        popup.y + 1,
    ));
}

fn render_edit_setting_popup(frame: &mut Frame, area: Rect, app: &App) {
    let Some(setting) = app.active_settings().get(app.settings_selected) else {
        return;
    };

    let is_secret = matches!(setting.kind, SettingKind::Secret { .. });
    let display_input = if is_secret {
        "*".repeat(app.input_buf.len())
    } else {
        app.input_buf.clone()
    };

    let title = format!(" Edit: {} ", setting.label);
    let w = (title.len() as u16 + 10).max(52).min(area.width);
    let h = 5u16.min(area.height);
    let popup = Rect::new(
        area.x + (area.width - w) / 2,
        area.y + (area.height - h) / 2,
        w,
        h,
    );

    frame.render_widget(Clear, popup);
    frame.render_widget(
        Paragraph::new(format!(" {}", display_input)).block(
            Block::bordered()
                .title(title)
                .title_alignment(Alignment::Center)
                .border_type(BorderType::Double)
                .style(Style::default().fg(Color::Cyan)),
        ),
        popup,
    );

    frame.set_cursor_position((
        popup.x + 2 + display_input.len() as u16,
        popup.y + 1,
    ));
}

fn render_security_warning_popup(
    frame: &mut Frame,
    area: Rect,
    section: SettingsSection,
    idx: usize,
    app: &App,
) {
    let settings = match section {
        SettingsSection::Basic => &app.settings_basic,
        SettingsSection::Advanced => &app.settings_advanced,
    };
    let Some(setting) = settings.get(idx) else { return };
    let Some(warn_msg) = setting.warn_message else { return };

    let w = 60u16.min(area.width);
    let h = 11u16.min(area.height);
    let popup = Rect::new(
        area.x + (area.width - w) / 2,
        area.y + (area.height - h) / 2,
        w,
        h,
    );

    let mut lines = vec![Line::from("")];
    for msg_line in warn_msg.lines() {
        lines.push(Line::from(Span::styled(
            format!("  {}", msg_line),
            Style::default().fg(Color::Yellow),
        )));
    }
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "  Enable anyway?",
        Style::default().fg(Color::Reset),
    )));
    lines.push(Line::from(""));
    lines.push(Line::from(vec![
        Span::styled("  y", Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)),
        Span::styled(": confirm   ", Style::default().fg(Color::DarkGray)),
        Span::styled("Esc/n", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
        Span::styled(": cancel", Style::default().fg(Color::DarkGray)),
    ]));

    frame.render_widget(Clear, popup);
    frame.render_widget(
        Paragraph::new(lines).block(
            Block::bordered()
                .title(" ⚠ Security Warning ")
                .title_alignment(Alignment::Center)
                .border_type(BorderType::Double)
                .style(Style::default().fg(Color::Yellow)),
        ),
        popup,
    );
}

// ── Main loop ─────────────────────────────────────────────────────────────────

pub fn run(terminal: &mut ratatui::DefaultTerminal, app: &mut App) -> io::Result<()> {
    loop {
        // Drain daemon events before drawing so the frame always reflects the
        // latest state rather than being one frame behind.
        app.drain_daemon_events();
        terminal.draw(|frame| ui(frame, app))?;
        // 50 ms poll keeps CPU near zero when idle while still feeling responsive.
        if event::poll(Duration::from_millis(50))? {
            handle_input(app)?;
        }
        if app.should_quit {
            return Ok(());
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use cesa_conn_ipc::DaemonEvent;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::mpsc::channel;

    fn test_addr() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 3232)
    }

    fn connected_app() -> (App, std::sync::mpsc::Sender<DaemonEvent>) {
        let mut app = App::new();
        let (event_tx, event_rx) = channel();
        let (cmd_tx, _cmd_rx) = channel();
        app.connect_channels(event_rx, cmd_tx);
        (app, event_tx)
    }

    // ── App::new ──────────────────────────────────────────────────────────

    #[test]
    fn new_starts_without_daemon() {
        let app = App::new();
        assert!(!app.daemon_connected);
        assert!(app.devices.is_empty());
        assert!(app.logs.is_empty());
        assert!(!app.should_quit);
    }

    #[test]
    fn new_has_expected_basic_settings() {
        let app = App::new();
        let labels: Vec<_> = app.settings_basic.iter().map(|s| s.label).collect();
        assert!(labels.contains(&"Auth key"));
        assert!(labels.contains(&"Data key"));
        assert!(labels.contains(&"Key persistence"));
    }

    #[test]
    fn new_has_expected_advanced_settings() {
        let app = App::new();
        let labels: Vec<_> = app.settings_advanced.iter().map(|s| s.label).collect();
        assert!(labels.contains(&"Listen address"));
        assert!(labels.contains(&"Listen port"));
    }

    // ── connect_channels ──────────────────────────────────────────────────

    #[test]
    fn connect_channels_marks_daemon_connected() {
        let (app, _tx) = connected_app();
        assert!(app.daemon_connected);
    }

    // ── DaemonEvent handling ──────────────────────────────────────────────

    #[test]
    fn device_connected_event_adds_device() {
        let (mut app, tx) = connected_app();
        let addr = test_addr();
        tx.send(DaemonEvent::DeviceConnected { addr }).unwrap();
        app.drain_daemon_events();
        assert_eq!(app.devices.len(), 1);
        assert_eq!(app.devices[0].addr, addr.to_string());
        assert_eq!(app.devices[0].status, DeviceStatus::Connected);
    }

    #[test]
    fn device_connected_event_updates_existing_device() {
        // If the device was already in the list (e.g. from a Connect command),
        // the event should update its status rather than adding a duplicate.
        let (mut app, tx) = connected_app();
        let addr = test_addr();
        app.devices.push(Device { addr: addr.to_string(), status: DeviceStatus::Connecting });
        tx.send(DaemonEvent::DeviceConnected { addr }).unwrap();
        app.drain_daemon_events();
        assert_eq!(app.devices.len(), 1);
        assert_eq!(app.devices[0].status, DeviceStatus::Connected);
    }

    #[test]
    fn device_disconnected_event_updates_status() {
        let (mut app, tx) = connected_app();
        let addr = test_addr();
        app.devices.push(Device { addr: addr.to_string(), status: DeviceStatus::Connected });
        tx.send(DaemonEvent::DeviceDisconnected { addr }).unwrap();
        app.drain_daemon_events();
        assert_eq!(app.devices[0].status, DeviceStatus::Disconnected);
    }

    #[test]
    fn device_connecting_event_updates_status() {
        let (mut app, tx) = connected_app();
        let addr = test_addr();
        app.devices.push(Device { addr: addr.to_string(), status: DeviceStatus::Disconnected });
        tx.send(DaemonEvent::DeviceConnecting { addr }).unwrap();
        app.drain_daemon_events();
        assert_eq!(app.devices[0].status, DeviceStatus::Connecting);
    }

    #[test]
    fn key_configured_auth_updates_setting() {
        let (mut app, tx) = connected_app();
        tx.send(DaemonEvent::KeyConfigured { is_auth: true }).unwrap();
        app.drain_daemon_events();
        let s = app.settings_basic.iter().find(|s| s.label == "Auth key").unwrap();
        assert_eq!(s.kind, SettingKind::Secret { configured: true });
    }

    #[test]
    fn key_configured_data_updates_setting() {
        let (mut app, tx) = connected_app();
        tx.send(DaemonEvent::KeyConfigured { is_auth: false }).unwrap();
        app.drain_daemon_events();
        let s = app.settings_basic.iter().find(|s| s.label == "Data key").unwrap();
        assert_eq!(s.kind, SettingKind::Secret { configured: true });
    }

    #[test]
    fn log_event_appends_to_logs() {
        let (mut app, tx) = connected_app();
        tx.send(DaemonEvent::Log { message: "hello".into() }).unwrap();
        app.drain_daemon_events();
        assert_eq!(app.logs, vec!["hello"]);
    }

    #[test]
    fn multiple_events_drained_in_one_call() {
        let (mut app, tx) = connected_app();
        tx.send(DaemonEvent::Log { message: "a".into() }).unwrap();
        tx.send(DaemonEvent::Log { message: "b".into() }).unwrap();
        tx.send(DaemonEvent::Log { message: "c".into() }).unwrap();
        app.drain_daemon_events();
        assert_eq!(app.logs, vec!["a", "b", "c"]);
    }

    // ── Channel disconnect detection ──────────────────────────────────────

    #[test]
    fn channel_drop_clears_daemon_connected() {
        let (mut app, tx) = connected_app();
        drop(tx); // simulate daemon exit
        app.drain_daemon_events();
        assert!(!app.daemon_connected);
    }

    #[test]
    fn channel_drop_logs_warning() {
        let (mut app, tx) = connected_app();
        drop(tx);
        app.drain_daemon_events();
        assert!(app.logs.iter().any(|l| l.contains("Lost connection")));
    }

    // ── Settings display ──────────────────────────────────────────────────

    #[test]
    fn secret_unconfigured_shows_not_configured() {
        let s = Setting {
            label: "Auth key",
            kind: SettingKind::Secret { configured: false },
            value: String::new(),
            warn_message: None,
        };
        let (text, _) = s.display_value();
        assert_eq!(text, "[not configured]");
    }

    #[test]
    fn secret_configured_shows_configured() {
        let s = Setting {
            label: "Auth key",
            kind: SettingKind::Secret { configured: true },
            value: String::new(),
            warn_message: None,
        };
        let (text, _) = s.display_value();
        assert_eq!(text, "[configured]");
    }

    #[test]
    fn bool_setting_shows_on_off() {
        let on = Setting { label: "x", kind: SettingKind::Bool(true), value: String::new(), warn_message: None };
        let off = Setting { label: "x", kind: SettingKind::Bool(false), value: String::new(), warn_message: None };
        assert_eq!(on.display_value().0, "on");
        assert_eq!(off.display_value().0, "off");
    }

    #[test]
    fn text_setting_empty_shows_not_set() {
        let s = Setting { label: "x", kind: SettingKind::Text, value: String::new(), warn_message: None };
        assert_eq!(s.display_value().0, "[not set]");
    }

    #[test]
    fn text_setting_with_value_shows_value() {
        let s = Setting { label: "x", kind: SettingKind::Text, value: "0.0.0.0".into(), warn_message: None };
        assert_eq!(s.display_value().0, "0.0.0.0");
    }

    // ── push_log ──────────────────────────────────────────────────────────

    #[test]
    fn push_log_accepts_str_and_string() {
        let mut app = App::new();
        app.push_log("static str");
        app.push_log(String::from("owned string"));
        assert_eq!(app.logs.len(), 2);
    }
}

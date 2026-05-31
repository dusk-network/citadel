// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use std::{
    io::{self, Write},
    path::PathBuf,
    time::Duration,
};

use anyhow::{Result, bail};
use chrono::Local;
use chrono::Utc;
use crossterm::{
    event::{self, Event, KeyCode, KeyEvent},
    execute,
    terminal::{
        Clear, ClearType, EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode,
        enable_raw_mode,
    },
};
use ratatui::{
    Terminal,
    backend::CrosstermBackend,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear as WidgetClear, List, ListItem, ListState, Paragraph, Wrap},
};
use zeroize::Zeroizing;

use crate::{
    citadel,
    cli::{
        Cli, DEFAULT_CALL_GAS_PRICE, DEFAULT_DEPLOY_GAS_LIMIT, DEFAULT_DEPLOY_GAS_PRICE,
        DEFAULT_ISSUE_LICENSE_GAS_LIMIT, DEFAULT_USE_LICENSE_GAS_LIMIT, default_contract_wasm,
    },
    dusk::{
        CitadelQuery, ContractDeploy, Dusk, IssueLicense, ReceiveLicense, RuskWallet,
        RuskWalletConfig, UseLicense,
    },
    state::{CitadelWalletState, SessionCookieRecord, SessionCookieStore},
};

const PROFILE_IDX: u8 = 0;
const TERRACOTTA: Color = Color::Rgb(188, 84, 56);
const CLAY: Color = Color::Rgb(139, 58, 42);
const ORANGE: Color = Color::Rgb(224, 121, 54);
const GOLD: Color = Color::Rgb(232, 178, 96);
const CREAM: Color = Color::Rgb(246, 228, 205);
const MUTED: Color = Color::Rgb(168, 130, 112);

#[derive(Clone, Copy, PartialEq, Eq)]
enum Action {
    ToggleAccount,
    Deploy,
    SetActiveContract,
    ReceiveLicense,
    IssueRequestLicense,
    IssueLicense,
    ListLicenses,
    GetLicense,
    UseLicense,
    ListCookies,
    GetSession,
    Metadata,
    Roots,
    Info,
}

impl Action {
    const ALL: [Self; 14] = [
        Self::ToggleAccount,
        Self::Deploy,
        Self::SetActiveContract,
        Self::ReceiveLicense,
        Self::IssueRequestLicense,
        Self::IssueLicense,
        Self::ListLicenses,
        Self::GetLicense,
        Self::UseLicense,
        Self::ListCookies,
        Self::GetSession,
        Self::Metadata,
        Self::Roots,
        Self::Info,
    ];

    const fn title(self) -> &'static str {
        match self {
            Self::ToggleAccount => "Toggle public/shielded",
            Self::Deploy => "Deploy license contract",
            Self::SetActiveContract => "Set active contract",
            Self::ReceiveLicense => "Receive license",
            Self::IssueRequestLicense => "Issue from request",
            Self::IssueLicense => "Issue license",
            Self::ListLicenses => "List licenses",
            Self::GetLicense => "Get license",
            Self::UseLicense => "Use license",
            Self::ListCookies => "List cookies",
            Self::GetSession => "Get session",
            Self::Metadata => "Metadata",
            Self::Roots => "Roots",
            Self::Info => "Info",
        }
    }

    const fn detail(self) -> &'static str {
        match self {
            Self::ToggleAccount => "Switch profile 0 between public and shielded",
            Self::Deploy => "Deploy the default license contract WASM",
            Self::SetActiveContract => "Persist an existing contract ID",
            Self::ReceiveLicense => "Print a fresh encrypted request blob",
            Self::IssueRequestLicense => "Issue a license from a request blob",
            Self::IssueLicense => "Issue attributes to a shielded address",
            Self::ListLicenses => "Sync and decrypt licenses owned by profile 0",
            Self::GetLicense => "Read one encrypted license by position",
            Self::UseLicense => "Use an owned license by tree position",
            Self::ListCookies => "List saved session cookies",
            Self::GetSession => "Read accepted session public inputs",
            Self::Metadata => "Read deployment and circuit metadata",
            Self::Roots => "Read current and accepted roots",
            Self::Info => "Read active contract counters",
        }
    }
}

#[derive(Clone)]
struct Prompt {
    label: &'static str,
    default: String,
    required: bool,
}

struct PendingAction {
    action: Action,
    prompts: Vec<Prompt>,
    answers: Vec<String>,
    index: usize,
}

struct LicenseChoice {
    position: u64,
    attr_data: String,
    lp_public_key: String,
}

struct LicensePicker {
    choices: Vec<LicenseChoice>,
    selected: usize,
}

struct OutputPopup {
    selected: usize,
    horizontal_offset: usize,
}

#[derive(Clone, Copy)]
enum LogKind {
    Command,
    Info,
    Error,
}

struct LogEntry {
    kind: LogKind,
    timestamp: String,
    message: String,
}

struct App {
    selected: usize,
    wallet_state: CitadelWalletState,
    wallet_password: Option<Zeroizing<String>>,
    storage_key: Zeroizing<[u8; 32]>,
    addresses: (String, String),
    running: bool,
    status: String,
    log: Vec<LogEntry>,
    latest_output: Vec<String>,
    input: String,
    pending: Option<PendingAction>,
    license_picker: Option<LicensePicker>,
    output_popup: Option<OutputPopup>,
}

impl App {
    fn new(
        wallet_state: CitadelWalletState,
        wallet_password: Option<Zeroizing<String>>,
        storage_key: Zeroizing<[u8; 32]>,
        addresses: (String, String),
    ) -> Self {
        Self {
            selected: 0,
            wallet_state,
            wallet_password,
            storage_key,
            addresses,
            running: false,
            status: String::from("Select an action and press Enter"),
            log: vec![log_info("Citadel Wallet TUI ready.")],
            latest_output: Vec::new(),
            input: String::new(),
            pending: None,
            license_picker: None,
            output_popup: None,
        }
    }

    fn selected_action(&self) -> Action {
        Action::ALL[self.selected]
    }

    fn begin_action(&mut self) -> Option<Action> {
        let action = self.selected_action();
        let prompts = prompts_for(action, &self.wallet_state);

        if prompts.is_empty() {
            return Some(action);
        }

        self.input = prompts[0].default.clone();
        self.status = format!("{}: {}", action.title(), prompts[0].label);
        self.pending = Some(PendingAction {
            action,
            prompts,
            answers: Vec::new(),
            index: 0,
        });
        None
    }

    fn cancel_input(&mut self) {
        self.pending = None;
        self.input.clear();
        self.status = String::from("Input cancelled");
    }

    fn accept_input(&mut self) -> Result<Option<(Action, Vec<String>)>> {
        let Some(pending) = self.pending.as_mut() else {
            return Ok(None);
        };
        let prompt = &pending.prompts[pending.index];
        let value = self.input.trim().to_string();
        if prompt.required && value.is_empty() {
            bail!("{} is required", prompt.label);
        }

        pending.answers.push(value);
        pending.index += 1;
        if pending.index < pending.prompts.len() {
            let next = &pending.prompts[pending.index];
            self.input = next.default.clone();
            self.status = format!("{}: {}", pending.action.title(), next.label);
            return Ok(None);
        }

        let pending = self.pending.take().expect("pending action exists");
        self.input.clear();
        Ok(Some((pending.action, pending.answers)))
    }
}

pub async fn run(cli: &Cli) -> Result<()> {
    let wallet_password = match &cli.password {
        Some(password) => Some(Zeroizing::new(password.clone())),
        None => Some(prompt_wallet_password()?),
    };

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    let result = run_loop(&mut terminal, cli, wallet_password).await;
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    result
}

fn prompt_wallet_password() -> Result<Zeroizing<String>> {
    let mut stdout = io::stdout();
    execute!(
        stdout,
        Clear(ClearType::All),
        crossterm::cursor::MoveTo(0, 0)
    )?;
    println!("Citadel Wallet v{}", env!("CARGO_PKG_VERSION"));
    println!();
    Ok(Zeroizing::new(
        rpassword::prompt_password("rusk-wallet password: ")
            .map_err(|error| anyhow::anyhow!("failed to read password: {error}"))?,
    ))
}

async fn run_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    cli: &Cli,
    wallet_password: Option<Zeroizing<String>>,
) -> Result<()> {
    let addresses = wallet(cli, wallet_password.as_ref()).addresses()?;
    let storage_key = wallet(cli, wallet_password.as_ref()).citadel_storage_key()?;
    let mut app = App::new(
        CitadelWalletState::load(&cli.wallet_dir, &storage_key)?,
        wallet_password,
        storage_key,
        addresses,
    );

    loop {
        render(terminal, cli, &app)?;

        if event::poll(Duration::from_millis(250))?
            && let Event::Key(key) = event::read()?
        {
            if app.output_popup.is_some() {
                handle_output_popup_key(&mut app, key);
            } else if app.pending.is_some() {
                match handle_input_key(&mut app, key) {
                    Ok(Some((action, answers))) => {
                        run_and_log(terminal, cli, &mut app, action, answers).await?;
                    }
                    Ok(None) => {}
                    Err(error) => {
                        app.status = error.to_string();
                        app.log.push(log_error(format!("error: {error}")));
                    }
                }
            } else if app.license_picker.is_some() {
                if let Some(position) = handle_license_picker_key(&mut app, key) {
                    begin_use_license_context_prompts(&mut app, position);
                }
            } else {
                match key.code {
                    KeyCode::Char('q') | KeyCode::Esc => break,
                    KeyCode::Up | KeyCode::Char('k') => {
                        app.selected = app.selected.saturating_sub(1);
                    }
                    KeyCode::Down | KeyCode::Char('j') => {
                        app.selected = (app.selected + 1).min(Action::ALL.len() - 1);
                    }
                    KeyCode::Enter => {
                        if app.selected_action() == Action::UseLicense {
                            begin_license_picker(terminal, cli, &mut app).await?;
                        } else if let Some(action) = app.begin_action() {
                            run_and_log(terminal, cli, &mut app, action, Vec::new()).await?;
                        }
                    }
                    KeyCode::Char('o') => match open_output_popup(&mut app) {
                        Ok(()) => {}
                        Err(error) => {
                            app.status = error.to_string();
                            app.log.push(log_error(format!("error: {error}")));
                        }
                    },
                    _ => {}
                }
            }
        }
    }

    Ok(())
}

fn handle_input_key(app: &mut App, key: KeyEvent) -> Result<Option<(Action, Vec<String>)>> {
    match key.code {
        KeyCode::Esc => {
            app.cancel_input();
            Ok(None)
        }
        KeyCode::Enter => app.accept_input(),
        KeyCode::Backspace => {
            app.input.pop();
            Ok(None)
        }
        KeyCode::Char(character) => {
            app.input.push(character);
            Ok(None)
        }
        _ => Ok(None),
    }
}

fn handle_license_picker_key(app: &mut App, key: KeyEvent) -> Option<u64> {
    let picker = app.license_picker.as_mut()?;
    match key.code {
        KeyCode::Esc => {
            app.license_picker = None;
            app.status = String::from("License selection cancelled");
            None
        }
        KeyCode::Up | KeyCode::Char('k') => {
            picker.selected = picker.selected.saturating_sub(1);
            None
        }
        KeyCode::Down | KeyCode::Char('j') => {
            picker.selected = (picker.selected + 1).min(picker.choices.len() - 1);
            None
        }
        KeyCode::Enter => {
            let position = picker.choices[picker.selected].position;
            app.license_picker = None;
            Some(position)
        }
        _ => None,
    }
}

fn open_output_popup(app: &mut App) -> Result<()> {
    if app.latest_output.is_empty() {
        bail!("no command output to show");
    }

    app.output_popup = Some(OutputPopup {
        selected: 0,
        horizontal_offset: 0,
    });
    app.status = String::from("Output popup open");
    Ok(())
}

fn handle_output_popup_key(app: &mut App, key: KeyEvent) {
    let Some(popup) = app.output_popup.as_mut() else {
        return;
    };

    match key.code {
        KeyCode::Esc | KeyCode::Char('o') => {
            app.output_popup = None;
            app.status = String::from("Output popup closed");
        }
        KeyCode::Up | KeyCode::Char('k') => {
            popup.selected = popup.selected.saturating_sub(1);
            popup.horizontal_offset = 0;
        }
        KeyCode::Down | KeyCode::Char('j') => {
            popup.selected = (popup.selected + 1).min(app.latest_output.len() - 1);
            popup.horizontal_offset = 0;
        }
        KeyCode::Left | KeyCode::Char('h') => {
            popup.horizontal_offset = popup.horizontal_offset.saturating_sub(8);
        }
        KeyCode::Right | KeyCode::Char('l') => {
            popup.horizontal_offset = popup.horizontal_offset.saturating_add(8);
        }
        KeyCode::Home => {
            popup.horizontal_offset = 0;
        }
        KeyCode::Char('c') => {
            let value = output_value(&app.latest_output[popup.selected]);
            match copy_to_terminal_clipboard(value) {
                Ok(()) => {
                    app.status = String::from("Copied selected output value");
                    app.log.push(log_info("copied selected output value"));
                }
                Err(error) => {
                    app.status = format!("Copy failed: {error}");
                    app.log.push(log_error(format!("error: {error}")));
                }
            }
        }
        _ => {}
    }
}

fn begin_use_license_context_prompts(app: &mut App, position: u64) {
    let prompts = vec![
        Prompt {
            label: "service provider address",
            default: String::new(),
            required: true,
        },
        Prompt {
            label: "challenge",
            default: String::new(),
            required: true,
        },
    ];
    app.input = prompts[0].default.clone();
    app.status = format!("{}: {}", Action::UseLicense.title(), prompts[0].label);
    app.pending = Some(PendingAction {
        action: Action::UseLicense,
        prompts,
        answers: vec![position.to_string()],
        index: 0,
    });
}

async fn begin_license_picker(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    cli: &Cli,
    app: &mut App,
) -> Result<()> {
    app.running = true;
    app.status = String::from("Running List licenses...");
    app.log = vec![log_command("> List licenses")];
    render(terminal, cli, app)?;

    match wallet(cli, app.wallet_password.as_ref())
        .list_owned_licenses(app.wallet_state.active_contract()?)
        .await
    {
        Ok(licenses) => {
            app.running = false;
            if licenses.is_empty() {
                app.status = String::from("No owned licenses found");
                app.log.push(log_info("no owned licenses found"));
                return Ok(());
            }

            let choices = licenses
                .into_iter()
                .map(|license| LicenseChoice {
                    position: license.position,
                    attr_data: hex::encode(license.attr_data.to_bytes()),
                    lp_public_key: citadel::public_key_hex(&license.issuer),
                })
                .collect::<Vec<_>>();
            let lines = choices
                .iter()
                .map(|license| {
                    format!(
                        "position: {} lp_public_key: {} attr_data: {}",
                        license.position, license.lp_public_key, license.attr_data
                    )
                })
                .collect::<Vec<_>>();
            app.latest_output = lines.clone();
            app.log.extend(lines.into_iter().map(log_info));
            app.status = String::from("Select a license and press Enter");
            app.license_picker = Some(LicensePicker {
                choices,
                selected: 0,
            });
        }
        Err(error) => {
            app.running = false;
            app.status = format!("List licenses failed: {error}");
            app.log.push(log_error(format!("error: {error}")));
        }
    }

    Ok(())
}

async fn run_and_log(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    cli: &Cli,
    app: &mut App,
    action: Action,
    answers: Vec<String>,
) -> Result<()> {
    app.running = true;
    app.status = format!("Running {}...", action.title());
    app.log = vec![log_command(format!("> {}", action.title()))];
    render(terminal, cli, app)?;

    let storage_key = Zeroizing::new(*app.storage_key);
    match execute_action(
        cli,
        app.wallet_password.as_ref(),
        &storage_key,
        &mut app.wallet_state,
        action,
        answers,
    )
    .await
    {
        Ok(lines) => {
            app.running = false;
            app.status = format!("{} completed", action.title());
            app.latest_output = lines.clone();
            app.log.extend(lines.into_iter().map(log_info));
        }
        Err(error) => {
            app.running = false;
            app.status = format!("{} failed: {error}", action.title());
            app.log.push(log_error(format!("error: {error}")));
        }
    }

    Ok(())
}

fn render(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    cli: &Cli,
    app: &App,
) -> Result<()> {
    terminal.draw(|frame| {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3),
                Constraint::Length(9),
                Constraint::Min(10),
                Constraint::Length(3),
            ])
            .split(frame.area());

        let title = Paragraph::new(Line::from(vec![Span::styled(
            "Citadel Wallet",
            Style::default().fg(ORANGE).add_modifier(Modifier::BOLD),
        )]))
        .alignment(Alignment::Center)
        .style(Style::default().fg(CREAM))
        .block(panel_block(""));
        frame.render_widget(title, chunks[0]);

        render_config(frame, chunks[1], cli, app);

        let body = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Length(42), Constraint::Min(30)])
            .split(chunks[2]);
        render_commands(frame, body[0], app);
        render_log(frame, body[1], &app.log);

        frame.render_widget(input_panel(app), chunks[3]);

        if let Some(popup) = &app.output_popup {
            render_output_popup(frame, frame.area(), app, popup);
        }
    })?;
    Ok(())
}

fn render_commands(frame: &mut ratatui::Frame<'_>, area: ratatui::layout::Rect, app: &App) {
    if let Some(picker) = &app.license_picker {
        render_license_picker(frame, area, picker);
        return;
    }

    let text_width = area.width.saturating_sub(4).saturating_sub(2).max(1);
    let items = Action::ALL.map(|action| {
        let mut lines = vec![Line::from(Span::styled(
            action.title(),
            Style::default().fg(CREAM).add_modifier(Modifier::BOLD),
        ))];
        lines.extend(
            wrap_text(action.detail(), text_width)
                .into_iter()
                .map(|line| Line::from(Span::styled(line, Style::default().fg(MUTED)))),
        );
        ListItem::new(lines)
    });
    let selected_height = command_item_height(app.selected_action(), text_width);
    let visible_items = usize::from(area.height.saturating_sub(2))
        .saturating_div(selected_height)
        .max(1);
    let offset = app.selected.saturating_sub(visible_items.saturating_sub(1));
    let mut state = ListState::default()
        .with_selected(Some(app.selected))
        .with_offset(offset);
    let commands = List::new(items)
        .highlight_style(Style::default().bg(CLAY).fg(Color::White))
        .highlight_symbol("> ")
        .block(panel_block("Commands"));
    frame.render_stateful_widget(commands, area, &mut state);
}

fn render_license_picker(
    frame: &mut ratatui::Frame<'_>,
    area: ratatui::layout::Rect,
    picker: &LicensePicker,
) {
    let items = picker.choices.iter().map(|license| {
        ListItem::new(vec![
            Line::from(Span::styled(
                format!("position {}", license.position),
                Style::default().fg(CREAM).add_modifier(Modifier::BOLD),
            )),
            Line::from(Span::styled(
                format!("lp_public_key {}", license.lp_public_key),
                Style::default().fg(MUTED),
            )),
            Line::from(Span::styled(
                format!("attr_data {}", license.attr_data),
                Style::default().fg(MUTED),
            )),
        ])
    });
    let mut state = ListState::default();
    state.select(Some(picker.selected));
    let licenses = List::new(items)
        .highlight_style(Style::default().bg(CLAY).fg(Color::White))
        .highlight_symbol("> ")
        .block(panel_block("Licenses"));
    frame.render_stateful_widget(licenses, area, &mut state);
}

fn render_log(frame: &mut ratatui::Frame<'_>, area: ratatui::layout::Rect, log: &[LogEntry]) {
    let height = usize::from(area.height.saturating_sub(2));
    let start = log.len().saturating_sub(height);
    let lines = log[start..]
        .iter()
        .map(|entry| {
            let message_style = match entry.kind {
                LogKind::Command => Style::default().fg(ORANGE).add_modifier(Modifier::BOLD),
                LogKind::Info => Style::default().fg(CREAM),
                LogKind::Error => Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            };
            Line::from(vec![
                Span::styled(
                    "[ log ]",
                    Style::default().fg(GOLD).add_modifier(Modifier::BOLD),
                ),
                Span::styled(" : ", Style::default().fg(MUTED)),
                Span::styled(entry.timestamp.clone(), Style::default().fg(MUTED)),
                Span::styled(" : ", Style::default().fg(MUTED)),
                Span::styled(entry.message.clone(), message_style),
            ])
        })
        .collect::<Vec<_>>();
    let log = Paragraph::new(lines)
        .style(Style::default().fg(CREAM))
        .block(panel_block("Log"))
        .wrap(Wrap { trim: false });
    frame.render_widget(log, area);
}

fn render_output_popup(frame: &mut ratatui::Frame<'_>, area: Rect, app: &App, popup: &OutputPopup) {
    let area = centered_rect(88, 68, area);
    frame.render_widget(WidgetClear, area);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(4),
            Constraint::Length(4),
            Constraint::Length(2),
        ])
        .split(area);

    let items = app.latest_output.iter().map(|line| {
        let label = output_label(line);
        ListItem::new(Line::from(Span::styled(label, Style::default().fg(CREAM))))
    });
    let mut state = ListState::default().with_selected(Some(popup.selected));
    let list = List::new(items)
        .highlight_style(Style::default().bg(CLAY).fg(Color::White))
        .highlight_symbol("> ")
        .block(panel_block("Latest Output"));
    frame.render_stateful_widget(list, chunks[0], &mut state);

    let selected = output_value(&app.latest_output[popup.selected]);
    let selected = horizontal_slice(selected, popup.horizontal_offset, chunks[1].width);
    let value = Paragraph::new(selected)
        .style(Style::default().fg(CREAM))
        .block(panel_block("Selected Value"));
    frame.render_widget(value, chunks[1]);

    let help = Paragraph::new("Up/Down select | Left/Right scroll | c copy value | Esc close")
        .alignment(Alignment::Center)
        .style(Style::default().fg(GOLD));
    frame.render_widget(help, chunks[2]);
}

fn input_panel(app: &App) -> Paragraph<'static> {
    let text = if let Some(pending) = &app.pending {
        let prompt = &pending.prompts[pending.index];
        format!(
            "{} ({}/{}) {}: {}",
            pending.action.title(),
            pending.index + 1,
            pending.prompts.len(),
            prompt.label,
            app.input
        )
    } else if app.license_picker.is_some() {
        String::from("Select license | Enter use | arrows move | Esc cancel")
    } else if app.output_popup.is_some() {
        String::from("Output | Up/Down select | Left/Right scroll | c copy | Esc close")
    } else {
        format!(
            "{} | Enter run | o output | arrows move | q quit",
            app.status
        )
    };

    let style = if app.running {
        Style::default()
            .fg(ORANGE)
            .add_modifier(Modifier::SLOW_BLINK | Modifier::BOLD)
    } else {
        Style::default().fg(GOLD)
    };

    Paragraph::new(text).style(style).block(panel_block(""))
}

fn render_config(frame: &mut ratatui::Frame<'_>, area: Rect, cli: &Cli, app: &App) {
    let prover = cli.prover.as_deref().unwrap_or(&cli.state).to_string();
    let archiver = cli.archiver.as_deref().unwrap_or(&cli.state).to_string();
    let (_, shielded_address) = app.addresses.clone();

    let rows = [
        ("State node", cli.state.clone()),
        ("Prover", prover),
        ("Archiver", archiver),
        ("Wallet dir", cli.wallet_dir.display().to_string()),
        ("Account mode", app.wallet_state.account_label().to_string()),
        ("Your Citadel address", shielded_address),
        (
            "Active contract",
            app.wallet_state
                .active_contract
                .clone()
                .unwrap_or_else(|| "not set".to_string()),
        ),
    ];

    let block = panel_block("Config");
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let value_width = rows
        .iter()
        .map(|(label, _)| label.len() + 2)
        .max()
        .and_then(|prefix| usize::from(inner.width).checked_sub(prefix))
        .unwrap_or(1)
        .max(1) as u16;
    let mut lines = Vec::new();
    for (label, value) in rows {
        lines.extend(info_lines(label, value, value_width));
    }

    let visible = usize::from(inner.height);
    let start = lines.len().saturating_sub(visible);
    let config = Paragraph::new(lines[start..].to_vec()).style(Style::default().fg(CREAM));
    frame.render_widget(config, inner);
}

fn info_lines(label: &'static str, value: String, value_width: u16) -> Vec<Line<'static>> {
    let wrapped = wrap_text(&value, value_width);
    let mut lines = Vec::with_capacity(wrapped.len().max(1));
    let prefix = format!("{label}: ");
    let indent = " ".repeat(prefix.len());

    for (index, value) in wrapped.into_iter().enumerate() {
        let label = if index == 0 {
            Span::styled(
                prefix.clone(),
                Style::default().fg(GOLD).add_modifier(Modifier::BOLD),
            )
        } else {
            Span::raw(indent.clone())
        };
        lines.push(Line::from(vec![label, Span::raw(value)]));
    }

    lines
}

fn centered_rect(percent_x: u16, percent_y: u16, area: Rect) -> Rect {
    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(area);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(vertical[1])[1]
}

fn command_item_height(action: Action, width: u16) -> usize {
    1 + wrap_text(action.detail(), width).len()
}

fn wrap_text(text: &str, width: u16) -> Vec<String> {
    let width = usize::from(width).max(1);
    if text.is_empty() {
        return vec![String::new()];
    }

    let mut lines = Vec::new();
    let mut current = String::new();

    for word in text.split_whitespace() {
        if current.is_empty() {
            push_wrapped_word(word, width, &mut current, &mut lines);
        } else if current.chars().count() + 1 + word.chars().count() <= width {
            current.push(' ');
            current.push_str(word);
        } else {
            lines.push(current);
            current = String::new();
            push_wrapped_word(word, width, &mut current, &mut lines);
        }
    }

    if !current.is_empty() {
        lines.push(current);
    }

    if lines.is_empty() {
        lines.push(String::new());
    }

    lines
}

fn push_wrapped_word(word: &str, width: usize, current: &mut String, lines: &mut Vec<String>) {
    let mut chars = word.chars().peekable();
    while chars.peek().is_some() {
        let chunk = chars.by_ref().take(width).collect::<String>();
        if chunk.chars().count() == width && chars.peek().is_some() {
            lines.push(chunk);
        } else {
            *current = chunk;
        }
    }
}

fn output_label(line: &str) -> String {
    let Some((label, value)) = line.split_once(": ") else {
        return line.to_string();
    };

    let preview = horizontal_slice(value, 0, 40);
    format!("{label}: {preview}")
}

fn output_value(line: &str) -> &str {
    line.split_once(": ")
        .map(|(_, value)| value)
        .unwrap_or(line)
}

fn horizontal_slice(value: &str, offset: usize, width: u16) -> String {
    let width = usize::from(width.saturating_sub(4)).max(1);
    let visible = value.chars().skip(offset).take(width).collect::<String>();
    if value.chars().count() > offset + visible.chars().count() {
        format!("{visible}...")
    } else {
        visible
    }
}

fn copy_to_terminal_clipboard(value: &str) -> Result<()> {
    // OSC 52 is the most portable clipboard path for a terminal UI. Terminals
    // that disable clipboard access will return an I/O error that the UI shows.
    let payload = base64_encode(value.as_bytes());
    let mut stdout = io::stdout();
    stdout.write_all(format!("\x1b]52;c;{payload}\x07").as_bytes())?;
    stdout.flush()?;
    Ok(())
}

fn base64_encode(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut encoded = String::with_capacity(bytes.len().div_ceil(3) * 4);

    for chunk in bytes.chunks(3) {
        let b0 = chunk[0];
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);

        encoded.push(TABLE[(b0 >> 2) as usize] as char);
        encoded.push(TABLE[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);
        if chunk.len() > 1 {
            encoded.push(TABLE[(((b1 & 0x0f) << 2) | (b2 >> 6)) as usize] as char);
        } else {
            encoded.push('=');
        }
        if chunk.len() > 2 {
            encoded.push(TABLE[(b2 & 0x3f) as usize] as char);
        } else {
            encoded.push('=');
        }
    }

    encoded
}

fn session_cookie_lines(index: usize, record: &SessionCookieRecord) -> Vec<String> {
    vec![
        format!("cookie[{index}].created_at: {}", record.created_at),
        format!("cookie[{index}].contract_id: {}", record.contract_id),
        format!("cookie[{index}].position: {}", record.position),
        format!(
            "cookie[{index}].service_provider: {}",
            record.service_provider
        ),
        format!("cookie[{index}].session_id: {}", record.session_id),
        format!("cookie[{index}].tx_hash: {}", record.tx_hash),
        format!("cookie[{index}].session_cookie: {}", record.session_cookie),
    ]
}

fn log_command(message: impl Into<String>) -> LogEntry {
    log_entry(LogKind::Command, message)
}

fn log_info(message: impl Into<String>) -> LogEntry {
    log_entry(LogKind::Info, message)
}

fn log_error(message: impl Into<String>) -> LogEntry {
    log_entry(LogKind::Error, message)
}

fn log_entry(kind: LogKind, message: impl Into<String>) -> LogEntry {
    LogEntry {
        kind,
        timestamp: Local::now().format("%H:%M:%S").to_string(),
        message: message.into(),
    }
}

fn prompts_for(action: Action, wallet_state: &CitadelWalletState) -> Vec<Prompt> {
    match action {
        Action::ToggleAccount
        | Action::Info
        | Action::ListLicenses
        | Action::ListCookies
        | Action::Metadata
        | Action::Roots => Vec::new(),
        Action::Deploy => vec![Prompt {
            label: "WASM path",
            default: default_contract_wasm().display().to_string(),
            required: true,
        }],
        Action::SetActiveContract => vec![Prompt {
            label: "contract ID hex",
            default: wallet_state.active_contract.clone().unwrap_or_default(),
            required: true,
        }],
        Action::ReceiveLicense => vec![Prompt {
            label: "issuer address",
            default: String::new(),
            required: true,
        }],
        Action::IssueRequestLicense => vec![
            Prompt {
                label: "request blob hex",
                default: String::new(),
                required: true,
            },
            Prompt {
                label: "attributes",
                default: String::new(),
                required: true,
            },
        ],
        Action::IssueLicense => vec![
            Prompt {
                label: "attributes",
                default: String::new(),
                required: true,
            },
            Prompt {
                label: "recipient address",
                default: String::new(),
                required: true,
            },
        ],
        Action::GetLicense => vec![Prompt {
            label: "position",
            default: String::new(),
            required: true,
        }],
        Action::UseLicense => vec![
            Prompt {
                label: "license position",
                default: String::new(),
                required: true,
            },
            Prompt {
                label: "service provider address",
                default: String::new(),
                required: true,
            },
            Prompt {
                label: "challenge",
                default: String::new(),
                required: true,
            },
        ],
        Action::GetSession => vec![Prompt {
            label: "session ID hex",
            default: String::new(),
            required: true,
        }],
    }
}

async fn execute_action(
    cli: &Cli,
    wallet_password: Option<&Zeroizing<String>>,
    storage_key: &[u8; 32],
    wallet_state: &mut CitadelWalletState,
    action: Action,
    answers: Vec<String>,
) -> Result<Vec<String>> {
    match action {
        Action::ToggleAccount => {
            wallet_state.use_shielded = !wallet_state.use_shielded;
            wallet_state.save(&cli.wallet_dir, storage_key)?;
            Ok(vec![format!(
                "profile {PROFILE_IDX} now uses {} account",
                wallet_state.account_label()
            )])
        }
        Action::Deploy => {
            let deploy_nonce = RuskWallet::generated_deploy_nonce();
            let receipt = wallet(cli, wallet_password)
                .deploy(ContractDeploy {
                    code: PathBuf::from(answer(&answers, 0, "WASM path")?),
                    init_args: String::new(),
                    deploy_nonce,
                    address: None,
                    profile_idx: Some(PROFILE_IDX),
                    shielded: wallet_state.use_shielded,
                    gas_limit: DEFAULT_DEPLOY_GAS_LIMIT,
                    gas_price: DEFAULT_DEPLOY_GAS_PRICE,
                })
                .await?;

            wallet_state.set_active_contract(receipt.contract_id.clone())?;
            wallet_state.save(&cli.wallet_dir, storage_key)?;
            Ok(vec![
                format!("deploy_nonce: {deploy_nonce}"),
                format!("contract_id: {}", receipt.contract_id),
                format!("tx_hash: {}", receipt.tx_hash),
                format!(
                    "active contract stored in {}",
                    CitadelWalletState::path(&cli.wallet_dir).display()
                ),
            ])
        }
        Action::SetActiveContract => {
            wallet_state.set_active_contract(answer(&answers, 0, "contract ID")?)?;
            wallet_state.save(&cli.wallet_dir, storage_key)?;
            Ok(vec![format!(
                "active contract: {}",
                wallet_state.active_contract()?
            )])
        }
        Action::ReceiveLicense => {
            let issuer_address = answer(&answers, 0, "issuer address")?;
            let issuer_public_key = citadel::parse_shielded_address(&issuer_address)?;
            let receipt = wallet(cli, wallet_password).receive_license(
                ReceiveLicense {
                    profile_idx: Some(PROFILE_IDX),
                },
                issuer_public_key,
            )?;
            Ok(vec![
                format!("request_id: {}", receipt.request_id),
                format!("version: {}", receipt.version),
                format!("deployment_id: {}", receipt.deployment_id),
                format!("request_blob: {}", receipt.request_blob),
            ])
        }
        Action::IssueRequestLicense => {
            let request = citadel::parse_request_blob_hex(&answer(&answers, 0, "request blob")?)?;
            let attributes = answer(&answers, 1, "attributes")?;
            let contract_id = wallet_state.active_contract()?.to_string();
            let issuer = wallet(cli, wallet_password).citadel_secret_key(PROFILE_IDX)?;
            let (issue_arg, request_id) =
                citadel::issue_license_from_request_arg(&attributes, &request, &issuer)?;
            let receipt = wallet(cli, wallet_password)
                .issue_license(
                    IssueLicense {
                        contract_id,
                        profile_idx: Some(PROFILE_IDX),
                        shielded: wallet_state.use_shielded,
                        gas_limit: DEFAULT_ISSUE_LICENSE_GAS_LIMIT,
                        gas_price: DEFAULT_CALL_GAS_PRICE,
                    },
                    issue_arg,
                )
                .await?;
            wallet_state.save(&cli.wallet_dir, storage_key)?;
            Ok(vec![
                format!("tx_hash: {}", receipt.tx_hash),
                format!("request_id: {}", hex::encode(request_id.to_bytes())),
                format!(
                    "attribute_scalar: {}",
                    citadel::attribute_scalar_hex(&attributes)
                ),
                format!(
                    "issuer_public_key: {}",
                    citadel::issuer_public_key_hex(&issuer)
                ),
            ])
        }
        Action::IssueLicense => {
            let attributes = answer(&answers, 0, "attributes")?;
            let recipient = answer(&answers, 1, "recipient address")?;
            let issuer = wallet(cli, wallet_password).citadel_secret_key(PROFILE_IDX)?;
            let recipient_key = citadel::parse_shielded_address(&recipient)?;
            let issue_arg = citadel::issue_license_arg(&attributes, recipient_key, &issuer)?;
            let receipt = wallet(cli, wallet_password)
                .issue_license(
                    IssueLicense {
                        contract_id: wallet_state.active_contract()?.to_string(),
                        profile_idx: Some(PROFILE_IDX),
                        shielded: wallet_state.use_shielded,
                        gas_limit: DEFAULT_ISSUE_LICENSE_GAS_LIMIT,
                        gas_price: DEFAULT_CALL_GAS_PRICE,
                    },
                    issue_arg,
                )
                .await?;
            wallet_state.save(&cli.wallet_dir, storage_key)?;
            Ok(vec![
                format!("tx_hash: {}", receipt.tx_hash),
                format!("recipient_address: {recipient}"),
                format!(
                    "attribute_scalar: {}",
                    citadel::attribute_scalar_hex(&attributes)
                ),
                format!(
                    "issuer_public_key: {}",
                    citadel::issuer_public_key_hex(&issuer)
                ),
            ])
        }
        Action::ListLicenses => {
            let licenses = wallet(cli, wallet_password)
                .list_owned_licenses(wallet_state.active_contract()?)
                .await?;
            if licenses.is_empty() {
                return Ok(vec![String::from("no owned licenses found")]);
            }
            Ok(licenses
                .into_iter()
                .map(|license| {
                    format!(
                        "position: {} lp_public_key: {} attr_data: {}",
                        license.position,
                        citadel::public_key_hex(&license.issuer),
                        hex::encode(license.attr_data.to_bytes())
                    )
                })
                .collect())
        }
        Action::GetLicense => {
            let position = answer(&answers, 0, "position")?
                .parse()
                .map_err(|_| anyhow::anyhow!("position must be a number"))?;
            let Some(license) = Dusk::new(cli.state.clone())
                .license(wallet_state.active_contract()?, position)
                .await?
            else {
                return Ok(vec![String::from("license not found")]);
            };
            let info = citadel::license_info(position, &license)?;
            Ok(vec![
                format!("position: {}", info.position),
                format!("version: {}", hex::encode(info.version.to_bytes())),
                format!(
                    "deployment_id: {}",
                    hex::encode(info.deployment_id.to_bytes())
                ),
                format!("lpk_u: {}", hex::encode(info.lpk_u.to_bytes())),
                format!("lpk_v: {}", hex::encode(info.lpk_v.to_bytes())),
                format!("license_blob: {}", hex::encode(license)),
            ])
        }
        Action::UseLicense => {
            let position = answer(&answers, 0, "license position")?
                .parse()
                .map_err(|_| anyhow::anyhow!("license position must be a number"))?;
            let contract_id = wallet_state.active_contract()?.to_string();
            let service_provider =
                citadel::parse_shielded_address(&answer(&answers, 1, "service provider address")?)?;
            let service_provider_hex = citadel::public_key_hex(&service_provider);
            let challenge = citadel::encode_challenge(&answer(&answers, 2, "challenge")?)?;
            let receipt = wallet(cli, wallet_password)
                .use_license(UseLicense {
                    contract_id: contract_id.clone(),
                    position,
                    service_provider,
                    challenge,
                    profile_idx: Some(PROFILE_IDX),
                    shielded: wallet_state.use_shielded,
                    gas_limit: DEFAULT_USE_LICENSE_GAS_LIMIT,
                    gas_price: DEFAULT_CALL_GAS_PRICE,
                })
                .await?;
            wallet_state.save(&cli.wallet_dir, storage_key)?;
            let cookie_path = SessionCookieStore::append(
                &cli.wallet_dir,
                storage_key,
                SessionCookieRecord {
                    created_at: Utc::now().to_rfc3339(),
                    contract_id,
                    position,
                    service_provider: service_provider_hex,
                    session_id: receipt.session_id.clone(),
                    tx_hash: receipt.tx_hash.clone(),
                    session_cookie: receipt.session_cookie.clone(),
                },
            )?;
            Ok(vec![
                format!("position: {position}"),
                format!("tx_hash: {}", receipt.tx_hash),
                format!("session_id: {}", receipt.session_id),
                format!("session_cookie: {}", receipt.session_cookie),
                format!("session_cookie_file: {}", cookie_path.display()),
            ])
        }
        Action::ListCookies => {
            let store = SessionCookieStore::load(&cli.wallet_dir, storage_key)?;
            if store.records.is_empty() {
                return Ok(vec![String::from("no saved session cookies found")]);
            }
            let mut lines = Vec::new();
            for (index, record) in store.records.iter().enumerate() {
                lines.extend(session_cookie_lines(index, record));
            }
            Ok(lines)
        }
        Action::GetSession => {
            let session_id =
                citadel::parse_bls_scalar_hex(&answer(&answers, 0, "session ID")?, "session ID")?;
            let Some(session) = Dusk::new(cli.state.clone())
                .session(wallet_state.active_contract()?, session_id)
                .await?
            else {
                return Ok(vec![String::from("session not found")]);
            };
            let mut lines = vec![format!(
                "session_id: {}",
                hex::encode(session_id.to_bytes())
            )];
            lines.extend(
                session
                    .public_inputs
                    .iter()
                    .enumerate()
                    .map(|(index, input)| {
                        format!("public_input[{index}]: {}", hex::encode(input.to_bytes()))
                    }),
            );
            Ok(lines)
        }
        Action::Metadata => {
            let metadata = Dusk::new(cli.state.clone())
                .metadata(wallet_state.active_contract()?)
                .await?;
            Ok(vec![
                format!(
                    "deployment_id: {}",
                    hex::encode(metadata.deployment_id.to_bytes())
                ),
                format!(
                    "protocol_version: {}",
                    hex::encode(metadata.protocol_version.to_bytes())
                ),
                format!("chain_id: {}", hex::encode(metadata.chain_id.to_bytes())),
                format!(
                    "contract_id: {}",
                    hex::encode(metadata.contract_id.to_bytes())
                ),
                format!(
                    "verifier_key_hash: {}",
                    hex::encode(metadata.verifier_key_hash.to_bytes())
                ),
                format!(
                    "circuit_hash: {}",
                    hex::encode(metadata.circuit_hash.to_bytes())
                ),
                format!("merkle_arity: {}", metadata.merkle_arity),
                format!("merkle_depth: {}", metadata.merkle_depth),
                format!("root_history_size: {}", metadata.root_history_size),
                format!("public_inputs_len: {}", metadata.public_inputs_len),
            ])
        }
        Action::Roots => {
            let current_root = Dusk::new(cli.state.clone())
                .current_root(wallet_state.active_contract()?)
                .await?;
            let accepted_roots = Dusk::new(cli.state.clone())
                .accepted_roots(wallet_state.active_contract()?)
                .await?;
            let mut lines = vec![format!(
                "current_root: {}",
                hex::encode(current_root.to_bytes())
            )];
            if accepted_roots.is_empty() {
                lines.push(String::from("accepted_roots: none"));
            } else {
                lines.extend(accepted_roots.iter().enumerate().map(|(index, root)| {
                    format!("accepted_root[{index}]: {}", hex::encode(root.to_bytes()))
                }));
            }
            Ok(lines)
        }
        Action::Info => {
            let contract_id = wallet_state.active_contract()?.to_string();
            let CitadelQuery {
                licenses,
                tree_len,
                sessions,
                accepted_roots,
                current_root,
            } = Dusk::new(cli.state.clone())
                .citadel_info(&contract_id)
                .await?;
            Ok(vec![
                format!("licenses: {licenses}"),
                format!("tree_len: {tree_len}"),
                format!("sessions: {sessions}"),
                format!("accepted_roots: {accepted_roots}"),
                format!("current_root: {}", hex::encode(current_root.to_bytes())),
            ])
        }
    }
}

fn answer(answers: &[String], index: usize, label: &str) -> Result<String> {
    let value = answers
        .get(index)
        .ok_or_else(|| anyhow::anyhow!("missing {label}"))?
        .trim()
        .to_string();
    if value.is_empty() {
        bail!("{label} is required");
    }
    Ok(value)
}

fn panel_block(title: &'static str) -> Block<'static> {
    Block::default()
        .title(title)
        .borders(Borders::ALL)
        .border_style(Style::default().fg(TERRACOTTA))
}

fn wallet(cli: &Cli, password: Option<&Zeroizing<String>>) -> RuskWallet {
    RuskWallet::new(RuskWalletConfig {
        wallet_dir: cli.wallet_dir.clone(),
        password: password.cloned().or_else(|| {
            cli.password
                .as_ref()
                .map(|password| Zeroizing::new(password.clone()))
        }),
        state: cli.state.clone(),
        prover: cli.prover.clone().unwrap_or_else(|| cli.state.clone()),
        archiver: cli.archiver.clone().unwrap_or_else(|| cli.state.clone()),
    })
}

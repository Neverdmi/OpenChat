//! `oc-tui` — OpenChat terminal UI (ratatui).
//!
//! Run without arguments for the TUI. Pass `--cli` anywhere before the
//! subcommand to run the exact same command-line interface as the `oc`
//! binary instead, e.g. `oc-tui --cli chat <peer>`.

mod app;

use std::ffi::OsString;
use std::io;
use std::time::Duration;

use app::{Focus, TuiApp};
use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph};
use ratatui::Terminal;

/// Whether the given argv requests CLI mode (`--cli` present).
fn is_cli_mode(argv: &[OsString]) -> bool {
    argv.iter().any(|arg| arg == "--cli")
}

/// Build the argv for the CLI entry point: drop `--cli`, keep the rest.
fn cli_args_from(argv: &[OsString]) -> Vec<OsString> {
    let mut args = vec![OsString::from("oc")];
    args.extend(
        argv.iter()
            .skip(1)
            .filter(|arg| *arg != "--cli")
            .cloned(),
    );
    args
}

fn main() {
    let argv: Vec<OsString> = std::env::args_os().collect();
    if is_cli_mode(&argv) {
        if let Err(error) = oc_cli::run_cli_from(cli_args_from(&argv)) {
            eprintln!("error: {error:#}");
            std::process::exit(1);
        }
        return;
    }

    if let Err(error) = run_tui() {
        eprintln!("tui error: {error:#}");
        std::process::exit(1);
    }
}

fn run_tui() -> anyhow::Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let result = event_loop(&mut terminal);

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    result
}

fn event_loop(terminal: &mut Terminal<CrosstermBackend<io::Stdout>>) -> anyhow::Result<()> {
    let mut app = TuiApp::new();

    loop {
        app.poll_events();
        terminal.draw(|frame| draw(frame, &mut app))?;

        if app.should_quit {
            break;
        }

        if event::poll(Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Release {
                    continue;
                }
                handle_key(&mut app, key.code, key.modifiers);
            }
        }
    }
    Ok(())
}

fn handle_key(app: &mut TuiApp, code: KeyCode, modifiers: KeyModifiers) {
    if modifiers.contains(KeyModifiers::CONTROL) && code == KeyCode::Char('c') {
        app.should_quit = true;
        return;
    }

    if app.locked {
        // Tab switches between the home directory and passphrase fields.
        match code {
            KeyCode::Tab => {
                app.lock_field = match app.lock_field {
                    app::LockField::Home => app::LockField::Passphrase,
                    app::LockField::Passphrase => app::LockField::Home,
                };
            }
            KeyCode::Enter => app.unlock(),
            KeyCode::Backspace => {
                match app.lock_field {
                    app::LockField::Home => {
                        app.home.pop();
                    }
                    app::LockField::Passphrase => {
                        app.passphrase.pop();
                    }
                }
            }
            KeyCode::Char(ch) => match app.lock_field {
                app::LockField::Home => app.home.push(ch),
                app::LockField::Passphrase => app.passphrase.push(ch),
            },
            _ => {}
        }
        return;
    }

    match app.focus {
        Focus::Input => match code {
            KeyCode::Enter => app.submit_input(),
            KeyCode::Backspace => {
                app.input.pop();
            }
            KeyCode::Tab => app.focus = Focus::Contacts,
            KeyCode::Char(ch) => app.input.push(ch),
            _ => {}
        },
        Focus::Contacts => match code {
            KeyCode::Up => app.move_selection(-1),
            KeyCode::Down => app.move_selection(1),
            KeyCode::Enter | KeyCode::Tab => app.focus = Focus::Input,
            _ => {}
        },
    }
}

fn draw(frame: &mut ratatui::Frame, app: &mut TuiApp) {
    if app.locked {
        draw_unlock(frame, app);
        return;
    }

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(0),
            Constraint::Length(3),
            Constraint::Length(1),
        ])
        .split(frame.area());

    // Header: title, status, invite, outbox.
    let header_text = vec![
        Line::from(vec![
            Span::styled("OpenChat", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(format!("  outbox: {}  {}", app.outbox_len, app.status)),
        ]),
        Line::from(format!("invite: {}", app.invite)),
    ];
    let header = Paragraph::new(header_text).block(Block::default().borders(Borders::ALL));
    frame.render_widget(header, chunks[0]);

    // Body: contacts | conversation.
    let body = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Length(30), Constraint::Min(0)])
        .split(chunks[1]);

    let items: Vec<ListItem> = app
        .contacts
        .iter()
        .map(|contact| {
            let marker = if contact.verified { "✓" } else { "?" };
            ListItem::new(format!("{} {}", contact.short, marker))
        })
        .collect();
    let mut state = ListState::default();
    if !app.contacts.is_empty() {
        state.select(Some(app.selected.min(app.contacts.len() - 1)));
    }
    let contacts = List::new(items)
        .block(Block::default().borders(Borders::ALL).title("Contacts (Tab)"))
        .highlight_style(Style::default().add_modifier(Modifier::BOLD));
    frame.render_stateful_widget(contacts, body[0], &mut state);

    // Conversation, auto-scrolled to the end.
    let title = match (app.selected_short(), app.contacts.get(app.selected)) {
        (Some(short), Some(contact)) => {
            format!("Chat with {short} · safety: {}", contact.safety)
        }
        _ => "No contact selected".to_string(),
    };
    let lines: Vec<Line> = app
        .lines
        .iter()
        .map(|line| {
            let style = if line.outgoing {
                Style::default().fg(Color::Green)
            } else if line.author == "system" {
                Style::default().fg(Color::Yellow)
            } else {
                Style::default()
            };
            Line::from(vec![
                Span::styled(format!("{}: ", line.author), style),
                Span::raw(line.text.clone()),
            ])
        })
        .collect();
    let height = body[1].height.saturating_sub(2) as usize;
    let scroll = (lines.len().saturating_sub(height)) as u16;
    let messages = Paragraph::new(lines)
        .block(Block::default().borders(Borders::ALL).title(title))
        .scroll((scroll, 0));
    frame.render_widget(messages, body[1]);

    // Input.
    let input_title = match app.focus {
        Focus::Input => "Message (Enter send · Tab contacts · /add <invite> · /help · Ctrl+C quit)",
        Focus::Contacts => "Contacts (↑↓ select · Enter back to input · Ctrl+C quit)",
    };
    let input_style = if app.can_send() {
        Style::default().fg(Color::Green)
    } else {
        Style::default()
    };
    let input = Paragraph::new(app.input.clone()).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(input_style)
            .title(input_title),
    );
    frame.render_widget(input, chunks[2]);

    // Footer: errors win over the status line.
    let footer = match &app.error {
        Some(error) => Span::styled(error.clone(), Style::default().fg(Color::Red)),
        None => Span::raw(app.status.clone()),
    };
    frame.render_widget(Paragraph::new(Line::from(footer)), chunks[3]);
}

fn draw_unlock(frame: &mut ratatui::Frame, app: &TuiApp) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Length(1),
        ])
        .split(frame.area());

    let title = Paragraph::new("OpenChat — unlock your encrypted state")
        .block(Block::default().borders(Borders::ALL));
    frame.render_widget(title, chunks[0]);

    let home_style = if app.lock_field == app::LockField::Home {
        Style::default().fg(Color::Green)
    } else {
        Style::default()
    };
    let home = Paragraph::new(app.home.clone()).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(home_style)
            .title("State directory (Tab to switch field)"),
    );
    frame.render_widget(home, chunks[1]);

    let pass_style = if app.lock_field == app::LockField::Passphrase {
        Style::default().fg(Color::Green)
    } else {
        Style::default()
    };
    let masked = "*".repeat(app.passphrase.chars().count());
    let passphrase = Paragraph::new(masked).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(pass_style)
            .title("Passphrase (Enter to unlock)"),
    );
    frame.render_widget(passphrase, chunks[2]);

    let footer = match &app.error {
        Some(error) => Span::styled(error.clone(), Style::default().fg(Color::Red)),
        None => Span::raw("First run? Create state first: oc init (you invent the passphrase there)"),
    };
    frame.render_widget(Paragraph::new(Line::from(footer)), chunks[3]);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(items: &[&str]) -> Vec<OsString> {
        items.iter().map(OsString::from).collect()
    }

    #[test]
    fn cli_mode_detection() {
        assert!(is_cli_mode(&argv(&["oc-tui", "--cli"])));
        assert!(is_cli_mode(&argv(&["oc-tui", "--cli", "chat"])));
        assert!(!is_cli_mode(&argv(&["oc-tui"])));
    }

    #[test]
    fn cli_args_strip_flag_and_keep_subcommand() {
        assert_eq!(
            cli_args_from(&argv(&["oc-tui", "--cli", "chat", "ABCD"])),
            argv(&["oc", "chat", "ABCD"])
        );
        assert_eq!(cli_args_from(&argv(&["oc-tui"])), argv(&["oc"]));
    }
}

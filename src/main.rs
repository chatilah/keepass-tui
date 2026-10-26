use std::{
    fs::{self, File},
    io::{self, Write},
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{anyhow, bail, Context, Result};
use arboard::Clipboard;
use base64::Engine;
use clap::Parser;
use crossterm::{
    event::{
        self, EnableMouseCapture, Event, KeyCode, KeyEvent, KeyModifiers, MouseButton, MouseEvent,
        MouseEventKind,
    },
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use hmac::{Hmac, Mac};
use keepass_rs::{
    open_database, save_database, CompositeKey, Database, Entry, IconImage, IconImageStandard,
    NodeId, ProtectedString,
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Text},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap},
    Frame, Terminal,
};
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use tempfile::NamedTempFile;
use url::Url;
use zeroize::{Zeroize, Zeroizing};

#[derive(Debug, Parser)]
#[command(about = "Browse KeePass KDBX databases in a terminal.")]
struct Args {
    #[arg(value_name = "DATABASE")]
    database: PathBuf,
    #[arg(short, long, value_name = "KEYFILE")]
    keyfile: Option<PathBuf>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ItemKind {
    Group,
    Entry,
}

#[derive(Clone, Debug)]
struct BrowserItem {
    kind: ItemKind,
    id: NodeId,
    title: String,
    subtitle: String,
    icon: String,
}

#[derive(Default)]
struct EntryForm {
    values: [String; 5],
    active: usize,
}

impl Drop for EntryForm {
    fn drop(&mut self) {
        self.values[2].zeroize();
    }
}

#[derive(Default)]
struct PathForm {
    value: String,
}

#[derive(Default)]
enum InputMode {
    #[default]
    Browse,
    Menu {
        menu: usize,
        selected: usize,
    },
    Search,
    Help,
    About,
    AddEntry(EntryForm),
    AddAttachment(PathForm),
}

#[derive(Clone, Copy)]
enum MenuAction {
    Quit,
    Search,
    Parent,
    FirstItem,
    LastItem,
    PreviousPage,
    NextPage,
    AddEntry,
    AddAttachment,
    TogglePassword,
    GeneralTab,
    AttachmentsTab,
    DetailsTab,
    CopyUsername,
    CopyPassword,
    CopyUrl,
    CopyTotp,
    Help,
    About,
}

#[derive(Clone, Copy)]
struct MenuItem {
    label: &'static str,
    shortcut: &'static str,
    action: MenuAction,
}

const MENU_LABELS: [&str; 4] = ["File", "Navigate", "Entry", "Help"];

/// Represents the state of the application.
struct App {
    database: Database,
    database_path: PathBuf,
    key: CompositeKey,
    current_group: NodeId,
    group_history: Vec<(NodeId, usize)>,
    query: String,
    previous_query: String,
    selected: usize,
    reveal_password: bool,
    details_focused: bool,
    detail_tab: usize,
    mode: InputMode,
    status: String,
    page_repeat_direction: Option<bool>,
    page_repeat_count: usize,
    last_page_key: SystemTime,
}

/// Parses arguments, opens the KeePass database, and runs the application.
fn main() -> Result<()> {
    let args = Args::parse();

    // Validate database and keyfile paths
    if !args.database.is_file() {
        bail!("Database file not found: {}", args.database.display());
    }

    // Validate keyfile path if provided
    if let Some(keyfile) = &args.keyfile {
        if !keyfile.is_file() {
            bail!("Keyfile not found: {}", keyfile.display());
        }
    }

    // Prompt for the master password
    let password = Zeroizing::new(
        rpassword::prompt_password("Master password: ")
            .context("Could not read master password")?,
    );

    // Create the composite key using the password and optional keyfile
    let key = make_key(password.as_bytes(), args.keyfile.as_deref())?;

    // Open the KeePass database with the provided key
    let database = open_database(File::open(&args.database)?, &key)
        .context("Could not open KeePass database")?;

    // Ensure the database has a root group
    let current_group = database
        .root_group_id
        .context("KeePass database has no root group")?;

    // Initialize the application state
    let mut app = App {
        database,
        database_path: args.database,
        key,
        current_group,
        group_history: Vec::new(),
        query: String::new(),
        previous_query: String::new(),
        selected: 0,
        reveal_password: false,
        details_focused: false,
        detail_tab: 0,
        mode: InputMode::Browse,
        status: String::new(),
        page_repeat_direction: None,
        page_repeat_count: 0,
        last_page_key: SystemTime::UNIX_EPOCH,
    };

    // Run the main application loop
    run_app(&mut app)
}

fn make_key(password: &[u8], keyfile: Option<&Path>) -> Result<CompositeKey> {
    let mut key = CompositeKey::new().with_password(password);
    if let Some(path) = keyfile {
        let contents = fs::read(path)
            .with_context(|| format!("Could not read keyfile: {}", path.display()))?;
        key = key.with_key_file(&decode_keyfile(&contents)?);
    }
    Ok(key)
}

fn decode_keyfile(contents: &[u8]) -> Result<Vec<u8>> {
    let trimmed = contents
        .strip_prefix(&[0xef, 0xbb, 0xbf])
        .unwrap_or(contents)
        .to_vec();
    let text = std::str::from_utf8(&trimmed).ok().map(str::trim);
    if let Some(text) = text {
        if let Some(start) = text.find("<Data") {
            let data_start = text[start..]
                .find('>')
                .map(|index| start + index + 1)
                .ok_or_else(|| anyhow!("Malformed XML keyfile"))?;
            let data_end = text[data_start..]
                .find("</Data>")
                .map(|index| data_start + index)
                .ok_or_else(|| anyhow!("Malformed XML keyfile"))?;
            let encoded = text[data_start..data_end]
                .bytes()
                .filter(|byte| !byte.is_ascii_whitespace())
                .collect::<Vec<_>>();
            if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(&encoded) {
                if decoded.len() == 32 {
                    return Ok(decoded);
                }
            }
            if encoded.len() == 64 && encoded.iter().all(u8::is_ascii_hexdigit) {
                return hex::decode(encoded).context("Malformed hexadecimal XML keyfile");
            }
            bail!("Unsupported XML keyfile data");
        }
        if text.len() == 64 && text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return hex::decode(text).context("Malformed hexadecimal keyfile");
        }
    }
    Ok(trimmed)
}

fn run_app(app: &mut App) -> Result<()> {
    enable_raw_mode().context("Could not enable raw terminal mode")?;
    let mut stdout = io::stdout();
    if let Err(error) = execute!(stdout, EnterAlternateScreen, EnableMouseCapture) {
        let _ = disable_raw_mode();
        return Err(error).context("Could not enter alternate screen");
    }

    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend).context("Could not initialize terminal")?;
    let result = event_loop(&mut terminal, app);
    let mouse_result = execute!(
        terminal.backend_mut(),
        crossterm::event::DisableMouseCapture,
        LeaveAlternateScreen
    );
    let raw_mode_result = disable_raw_mode();
    let cursor_result = terminal.show_cursor();
    result?;
    mouse_result.context("Could not leave alternate screen")?;
    raw_mode_result.context("Could not restore terminal mode")?;
    cursor_result.context("Could not restore cursor")?;
    Ok(())
}

fn event_loop(terminal: &mut Terminal<CrosstermBackend<io::Stdout>>, app: &mut App) -> Result<()> {
    loop {
        let items = current_items(&app.database, app.current_group, &app.query);
        app.selected = app.selected.min(items.len().saturating_sub(1));
        terminal.draw(|frame| draw(frame, app, &items))?;

        if !event::poll(Duration::from_millis(250))? {
            continue;
        }
        match event::read()? {
            Event::Key(key) => {
                if handle_key(app, &items, key)? {
                    return Ok(());
                }
            }
            Event::Mouse(mouse) => {
                let size = terminal.size()?;
                let area = Rect::new(0, 0, size.width, size.height);
                if handle_mouse(app, &items, mouse, area)? {
                    return Ok(());
                }
            }
            _ => {}
        }
    }
}

fn current_items(database: &Database, group_id: NodeId, query: &str) -> Vec<BrowserItem> {
    let Some(group) = database.get_group(&group_id) else {
        return Vec::new();
    };
    let query = query.to_lowercase();
    let mut items = Vec::new();
    for id in &group.child_group_ids {
        let Some(child) = database.get_group(id) else {
            continue;
        };
        if query.is_empty() || child.title.to_lowercase().contains(&query) {
            items.push(BrowserItem {
                kind: ItemKind::Group,
                id: *id,
                title: format!("[+] {}", empty_or(&child.title, "(unnamed group)")),
                subtitle: format!(
                    "{} folders, {} entries",
                    child.child_group_ids.len(),
                    child.child_entry_ids.len()
                ),
                icon: String::new(),
            });
        }
    }
    for id in &group.child_entry_ids {
        let Some(entry) = database.get_entry(id) else {
            continue;
        };
        let title = resolve_field(database, entry, &entry.title);
        let username = resolve_field(database, entry, entry.username.as_str());
        let url = resolve_field(database, entry, &entry.url);
        let notes = resolve_field(database, entry, entry.notes.as_str());
        if query.is_empty()
            || [
                title.as_str(),
                username.as_str(),
                url.as_str(),
                notes.as_str(),
            ]
            .iter()
            .any(|value| value.to_lowercase().contains(&query))
        {
            items.push(BrowserItem {
                kind: ItemKind::Entry,
                id: *id,
                title: empty_or(&title, "(untitled)").to_string(),
                subtitle: empty_or(&username, "(no username)").to_string(),
                icon: icon_glyph(&entry.icon, entry.custom_icon_uuid.is_some()),
            });
        }
    }
    items
}

fn resolve_field(database: &Database, current: &Entry, value: &str) -> String {
    let mut resolved = value.to_string();
    let mut replacements = 0;
    let mut search_from = 0;
    while let Some(start) = resolved[search_from..].find("{REF:") {
        let start = search_from + start;
        let Some(relative_end) = resolved[start..].find('}') else {
            break;
        };
        let end = start + relative_end + 1;
        let reference = &resolved[start..end];
        let replacement = resolve_reference(database, current, reference);
        if replacement == reference {
            search_from = end;
            continue;
        }
        if replacements >= 8 {
            break;
        }
        resolved.replace_range(start..end, &replacement);
        replacements += 1;
        search_from = start + replacement.len();
    }
    resolved
}

fn resolve_reference(database: &Database, current: &Entry, reference: &str) -> String {
    let Some(inner) = reference
        .strip_prefix("{REF:")
        .and_then(|value| value.strip_suffix('}'))
    else {
        return reference.to_string();
    };
    let Some((target, search)) = inner.split_once('@') else {
        return reference.to_string();
    };
    let Some((search_field, search_value)) = search.split_once(':') else {
        return reference.to_string();
    };
    let Some((search_code, target_code)) = (|| {
        Some((
            search_field.chars().next()?.to_ascii_uppercase(),
            target.chars().next()?.to_ascii_uppercase(),
        ))
    })() else {
        return reference.to_string();
    };
    let search_uuid = search_value.replace('-', "");
    let target_entry = database.entries.values().find(|entry| match search_code {
        'I' => entry
            .id
            .as_uuid()
            .is_some_and(|uuid| uuid.simple().to_string().eq_ignore_ascii_case(&search_uuid)),
        'T' => entry.title.eq_ignore_ascii_case(search_value),
        'U' => entry.username.as_str().eq_ignore_ascii_case(search_value),
        'P' => entry.password.as_str().eq_ignore_ascii_case(search_value),
        'A' => entry.url.eq_ignore_ascii_case(search_value),
        'N' => entry.notes.as_str().eq_ignore_ascii_case(search_value),
        _ => false,
    });
    let Some(target_entry) = target_entry else {
        return reference.to_string();
    };
    match target_code {
        'T' => target_entry.title.clone(),
        'U' => target_entry.username.as_str().to_string(),
        'P' => target_entry.password.as_str().to_string(),
        'A' => target_entry.url.clone(),
        'N' => target_entry.notes.as_str().to_string(),
        'I' => target_entry
            .id
            .as_uuid()
            .map(|uuid| uuid.to_string())
            .unwrap_or_default(),
        'O' => current
            .id
            .as_uuid()
            .map(|uuid| uuid.to_string())
            .unwrap_or_default(),
        _ => reference.to_string(),
    }
}

fn menu_items(menu: usize) -> &'static [MenuItem] {
    const FILE: [MenuItem; 1] = [MenuItem {
        label: "Quit",
        shortcut: "q",
        action: MenuAction::Quit,
    }];
    const NAVIGATE: [MenuItem; 6] = [
        MenuItem {
            label: "Search",
            shortcut: "/",
            action: MenuAction::Search,
        },
        MenuItem {
            label: "Parent group",
            shortcut: "Esc",
            action: MenuAction::Parent,
        },
        MenuItem {
            label: "First item",
            shortcut: "Home",
            action: MenuAction::FirstItem,
        },
        MenuItem {
            label: "Last item",
            shortcut: "End",
            action: MenuAction::LastItem,
        },
        MenuItem {
            label: "Previous page",
            shortcut: "Page Up",
            action: MenuAction::PreviousPage,
        },
        MenuItem {
            label: "Next page",
            shortcut: "Page Down",
            action: MenuAction::NextPage,
        },
    ];
    const ENTRY: [MenuItem; 10] = [
        MenuItem {
            label: "Add entry",
            shortcut: "a",
            action: MenuAction::AddEntry,
        },
        MenuItem {
            label: "Add attachment",
            shortcut: "2, a",
            action: MenuAction::AddAttachment,
        },
        MenuItem {
            label: "Reveal / hide password",
            shortcut: "p",
            action: MenuAction::TogglePassword,
        },
        MenuItem {
            label: "General tab",
            shortcut: "1",
            action: MenuAction::GeneralTab,
        },
        MenuItem {
            label: "Attachments tab",
            shortcut: "2",
            action: MenuAction::AttachmentsTab,
        },
        MenuItem {
            label: "Details tab",
            shortcut: "3",
            action: MenuAction::DetailsTab,
        },
        MenuItem {
            label: "Copy username",
            shortcut: "u",
            action: MenuAction::CopyUsername,
        },
        MenuItem {
            label: "Copy password",
            shortcut: "w",
            action: MenuAction::CopyPassword,
        },
        MenuItem {
            label: "Copy URL",
            shortcut: "l",
            action: MenuAction::CopyUrl,
        },
        MenuItem {
            label: "Copy TOTP",
            shortcut: "t",
            action: MenuAction::CopyTotp,
        },
    ];
    const HELP: [MenuItem; 2] = [
        MenuItem {
            label: "Keyboard shortcuts",
            shortcut: "?",
            action: MenuAction::Help,
        },
        MenuItem {
            label: "About",
            shortcut: "",
            action: MenuAction::About,
        },
    ];
    match menu {
        0 => &FILE,
        1 => &NAVIGATE,
        2 => &ENTRY,
        _ => &HELP,
    }
}

fn menu_bar_item_x(menu: usize) -> u16 {
    let preceding_width = MENU_LABELS[..menu]
        .iter()
        .map(|label| label.len() as u16 + 4)
        .sum::<u16>();
    1 + preceding_width
}

fn menu_index_at(column: u16) -> Option<usize> {
    MENU_LABELS.iter().enumerate().find_map(|(menu, label)| {
        let start = menu_bar_item_x(menu);
        (column >= start && column < start + label.len() as u16 + 2).then_some(menu)
    })
}

fn menu_popup_rect(menu: usize, area: Rect) -> Option<Rect> {
    let items = menu_items(menu);
    let width = items
        .iter()
        .map(|item| item.label.len() + item.shortcut.len() + 5)
        .max()
        .unwrap_or(16)
        .min(area.width.saturating_sub(2) as usize) as u16;
    let height = (items.len() as u16 + 2).min(area.height.saturating_sub(3));
    if width == 0 || height <= 2 {
        return None;
    }
    let x = menu_bar_item_x(menu).min(area.width.saturating_sub(width));
    Some(Rect::new(area.x + x, area.y + 2, width, height))
}

fn content_panes(area: Rect) -> [Rect; 2] {
    let outer = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(5),
            Constraint::Length(1),
        ])
        .split(area);
    let content = if area.width < 80 {
        Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Percentage(55), Constraint::Min(5)])
            .split(outer[1])
    } else {
        Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(38), Constraint::Min(25)])
            .split(outer[1])
    };
    [content[0], content[1]]
}

fn handle_mouse(
    app: &mut App,
    items: &[BrowserItem],
    mouse: MouseEvent,
    area: Rect,
) -> Result<bool> {
    if !matches!(
        mouse.kind,
        MouseEventKind::Down(MouseButton::Left)
            | MouseEventKind::ScrollUp
            | MouseEventKind::ScrollDown
    ) {
        return Ok(false);
    }

    if matches!(&app.mode, InputMode::Browse | InputMode::Menu { .. })
        && mouse.kind == MouseEventKind::Down(MouseButton::Left)
        && mouse.row == area.y + 1
    {
        if let Some(menu) = menu_index_at(mouse.column.saturating_sub(area.x)) {
            app.mode = InputMode::Menu { menu, selected: 0 };
            return Ok(false);
        }
    }

    if matches!(app.mode, InputMode::Menu { .. }) {
        if let InputMode::Menu { menu, .. } = &app.mode {
            let menu = *menu;
            if let Some(popup) = menu_popup_rect(menu, area) {
                if mouse.column >= popup.x
                    && mouse.column < popup.x + popup.width
                    && mouse.row > popup.y
                    && mouse.row < popup.y + popup.height - 1
                {
                    let selected = (mouse.row - popup.y - 1) as usize;
                    if let InputMode::Menu {
                        selected: active, ..
                    } = &mut app.mode
                    {
                        *active = selected;
                    }
                    if mouse.kind == MouseEventKind::Down(MouseButton::Left) {
                        return activate_menu_item(app, items, menu_items(menu)[selected].action);
                    }
                    return Ok(false);
                }
            }
        }
        if mouse.kind == MouseEventKind::Down(MouseButton::Left) {
            app.mode = InputMode::Browse;
        } else {
            return Ok(false);
        }
    } else if !matches!(app.mode, InputMode::Browse) {
        return Ok(false);
    }

    let list = content_panes(area)[0];
    match mouse.kind {
        MouseEventKind::Down(MouseButton::Left)
            if mouse.column >= list.x
                && mouse.column < list.x + list.width
                && mouse.row > list.y
                && mouse.row < list.y + list.height - 1 =>
        {
            let visible = usize::from(list.height.saturating_sub(2) / 2).max(1);
            let offset = app.selected.saturating_sub(visible.saturating_sub(1));
            let clicked = offset + usize::from(mouse.row - list.y - 1) / 2;
            if clicked < items.len() {
                app.selected = clicked;
                clear_focus(app);
            }
        }
        MouseEventKind::ScrollUp => {
            app.selected = app.selected.saturating_sub(3);
            clear_focus(app);
        }
        MouseEventKind::ScrollDown => {
            app.selected = app
                .selected
                .saturating_add(3)
                .min(items.len().saturating_sub(1));
            clear_focus(app);
        }
        _ => {}
    }
    Ok(false)
}

fn activate_menu_item(app: &mut App, items: &[BrowserItem], action: MenuAction) -> Result<bool> {
    app.mode = InputMode::Browse;
    match action {
        MenuAction::Quit => return Ok(true),
        MenuAction::Search => {
            app.previous_query = app.query.clone();
            app.query.clear();
            app.selected = 0;
            app.mode = InputMode::Search;
        }
        MenuAction::Parent => {
            if let Some((group, selected)) = app.group_history.pop() {
                app.current_group = group;
                app.selected = selected;
                app.query.clear();
                app.detail_tab = 0;
                clear_focus(app);
            }
        }
        MenuAction::FirstItem | MenuAction::LastItem => {
            app.selected = if matches!(action, MenuAction::FirstItem) {
                0
            } else {
                items.len().saturating_sub(1)
            };
            clear_focus(app);
        }
        MenuAction::PreviousPage | MenuAction::NextPage => {
            let down = matches!(action, MenuAction::NextPage);
            let step = accelerated_step(app, down, items.len(), 8);
            if down {
                app.selected = app
                    .selected
                    .saturating_add(step)
                    .min(items.len().saturating_sub(1));
            } else {
                app.selected = app.selected.saturating_sub(step);
            }
            clear_focus(app);
        }
        MenuAction::AddEntry => app.mode = InputMode::AddEntry(EntryForm::default()),
        MenuAction::AddAttachment => {
            if items
                .get(app.selected)
                .is_some_and(|item| item.kind == ItemKind::Entry)
            {
                app.mode = InputMode::AddAttachment(PathForm::default());
            } else {
                app.status = "Select an entry first.".to_string();
            }
        }
        MenuAction::TogglePassword => {
            if items
                .get(app.selected)
                .is_some_and(|item| item.kind == ItemKind::Entry)
            {
                app.reveal_password = !app.reveal_password;
            } else {
                app.status = "Select an entry first.".to_string();
            }
        }
        MenuAction::GeneralTab | MenuAction::AttachmentsTab | MenuAction::DetailsTab => {
            if items
                .get(app.selected)
                .is_some_and(|item| item.kind == ItemKind::Entry)
            {
                app.detail_tab = match action {
                    MenuAction::GeneralTab => 0,
                    MenuAction::AttachmentsTab => 1,
                    _ => 2,
                };
                app.details_focused = true;
            } else {
                app.status = "Select an entry first.".to_string();
            }
        }
        MenuAction::CopyUsername
        | MenuAction::CopyPassword
        | MenuAction::CopyUrl
        | MenuAction::CopyTotp => {
            let code = match action {
                MenuAction::CopyUsername => 'u',
                MenuAction::CopyPassword => 'w',
                MenuAction::CopyUrl => 'l',
                _ => 't',
            };
            if let Some(item) = items
                .get(app.selected)
                .filter(|item| item.kind == ItemKind::Entry)
            {
                if let Err(error) = copy_entry_value(app, item.id, KeyCode::Char(code)) {
                    app.status = format!("Copy failed: {error:#}");
                }
            } else {
                app.status = "Select an entry first.".to_string();
            }
        }
        MenuAction::Help => app.mode = InputMode::Help,
        MenuAction::About => app.mode = InputMode::About,
    }
    Ok(false)
}

fn draw(frame: &mut Frame<'_>, app: &App, items: &[BrowserItem]) {
    let area = frame.area();
    let outer = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(5),
            Constraint::Length(1),
        ])
        .split(area);
    let header = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(1), Constraint::Length(2)])
        .split(outer[0]);
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            "KEEPASS TUI".into(),
            format!("  {}", group_path(&app.database, app.current_group)).into(),
        ])),
        header[0],
    );
    let menu_mode = match &app.mode {
        InputMode::Menu { menu, .. } => Some(*menu),
        _ => None,
    };
    let mut menu_spans = Vec::new();
    menu_spans.push(" ".into());
    for (index, label) in MENU_LABELS.iter().enumerate() {
        let style = if menu_mode == Some(index) {
            Style::default().add_modifier(Modifier::REVERSED | Modifier::BOLD)
        } else {
            Style::default().add_modifier(Modifier::BOLD)
        };
        menu_spans.push(ratatui::text::Span::styled(format!(" {label} "), style));
        menu_spans.push("  ".into());
    }
    frame.render_widget(
        Paragraph::new(Line::from(menu_spans)).block(Block::default().borders(Borders::BOTTOM)),
        header[1],
    );

    let panes = content_panes(area);
    let list_items = items
        .iter()
        .map(|item| {
            let title = if item.kind == ItemKind::Entry && !item.icon.is_empty() {
                format!("{}  {}", item.icon, item.title)
            } else {
                item.title.clone()
            };
            ListItem::new(Text::from(vec![
                Line::from(title),
                Line::from(format!("  {}", item.subtitle)),
            ]))
        })
        .collect::<Vec<_>>();
    let mut list_state = ListState::default();
    if !items.is_empty() {
        list_state.select(Some(app.selected));
    }
    let list_title = format!("CONTENTS  {}", items.len());
    let list = List::new(list_items)
        .block(Block::default().title(list_title).borders(Borders::ALL))
        .highlight_style(Style::default().add_modifier(Modifier::REVERSED | Modifier::BOLD))
        .highlight_symbol("› ");
    frame.render_stateful_widget(list, panes[0], &mut list_state);

    if let Some(item) = items.get(app.selected) {
        let details = item_details(&app.database, item, app.reveal_password, app.detail_tab);
        let title = if app.details_focused {
            "DETAILS  [FOCUSED]"
        } else {
            "DETAILS"
        };
        frame.render_widget(
            Paragraph::new(details)
                .block(Block::default().title(title).borders(Borders::ALL))
                .wrap(Wrap { trim: false }),
            panes[1],
        );
    } else {
        frame.render_widget(
            Paragraph::new(if app.query.is_empty() {
                "This group is empty"
            } else {
                "No matching items"
            })
            .block(Block::default().title("DETAILS").borders(Borders::ALL)),
            panes[1],
        );
    }

    let footer = match &app.mode {
        InputMode::Menu { .. } => {
            "Menu: ←/→ choose | ↑/↓ move | Enter select | Esc close | F10 toggle".to_string()
        }
        InputMode::Search => format!("Search: {}_", app.query),
        InputMode::Help => "Press ? or Esc to return.".to_string(),
        InputMode::About => "Press Enter or Esc to close.".to_string(),
        InputMode::AddEntry(form) => format!(
            "ADD ENTRY  {}: {}",
            ["Title", "Username", "Password", "URL", "Notes"][form.active],
            if form.active == 2 {
                "*".repeat(form.values[2].len())
            } else {
                form.values[form.active].clone()
            }
        ),
        InputMode::AddAttachment(form) => format!("Attachment path: {}_", form.value),
        InputMode::Browse => {
            if app.status.is_empty() {
                "j/k or arrows navigate | Enter open | a add | q quit | Passwords hidden by default"
                    .to_string()
            } else {
                app.status.clone()
            }
        }
    };
    frame.render_widget(
        Paragraph::new(footer).style(Style::default().add_modifier(Modifier::DIM)),
        outer[2],
    );

    if let InputMode::Menu { menu, selected } = &app.mode {
        let menu_items = menu_items(*menu);
        if let Some(popup) = menu_popup_rect(*menu, area) {
            let list_items = menu_items
                .iter()
                .map(|item| {
                    ListItem::new(format!(
                        "{:<width$} {}",
                        item.label,
                        item.shortcut,
                        width = (popup.width as usize).saturating_sub(item.shortcut.len() + 4)
                    ))
                })
                .collect::<Vec<_>>();
            let mut list_state = ListState::default();
            list_state.select(Some(*selected));
            frame.render_widget(ratatui::widgets::Clear, popup);
            frame.render_stateful_widget(
                List::new(list_items)
                    .block(Block::default().borders(Borders::ALL))
                    .highlight_style(
                        Style::default().add_modifier(Modifier::REVERSED | Modifier::BOLD),
                    )
                    .highlight_symbol("› "),
                popup,
                &mut list_state,
            );
        }
    }

    if matches!(app.mode, InputMode::Help) {
        let help_area = centered_rect(76, 80, area);
        let lines = [
            "F10                    Open / close menu bar",
            "Menu arrows / Enter    Choose and activate menu items",
            "j / Down, k / Up       Move selection",
            "Home / End             Jump to first / last item",
            "Page Up / Page Down    Move by page; repeated presses accelerate",
            "Alt+Up / Down          Jump to first / last item",
            "Enter                  Open group / focus details",
            "Backspace / Esc        Return to parent group",
            "/                      Search current group",
            "a                      Add an entry",
            "1 / 2 / 3              General / Attachments / Details",
            "2 then a               Attach a file to selected entry",
            "p                      Reveal / hide password",
            "u / w / l / t          Copy username / password / URL / TOTP",
            "q                      Quit",
        ];
        let help = Paragraph::new(lines.join("\n"))
            .block(
                Block::default()
                    .title("KEYBOARD SHORTCUTS")
                    .borders(Borders::ALL),
            )
            .wrap(Wrap { trim: false });
        frame.render_widget(ratatui::widgets::Clear, help_area);
        frame.render_widget(help, help_area);
    }
    if matches!(app.mode, InputMode::About) {
        let about_area = centered_rect(60, 35, area);
        let about = Paragraph::new(format!(
            "KeePass TUI\n\nVersion: {}\nCommit: {}\nPlatform: {}\n\nPress Enter or Esc to close.",
            env!("CARGO_PKG_VERSION"),
            env!("KEEPASS_TUI_COMMIT"),
            env!("KEEPASS_TUI_TARGET"),
        ))
        .block(Block::default().title("ABOUT").borders(Borders::ALL))
        .wrap(Wrap { trim: false });
        frame.render_widget(ratatui::widgets::Clear, about_area);
        frame.render_widget(about, about_area);
    }
    match &app.mode {
        InputMode::AddEntry(form) => {
            let fields = ["Title", "Username", "Password", "URL", "Notes"];
            let lines = fields
                .iter()
                .enumerate()
                .map(|(index, field)| {
                    let marker = if index == form.active { ">" } else { " " };
                    let value = if index == 2 {
                        "*".repeat(form.values[index].len())
                    } else {
                        form.values[index].clone()
                    };
                    format!("{marker} {field}: {value}")
                })
                .collect::<Vec<_>>();
            let form_area = centered_rect(72, 65, area);
            frame.render_widget(ratatui::widgets::Clear, form_area);
            frame.render_widget(
                Paragraph::new(lines.join("\n"))
                    .block(Block::default().title("ADD ENTRY").borders(Borders::ALL))
                    .wrap(Wrap { trim: false }),
                form_area,
            );
        }
        InputMode::AddAttachment(form) => {
            let form_area = centered_rect(72, 30, area);
            frame.render_widget(ratatui::widgets::Clear, form_area);
            frame.render_widget(
                Paragraph::new(format!(
                    "Attachment file path:\n{}\n\nEnter to attach; Esc to cancel",
                    form.value
                ))
                .block(
                    Block::default()
                        .title("ADD ATTACHMENT")
                        .borders(Borders::ALL),
                )
                .wrap(Wrap { trim: false }),
                form_area,
            );
        }
        _ => {}
    }
}

fn item_details(
    database: &Database,
    item: &BrowserItem,
    reveal_password: bool,
    tab: usize,
) -> String {
    match item.kind {
        ItemKind::Group => {
            let Some(group) = database.get_group(&item.id) else {
                return String::new();
            };
            format!(
                "{}\n\nFolder\n{} subfolders\n{} entries\n\n{}",
                empty_or(&group.title, "(unnamed group)"),
                group.child_group_ids.len(),
                group.child_entry_ids.len(),
                group.notes
            )
        }
        ItemKind::Entry => {
            let Some(entry) = database.get_entry(&item.id) else {
                return String::new();
            };
            let resolved_title = resolve_field(database, entry, &entry.title);
            let title = empty_or(&resolved_title, "(untitled)");
            if tab == 1 {
                let attachments = entry
                    .binaries
                    .iter()
                    .map(|(name, data)| format!("{name} ({} bytes)", data.len()))
                    .collect::<Vec<_>>();
                return format!(
                    "{}\n\n1 General   [2 Attachments]   3 Details\n\n{}",
                    title,
                    if attachments.is_empty() {
                        "No attachments. Press a to add a file.".to_string()
                    } else {
                        attachments.join("\n")
                    }
                );
            }
            if tab == 2 {
                return format!(
                    "{}\n\n1 General   2 Attachments   [3 Details]\n\nID\n{}\n\nGroup\n{}\n\nTags\n{}\n\nCreated\n{:?}\n\nModified\n{:?}",
                    title,
                    entry.id.as_uuid().map(|uuid| uuid.to_string()).unwrap_or_else(|| format!("{:?}", entry.id)),
                    group_path_for_entry(database, entry.id),
                    empty_or(&entry.tags.join(", "), "(none)"),
                    entry.creation_time,
                    entry.last_modification_time
                );
            }
            let totp = totp_value(entry)
                .map(|(code, remaining)| format!("TOTP\n{code}  ({remaining}s)\n\n"))
                .unwrap_or_default();
            let password = if reveal_password {
                resolve_field(database, entry, entry.password.as_str())
            } else if entry.password.is_empty() {
                "(empty)".to_string()
            } else {
                "********  (press p to reveal)".to_string()
            };
            format!(
                "{}\n\n1 General   2 Attachments   3 Details\n\n{}Username\n{}\n\nPassword\n{}\n\nURL\n{}\n\nNotes\n{}",
                title,
                totp,
                resolve_field(database, entry, entry.username.as_str()),
                password,
                resolve_field(database, entry, &entry.url),
                resolve_field(database, entry, entry.notes.as_str())
            )
        }
    }
}

fn handle_key(app: &mut App, items: &[BrowserItem], key: KeyEvent) -> Result<bool> {
    app.status.clear();
    match std::mem::take(&mut app.mode) {
        InputMode::Menu {
            mut menu,
            mut selected,
        } => {
            match key.code {
                KeyCode::Esc | KeyCode::F(10) => app.mode = InputMode::Browse,
                KeyCode::Left => {
                    menu = (menu + MENU_LABELS.len() - 1) % MENU_LABELS.len();
                    selected = 0;
                    app.mode = InputMode::Menu { menu, selected };
                }
                KeyCode::Right => {
                    menu = (menu + 1) % MENU_LABELS.len();
                    selected = 0;
                    app.mode = InputMode::Menu { menu, selected };
                }
                KeyCode::Up => {
                    selected = (selected + menu_items(menu).len() - 1) % menu_items(menu).len();
                    app.mode = InputMode::Menu { menu, selected };
                }
                KeyCode::Down => {
                    selected = (selected + 1) % menu_items(menu).len();
                    app.mode = InputMode::Menu { menu, selected };
                }
                KeyCode::Enter => {
                    let action = menu_items(menu)[selected].action;
                    return activate_menu_item(app, items, action);
                }
                _ => app.mode = InputMode::Menu { menu, selected },
            }
            return Ok(false);
        }
        InputMode::Help => {
            if key.code == KeyCode::Esc || key.code == KeyCode::Char('?') {
                app.mode = InputMode::Browse;
            } else {
                app.mode = InputMode::Help;
            }
            return Ok(false);
        }
        InputMode::About => {
            app.mode = InputMode::About;
            if matches!(key.code, KeyCode::Enter | KeyCode::Esc) {
                app.mode = InputMode::Browse;
            }
            return Ok(false);
        }
        InputMode::Search => {
            let mut finished = false;
            match key.code {
                KeyCode::Esc => {
                    app.query = app.previous_query.clone();
                    app.selected = 0;
                    finished = true;
                }
                KeyCode::Enter => finished = true,
                KeyCode::Backspace => {
                    app.query.pop();
                    app.selected = 0;
                }
                KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    app.query.clear();
                    app.selected = 0;
                }
                KeyCode::Char(ch) if !key.modifiers.contains(KeyModifiers::CONTROL) => {
                    app.query.push(ch);
                    app.selected = 0;
                }
                _ => {}
            }
            if !finished {
                app.mode = InputMode::Search;
            }
            return Ok(false);
        }
        InputMode::AddEntry(mut form) => {
            let mut save_form = false;
            match key.code {
                KeyCode::Esc => app.mode = InputMode::Browse,
                KeyCode::Tab | KeyCode::Down => form.active = (form.active + 1) % form.values.len(),
                KeyCode::BackTab | KeyCode::Up => {
                    form.active = (form.active + form.values.len() - 1) % form.values.len()
                }
                KeyCode::Enter => {
                    if form.active < form.values.len() - 1 {
                        form.active += 1;
                    } else if form.values[0].trim().is_empty() {
                        app.status = "Title is required.".to_string();
                    } else {
                        save_form = true;
                    }
                }
                KeyCode::Backspace => {
                    form.values[form.active].pop();
                }
                KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    form.values[form.active].clear();
                }
                KeyCode::Char(ch) if !key.modifiers.contains(KeyModifiers::CONTROL) => {
                    form.values[form.active].push(ch);
                }
                _ => {}
            }
            if save_form {
                let values = std::mem::take(&mut form.values);
                if let Err(error) = add_entry(app, values) {
                    app.status = format!("Could not save entry: {error:#}");
                }
                app.mode = InputMode::Browse;
            } else if matches!(app.mode, InputMode::Browse) && key.code != KeyCode::Esc {
                app.mode = InputMode::AddEntry(form);
            }
            return Ok(false);
        }
        InputMode::AddAttachment(mut form) => {
            let mut save_attachment = false;
            match key.code {
                KeyCode::Esc => app.mode = InputMode::Browse,
                KeyCode::Enter => {
                    save_attachment = true;
                }
                KeyCode::Backspace => {
                    form.value.pop();
                }
                KeyCode::Char(ch) if !key.modifiers.contains(KeyModifiers::CONTROL) => {
                    form.value.push(ch);
                }
                _ => {}
            }
            if save_attachment {
                let path = PathBuf::from(form.value.trim()).expanduser();
                if let Some(item) = items
                    .get(app.selected)
                    .filter(|item| item.kind == ItemKind::Entry)
                {
                    if let Err(error) = add_attachment(app, item.id, &path) {
                        app.status = format!("Could not add attachment: {error:#}");
                    }
                }
                app.mode = InputMode::Browse;
            } else if matches!(app.mode, InputMode::Browse) && key.code != KeyCode::Esc {
                app.mode = InputMode::AddAttachment(form);
            }
            return Ok(false);
        }
        InputMode::Browse => {}
    }

    let modified = key.modifiers;
    let count = items.len();
    let accelerating = modified.contains(KeyModifiers::ALT)
        && modified.contains(KeyModifiers::SHIFT)
        && matches!(key.code, KeyCode::Up | KeyCode::Down);
    let paging = matches!(key.code, KeyCode::PageUp | KeyCode::PageDown);
    if !accelerating && !paging {
        app.page_repeat_direction = None;
        app.page_repeat_count = 0;
    }
    match key.code {
        KeyCode::Char('q') => return Ok(true),
        KeyCode::F(10) => {
            app.mode = InputMode::Menu {
                menu: 0,
                selected: 0,
            }
        }
        KeyCode::Char('?') => app.mode = InputMode::Help,
        KeyCode::Char('/') => {
            app.previous_query = app.query.clone();
            app.query.clear();
            app.selected = 0;
            app.mode = InputMode::Search;
        }
        KeyCode::Up if accelerating => {
            app.selected = app
                .selected
                .saturating_sub(accelerated_step(app, false, count, 1));
            clear_focus(app);
        }
        KeyCode::Down if accelerating => {
            let step = accelerated_step(app, true, count, 1);
            app.selected = app
                .selected
                .saturating_add(step)
                .min(count.saturating_sub(1));
            clear_focus(app);
        }
        KeyCode::Up if modified.contains(KeyModifiers::ALT) => {
            app.selected = 0;
            clear_focus(app);
        }
        KeyCode::Down if modified.contains(KeyModifiers::ALT) => {
            app.selected = count.saturating_sub(1);
            clear_focus(app);
        }
        KeyCode::Char('j') | KeyCode::Down => {
            app.selected = app.selected.saturating_add(1).min(count.saturating_sub(1));
            clear_focus(app);
        }
        KeyCode::Char('k') | KeyCode::Up => {
            app.selected = app.selected.saturating_sub(1);
            clear_focus(app);
        }
        KeyCode::Home => {
            app.selected = 0;
            clear_focus(app);
        }
        KeyCode::End => {
            app.selected = count.saturating_sub(1);
            clear_focus(app);
        }
        KeyCode::PageUp | KeyCode::PageDown => {
            let down = key.code == KeyCode::PageDown;
            let step = accelerated_step(app, down, count, 8);
            if down {
                app.selected = app
                    .selected
                    .saturating_add(step)
                    .min(count.saturating_sub(1));
            } else {
                app.selected = app.selected.saturating_sub(step);
            }
            clear_focus(app);
        }
        KeyCode::Enter => {
            if let Some(item) = items.get(app.selected) {
                if item.kind == ItemKind::Group {
                    app.group_history.push((app.current_group, app.selected));
                    app.current_group = item.id;
                    app.query.clear();
                    app.selected = 0;
                    app.detail_tab = 0;
                    clear_focus(app);
                } else {
                    app.details_focused = true;
                }
            }
        }
        KeyCode::Esc | KeyCode::Backspace => {
            if let Some((group, selected)) = app.group_history.pop() {
                app.current_group = group;
                app.selected = selected;
                app.query.clear();
                app.detail_tab = 0;
                clear_focus(app);
            }
        }
        KeyCode::Char(ch @ ('1' | '2' | '3')) => {
            if items
                .get(app.selected)
                .is_some_and(|item| item.kind == ItemKind::Entry)
            {
                app.detail_tab = (ch as usize) - ('1' as usize);
                app.details_focused = true;
            }
        }
        KeyCode::Char('p') => {
            if items
                .get(app.selected)
                .is_some_and(|item| item.kind == ItemKind::Entry)
            {
                app.reveal_password = !app.reveal_password;
            } else {
                app.status = "Select an entry first.".to_string();
            }
        }
        KeyCode::Char('u' | 'w' | 'l' | 't') => {
            if let Some(item) = items
                .get(app.selected)
                .filter(|item| item.kind == ItemKind::Entry)
            {
                if let Err(error) = copy_entry_value(app, item.id, key.code) {
                    app.status = format!("Copy failed: {error:#}");
                }
            }
        }
        KeyCode::Char('a') => {
            if app.detail_tab == 1
                && items
                    .get(app.selected)
                    .is_some_and(|item| item.kind == ItemKind::Entry)
            {
                app.mode = InputMode::AddAttachment(PathForm::default());
            } else {
                app.mode = InputMode::AddEntry(EntryForm::default());
            }
        }
        _ => {}
    }
    Ok(false)
}

fn add_entry(app: &mut App, mut values: [String; 5]) -> Result<()> {
    let mut entry = Entry::new(NodeId::new_uuid());
    entry.title = values[0].trim().to_string();
    entry.username = ProtectedString::new_protected(&values[1]);
    let password = Zeroizing::new(std::mem::take(&mut values[2]));
    entry.password = ProtectedString::new_protected(password.as_str());
    entry.url = values[3].clone();
    entry.notes = ProtectedString::new_protected(&values[4]);
    let id = entry.id;
    if !app.database.add_entry(entry, &app.current_group) {
        bail!("Could not add entry to the current group");
    }
    if let Err(error) = save_database_to_path(&mut app.database, &app.database_path, &app.key) {
        app.database.remove_entry(&id, false);
        return Err(error);
    }
    app.query.clear();
    app.selected = app
        .database
        .get_group(&app.current_group)
        .map(|group| group.child_group_ids.len() + group.child_entry_ids.len() - 1)
        .unwrap_or(0);
    app.detail_tab = 0;
    app.reveal_password = false;
    app.details_focused = false;
    app.status = format!(
        "Entry added ({})",
        id.as_uuid()
            .map(|uuid| uuid.to_string())
            .unwrap_or_default()
    );
    Ok(())
}

fn add_attachment(app: &mut App, entry_id: NodeId, path: &Path) -> Result<()> {
    if !path.is_file() {
        bail!("Attachment file not found: {}", path.display());
    }
    let filename = path
        .file_name()
        .and_then(|name| name.to_str())
        .context("Attachment path has no valid filename")?
        .to_string();
    let data =
        fs::read(path).with_context(|| format!("Could not read attachment: {}", path.display()))?;
    let entry = app
        .database
        .get_entry_mut(&entry_id)
        .context("Selected entry no longer exists")?;
    entry.binaries.push((filename.clone(), data));
    app.database.mark_modified();
    if let Err(error) = save_database_to_path(&mut app.database, &app.database_path, &app.key) {
        if let Some(entry) = app.database.get_entry_mut(&entry_id) {
            entry.binaries.pop();
        }
        return Err(error);
    }
    app.status = format!("Attached {filename}.");
    Ok(())
}

fn save_database_to_path(database: &mut Database, path: &Path, key: &CompositeKey) -> Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut temporary =
        NamedTempFile::new_in(parent).context("Could not create temporary database file")?;
    save_database(&mut temporary, database, key).context("Could not save KeePass database")?;
    temporary
        .flush()
        .context("Could not flush KeePass database")?;
    temporary
        .persist(path)
        .map_err(|error| error.error)
        .context("Could not replace KeePass database")?;
    Ok(())
}

fn copy_entry_value(app: &mut App, id: NodeId, key: KeyCode) -> Result<()> {
    let entry = app
        .database
        .get_entry(&id)
        .context("Selected entry no longer exists")?;
    let (value, field) = match key {
        KeyCode::Char('u') => (
            resolve_field(&app.database, entry, entry.username.as_str()),
            "username",
        ),
        KeyCode::Char('w') => (
            resolve_field(&app.database, entry, entry.password.as_str()),
            "password",
        ),
        KeyCode::Char('l') => (resolve_field(&app.database, entry, &entry.url), "URL"),
        KeyCode::Char('t') => {
            let (code, _) =
                totp_value(entry).context("Selected entry has no valid TOTP configured")?;
            (code, "TOTP")
        }
        _ => return Ok(()),
    };
    if value.is_empty() {
        bail!("Selected entry has no {field} value");
    }
    Clipboard::new()
        .context("Could not access system clipboard")?
        .set_text(value)
        .context("Could not copy to system clipboard")?;
    app.status = format!("Copied {field} to clipboard.");
    Ok(())
}

fn accelerated_step(app: &mut App, down: bool, count: usize, base_step: usize) -> usize {
    let now = SystemTime::now();
    if app.page_repeat_direction == Some(down)
        && now.duration_since(app.last_page_key).unwrap_or_default() <= Duration::from_millis(400)
    {
        app.page_repeat_count += 1;
    } else {
        app.page_repeat_direction = Some(down);
        app.page_repeat_count = 0;
    }
    app.last_page_key = now;
    (base_step * (app.page_repeat_count + 1)).min(count.max(1))
}

fn totp_value(entry: &Entry) -> Option<(String, u64)> {
    let otp = entry
        .get_field("otp")
        .map(|value| value.as_str().to_string());
    let mut secret = String::new();
    let mut algorithm = "SHA1".to_string();
    let mut digits = 6_u32;
    let mut period = 30_u64;
    if let Some(otp) = otp.filter(|value| !value.is_empty()) {
        if otp.starts_with("otpauth://") {
            let uri = Url::parse(&otp).ok()?;
            if uri.scheme() != "otpauth" || uri.host_str() != Some("totp") {
                return None;
            }
            for (key, value) in uri.query_pairs() {
                match key.to_ascii_lowercase().as_str() {
                    "secret" => secret = value.into_owned(),
                    "algorithm" => algorithm = value.to_ascii_uppercase(),
                    "digits" => digits = value.parse().ok()?,
                    "period" => period = value.parse().ok()?,
                    _ => {}
                }
            }
        } else {
            secret = otp;
        }
    } else {
        for field in &entry.custom_fields {
            let value = field.value.as_str();
            match field.name.to_ascii_lowercase().as_str() {
                "timeotp-secret-base32" | "totp seed" => secret = value.to_string(),
                "timeotp-algorithm" => algorithm = value.to_ascii_uppercase(),
                "timeotp-length" => digits = value.parse().ok()?,
                "timeotp-period" => period = value.parse().ok()?,
                _ => {}
            }
        }
    }
    if secret.is_empty() || !(6..=8).contains(&digits) || period == 0 {
        return None;
    }
    let key = decode_base32(&secret)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs();
    let counter = now / period;
    let code = match algorithm.as_str() {
        "SHA1" => generate_totp::<Hmac<Sha1>>(&key, counter, digits)?,
        "SHA256" => generate_totp::<Hmac<Sha256>>(&key, counter, digits)?,
        "SHA512" => generate_totp::<Hmac<Sha512>>(&key, counter, digits)?,
        _ => return None,
    };
    Some((code, period - now % period))
}

fn generate_totp<M: Mac + hmac::digest::KeyInit>(
    key: &[u8],
    counter: u64,
    digits: u32,
) -> Option<String> {
    let mut mac = <M as Mac>::new_from_slice(key).ok()?;
    mac.update(&counter.to_be_bytes());
    let digest = mac.finalize().into_bytes();
    let offset = usize::from(digest[digest.len() - 1] & 0x0f);
    let binary = u32::from(digest[offset] & 0x7f) << 24
        | u32::from(digest[offset + 1]) << 16
        | u32::from(digest[offset + 2]) << 8
        | u32::from(digest[offset + 3]);
    let modulus = 10_u32.checked_pow(digits)?;
    Some(format!(
        "{:0width$}",
        binary % modulus,
        width = digits as usize
    ))
}

fn decode_base32(value: &str) -> Option<Vec<u8>> {
    let mut output = Vec::new();
    let mut buffer = 0_u32;
    let mut bits = 0_u8;
    for byte in value
        .bytes()
        .filter(|byte| !byte.is_ascii_whitespace() && *byte != b'=')
    {
        let byte = byte.to_ascii_uppercase();
        let digit = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'2'..=b'7' => byte - b'2' + 26,
            _ => return None,
        };
        buffer = (buffer << 5) | u32::from(digit);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            output.push((buffer >> bits) as u8);
        }
    }
    Some(output)
}

fn group_path(database: &Database, group_id: NodeId) -> String {
    let mut names = Vec::new();
    let Some(root_id) = database.root_group_id else {
        return "Root".to_string();
    };
    let mut pending = vec![root_id];
    while let Some(id) = pending.pop() {
        let Some(group) = database.get_group(&id) else {
            continue;
        };
        if id == group_id {
            names.push(group.title.clone());
            return names.join(" / ");
        }
        if is_descendant(database, id, group_id) {
            names.push(group.title.clone());
            let Some(child) = group
                .child_group_ids
                .iter()
                .copied()
                .find(|child| is_descendant(database, *child, group_id))
            else {
                continue;
            };
            pending.push(child);
        }
    }
    "Root".to_string()
}

fn is_descendant(database: &Database, parent: NodeId, target: NodeId) -> bool {
    if parent == target {
        return true;
    }
    database.get_group(&parent).is_some_and(|group| {
        group
            .child_group_ids
            .iter()
            .any(|child| is_descendant(database, *child, target))
    })
}

fn group_path_for_entry(database: &Database, id: NodeId) -> String {
    fn find(
        database: &Database,
        group_id: NodeId,
        entry_id: NodeId,
        path: &mut Vec<String>,
    ) -> bool {
        let Some(group) = database.get_group(&group_id) else {
            return false;
        };
        path.push(group.title.clone());
        if group.child_entry_ids.contains(&entry_id) {
            return true;
        }
        for child in &group.child_group_ids {
            if find(database, *child, entry_id, path) {
                return true;
            }
        }
        path.pop();
        false
    }
    let mut path = Vec::new();
    if let Some(root) = database.root_group_id {
        if find(database, root, id, &mut path) {
            return path.join(" / ");
        }
    }
    "Root".to_string()
}

fn icon_glyph(icon: &IconImage, is_custom: bool) -> String {
    if is_custom {
        return "◆".to_string();
    }
    let id = match icon {
        IconImage::Standard(IconImageStandard { icon_id }) => *icon_id,
        IconImage::Custom(_) => return "◆".to_string(),
    };
    const ICONS: [&str; 69] = [
        "🔑", "🌐", "⚠", "🖥", "📌", "💬", "▦", "📝", "🌐", "🪪", "✅", "📷", "📡", "🗝", "⚡", "📷",
        "🌟", "💿", "🖥", "✉", "⚙", "☑", "🗒", "🖥", "⚠", "📥", "💾", "🗄", "❔", "🔐", ">_", "🖨",
        "📊", "🇭🇷", "🔧", "🌐", "📦", "%", "🖥", "🕒", "🔍", "⚑", "💾", "♻", "🗒", "✖", "ℹ", "📦",
        "📁", "📂", "🗂", "🔓", "🔒", "✅", "🖋", "🖼", "📖", "▤", "👤", "🔨", "🏠", "⭐", "🐧", "🪶",
        "🍎", "🌐", "$", "📜", "📱",
    ];
    ICONS.get(id as usize).unwrap_or(&"◆").to_string()
}

fn centered_rect(width_percent: u16, height_percent: u16, area: Rect) -> Rect {
    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - height_percent) / 2),
            Constraint::Percentage(height_percent),
            Constraint::Percentage((100 - height_percent) / 2),
        ])
        .split(area);
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - width_percent) / 2),
            Constraint::Percentage(width_percent),
            Constraint::Percentage((100 - width_percent) / 2),
        ])
        .split(vertical[1])[1]
}

fn clear_focus(app: &mut App) {
    app.reveal_password = false;
    app.details_focused = false;
}

fn empty_or<'a>(value: &'a str, fallback: &'a str) -> &'a str {
    if value.is_empty() {
        fallback
    } else {
        value
    }
}

trait ExpandPath {
    fn expanduser(&self) -> PathBuf;
}

impl ExpandPath for PathBuf {
    fn expanduser(&self) -> PathBuf {
        let Some(text) = self.to_str() else {
            return self.clone();
        };
        if text == "~" {
            return std::env::var_os("HOME")
                .map(PathBuf::from)
                .unwrap_or_else(|| self.clone());
        }
        if let Some(rest) = text.strip_prefix("~/") {
            if let Some(home) = std::env::var_os("HOME") {
                return PathBuf::from(home).join(rest);
            }
        }
        self.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use keepass_rs::{open_database, save_database, DatabaseVersion, EntryField, Group};

    fn test_database(version: DatabaseVersion) -> (Database, NodeId) {
        let mut database = Database::new(version);
        let root = Group::new(NodeId::new_uuid());
        let root_id = root.id;
        database.groups.insert(root_id, root);
        database.root_group_id = Some(root_id);
        (database, root_id)
    }

    #[test]
    fn test_kdbx31_round_trip_preserves_entry_and_attachment() {
        let (mut database, root_id) = test_database(DatabaseVersion::KDBX31);
        let mut entry = Entry::new(NodeId::new_uuid());
        entry.title = "Mail".to_string();
        entry.username = ProtectedString::new_protected("alice");
        entry.password = ProtectedString::new_protected("secret");
        entry
            .binaries
            .push(("note.txt".to_string(), b"contents".to_vec()));
        assert!(database.add_entry(entry, &root_id));
        let key = CompositeKey::new().with_password(b"test-password");
        let mut encoded = Vec::new();
        save_database(&mut encoded, &database, &key).unwrap();
        let reopened = open_database(encoded.as_slice(), &key).unwrap();
        let saved_entry = reopened.entries.values().next().unwrap();
        assert_eq!(saved_entry.title, "Mail");
        assert_eq!(saved_entry.username.as_str(), "alice");
        assert_eq!(saved_entry.binaries[0].1, b"contents");
    }

    #[test]
    fn test_kdbx4_round_trip_preserves_entry() {
        let (mut database, root_id) = test_database(DatabaseVersion::KDBX4);
        let mut entry = Entry::new(NodeId::new_uuid());
        entry.title = "Secure entry".to_string();
        entry.password = ProtectedString::new_protected("secret");
        assert!(database.add_entry(entry, &root_id));
        let key = CompositeKey::new().with_password(b"test-password");
        let mut encoded = Vec::new();
        save_database(&mut encoded, &database, &key).unwrap();
        let reopened = open_database(encoded.as_slice(), &key).unwrap();
        assert_eq!(
            reopened.entries.values().next().unwrap().password.as_str(),
            "secret"
        );
    }

    #[test]
    fn test_kdbx4_opens_database_written_by_keepass() {
        let password = "test-password";
        let mut reference = keepass::Database::new();
        let mut root = reference.root_mut();
        let mut reference_entry = root.add_entry();
        reference_entry.set_unprotected(keepass::db::fields::TITLE, "Interop");
        reference_entry.set_protected(keepass::db::fields::PASSWORD, "entry-secret");
        let mut encoded = Vec::new();
        reference
            .save(
                &mut encoded,
                keepass::DatabaseKey::new().with_password(password),
            )
            .unwrap();

        let key = CompositeKey::new().with_password(password.as_bytes());
        let opened = open_database(encoded.as_slice(), &key).unwrap();
        assert_eq!(opened.entries.values().next().unwrap().title, "Interop");
        assert_eq!(
            opened.entries.values().next().unwrap().password.as_str(),
            "entry-secret"
        );
    }

    #[test]
    fn test_kdbx4_opens_keepass_database_with_xml_keyfile() {
        let password = "test-password";
        let keyfile_bytes = vec![0x5a; 32];
        let keyfile_hash = hex::encode(&keepass_rs::HashEngine::sha256(&keyfile_bytes)[..4]);
        let keyfile_hex = hex::encode(&keyfile_bytes);
        let xml_keyfile = format!(
            "<KeyFile><Meta><Version>2.0</Version></Meta><Key><Data Hash=\"{keyfile_hash}\">{keyfile_hex}</Data></Key></KeyFile>"
        );

        let mut reference = keepass::Database::new();
        reference.config.compression_config = keepass::config::CompressionConfig::None;
        let mut keyfile_reader = io::Cursor::new(xml_keyfile.as_bytes());
        let reference_key = keepass::DatabaseKey::new()
            .with_password(password)
            .with_keyfile(&mut keyfile_reader)
            .unwrap();
        let mut encoded = Vec::new();
        reference.save(&mut encoded, reference_key).unwrap();

        let key = CompositeKey::new()
            .with_password(password.as_bytes())
            .with_key_file(&decode_keyfile(xml_keyfile.as_bytes()).unwrap());
        let opened = open_database(encoded.as_slice(), &key).unwrap();
        assert!(opened.root_group_id.is_some());
    }

    #[test]
    fn test_keepass_opens_kdbx4_written_by_app() {
        let (mut database, root_id) = test_database(DatabaseVersion::KDBX4);
        let mut entry = Entry::new(NodeId::new_uuid());
        entry.title = "Interop".to_string();
        entry.password = ProtectedString::new_protected("entry-secret");
        assert!(database.add_entry(entry, &root_id));
        let password = "test-password";
        let key = CompositeKey::new().with_password(password.as_bytes());
        let mut encoded = Vec::new();
        save_database(&mut encoded, &database, &key).unwrap();

        let opened = keepass::Database::open(
            &mut encoded.as_slice(),
            keepass::DatabaseKey::new().with_password(password),
        )
        .unwrap();
        assert_eq!(
            opened
                .root()
                .entries()
                .next()
                .unwrap()
                .get(keepass::db::fields::PASSWORD),
            Some("entry-secret")
        );
    }

    #[test]
    fn test_filters_group_entries_case_insensitively() {
        let (mut database, root_id) = test_database(DatabaseVersion::KDBX31);
        let mut entry = Entry::new(NodeId::new_uuid());
        entry.title = "Mail".to_string();
        entry.username = ProtectedString::new_protected("alice");
        assert!(database.add_entry(entry, &root_id));
        assert_eq!(current_items(&database, root_id, "ALICE").len(), 1);
        assert!(current_items(&database, root_id, "missing").is_empty());
    }

    #[test]
    fn test_field_references_resolve_by_uuid() {
        let (mut database, root_id) = test_database(DatabaseVersion::KDBX31);
        let mut source = Entry::new(NodeId::new_uuid());
        source.title = "Source".to_string();
        source.username = ProtectedString::new_protected("alice");
        source.password = ProtectedString::new_protected("secret");
        let source_id = source.id;
        assert!(database.add_entry(source, &root_id));
        let mut reference = Entry::new(NodeId::new_uuid());
        reference.title = "Reference".to_string();
        let source_uuid = source_id.as_uuid().unwrap();
        let field = format!("{{REF:U@I:{source_uuid}}}");
        assert_eq!(resolve_field(&database, &reference, &field), "alice");

        let unhyphenated_uuid = source_uuid.simple().to_string();
        let field = format!("{{REF:U@I:{unhyphenated_uuid}}}");
        assert_eq!(resolve_field(&database, &reference, &field), "alice");

        let field =
            format!("{{REF:U@I:00000000000000000000000000000000}} {{REF:U@I:{unhyphenated_uuid}}}");
        assert_eq!(
            resolve_field(&database, &reference, &field),
            "{REF:U@I:00000000000000000000000000000000} alice"
        );
    }

    #[test]
    fn test_menu_opens_search_without_removing_keyboard_shortcut() {
        let (database, root_id) = test_database(DatabaseVersion::KDBX31);
        let mut app = App {
            database,
            database_path: PathBuf::new(),
            key: CompositeKey::new(),
            current_group: root_id,
            group_history: Vec::new(),
            query: String::new(),
            previous_query: String::new(),
            selected: 0,
            reveal_password: false,
            details_focused: false,
            detail_tab: 0,
            mode: InputMode::Browse,
            status: String::new(),
            page_repeat_direction: None,
            page_repeat_count: 0,
            last_page_key: SystemTime::UNIX_EPOCH,
        };
        let items = [];
        handle_key(
            &mut app,
            &items,
            KeyEvent::new(KeyCode::F(10), KeyModifiers::NONE),
        )
        .unwrap();
        handle_key(
            &mut app,
            &items,
            KeyEvent::new(KeyCode::Right, KeyModifiers::NONE),
        )
        .unwrap();
        handle_key(
            &mut app,
            &items,
            KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE),
        )
        .unwrap();
        assert!(matches!(app.mode, InputMode::Search));

        app.mode = InputMode::Browse;
        handle_key(
            &mut app,
            &items,
            KeyEvent::new(KeyCode::Char('/'), KeyModifiers::NONE),
        )
        .unwrap();
        assert!(matches!(app.mode, InputMode::Search));
    }

    #[test]
    fn test_mouse_click_opens_and_activates_menu_item() {
        let (database, root_id) = test_database(DatabaseVersion::KDBX31);
        let mut app = App {
            database,
            database_path: PathBuf::new(),
            key: CompositeKey::new(),
            current_group: root_id,
            group_history: Vec::new(),
            query: String::new(),
            previous_query: String::new(),
            selected: 0,
            reveal_password: false,
            details_focused: false,
            detail_tab: 0,
            mode: InputMode::Browse,
            status: String::new(),
            page_repeat_direction: None,
            page_repeat_count: 0,
            last_page_key: SystemTime::UNIX_EPOCH,
        };
        let items = [
            BrowserItem {
                kind: ItemKind::Entry,
                id: NodeId::new_uuid(),
                title: "First".to_string(),
                subtitle: String::new(),
                icon: String::new(),
            },
            BrowserItem {
                kind: ItemKind::Entry,
                id: NodeId::new_uuid(),
                title: "Second".to_string(),
                subtitle: String::new(),
                icon: String::new(),
            },
        ];
        let area = Rect::new(0, 0, 100, 30);
        app.selected = 1;
        handle_mouse(
            &mut app,
            &items,
            MouseEvent {
                kind: MouseEventKind::Down(MouseButton::Left),
                column: 2,
                row: 4,
                modifiers: KeyModifiers::NONE,
            },
            area,
        )
        .unwrap();
        assert_eq!(app.selected, 0);
        handle_mouse(
            &mut app,
            &items,
            MouseEvent {
                kind: MouseEventKind::Down(MouseButton::Left),
                column: 10,
                row: 1,
                modifiers: KeyModifiers::NONE,
            },
            area,
        )
        .unwrap();
        assert!(matches!(app.mode, InputMode::Menu { menu: 1, .. }));
        handle_mouse(
            &mut app,
            &items,
            MouseEvent {
                kind: MouseEventKind::Down(MouseButton::Left),
                column: 10,
                row: 3,
                modifiers: KeyModifiers::NONE,
            },
            area,
        )
        .unwrap();
        assert!(matches!(app.mode, InputMode::Search));
    }

    #[test]
    fn test_help_menu_opens_about_dialog() {
        let (database, root_id) = test_database(DatabaseVersion::KDBX31);
        let mut app = App {
            database,
            database_path: PathBuf::new(),
            key: CompositeKey::new(),
            current_group: root_id,
            group_history: Vec::new(),
            query: String::new(),
            previous_query: String::new(),
            selected: 0,
            reveal_password: false,
            details_focused: false,
            detail_tab: 0,
            mode: InputMode::Browse,
            status: String::new(),
            page_repeat_direction: None,
            page_repeat_count: 0,
            last_page_key: SystemTime::UNIX_EPOCH,
        };
        assert_eq!(menu_items(3)[1].label, "About");
        activate_menu_item(&mut app, &[], menu_items(3)[1].action).unwrap();
        assert!(matches!(app.mode, InputMode::About));
        handle_key(
            &mut app,
            &[],
            KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE),
        )
        .unwrap();
        assert!(matches!(app.mode, InputMode::Browse));
    }

    #[test]
    fn test_keyfile_decoder_accepts_hex_and_xml_keyfiles() {
        let bytes = vec![0x5a; 32];
        let hex_key = hex::encode(&bytes);
        assert_eq!(decode_keyfile(hex_key.as_bytes()).unwrap(), bytes);

        let encoded = base64::engine::general_purpose::STANDARD.encode(&bytes);
        let xml_key = format!("<Key><Data>{encoded}</Data></Key>");
        assert_eq!(decode_keyfile(xml_key.as_bytes()).unwrap(), bytes);

        let wrapped_base64 = format!(
            "<Key><Data Hash=\"key-hash\">\n  {}\n</Data></Key>",
            encoded
        );
        assert_eq!(decode_keyfile(wrapped_base64.as_bytes()).unwrap(), bytes);

        let wrapped_hex = format!("<Key><Data>\n{}\n</Data></Key>", hex_key);
        assert_eq!(decode_keyfile(wrapped_hex.as_bytes()).unwrap(), bytes);
    }

    #[test]
    fn test_list_navigation_home_end_and_acceleration() {
        let (mut database, root_id) = test_database(DatabaseVersion::KDBX31);
        for index in 0..20 {
            let mut entry = Entry::new(NodeId::new_uuid());
            entry.title = format!("Entry {index}");
            database.add_entry(entry, &root_id);
        }
        let items = current_items(&database, root_id, "");
        let mut app = App {
            database,
            database_path: PathBuf::from("test.kdbx"),
            key: CompositeKey::new().with_password(b"test-password"),
            current_group: root_id,
            group_history: Vec::new(),
            query: String::new(),
            previous_query: String::new(),
            selected: 0,
            reveal_password: false,
            details_focused: false,
            detail_tab: 0,
            mode: InputMode::Browse,
            status: String::new(),
            page_repeat_direction: None,
            page_repeat_count: 0,
            last_page_key: SystemTime::UNIX_EPOCH,
        };

        handle_key(
            &mut app,
            &items,
            KeyEvent::new(KeyCode::End, KeyModifiers::NONE),
        )
        .unwrap();
        assert_eq!(app.selected, 19);
        handle_key(
            &mut app,
            &items,
            KeyEvent::new(KeyCode::Home, KeyModifiers::NONE),
        )
        .unwrap();
        assert_eq!(app.selected, 0);

        let alt_shift = KeyModifiers::ALT | KeyModifiers::SHIFT;
        for expected in [1, 3, 6] {
            handle_key(&mut app, &items, KeyEvent::new(KeyCode::Down, alt_shift)).unwrap();
            assert_eq!(app.selected, expected);
        }
    }

    #[test]
    fn test_totp_matches_rfc6238_sha1_vector() {
        let mut entry = Entry::new(NodeId::new_uuid());
        entry.custom_fields.push(EntryField {
            name: "TimeOtp-Secret-Base32".to_string(),
            value: ProtectedString::new_plain("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"),
            is_protected: true,
        });
        let key = decode_base32(entry.custom_fields[0].value.as_str()).unwrap();
        assert_eq!(
            generate_totp::<Hmac<Sha1>>(&key, 1_111_111_109 / 30, 8).unwrap(),
            "07081804"
        );
    }
}

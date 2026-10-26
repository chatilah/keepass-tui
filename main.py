#!/usr/bin/env python3
"""A small terminal browser for KeePass KDBX databases."""

import argparse
import curses
import getpass
import hashlib
import shutil
import subprocess
import sys
import time
from pathlib import Path
from textwrap import wrap
from typing import Any, Optional

import pyotp
from pykeepass import PyKeePass
from pykeepass.exceptions import CredentialsError, HeaderChecksumError, PayloadChecksumError


def resolved_value(database: PyKeePass, value: Optional[str]) -> str:
    """Resolve KeePass field references, preserving the stored value if unresolved."""
    if not value:
        return value or ""
    resolved = database.deref(value)
    return resolved if resolved is not None else value


def entry_matches(database: PyKeePass, entry: Any, query: str) -> bool:
    """Return whether an entry's searchable fields contain the query."""
    query = query.casefold()
    return any(
        query in resolved_value(database, value).casefold()
        for value in (entry.title, entry.username, entry.url, entry.notes)
    )


def group_items(database: PyKeePass, group: Any, query: str) -> list[tuple[str, Any]]:
    """Return only this group's child groups and direct entries."""
    normalized_query = query.casefold()
    groups = [
        ("group", child)
        for child in group.subgroups
        if not normalized_query or normalized_query in (child.name or "").casefold()
    ]
    entries = [
        ("entry", entry)
        for entry in group.entries
        if not normalized_query or entry_matches(database, entry, query)
    ]
    return groups + entries


def add_attachment_to_entry(database: PyKeePass, entry: Any, path: Path) -> Any:
    """Store a file in the database and attach it to an entry."""
    if not path.is_file():
        raise ValueError(f"Attachment file not found: {path}")

    binary_id = database.add_binary(path.read_bytes())
    try:
        attachment = entry.add_attachment(binary_id, path.name)
        database.save()
    except (OSError, ValueError, TypeError, RuntimeError):
        database.delete_binary(binary_id)
        raise
    return attachment


def entry_totp(entry: Any) -> Optional[pyotp.TOTP]:
    """Build a TOTP generator from a standard KeePass OTP field or seed property."""
    otp_value = entry.otp
    if otp_value:
        if otp_value.startswith("otpauth://"):
            otp = pyotp.parse_uri(otp_value)
            if not isinstance(otp, pyotp.TOTP):
                raise ValueError("Only time-based OTP entries are supported.")
            return otp
        return pyotp.TOTP(otp_value)

    properties = {
        key.casefold(): value
        for key, value in entry.custom_properties.items()
        if value
    }
    secret = properties.get("timeotp-secret-base32") or properties.get("totp seed")
    if not secret:
        return None

    algorithm_name = properties.get("timeotp-algorithm", "SHA1").upper()
    digest = {
        "SHA1": hashlib.sha1,
        "SHA256": hashlib.sha256,
        "SHA512": hashlib.sha512,
    }.get(algorithm_name)
    if digest is None:
        raise ValueError(f"Unsupported TOTP algorithm: {algorithm_name}")

    return pyotp.TOTP(
        secret,
        digits=int(properties.get("timeotp-length", "6")),
        digest=digest,
        interval=int(properties.get("timeotp-period", "30")),
    )


def copy_to_clipboard(value: str) -> None:
    """Copy text using the clipboard utility available on the current system."""
    candidates = (
        (("pbcopy",),)
        if sys.platform == "darwin"
        else (("clip",),)
        if sys.platform == "win32"
        else (
            ("wl-copy",),
            ("xclip", "-selection", "clipboard"),
            ("xsel", "--clipboard", "--input"),
        )
    )
    command = next(
        (candidate for candidate in candidates if shutil.which(candidate[0])),
        None,
    )
    if command is None:
        raise RuntimeError("No supported clipboard utility was found.")
    try:
        result = subprocess.run(
            command,
            input=value,
            text=True,
            capture_output=True,
            check=False,
            timeout=5,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError(f"Clipboard command failed: {exc}") from exc
    if result.returncode:
        message = result.stderr.strip() or "clipboard command failed"
        raise RuntimeError(message)


def safe_addstr(window: Any, y: int, x: int, text: str, width: int, attr: int = 0) -> None:
    """Write a clipped line without allowing terminal-edge errors."""
    if width <= 0:
        return
    try:
        window.addnstr(y, x, text, width, attr)
    except curses.error:
        pass


def draw_list(
    stdscr: Any,
    database: PyKeePass,
    group: Any,
    items: list[tuple[str, Any]],
    query: str,
    selected: int,
    offset: int,
    reveal_password: bool,
    status: str = "",
    searching: bool = False,
    details_focused: bool = False,
    detail_tab: int = 0,
) -> int:
    stdscr.erase()
    height, width = stdscr.getmaxyx()
    safe_addstr(stdscr, 0, 0, "KEEPASS TUI", width, curses.A_BOLD)
    breadcrumb = " / ".join(group.path) or (group.name or "Root")
    safe_addstr(
        stdscr,
        1,
        0,
        (
            f"Search: {query}_ | type to filter | Enter: done | Esc: cancel"
            if searching
            else f"{breadcrumb} | / search | ? shortcuts"
        ),
        width,
        curses.A_DIM,
    )
    safe_addstr(stdscr, 2, 0, "-" * width, width, curses.A_DIM)

    stacked = width < 80
    if stacked:
        pane_x = 1
        list_width = max(1, width - 2)
        detail_width = list_width
        details_header_y = max(8, height - 12)
        list_start = 5
        visible_items = max(1, (details_header_y - list_start - 1) // 2)
        details_header = details_header_y
        details_y = details_header_y + 2
        detail_lines = max(0, height - details_y - 1)
    else:
        left_width = min(max(26, width * 36 // 100), width - 32)
        pane_x = left_width + 2
        list_width = left_width - 2
        detail_width = max(1, width - pane_x - 1)
        pane_border_attr = curses.A_REVERSE if details_focused else curses.A_DIM
        for y in range(3, max(3, height - 1)):
            safe_addstr(stdscr, y, left_width, "|", 1, pane_border_attr)
        visible_items = max(1, (height - 7) // 2)
        list_start = 5
        details_header = 3
        details_y = 5
        detail_lines = max(0, height - 7)

    safe_addstr(
        stdscr,
        3,
        1,
        f"CONTENTS  {len(items)}",
        list_width,
        curses.A_BOLD,
    )
    header_attr = curses.A_REVERSE | curses.A_BOLD if details_focused else curses.A_BOLD
    if stacked and details_header < height - 1:
        divider_attr = curses.A_REVERSE if details_focused else curses.A_DIM
        safe_addstr(stdscr, details_header - 1, 0, "-" * width, width, divider_attr)
    if details_header < height - 1:
        heading = "DETAILS  [FOCUSED]" if details_focused else "DETAILS"
        safe_addstr(stdscr, details_header, pane_x, heading, detail_width, header_attr)

    if selected < offset:
        offset = selected
    elif selected >= offset + visible_items:
        offset = selected - visible_items + 1
    offset = min(offset, max(0, len(items) - visible_items))

    for slot, item_index in enumerate(
        range(offset, min(len(items), offset + visible_items))
    ):
        item_type, item = items[item_index]
        row = list_start + slot * 2
        is_selected = item_index == selected
        title_attr = (
            curses.A_REVERSE | curses.A_BOLD if is_selected else curses.A_BOLD
        )
        subtitle_attr = curses.A_REVERSE if is_selected else curses.A_DIM
        if item_type == "group":
            title = f"[+] {item.name or '(unnamed group)'}"
            subtitle = f"{len(item.subgroups)} folders, {len(item.entries)} entries"
        else:
            title = resolved_value(database, item.title) or "(untitled)"
            subtitle = resolved_value(database, item.username) or "(no username)"
        safe_addstr(stdscr, row, 1, title, list_width, title_attr)
        if row + 1 < height - 1:
            safe_addstr(
                stdscr,
                row + 1,
                2,
                subtitle,
                max(1, list_width - 1),
                subtitle_attr,
            )

    if not items:
        empty_message = "No matching items" if query else "This group is empty"
        safe_addstr(stdscr, list_start, 1, empty_message, list_width, curses.A_DIM)
    elif selected < len(items):
        item_type, item = items[selected]
        if item_type == "entry":
            draw_entry_details(
                stdscr,
                database,
                item,
                reveal_password,
                pane_x,
                details_y,
                detail_width,
                detail_lines,
                compact=stacked,
                tab=detail_tab,
            )
        elif detail_lines:
            safe_addstr(
                stdscr,
                details_y,
                pane_x,
                item.name or "(unnamed group)",
                detail_width,
                curses.A_BOLD,
            )
            folder_details = [
                (2, "Folder", curses.A_BOLD),
                (3, f"{len(item.subgroups)} subfolders", curses.A_DIM),
                (4, f"{len(item.entries)} entries", curses.A_DIM),
                (6, item.notes, curses.A_DIM),
            ]
            for line_offset, text, attr in folder_details:
                if text and line_offset < detail_lines:
                    safe_addstr(
                        stdscr,
                        details_y + line_offset,
                        pane_x,
                        text,
                        detail_width,
                        attr,
                    )
    safe_addstr(
        stdscr,
        height - 1,
        0,
        status or "Passwords are hidden by default.",
        width,
        curses.A_DIM,
    )
    stdscr.refresh()
    return offset


def draw_entry_tabs(
    stdscr: Any, x: int, y: int, width: int, selected_tab: int
) -> None:
    tabs = ("1 General", "2 Attachments", "3 Details")
    cursor_x = x
    for index, label in enumerate(tabs):
        attr = curses.A_REVERSE | curses.A_BOLD if index == selected_tab else curses.A_DIM
        shown = label if cursor_x == x else f"  {label}"
        if cursor_x - x >= width:
            break
        safe_addstr(stdscr, y, cursor_x, shown, width - (cursor_x - x), attr)
        cursor_x += len(shown)


def draw_help(stdscr: Any) -> None:
    stdscr.erase()
    height, width = stdscr.getmaxyx()
    safe_addstr(stdscr, 0, 0, "KEYBOARD SHORTCUTS", width, curses.A_BOLD)
    safe_addstr(stdscr, 1, 0, "-" * width, width, curses.A_DIM)

    shortcuts = [
        ("Navigation", ""),
        ("j / ↓", "Move to the next item"),
        ("k / ↑", "Move to the previous item"),
        ("Enter", "Open the selected group"),
        ("Backspace", "Return to the parent group"),
        ("", ""),
        ("Search", ""),
        ("/", "Start live search in the current group"),
        ("Backspace", "Delete the last search character"),
        ("Ctrl+U", "Clear the search"),
        ("Enter", "Keep the current search filter"),
        ("Esc", "Cancel search and restore the previous filter"),
        ("", ""),
        ("Entry actions", ""),
        ("a", "Add an entry to the current group"),
        ("1 / 2 / 3", "Switch entry pane to General / Attachments / Details"),
        ("a (Attachments tab)", "Add a file to the selected entry"),
        ("p", "Show or hide the selected entry's password"),
        ("u", "Copy username"),
        ("w", "Copy password"),
        ("l", "Copy URL"),
        ("t", "Copy current TOTP code"),
        ("q", "Quit"),
        ("? / Esc", "Close this help screen"),
    ]
    y = 3
    for shortcut, description in shortcuts:
        if y >= height - 1:
            break
        if not shortcut:
            y += 1
            continue
        if not description:
            safe_addstr(stdscr, y, 1, shortcut, width - 1, curses.A_BOLD)
        else:
            safe_addstr(stdscr, y, 2, shortcut, 16, curses.A_BOLD)
            safe_addstr(stdscr, y, 20, description, max(1, width - 21))
        y += 1

    if height >= 2:
        safe_addstr(stdscr, height - 1, 0, "Press ? or Esc to return.", width, curses.A_DIM)
    stdscr.refresh()


def prompt_attachment_path(stdscr: Any) -> Optional[Path]:
    height, width = stdscr.getmaxyx()
    if height < 1 or width < 2:
        return None

    stdscr.erase()
    safe_addstr(stdscr, 0, 0, "Attachment file path:", width, curses.A_BOLD)
    safe_addstr(stdscr, 1, 0, "Press Enter to attach; empty cancels.", width, curses.A_DIM)
    stdscr.refresh()
    try:
        curses.echo()
        curses.curs_set(1)
        raw_path = stdscr.getstr(2, 0, max(1, width - 1))
    except curses.error:
        return None
    finally:
        curses.noecho()
        curses.curs_set(0)

    value = raw_path.decode("utf-8", errors="replace").strip()
    if not value:
        return None
    return Path(value).expanduser()


def prompt_new_entry(stdscr: Any) -> Optional[dict[str, str]]:
    fields = ("Title", "Username", "Password", "URL", "Notes")
    values = {field: "" for field in fields}
    active = 0
    error = ""
    height, width = stdscr.getmaxyx()
    stdscr.timeout(-1)

    while True:
        stdscr.erase()
        safe_addstr(stdscr, 0, 0, "ADD ENTRY", width, curses.A_BOLD)
        safe_addstr(stdscr, 1, 0, "-" * width, width, curses.A_DIM)
        safe_addstr(
            stdscr,
            2,
            0,
            "Tab: next field | Enter: next/save | Esc: cancel",
            width,
            curses.A_DIM,
        )

        for index, field in enumerate(fields):
            y = 4 + index * 2
            if y >= height - 2:
                break
            attr = curses.A_REVERSE | curses.A_BOLD if index == active else curses.A_BOLD
            safe_addstr(stdscr, y, 1, field, min(14, max(1, width - 1)), attr)
            value = values[field]
            display_value = "*" * len(value) if field == "Password" else value
            safe_addstr(
                stdscr,
                y + 1,
                3,
                display_value or "(empty)",
                max(1, width - 4),
                curses.A_REVERSE if index == active else curses.A_NORMAL,
            )

        if error and height >= 2:
            safe_addstr(stdscr, height - 2, 0, error, width, curses.A_BOLD)
        stdscr.refresh()

        try:
            key = stdscr.get_wch()
        except curses.error:
            continue

        if key in ("\x1b", 27):
            return None
        if key in ("\t", curses.KEY_DOWN):
            active = (active + 1) % len(fields)
            error = ""
        elif key == curses.KEY_BTAB:
            active = (active - 1) % len(fields)
            error = ""
        elif key in ("\n", "\r", curses.KEY_ENTER):
            if active < len(fields) - 1:
                active += 1
                error = ""
            elif not values["Title"].strip():
                active = 0
                error = "Title is required."
            else:
                return values
        elif key in ("\x7f", "\b", curses.KEY_BACKSPACE):
            values[fields[active]] = values[fields[active]][:-1]
            error = ""
        elif key == "\x15":
            values[fields[active]] = ""
            error = ""
        elif isinstance(key, str) and key.isprintable():
            values[fields[active]] += key
            error = ""


def draw_entry_details(
    stdscr: Any,
    database: PyKeePass,
    entry: Any,
    reveal_password: bool,
    x: int,
    y: int,
    width: int,
    max_lines: int,
    compact: bool = False,
    tab: int = 0,
) -> None:
    safe_addstr(
        stdscr,
        y,
        x,
        resolved_value(database, entry.title) or "(untitled)",
        width,
        curses.A_BOLD,
    )
    tabs_y = y + 1
    draw_entry_tabs(stdscr, x, tabs_y, width, tab)
    y = tabs_y + 2
    used = 3 if compact else 4

    if tab == 1:
        attachments = entry.attachments
        if not attachments:
            safe_addstr(stdscr, y, x, "No attachments. Press a to add a file.", width, curses.A_DIM)
            return
        for attachment in attachments:
            if used >= max_lines:
                break
            try:
                size = len(attachment.binary)
                description = f"{attachment.filename} ({size} bytes)"
            except (IndexError, ValueError):
                description = f"{attachment.filename} (unavailable)"
            safe_addstr(stdscr, y, x, description, width)
            y += 1
            used += 1
        return

    if tab == 2:
        details = [
            ("ID", str(entry.uuid)),
            ("Group", " / ".join(entry.path) or "Root"),
            ("Tags", ", ".join(entry.tags) or "(none)"),
            ("Created", str(entry.ctime)),
            ("Modified", str(entry.mtime)),
        ]
        for label, value in details:
            if used >= max_lines:
                break
            safe_addstr(stdscr, y, x, label, width, curses.A_BOLD)
            y += 1
            used += 1
            safe_addstr(stdscr, y, x, value, width, curses.A_DIM)
            y += 1
            used += 1
        return

    try:
        totp = entry_totp(entry)
        details = []
        if totp is not None:
            now = time.time()
            remaining = totp.interval - (int(now) % totp.interval)
            details.append(("TOTP", f"{totp.at(now)}  ({remaining}s)"))
    except (ValueError, TypeError) as exc:
        details = [("TOTP", f"Unavailable: {exc}")]
    details.extend(
        [
            ("Username", resolved_value(database, entry.username)),
            (
                "Password",
                resolved_value(database, entry.password)
                if reveal_password
                else (
                    "(empty)"
                    if not entry.password
                    else "********  (press p to reveal)"
                ),
            ),
            ("URL", resolved_value(database, entry.url)),
            ("Notes", resolved_value(database, entry.notes)),
        ]
    )
    for label, value in details:
        if used >= max_lines:
            break
        if compact:
            label_text = f"{label}: "
            safe_addstr(stdscr, y, x, label_text, width, curses.A_BOLD)
            value_x = x + min(len(label_text), max(0, width - 1))
            value_width = max(1, width - (value_x - x))
            y += 1
            used += 1
        else:
            safe_addstr(stdscr, y, x, f"{label}", width, curses.A_BOLD)
            y += 1
            used += 1
            value_x = x
            value_width = width
        lines = []
        for paragraph in value.splitlines() or [""]:
            lines.extend(wrap(paragraph, max(1, value_width)) or [""])
        for line in lines:
            if used >= max_lines:
                break
            safe_addstr(stdscr, y, value_x, line, value_width, curses.A_DIM)
            y += 1
            used += 1


def run_tui(stdscr: Any, database: PyKeePass) -> None:
    curses.curs_set(0)
    curses.noecho()
    curses.cbreak()
    stdscr.keypad(True)
    current_group = database.root_group
    group_history = []
    query = ""
    selected = 0
    offset = 0
    reveal_password = False
    status = ""
    searching = False
    previous_query = ""
    help_open = False
    details_focused = False
    detail_tab = 0

    while True:
        if help_open:
            draw_help(stdscr)
            stdscr.timeout(-1)
            try:
                key = stdscr.get_wch()
            except curses.error:
                continue
            if key in ("?", ord("?"), "\x1b", 27):
                help_open = False
            continue

        items = group_items(database, current_group, query)
        if items:
            selected = min(selected, len(items) - 1)
        else:
            selected = 0

        offset = draw_list(
            stdscr,
            database,
            current_group,
            items,
            query,
            selected,
            offset,
            reveal_password,
            status,
            searching,
            details_focused,
            detail_tab,
        )

        stdscr.timeout(1000)
        try:
            key = stdscr.get_wch()
        except curses.error:
            continue
        status = ""
        if searching:
            if key in ("\n", "\r", curses.KEY_ENTER):
                searching = False
            elif key in ("\x1b",):
                query = previous_query
                searching = False
                selected = 0
                offset = 0
            elif key in ("\x7f", "\b", curses.KEY_BACKSPACE):
                query = query[:-1]
                selected = 0
                offset = 0
            elif key == "\x15":
                query = ""
                selected = 0
                offset = 0
            elif isinstance(key, str) and key.isprintable():
                query += key
                selected = 0
                offset = 0
            continue

        if isinstance(key, str):
            key = ord(key)
        if key == ord("q"):
            break
        if key == ord("?"):
            help_open = True
        elif key in (ord("j"), curses.KEY_DOWN):
            selected = min(selected + 1, max(0, len(items) - 1))
            reveal_password = False
            details_focused = False
        elif key in (ord("k"), curses.KEY_UP):
            selected = max(0, selected - 1)
            reveal_password = False
            details_focused = False
        elif key in (curses.KEY_BACKSPACE, 127, 8, 27):
            if current_group.parentgroup is not None:
                current_group, selected = group_history.pop()
                offset = 0
                query = ""
                reveal_password = False
                details_focused = False
                detail_tab = 0
        elif key in (curses.KEY_ENTER, 10, 13) and items:
            item_type, item = items[selected]
            if item_type == "group":
                group_history.append((current_group, selected))
                current_group = item
                selected = 0
                offset = 0
                query = ""
                reveal_password = False
                details_focused = False
                detail_tab = 0
            else:
                details_focused = True
        elif key in (ord("1"), ord("2"), ord("3")) and items and items[selected][0] == "entry":
            detail_tab = int(chr(key)) - 1
            details_focused = True
        elif key == ord("p") and items and items[selected][0] == "entry":
            reveal_password = not reveal_password
        elif (
            key in (ord("u"), ord("w"), ord("l"), ord("t"))
            and items
            and items[selected][0] == "entry"
        ):
            entry = items[selected][1]
            try:
                if key == ord("u"):
                    value = resolved_value(database, entry.username)
                    field = "username"
                elif key == ord("w"):
                    value = resolved_value(database, entry.password)
                    field = "password"
                elif key == ord("l"):
                    value = resolved_value(database, entry.url)
                    field = "URL"
                else:
                    totp = entry_totp(entry)
                    if totp is None:
                        raise ValueError("Selected entry has no TOTP configured.")
                    value = totp.now()
                    field = "TOTP"

                if not value:
                    raise ValueError(f"Selected entry has no {field} value.")
                copy_to_clipboard(value)
                status = f"Copied {field} to clipboard."
            except (RuntimeError, ValueError, TypeError) as exc:
                status = f"Copy failed: {exc}"
        elif key == ord("a"):
            if items and items[selected][0] == "entry" and detail_tab == 1:
                entry = items[selected][1]
                attachment_path = prompt_attachment_path(stdscr)
                if attachment_path is not None:
                    try:
                        add_attachment_to_entry(database, entry, attachment_path)
                    except (OSError, ValueError, TypeError, RuntimeError) as exc:
                        status = f"Could not add attachment: {exc}"
                    else:
                        status = f"Attached {attachment_path.name}."
            else:
                values = prompt_new_entry(stdscr)
                if values is not None:
                    new_entry = None
                    try:
                        new_entry = database.add_entry(
                            current_group,
                            values["Title"].strip(),
                            values["Username"],
                            values["Password"],
                            url=values["URL"] or None,
                            notes=values["Notes"] or None,
                        )
                        database.save()
                    except (OSError, ValueError, TypeError, RuntimeError) as exc:
                        if new_entry is not None:
                            database.delete_entry(new_entry)
                        status = f"Could not save entry: {exc}"
                    else:
                        query = ""
                        selected = len(current_group.subgroups) + len(current_group.entries) - 1
                        offset = 0
                        reveal_password = False
                        details_focused = False
                        detail_tab = 0
                        status = "Entry added."
        elif key == ord("/"):
            previous_query = query
            searching = True
            selected = 0
            offset = 0
            reveal_password = False
            details_focused = False
        elif key == ord("p") and (not items or items[selected][0] != "entry"):
            status = "Select an entry first."


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Browse KeePass KDBX databases in a terminal.")
    parser.add_argument("database", type=Path, help="path to a .kdbx database")
    parser.add_argument("-k", "--keyfile", type=Path, help="path to the database keyfile")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if not args.database.is_file():
        print(f"Database file not found: {args.database}", file=sys.stderr)
        return 2
    if args.keyfile is not None and not args.keyfile.is_file():
        print(f"Keyfile not found: {args.keyfile}", file=sys.stderr)
        return 2

    password = getpass.getpass("Master password: ")
    try:
        database = PyKeePass(
            str(args.database),
            password=password,
            keyfile=str(args.keyfile) if args.keyfile is not None else None,
        )
    except (CredentialsError, HeaderChecksumError, PayloadChecksumError, OSError, ValueError) as exc:
        print(f"Could not open KeePass database: {exc}", file=sys.stderr)
        return 1

    try:
        curses.wrapper(run_tui, database)
    except curses.error as exc:
        print(f"Could not start the terminal interface: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

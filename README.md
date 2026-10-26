# KeePass TUI

A small terminal interface for browsing an existing KeePass KDBX database.

## Requirements

- Rust 1.89+ to build from source
- A terminal that supports interactive TUI applications

## Run

Install the latest macOS release from Homebrew:

```sh
brew install chatilah/tap/keepass-tui
keepass-tui /path/to/passwords.kdbx
```

Or build from source:

```sh
cargo install --path .
keepass-tui /path/to/passwords.kdbx
```

If the database also requires a keyfile, provide its path with `--keyfile`:

```sh
keepass-tui /path/to/passwords.kdbx --keyfile /path/to/database.key
```

The master password is requested without being echoed. Browsing does not modify
the database; adding an entry writes it to the database when you save the form.
KDBX 3.1 and KDBX 4 databases retain their existing format when saved.

For development, run `cargo test` and `cargo run -- --help`.

## CI and releases

GitHub Actions checks formatting and runs the Rust test suite. Pushing a
`vMAJOR.MINOR.PATCH` tag runs the tests, builds standalone Apple Silicon and
Intel macOS binaries, and creates a GitHub release. The release includes a
checksum-filled `keepass-tui.rb` Homebrew formula.

## Homebrew

Install the latest macOS release from the `chatilah/tap` Homebrew tap:

```sh
brew install chatilah/tap/keepass-tui
```

The formula is updated automatically when a new version is released. The
`keepass-tui` GitHub repository needs a `HOMEBREW_TAP_TOKEN` Actions secret
with write access to the `chatilah/homebrew-tap` repository. The release also
attaches the checksum-filled formula to its GitHub release. Its template is in
`Formula/keepass-tui.rb.template`.

## Controls

- `F10`: open the menu bar; use `Left` / `Right` to choose a menu, `Up` /
  `Down` to choose an item, `Enter` to activate it, and `Esc` to close it
- Mouse: click a menu name to open it and click an item to activate it; click
  an entry in the contents list to select it and use the scroll wheel to browse
- `?`: open the in-app shortcut guide
- `Home` / `End`: jump to the first / last item in the current list
- `Page Up` / `Page Down`: move by a page; repeated presses accelerate
- `Alt+Up` / `Alt+Down`: jump to the first / last item in the current list
- `Alt+Shift+Up` / `Alt+Shift+Down`: move progressively faster through the
  list when supported by the terminal
- `a`: add an entry to the current group (title required; username, password,
  URL, and notes are optional)
- In the add-entry form, use `Tab` or `Enter` to move between fields; `Enter`
  on the last field saves, and `Esc` cancels
- `Enter` on an entry highlights its already-visible details pane
- Entry details have `1 General`, `2 Attachments`, and `3 Details` tabs. The
  General tab shows credentials and TOTP, Attachments lists files, and Details
  shows the entry UUID, group, tags, and timestamps.
- Select an entry and press `2`, then `a`, to add a file attachment; enter its
  path when prompted. Attachments are stored inside the KDBX database.
- `Esc` or `Backspace`: return to the parent group; at the root, do nothing
- `q`: quit
- `/`: start live search in the current group
- The selected entry's details appear in the right pane
- The panes use columns on wide terminals and stack vertically on narrow ones

The menu bar provides File, Navigate, Entry, and Help actions. Existing
keyboard shortcuts remain available alongside the menus. On systems where a
terminal needs mouse reporting enabled, use a terminal that supports mouse
events. Help > About displays the application version, source commit, and
build target platform.

Entries display a terminal glyph for their assigned KeePass standard icon.
The glyphs are text approximations of KeePass's bitmap icons; entries without an
explicit icon use the default key glyph.

Passwords are masked by default and are not included in the entry list.
KeePass `{REF:...}` field references are resolved for display and search.
Configured TOTP codes are shown in the details pane and refreshed every second.
Copy shortcuts use the system clipboard (`pbcopy` on macOS, `clip` on Windows,
or `wl-copy`/`xclip`/`xsel` on Linux).

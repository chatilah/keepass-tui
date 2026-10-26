# KeePass TUI

A small terminal interface for browsing an existing KeePass KDBX database.

## Requirements

- Python 3.9+
- A terminal with curses support

## Run

```sh
python -m pip install .
keepass-tui /path/to/passwords.kdbx
```

If the database also requires a keyfile, provide its path with `--keyfile`:

```sh
keepass-tui /path/to/passwords.kdbx --keyfile /path/to/database.key
```

The master password is requested without being echoed. Browsing does not modify
the database; adding an entry writes it to the database when you save the form.

For development, install the project in editable mode with `python -m pip install -e .`.

## CI and releases

GitHub Actions runs the test suite on Python 3.9 through 3.13 and builds the
Python package. Pushing a `vMAJOR.MINOR.PATCH` tag runs the tests, builds
standalone Apple Silicon and Intel macOS binaries, and creates a GitHub release.
The release includes a checksum-filled `keepass-tui.rb` Homebrew formula.

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

- `?`: open the in-app shortcut guide
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

Passwords are masked by default and are not included in the entry list.
KeePass `{REF:...}` field references are resolved for display and search.
Configured TOTP codes are shown in the details pane and refreshed every second.
Copy shortcuts use the system clipboard (`pbcopy` on macOS, `clip` on Windows,
or `wl-copy`/`xclip`/`xsel` on Linux).

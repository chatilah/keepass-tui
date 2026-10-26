import curses
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pyotp
from pykeepass import PyKeePass, create_database

from main import (
    copy_to_clipboard,
    add_attachment_to_entry,
    draw_help,
    draw_list,
    draw_entry_details,
    entry_icon_glyph,
    entry_matches,
    entry_totp,
    prompt_new_entry,
    resolved_value,
)


class FakeWindow:
    def __init__(self, height, width):
        self.height = height
        self.width = width
        self.lines = {}
        self.attrs = {}
        self.snapshots = []

    def getmaxyx(self):
        return self.height, self.width

    def erase(self):
        self.lines.clear()

    def addnstr(self, y, x, text, width, attr=0):
        self.lines[(y, x)] = text[:width]
        self.attrs[(y, x)] = attr

    def refresh(self):
        self.snapshots.append(" ".join(self.lines.values()))


class FakeInputWindow(FakeWindow):
    def __init__(self, height, width, keys):
        super().__init__(height, width)
        self.keys = iter(keys)

    def keypad(self, enabled):
        pass

    def timeout(self, milliseconds):
        pass

    def get_wch(self):
        return next(self.keys)


class EntrySearchTests(unittest.TestCase):
    def test_entry_list_shows_assigned_standard_icon(self):
        with tempfile.TemporaryDirectory() as directory:
            database_path = Path(directory) / "test.kdbx"
            database = create_database(str(database_path), "password")
            entry = database.add_entry(
                database.root_group, "Email", "alice", "secret"
            )
            entry.icon = "19"
            database.save()
            database = PyKeePass(str(database_path), "password")
            entry = database.entries[0]
            window = FakeWindow(24, 100)

            draw_list(
                window,
                database,
                database.root_group,
                [("entry", entry)],
                "",
                0,
                0,
                False,
            )

            self.assertEqual(window.lines[(5, 1)], "✉")
            self.assertEqual(window.lines[(5, 4)], "Email")

    def test_entry_icon_uses_default_and_unknown_fallbacks(self):
        self.assertEqual(entry_icon_glyph(SimpleNamespace(icon=None)), "🔑")
        self.assertEqual(entry_icon_glyph(SimpleNamespace(icon="999")), "◆")
        self.assertEqual(entry_icon_glyph(SimpleNamespace(icon="custom")), "◆")

    def test_alt_arrows_jump_to_list_ends(self):
        with tempfile.TemporaryDirectory() as directory:
            database_path = Path(directory) / "test.kdbx"
            database = create_database(str(database_path), "password")
            for index in range(20):
                database.add_entry(
                    database.root_group, f"Entry {index}", "user", "secret"
                )
            database.save()
            database = PyKeePass(str(database_path), "password")
            window = FakeInputWindow(
                24,
                100,
                ["\x1b", "[", "1", ";", "3", "B", "\x1b", "[", "1", ";", "3", "A", "q"],
            )
            selections = []

            def record_draw(stdscr, database, group, items, query, selected, *args):
                selections.append(selected)
                return 0

            with patch("main.curses.curs_set"), patch("main.curses.noecho"), patch(
                "main.curses.cbreak"
            ), patch("main.draw_list", side_effect=record_draw):
                from main import run_tui

                run_tui(window, database)

            self.assertEqual(selections, [0, 19, 0])

    def test_alt_shift_arrows_accelerate_repeated_movement(self):
        with tempfile.TemporaryDirectory() as directory:
            database_path = Path(directory) / "test.kdbx"
            database = create_database(str(database_path), "password")
            for index in range(20):
                database.add_entry(
                    database.root_group, f"Entry {index}", "user", "secret"
                )
            database.save()
            database = PyKeePass(str(database_path), "password")
            window = FakeInputWindow(
                24,
                100,
                [
                    "\x1b", "[", "1", ";", "4", "B",
                    "\x1b", "[", "1", ";", "4", "B",
                    "\x1b", "[", "1", ";", "4", "B",
                    "q",
                ],
            )
            selections = []

            def record_draw(stdscr, database, group, items, query, selected, *args):
                selections.append(selected)
                return 0

            with patch("main.curses.curs_set"), patch("main.curses.noecho"), patch(
                "main.curses.cbreak"
            ), patch("main.draw_list", side_effect=record_draw):
                from main import run_tui

                run_tui(window, database)

            self.assertEqual(selections, [0, 1, 3, 6])

    def test_home_end_jump_to_list_ends(self):
        with tempfile.TemporaryDirectory() as directory:
            database_path = Path(directory) / "test.kdbx"
            database = create_database(str(database_path), "password")
            for index in range(20):
                database.add_entry(
                    database.root_group, f"Entry {index}", "user", "secret"
                )
            database.save()
            database = PyKeePass(str(database_path), "password")
            window = FakeInputWindow(
                24, 100, [curses.KEY_END, curses.KEY_HOME, "q"]
            )
            selections = []

            def record_draw(stdscr, database, group, items, query, selected, *args):
                selections.append(selected)
                return 0

            with patch("main.curses.curs_set"), patch("main.curses.noecho"), patch(
                "main.curses.cbreak"
            ), patch("main.draw_list", side_effect=record_draw):
                from main import run_tui

                run_tui(window, database)

            self.assertEqual(selections, [0, 19, 0])

    def test_page_keys_repeat_with_accelerating_steps(self):
        with tempfile.TemporaryDirectory() as directory:
            database_path = Path(directory) / "test.kdbx"
            database = create_database(str(database_path), "password")
            for index in range(50):
                database.add_entry(
                    database.root_group, f"Entry {index}", "user", "secret"
                )
            database.save()
            database = PyKeePass(str(database_path), "password")
            window = FakeInputWindow(
                24,
                100,
                [curses.KEY_NPAGE, curses.KEY_NPAGE, curses.KEY_PPAGE, "q"],
            )
            selections = []

            def record_draw(stdscr, database, group, items, query, selected, *args):
                selections.append(selected)
                return 0

            with patch("main.curses.curs_set"), patch("main.curses.noecho"), patch(
                "main.curses.cbreak"
            ), patch("main.draw_list", side_effect=record_draw):
                from main import run_tui

                run_tui(window, database)

            self.assertEqual(selections, [0, 8, 24, 16])

    def test_formula_renderer_inserts_release_version_and_checksums(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            arm_checksum = directory / "arm.sha256"
            intel_checksum = directory / "intel.sha256"
            output = directory / "keepass-tui.rb"
            arm_checksum.write_text("a" * 64, encoding="utf-8")
            intel_checksum.write_text("b" * 64, encoding="utf-8")

            subprocess.run(
                [
                    sys.executable,
                    "scripts/render_homebrew_formula.py",
                    "v1.2.3",
                    str(arm_checksum),
                    str(intel_checksum),
                    "--output",
                    str(output),
                ],
                check=True,
                capture_output=True,
                text=True,
            )

            formula = output.read_text(encoding="utf-8")
            self.assertIn('version "1.2.3"', formula)
            self.assertIn(f'sha256 "{"a" * 64}"', formula)
            self.assertIn(f'sha256 "{"b" * 64}"', formula)

    def test_entry_tabs_show_attachments_and_uuid(self):
        with tempfile.TemporaryDirectory() as directory:
            database_path = Path(directory) / "test.kdbx"
            database = create_database(str(database_path), password="test-password")
            entry = database.add_entry(
                database.root_group, "Tabbed entry", "alice", "secret"
            )
            database.save()
            database = PyKeePass(str(database_path), password="test-password")
            entry = database.entries[0]

            attachments_window = FakeWindow(24, 100)
            draw_entry_details(
                attachments_window, database, entry, False, 1, 5, 60, 18, tab=1
            )
            self.assertEqual(attachments_window.lines[(6, 1)], "1 General")
            self.assertEqual(attachments_window.lines[(8, 1)], "No attachments. Press a to add a file.")

            details_window = FakeWindow(24, 100)
            draw_entry_details(
                details_window, database, entry, False, 1, 5, 60, 18, tab=2
            )
            self.assertEqual(details_window.lines[(8, 1)], "ID")
            self.assertEqual(details_window.lines[(9, 1)], str(entry.uuid))

    def test_add_attachment_is_stored_and_persists(self):
        with tempfile.TemporaryDirectory() as directory:
            database_path = Path(directory) / "test.kdbx"
            attachment_path = Path(directory) / "document.txt"
            attachment_path.write_bytes(b"attachment contents")
            database = create_database(str(database_path), password="test-password")
            entry = database.add_entry(
                database.root_group, "Entry", "alice", "secret"
            )
            attachment = add_attachment_to_entry(database, entry, attachment_path)

            self.assertEqual(attachment.filename, "document.txt")
            self.assertEqual(attachment.binary, b"attachment contents")

            reopened = PyKeePass(str(database_path), password="test-password")
            saved_attachment = reopened.entries[0].attachments[0]
            self.assertEqual(saved_attachment.filename, "document.txt")
            self.assertEqual(saved_attachment.binary, b"attachment contents")

    def test_attachment_shortcut_adds_file_from_attachments_tab(self):
        with tempfile.TemporaryDirectory() as directory:
            database_path = Path(directory) / "test.kdbx"
            attachment_path = Path(directory) / "document.txt"
            attachment_path.write_bytes(b"attached from TUI")
            database = create_database(str(database_path), password="test-password")
            database.add_entry(database.root_group, "Entry", "alice", "secret")
            database.save()
            database = PyKeePass(str(database_path), password="test-password")
            window = FakeInputWindow(24, 100, ["2", "a", "q"])

            with patch("main.curses.curs_set"), patch("main.curses.noecho"), patch(
                "main.curses.cbreak"
            ), patch("main.prompt_attachment_path", return_value=attachment_path):
                from main import run_tui

                run_tui(window, database)

            reopened = PyKeePass(str(database_path), password="test-password")
            attachment = reopened.entries[0].attachments[0]
            self.assertEqual(attachment.filename, "document.txt")
            self.assertEqual(attachment.binary, b"attached from TUI")

    def test_add_entry_form_collects_fields_and_masks_password(self):
        keys = [
            "N", "e", "w", "\n",
            "a", "l", "i", "c", "e", "\n",
            "s", "e", "c", "r", "e", "t", "\n",
            "h", "t", "t", "p", "s", ":", "/", "/", "example", ".", "com", "\n",
            "n", "o", "t", "e", "s", "\n",
        ]
        window = FakeInputWindow(24, 100, keys)

        values = prompt_new_entry(window)

        self.assertEqual(
            values,
            {
                "Title": "New",
                "Username": "alice",
                "Password": "secret",
                "URL": "https://example.com",
                "Notes": "notes",
            },
        )
        self.assertTrue(all("secret" not in snapshot for snapshot in window.snapshots))

    def test_add_entry_shortcut_saves_entry_in_current_group(self):
        with tempfile.TemporaryDirectory() as directory:
            database_path = Path(directory) / "test.kdbx"
            database = create_database(str(database_path), password="test-password")
            group = database.add_group(database.root_group, "Mail")
            database.save()
            database = PyKeePass(str(database_path), password="test-password")
            window = FakeInputWindow(
                24,
                100,
                [
                    "\n",
                    "a",
                    "M", "a", "i", "l", "\n",
                    "a", "l", "i", "c", "e", "\n",
                    "s", "e", "c", "r", "e", "t", "\n",
                    "\n",
                    "\n",
                    "q",
                ],
            )

            with patch("main.curses.curs_set"), patch("main.curses.noecho"), patch(
                "main.curses.cbreak"
            ):
                from main import run_tui

                run_tui(window, database)

            reopened = PyKeePass(str(database_path), password="test-password")
            saved_group = next(group for group in reopened.groups if group.name == "Mail")
            self.assertEqual(len(saved_group.entries), 1)
            self.assertEqual(saved_group.entries[0].title, "Mail")
            self.assertEqual(saved_group.entries[0].username, "alice")
            self.assertEqual(saved_group.entries[0].password, "secret")

    def test_add_entry_form_requires_a_title(self):
        window = FakeInputWindow(
            24,
            100,
            ["\n", "\n", "\n", "\n", "\n", "T", "\n", "\n", "\n", "\n", "\n"],
        )

        values = prompt_new_entry(window)

        self.assertEqual(values["Title"], "T")
        self.assertTrue(any("Title is required." in snapshot for snapshot in window.snapshots))

    def test_add_entry_form_can_be_cancelled(self):
        window = FakeInputWindow(24, 100, ["\x1b"])

        self.assertIsNone(prompt_new_entry(window))

    def test_enter_on_entry_highlights_the_already_visible_details_pane(self):
        with tempfile.TemporaryDirectory() as directory:
            database_path = Path(directory) / "test.kdbx"
            database = create_database(str(database_path), password="test-password")
            database.add_entry(database.root_group, "Entry", "alice", "secret")
            database.save()
            database = PyKeePass(str(database_path), password="test-password")
            window = FakeInputWindow(24, 100, ["\n", "q"])
            focus_states = []

            def record_draw(stdscr, database, group, items, query, selected, offset,
                            reveal_password, status="", searching=False,
                            details_focused=False, detail_tab=0):
                focus_states.append(details_focused)
                return 0

            with patch("main.curses.curs_set"), patch("main.curses.noecho"), patch(
                "main.curses.cbreak"
            ), patch("main.draw_list", side_effect=record_draw):
                from main import run_tui

                run_tui(window, database)

            self.assertEqual(focus_states, [False, True])

            items = [("entry", database.entries[0])]
            draw_list(window, database, database.root_group, items, "", 0, 0, False,
                      details_focused=True)
            self.assertIn("DETAILS  [FOCUSED]", " ".join(window.lines.values()))
            self.assertTrue(window.attrs[(3, 38)] & curses.A_REVERSE)

    def test_help_screen_shows_shortcuts_without_listing_them_in_main_header(self):
        window = FakeWindow(30, 100)
        draw_help(window)

        displayed = " ".join(window.lines.values())
        for shortcut in ("Enter", "Backspace", "Ctrl+U", "u", "w", "l", "t", "q"):
            self.assertIn(shortcut, displayed)

    def test_help_shortcut_opens_and_closes_without_exiting(self):
        with tempfile.TemporaryDirectory() as directory:
            database_path = Path(directory) / "test.kdbx"
            database = create_database(str(database_path), password="test-password")
            database.save()
            database = PyKeePass(str(database_path), password="test-password")
            window = FakeInputWindow(24, 100, ["?", "\x1b", "q"])
            draw_calls = []
            help_calls = []

            def record_draw(*args, **kwargs):
                draw_calls.append(True)
                return 0

            with patch("main.curses.curs_set"), patch("main.curses.noecho"), patch(
                "main.curses.cbreak"
            ), patch("main.draw_list", side_effect=record_draw), patch(
                "main.draw_help", side_effect=lambda *args: help_calls.append(True)
            ):
                from main import run_tui

                run_tui(window, database)

            self.assertEqual(len(help_calls), 1)
            self.assertEqual(len(draw_calls), 2)

    def test_search_filters_during_typing_and_accepts_or_cancels(self):
        with tempfile.TemporaryDirectory() as directory:
            database_path = Path(directory) / "test.kdbx"
            database = create_database(str(database_path), password="test-password")
            database.add_entry(database.root_group, "Alpha", "alice", "secret")
            database.add_entry(database.root_group, "Beta", "bob", "secret")
            database.save()
            database = PyKeePass(str(database_path), password="test-password")
            window = FakeInputWindow(
                24,
                100,
                ["/", "a", "l", "\x7f", "l", "\n", "/", "z", "\x1b", "q"],
            )
            rendered_queries = []

            def record_draw(stdscr, database, group, items, query, *args):
                rendered_queries.append(
                    (
                        group.name,
                        query,
                        [item.name if kind == "group" else item.title for kind, item in items],
                    )
                )
                return 0

            with patch("main.curses.curs_set"), patch("main.curses.noecho"), patch(
                "main.curses.cbreak"
            ), patch("main.draw_list", side_effect=record_draw):
                from main import run_tui

                run_tui(window, database)

            self.assertIn(("Root", "a", ["Alpha", "Beta"]), rendered_queries)
            self.assertIn(("Root", "al", ["Alpha"]), rendered_queries)
            self.assertIn(("Root", "alz", []), rendered_queries)
            self.assertEqual(rendered_queries[-1], ("Root", "al", ["Alpha"]))

    def test_reads_otpauth_uri_and_custom_totp_seed(self):
        with tempfile.TemporaryDirectory() as directory:
            database_path = Path(directory) / "test.kdbx"
            database = create_database(str(database_path), password="test-password")
            uri = pyotp.TOTP("JBSWY3DPEHPK3PXP").provisioning_uri(
                name="alice", issuer_name="Example"
            )
            uri_entry = database.add_entry(
                database.root_group, "URI TOTP", "alice", "password", otp=uri
            )
            seed_entry = database.add_entry(
                database.root_group, "Seed TOTP", "bob", "password"
            )
            seed_entry.set_custom_property("TimeOtp-Secret-Base32", "JBSWY3DPEHPK3PXP")
            database.save()

            database = PyKeePass(str(database_path), password="test-password")
            uri_entry, seed_entry = database.entries

            self.assertEqual(
                entry_totp(uri_entry).at(1234567890),
                pyotp.TOTP("JBSWY3DPEHPK3PXP").at(1234567890),
            )
            self.assertEqual(
                entry_totp(seed_entry).at(1234567890),
                pyotp.TOTP("JBSWY3DPEHPK3PXP").at(1234567890),
            )

    def test_copies_value_to_detected_clipboard_utility(self):
        with patch("main.sys.platform", "darwin"), patch(
            "main.shutil.which", return_value="/usr/bin/pbcopy"
        ) as which:
            with patch(
                "main.subprocess.run",
                return_value=SimpleNamespace(returncode=0, stderr=""),
            ) as run:
                copy_to_clipboard("copied-value")

        which.assert_called_once_with("pbcopy")
        run.assert_called_once_with(
            ("pbcopy",),
            input="copied-value",
            text=True,
            capture_output=True,
            check=False,
            timeout=5,
        )

    def test_matches_searchable_fields_case_insensitively(self):
        with tempfile.TemporaryDirectory() as directory:
            database_path = Path(directory) / "test.kdbx"
            database = create_database(str(database_path), password="test-password")
            database.add_entry(
                database.root_group,
                "Mail",
                "alice",
                "secret",
                url="https://example.com",
                notes="Personal account",
            )
            database.save()

            database = PyKeePass(str(database_path), password="test-password")
            entry = database.entries[0]
            self.assertTrue(entry_matches(database, entry, "MAIL"))
            self.assertTrue(entry_matches(database, entry, "ALICE"))
            self.assertTrue(entry_matches(database, entry, "example.com"))
            self.assertTrue(entry_matches(database, entry, "personal"))
            self.assertFalse(entry_matches(database, entry, "missing"))

    def test_resolves_field_references_for_display_and_search(self):
        with tempfile.TemporaryDirectory() as directory:
            database_path = Path(directory) / "test.kdbx"
            database = create_database(str(database_path), password="test-password")
            source = database.add_entry(
                database.root_group, "Source", "source-user", "source-password"
            )
            reference = database.add_entry(
                database.root_group,
                "Reference",
                source.ref("username"),
                source.ref("password"),
                url=source.ref("title"),
            )
            database.save()

            database = PyKeePass(str(database_path), password="test-password")
            reference = next(entry for entry in database.entries if entry.title == "Reference")

            self.assertEqual(resolved_value(database, reference.username), "source-user")
            self.assertEqual(resolved_value(database, reference.password), "source-password")
            self.assertEqual(resolved_value(database, reference.url), "Source")
            self.assertTrue(entry_matches(database, reference, "source-user"))

    def test_selected_entry_appears_in_right_pane_with_password_masked(self):
        with tempfile.TemporaryDirectory() as directory:
            database_path = Path(directory) / "test.kdbx"
            database = create_database(str(database_path), password="test-password")
            database.add_entry(
                database.root_group, "Selected entry", "alice", "secret-password"
            )
            database.save()
            database = PyKeePass(str(database_path), password="test-password")
            window = FakeWindow(24, 100)

            items = [("entry", entry) for entry in database.entries]
            draw_list(window, database, database.root_group, items, "", 0, 0, False)

            self.assertEqual(window.lines[(5, 38)], "Selected entry")
            self.assertEqual(window.lines[(9, 38)], "alice")
            self.assertNotIn("secret-password", " ".join(window.lines.values()))
            self.assertIn("press p to reveal", " ".join(window.lines.values()))

    def test_narrow_terminal_stacks_details_below_the_list(self):
        with tempfile.TemporaryDirectory() as directory:
            database_path = Path(directory) / "test.kdbx"
            database = create_database(str(database_path), password="test-password")
            database.add_entry(
                database.root_group, "Selected entry", "alice", "secret-password"
            )
            database.save()
            database = PyKeePass(str(database_path), password="test-password")
            window = FakeWindow(24, 60)
            items = [("entry", entry) for entry in database.entries]

            draw_list(window, database, database.root_group, items, "", 0, 0, False)

            self.assertEqual(window.lines[(12, 1)], "DETAILS")
            self.assertEqual(window.lines[(14, 1)], "Selected entry")
            self.assertNotIn("|", window.lines.values())
            self.assertNotIn("secret-password", " ".join(window.lines.values()))

    def test_current_totp_is_shown_in_right_pane(self):
        with tempfile.TemporaryDirectory() as directory:
            database_path = Path(directory) / "test.kdbx"
            database = create_database(str(database_path), password="test-password")
            uri = pyotp.TOTP("JBSWY3DPEHPK3PXP").provisioning_uri(
                name="alice", issuer_name="Example"
            )
            database.add_entry(
                database.root_group, "TOTP entry", "alice", "password", otp=uri
            )
            database.save()
            database = PyKeePass(str(database_path), password="test-password")
            window = FakeWindow(24, 100)

            items = [("entry", entry) for entry in database.entries]
            draw_list(window, database, database.root_group, items, "", 0, 0, False)

            displayed = " ".join(window.lines.values())
            self.assertIn("TOTP", displayed)
            self.assertIn(entry_totp(database.entries[0]).now(), displayed)

    def test_group_navigation_keeps_child_entries_in_their_group(self):
        with tempfile.TemporaryDirectory() as directory:
            database_path = Path(directory) / "test.kdbx"
            database = create_database(str(database_path), password="test-password")
            database.add_entry(database.root_group, "Root entry", "root", "secret")
            child = database.add_group(database.root_group, "Child")
            database.add_entry(child, "Child entry", "child", "secret")
            database.save()
            database = PyKeePass(str(database_path), password="test-password")
            window = FakeInputWindow(24, 100, ["\n", "\n", "\x7f", "q"])
            rendered = []

            def record_draw(stdscr, database, group, items, *args):
                rendered.append(
                    (
                        group.name,
                        [
                            item.name if kind == "group" else item.title
                            for kind, item in items
                        ],
                    )
                )
                return 0

            with patch("main.curses.curs_set"), patch("main.curses.noecho"), patch(
                "main.curses.cbreak"
            ), patch("main.draw_list", side_effect=record_draw):
                from main import run_tui

                run_tui(window, database)

            self.assertIn(("Root", ["Child", "Root entry"]), rendered)
            self.assertIn(("Child", ["Child entry"]), rendered)

    def test_escape_goes_to_parent_and_does_not_quit_at_root(self):
        with tempfile.TemporaryDirectory() as directory:
            database_path = Path(directory) / "test.kdbx"
            database = create_database(str(database_path), password="test-password")
            child = database.add_group(database.root_group, "Child")
            database.add_entry(child, "Child entry", "child", "secret")
            database.save()
            database = PyKeePass(str(database_path), password="test-password")
            window = FakeInputWindow(24, 100, ["\x1b", "\n", "\x1b", "q"])
            rendered_groups = []

            def record_draw(stdscr, database, group, items, *args):
                rendered_groups.append(group.name)
                return 0

            with patch("main.curses.curs_set"), patch("main.curses.noecho"), patch(
                "main.curses.cbreak"
            ), patch("main.draw_list", side_effect=record_draw):
                from main import run_tui

                run_tui(window, database)

            self.assertEqual(rendered_groups, ["Root", "Root", "Child", "Root"])

    def test_opens_database_with_master_password_and_keyfile(self):
        with tempfile.TemporaryDirectory() as directory:
            database_path = Path(directory) / "test.kdbx"
            keyfile_path = Path(directory) / "database.key"
            keyfile_path.write_bytes(bytes(range(32)))

            create_database(
                str(database_path),
                password="test-password",
                keyfile=str(keyfile_path),
            )
            database = PyKeePass(
                str(database_path),
                password="test-password",
                keyfile=str(keyfile_path),
            )

            self.assertEqual(database.entries, [])


if __name__ == "__main__":
    unittest.main()

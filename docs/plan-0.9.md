# Plan for 0.9.0 (one home per job)

Agreed with the owner on 19 Nov 2026, after 0.8.2. It comes from a feature audit of every page, tab, menu, dialog and
the IPC behind them. The labels C1 to C17 (the audit's overlap clusters) and G1 to G11 (its gaps) say where each item
came from.

## Why

After 0.8.2 the app has the features it needs; the friction is how they are spread out:
- two implementations of one screen (two file browsers on the same connection);
- too many ways in for one job (three host pickers, two results lists and four homes for bulk work on four pages);
- two concepts for one need (stars on commands beside favourites, saved groups beside tags);
- controls repeated in a second or third place.

0.6.0 fixed the same kind of drift for 0.5.0; this plan does it for what 0.7.0 and 0.8.0 added.

0.9.0 changes **where things are and how many ways there are to do them**. The engines stay: the bus commands, tiers,
approvals and audit entries are as they are. Nothing is removed but stars on commands, Settings' copies of the
Presentation and Vault controls, and the third "Reset the vault…". New behaviour is limited to the gaps the audit
found and the owner chose: a drop that pushes to every picked host, a typed line kept as a run, the idle lock as a
setting, and running a command on the Sessions and VMs pages' picks.

## Decisions

| Question | Decision |
| --- | --- |
| Dragging files from Explorer onto an SSH terminal | **Unchanged (the owner's constraint).** A drop on a terminal pane uploads into that terminal's folder through the path it takes today: `lib.rs` `WindowEvent::DragDrop` → `files::dropped` → core `stage` → `files://dropped` → `TerminalPage` `paneAt` → `uploadStaged` → `files_upload` → `Command::FileUpload`, Low, a Prod session one higher, never as root. H1 pins it with a test before anything else moves. |
| Files here and the Files page's host pane (C1) | **Agreed. One component.** The drawer becomes the compact mode of the Files page's host pane: one row menu, one double-click setting, the editing list, find, preview, checksums and bookmarks in both. "Open in Files" becomes "Expand". Following the shell's folder and "Transfers as alice" stay on in compact mode. |
| Double-click on a file | **Agreed.** One setting for both places (Settings › Terminal's "Double-clicking a file in Files here" becomes "Double-clicking a file" under Files), defaulting as now to a terminal editor on the host. Preview stays in the row menu. |
| Where the Files page opens (C2) | **Agreed.** On its first host tab, or an empty state with "Open a host"; Many hosts stays a tab, no longer the default. |
| Dropping files while Type in all tabs is on (G1) | **Agreed.** The drop asks: "Upload to <tab>'s folder" (the default, today's behaviour) or "Push to the N picked hosts" (one BX-10 push into one folder, filled in with the current tab's folder). Without typing on, nothing changes. |
| Picking hosts (C5) | **Agreed.** One picker, `BulkTargetPicker`, for every bulk job, Compare hosts included; it opens already filled with the picked tabs and the tree's picks, so the quick path stays one step. |
| Saved MultiExec groups (QL-19) | **Agreed: keep and widen.** A group becomes a pick in every picker; Open group and Select group move to the typing bar's "Pick tabs ▸" and the palette. Groups keep their order and FD-07's format. |
| Compare hosts' results (C4) | **Agreed.** One list: one-shot runs and typed lines together, newest first, badged "Run on 12 hosts" or "Typed in 6 tabs"; the One-shot run / Type in all tabs view switch goes. Retry and the canary show only on runs; a typed line says why it has none. |
| Keeping a typed line (G5) | **Agreed.** "Keep this line" stores a recorded line as a run: its output as the journal stores a Compare run's (scrubbed as today, BX-02's retention), audited without the output. Until it is kept, a recording lives in memory and goes when typing stops, as today. |
| Bulk jobs in Activity (C6) | **Agreed.** Activity opens a remote exec, push or fetch, support bundle or key push job in the grouped results view (groups, diff, retry the failed hosts, export) instead of the raw per-host sheet; job notifications lead there. Compare hosts' "Earlier runs…" stays as a shortcut. |
| A command on picked sessions or VMs (G3) | **Agreed.** "Run a command on these…" on the Sessions page's selection bar and the VMs page's More › Organise, opening Compare hosts with those picks (VMs through their confirmed links, as BX-01 says). |
| Monitoring setup (C9) | **Agreed.** Alert rules open from the Dashboard header's ⋯ and the palette, not only from the Alerts widget. Rows and the palette get **Monitor ▸** (Watch its metrics, Add a check), and "Add a check" leaves the Toolbox submenu. A Toolbox result offers "Keep checking this…". |
| Reachability dots from checks | **Later, not in 0.9.0** unless the owner asks: a session whose host and port a check already covers would show the check's state instead of knocking again. |
| Commands: favourites and stars (C7) | **Agreed.** No stars in the Commands panel. A library row's star becomes "Add to favourites" (into a "Starred" folder); existing command stars move there once, audited as favourite adds. Stars stay on sessions and VMs. |
| Reports (C11) | **Agreed.** Activity ⋯ › **Reports ▸** holds the handover pack, the inventory (Excel) and the audit log (CSV). The Sessions page keeps Import from another app, **Move to another laptop ▸** (Export, Import), the Ansible inventory and the support bundle. One label per action everywhere. |
| Disk images (C13) | **Agreed.** Inspect, Convert and Verify move from the Templates page to a Toolbox tab; `MOVED_PAGES` keeps Ctrl+; and the old id. |
| Repeated controls (C14 to C16) | **Agreed.** Presentation: the top bar is the home, the palette the shortcut, and Settings shows one line with a link. Vault: "Reset the vault…" in the ⋯ menu and the locked form only; Settings' Vault card goes, and the settings search points at the Vault page's Unlocking card. The Waste finder uses the Schedules page's stored chain limits. One "recent" list (QL-26's) feeds the tree, the New terminal dialog and Ctrl+K. |
| The vault's idle lock (G11, SS-04) | **Agreed.** A setting for this PC (`settings::MACHINE_KEYS`), 1 to 60 minutes, 15 by default as SS-04 says; today it is a fixed constant (`vault/local.rs` `IDLE_TIMEOUT`). |
| Scheduled command runs and support bundles (G7, PRD BX-11) | **Not in 0.9.0** unless the owner asks: it needs a standing approval for commands, which no schedule has today. |
| Requirement IDs | The declutter prefix continues (**UX-14** to **UX-22**); new comfort items continue `QL-xx` (**QL-30** to **QL-32**); PRD IDs where one exists (BX-01, SS-04). Commit messages start with them. |
| UI rules | **Unchanged.** UX-01 to UX-13 apply to everything moved; a moved action keeps one home plus the palette (UX-03). |
| Releases | **Agreed. One release, 0.9.0**, when H1 to H8 are merged (H6 and H7 included). |

## Requirements

| ID | What | Audit | Package |
| --- | --- | --- | --- |
| UX-14 | One host file pane: Files here is the compact mode of the Files page's host pane; one double-click setting; a drop on the drawer uploads into the folder it shows | C1 | H1 |
| UX-15 | The Files page opens on a host; a drop on Many hosts fills the push; "Serve this over TFTP or HTTP…" on This PC's rows; Fetch and the support bundle link to each other | C2, C3, G6 | H1 |
| QL-30 | A drop on a terminal while Type in all tabs is on offers a push to the picked hosts | G1 | H6 |
| UX-16 | One host picker for every bulk job, Compare hosts included; saved groups as a pick, on the typing bar and in the palette | C5 | H2 |
| BX-01 | "Run a command on these…" on the Sessions and VMs selection | G3 | H2 |
| UX-17 | One results list in Compare hosts for runs and typed lines | C4 | H3 |
| UX-18 | Activity opens bulk jobs in the grouped results view, with retry, diff and export | C6, G2 | H3 |
| QL-31 | Keep a typed line as a run | G5 | H7 |
| UX-19 | Alert rules outside the widget; Monitor ▸ on rows and in the palette; "Keep checking this…" | C9, G4, G8 | H4 |
| UX-20 | Commands: favourites only, no stars | C7 | H5 |
| UX-21 | Reports in Activity; the Sessions page's ⋯ cut to sessions; one label per action | C11 | H5 |
| UX-22 | Repeats removed: Presentation and Vault cards, the third vault reset, one set of chain limits, one recent list, Disk images in the Toolbox, palette entries for install configs, address pools and workspaces, one qemu-img help key | C12 to C16, G9 | H5 |
| SS-04 | The vault's idle lock as a setting for this PC, 1 to 60 minutes, 15 by default | G11 | H5 |
| QL-32 | Reachability dots from checks (later, not in 0.9.0) | C9 | H9 |

## Approval tiers

The PRD's tier tables gain these rows. A Prod-labelled target moves an action up one tier, and protected targets are
skipped, as before.

| Action | Tier |
| --- | --- |
| Everything this plan moves or merges (the file pane, the picker, the results list, reports, Monitor ▸, Disk images) | **Unchanged**: the same commands, tiers and audit entries as today |
| A drop on an SSH terminal | **Unchanged**: an upload, Low; replacing a file at least Medium; never as root |
| A drop on the Files drawer | As the Files page's host pane today: an upload into the folder shown; as root one tier higher when the pane browses as root |
| A drop on Files › Many hosts, or "Push to the N picked hosts" after a drop on a terminal | A push (BX-10): Medium, High from the bulk threshold for commands on hosts (5) |
| A saved group used as a pick | A read: no tier, not audited |
| Run a command on picked sessions or VMs | As Compare hosts (BX-06): read-only Low; any other command Medium on up to 4 hosts, High from 5; a dangerous one High |
| Retry the failed hosts from Activity | As the run it retries: the same command resubmitted on the bus |
| Keep a typed line | No tier; audited (the line, the terminals, where it is kept; never the output); refused by the read-only lock |
| Move command stars into favourites | No tier; audited as favourite adds, once per workspace |
| Change the vault's idle lock | No tier; audited, refused by the read-only lock |

## Packages and order

Each package is one session and one pull request, in three waves:
1. **Now:** H1, H2, H4 and H8.
2. **Then:** H3 (after H2), H5 (after H2 and H4) and H6 (after H1).
3. **Last:** H7 (after H3).

H9 is not in 0.9.0. No migration is needed unless H7 keeps lines in a table of their own: **0040** is reserved for it
(the folder already skips 0038).

| # | Package | IDs | After | Migration |
| --- | --- | --- | --- | --- |
| H1 | One file pane, and the Files page's opening and drops | UX-14, UX-15 | now | none |
| H2 | One host picker; saved groups as picks; run on the selection | UX-16, BX-01 | now | none |
| H3 | One results list; bulk jobs in Activity | UX-17, UX-18 | H2 | none |
| H4 | Monitoring setup | UX-19 | now | none |
| H5 | Tidy: commands, reports, repeats, the idle lock | UX-20 to UX-22, SS-04 | H2, H4 | none |
| H6 | Drop to push while typing in all tabs | QL-30 | H1 | none |
| H7 | Keep a typed line | QL-31 | H3 | 0040 if needed |
| H8 | README catch-up for 0.8.0 | — | now | none |
| H9 | Reachability dots from checks (later, not in 0.9.0) | QL-32 | H4 | none |

**Shared files.** The later package merges main first, as in 0.5.0 and 0.8.0:
- `TerminalPage.tsx`: H1 (the drawer and the drop dispatch), H2 (the groups menu, the Compare panel's picks), H6 (the
  drop).
- The palette actions in `App.tsx`: H2, H4, H5.
- `SessionsPage.tsx`: H2 (the selection bar), H4 (the row menu), H5 (the ⋯ menu).
- `ComparePanel.tsx`: H2, then H3.
- `ToolboxPage.tsx`: H1 (the file server's fill-in), H5 (the Disk images tab).

## H1: one file pane (UX-14, UX-15)

- **First, pin the constraint.** Move the choice of which target gets a drop (a terminal pane, the Files drawer, a host
  pane or one of its folder rows, Many hosts, a VM row's ISO) out of the three `files://dropped` listeners into one
  pure function in `src/lib/`, with a node test. The test shows that a drop on a connected SSH pane uploads into that
  pane's shell folder (or its home) with `asRoot` false, whatever the drawer is doing. Each page keeps its own `active`
  check.
- **One component.** Take the Files page's host pane (`files/HostPane.tsx` with `FileTable`) as the base and give it:
  - the drawer's editing: Edit in the terminal, Edit on this PC, the terminal-editor choice and `EditingSessionsList`;
  - QL-09's handling of a folder that won't open and of a switched shell user;
  - following the shell's folder (OSC 7) and "Transfers as alice", on in compact mode.
- **The drawer.**
  - Mount the pane in compact mode in the Terminal's side panel and retire `FilesDrawer.tsx`'s own table.
  - Root state is read from `files_root_status` in both places.
  - "Open in Files" becomes "Expand", at the same folder.
  - A drop on the drawer uploads into the folder it shows; the upload conflict dialog is unchanged.
- **Double-click.** One setting for both places. Preview stays in the row menu, and a double-click previews when no
  editor is known.
- **The Files page.**
  - It opens on its first host tab, or on "No host open" with "Open a host". That empty state can't be seen today.
  - A drop on Many hosts fills Push's file list.
  - This PC's row menu gets "Serve this over TFTP or HTTP…", a `toolbox` link with the file server filled in.
  - Fetch gets "Collect a support bundle instead…", and the bundle dialog gets "Fetch one file from each…".
- **Done when:**
  - the drawer and the Files page show the same menu for the same file;
  - the drop test passes;
  - a hand check with `dev_ssh_server` covers a drop on a terminal, on the drawer, on a host pane and on Many hosts;
    editing from both places; and root browsing started in one place and seen in the other.

## H2: one host picker (UX-16, BX-01)

- **Core.** `TargetPicks` gains `group_ids`, a read resolved to the group's sessions in the shown workspace.
  - `bulk_targets` says "group 'web servers'" in each host's `via`.
  - `tests/workspaces.rs` gets a case for another workspace's group id being refused.
- **The picker.** `BulkTargetPicker` gains a Groups tab and a compact summary mode, so Compare hosts can show "12 hosts:
  6 picked tabs, folder 'Web', tag 'db'" with Change….
- **Compare hosts.** Its one-shot run uses the picker, opened with the picked tabs and the tree's picks. Ctrl+click in
  the tree and on tabs still adds picks.
- **Groups' menu.** Open group and Select group move from Terminal ⋯ › Saved groups to the typing bar's "Pick tabs ▸",
  with "Save picked tabs as a group…" and "Manage groups…". The palette gets "Open group: <name>".
- **Run on the selection.** "Run a command on these…" goes on the Sessions page's selection bar and in the VMs page's
  More › Organise. It opens the Terminal page's Compare hosts with those picks. VMs are reached through confirmed links
  only, and the picker says which VMs have none.
- **Done when:**
  - a Compare hosts run can target a tag, a saved filter, a group and picked VMs;
  - the rating per host and the protected-host skip match today's tests.

## H3: one results list (UX-17, UX-18)

- **Compare hosts.**
  - One list, newest first, of one-shot runs (`bulk_runs`) and recorded lines (`multiexec_recordings`).
  - Each opens the shared card: `GroupCard`, `HostOutputDialog`, `OutputDiffDialog` and export.
  - A recorded line says it goes when typing stops, and that it can't be retried (`WhyDisabled`).
  - The view switch goes.
- **Activity.**
  - A job of kind remote exec, bulk files, support bundle or SSH key push opens `BulkResultsView`, with grouping, diff,
    retry of the failed hosts and export. Other jobs keep the per-host sheet.
  - Job notifications and the status bar's jobs link go there.
  - The read-only notice's Activity line matches what Activity offers.
- **Done when:** a failed bulk job reached from its notification can be retried from Activity, and is rated again on
  the bus.

## H4: monitoring setup (UX-19)

- **Alert rules.**
  - "Alert rules…" in the Dashboard header's ⋯ on the Metrics tab, and "Alert rules" in the palette.
  - The status bar's alerts link opens the Alerts widget, or the rules sheet when the layout has no Alerts widget.
- **Monitor ▸** on session rows (the Sessions page and the tree), the VM details panel and the palette's VM and session
  views:
  - "Watch its metrics" (or "Stop watching") and "Add a check";
  - one line on what each costs: a login per poll, or a probe per interval;
  - "Add a check" leaves the Toolbox submenu.
- **"Keep checking this…"** on Ping, Check ports, Certificate and DNS results opens `CheckDialog` filled in.
- **Done when:** removing the Alerts widget leaves the rules reachable, and every "Add a check" entry point opens the
  same dialog.

## H5: tidy (UX-20 to UX-22, SS-04)

- **Commands (UX-20).**
  - The Commands panel loses its stars; a library row's star becomes "Add to favourites", into "Starred".
  - A one-time step in the core moves each workspace's command stars into favourites (library entries by their text and
    name), audits them as adds and deletes the stars. It isn't SQL, because the library lives in code.
- **Reports (UX-21).**
  - Activity ⋯ › Reports ▸ holds Handover pack…, Inventory (Excel)… and Audit log (CSV)….
  - The Sessions page's ⋯ keeps Import from another app, Move to another laptop ▸, Export an Ansible inventory… and
    Collect a support bundle….
  - Each action has one label on every menu and in the palette.
- **Repeats (UX-22).**
  - Settings' Presentation card becomes one line with a link; Settings' Vault card goes.
  - The Vault page keeps "Reset the vault…" in its ⋯ menu and on the locked form.
  - The Waste finder reads `schedule_chain_limits` for its defaults.
  - The tree's Recent group and the New terminal dialog read QL-26's recents (sessions only).
  - Disk images moves to a Toolbox tab (`MOVED_PAGES.images` points there).
  - The palette gets "New install config…", "New address pool…" and "Switch workspace…".
  - The qemu-img note becomes one help key.
- **The idle lock (SS-04).**
  - Settings › Privacy and data gets "Lock the vault after", 1 to 60 minutes, 15 by default.
  - It is kept in `settings::MACHINE_KEYS`; audited, and refused by the read-only lock.
  - The vault's idle timer and the status bar's countdown follow it.
  - Tests cover the bounds, a change while unlocked, and the setting staying with this PC across workspaces.
- **Small fixes the audit found.**
  - The Sessions page sorts starred first.
  - Its Host details checks the session kind, as the tree does.
  - The support bundle's help says which of its reads may use sudo (commands) and which never do (files).
  - `TemplatesPage.tsx`'s header comment lists today's tab order.
  - The unused per-widget chart range goes.

## H6: drop to push while typing in all tabs (QL-30)

- **The choice.** When Type in all tabs is on and more than one tab is picked, a drop on a terminal pane asks, with a
  small menu at the drop point:
  - "Upload to <tab>'s folder": the default, taken by Enter, today's path unchanged;
  - "Push to the N picked hosts…".
- **The push.**
  - It is `files_push` with `PushFrom::Staged` (the drop's staged id, which the core already takes) and the picked tabs
    as `TargetPicks.terminal_ids`.
  - The folder is filled in with the current tab's folder, and can be changed.
  - Its results show in the Compare hosts list (after H3) or in a notice.
- **Quick connections** can't be pushed to: they have no saved session. The menu says how many are left out.
- **Done when:**
  - H1's drop test still shows the default unchanged;
  - the push's approval names every host.

## H7: keep a typed line (QL-31)

- **What is kept.** "Keep this line" on a recorded line stores it as a run:
  - its line, terminals and sessions;
  - its exit state, where known;
  - each terminal's recorded output, already scrubbed.
- **How it is treated.**
  - It is kept under BX-02's job-output retention.
  - It shows in the results list and in Activity like a run, but without retry.
  - Keeping a line is audited, and refused by the read-only lock.
- **Where it is stored.** In the job journal if a "recorded line" job kind fits its constraints, else in a table of its
  own (migration 0040). Either way it is per workspace (rule 8), with a case in `tests/workspaces.rs`.

## H8: README catch-up (docs only)

- **New sections for 0.8.0:**
  - the Files page: two panes, bookmarks, find, preview, checksums, compare and sync, many hosts;
  - editing: Edit in the terminal, Edit on this PC;
  - install configs, address pools and golden images.
- **"File transfer in the terminal"** catches up with folders, root browsing and the transfer queue.
- **Shortcuts follow `navigation.ts`:** Templates Ctrl+2 (README says Ctrl+9), Containers Ctrl+6 (README says Ctrl+3),
  and Image tools as a Templates tab.
- Later packages update README for their own changes, as usual.

## H9: reachability dots from checks (QL-32, later)

Not in 0.9.0 unless the owner asks.
- **What changes.** A session whose host and port an active check covers (a TCP port check, or a ping for the host)
  shows the check's last state instead of knocking; the tooltip names the check.
- **What stays.** Sessions without such a check are knocked as today.
- **Reads only.** README "Reachability dots" says what changes in the host's logs.

## Development safety for 0.9.0

- **Core rules.** 0.9.0 moves UI and adds small paths onto existing commands. A package that finds it must change a
  core rule (a tier, an approval step, an audit entry) says so in its PR and keeps the existing tests passing unchanged.
- **The drop.** H1's drop-target test and the core's staging and upload tests (`crates/core/tests/files.rs`,
  `files_page.rs`) must pass at every package's head. Every package that touches `TerminalPage.tsx` includes a hand
  check of a drop onto a terminal with `dev_ssh_server`.
- **Hand checks.** They use demo data only:
  - a temp `REMOTELY_DATA_DIR`;
  - `dev_ssh_server` with its SFTP folder, Telnet and WinRM stand-ins;
  - stand-in `vmrun` and `VBoxManage`.
  Never the owner's VMs or hosts. Screenshots stay out of the repo.

## Not in 0.9.0 unless the owner asks

- Reachability dots from checks (H9).
- Scheduled command runs and support bundles (BX-11).
- One "Run on hosts…" sheet for every bulk job.
- Merging the Sessions page into the Terminal page.
- Dragging from a host pane out to Explorer.
- "Keep a folder up to date" (0.8.0 deferred it).
- Email, Teams or Slack alerts.
- Anything that removes Type in all tabs, Compare hosts, push and fetch, the support bundle or the quick file server:
  the audit found each does a job the others don't.

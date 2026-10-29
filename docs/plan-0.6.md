# Plan for 0.6.0 (declutter) and 0.7.0 (features)

Agreed with the owner on 30 Oct 2026, after 0.5.0. The owner's words: the app has "too many unorganized buttons and too
much text/prose"; it should be decluttered, and easy to understand without a manual. 0.6.0 changes how the app looks
and reads, not what it can do: no feature is removed, and every safety step (tiers, approvals, the vault password asked
again, presentation mode) stays. 0.7.0 then adds the feature groups the owner picked, built on 0.6.0's patterns.

Requirement IDs: the declutter gets its own prefix (`UX-xx`); 0.7.0 uses the PRD's IDs where they exist (FD-04, FD-05,
FD-06, FD-08, FD-09, MO-05, MO-08, SS-12, BX-12) and continues `QL-xx` for the rest. Commit messages start with them.

## What the audit found (0.5.0, 30 Oct 2026)

Screenshots of every page and dialog with demo data, and an inventory of the UI code:

- 452 buttons, 148 menu items and 74 alerts in the UI; the VMs page shows 19 buttons above the first VM (three rows,
  a bulk bar that is there, disabled, with nothing selected); the Terminal page's 16 toolbar icons squeeze the open
  tabs to about 50 px.
- 121 paragraphs of explanation shown by default (about 24,000 characters); Settings › General is 5 screens and about
  700 words with 5 separate Save buttons; Settings › Approval rules is 195 controls on a 5,000 px page; the approval
  dialog, which opens before every risky action, holds the most text of any component.
- The same action in several places (Compare output 4, snapshot, power, resize and Tools actions in both the VMs
  toolbar and the details panel) and the same explanation in several places (Windows unlock 5 times, presentation mode
  about 8).
- Internal requirement codes and jargon on screen ("Do not touch (AP-04)", "(AP-06)", "medium -> high", "chain 0
  deep"); terms explained only in a paragraph elsewhere (tiers, Prod, MultiExec, golden VM, launch template, standing
  approval, workspace).
- Dead ends: Deploy with no template says so but offers no way to make one; Templates opens on a disabled button;
  Containers opens on a red error when Docker Desktop isn't running.
- No shared page header, row-action, help or tooltip pattern; seven different names for "refresh"; page titles that
  differ from the sidebar.

## Decisions

| Question | Decision |
| --- | --- |
| Pages | **Group and merge.** The sidebar has three groups: **Machines** (Virtual machines, Templates, Schedules), **Remote** (Sessions, Terminal, Containers) and **Overview** (Dashboard, Activity), with Vault and Settings at the bottom. Image tools becomes a Templates tab ("Disk images"), the Map a Dashboard tab, Known hosts a Vault tab. Page shortcuts follow the sidebar's order; old shortcuts keep working where they don't clash (as `MOVED_PAGES` does for Snapshots). |
| Wording | **Plain names and hover help.** One name per concept: Protect/Do not touch → **Protected**; Label/Environment label → **Environment**; Compare output → **Compare hosts**; MultiExec → **Type in all tabs** (in text; the feature keeps its ID); page titles match the sidebar; one refresh icon with a "Refresh" tooltip. No requirement ID appears in any user-facing string. Every remaining term (tiers, Prod, golden VM, launch template, stack, standing approval, workspace, safety snapshot, change ID...) gets a hover definition, written once. |
| Help | **Hints, popovers, empty states; no tour.** A "?" next to each page title and on any control that needs more than its label; hover definitions on terms; at most one line of help text visible by default; one-time tips the user dismisses (reset in Settings); empty states that say what the space is for and offer the one action that fills it. |
| Safety | Unchanged. Tiers, approval steps, countdowns, safety snapshots, AP-06 and the read-only lock work exactly as in 0.5.0; only how the dialogs read changes. Type-to-confirm (AP-03) stays, asking for a VM's name instead of a count of 1. |
| Releases | **0.6.0** when U1 to U5 are merged; **0.7.0** when F1 to F4 are merged. |

## UX requirements (0.6.0)

- **UX-01 Page header.** One shared header per page: title (as in the sidebar), a "?" help popover, search and filters
  where the page has a list, at most one primary action (filled), and everything else in one "Tools" or "⋯" menu.
- **UX-02 Selection and rows.** Bulk actions show only when rows are selected, in a selection bar that replaces the
  search row ("2 selected · Start · Shut down · Snapshot · ⋯ · ✕"). Every list has the same row "⋯" menu (one trigger
  size, one label pattern); a row's main action may also be its click or a hover icon, never a third copy.
- **UX-03 One home per action.** Each action lives in one place, plus the Ctrl+K palette. The audit's duplicates go
  (Compare hosts, snapshot actions, power in the details panel, Tools install, resize, Open a shell, output actions,
  Watch on the dashboard, Deploy on template rows).
- **UX-04 Help text budget.** At most one line of help visible by default per card, dialog or empty state; longer
  explanations live in "?" popovers (`HelpTip`), written once in a help registry and referenced by key, so the
  duplicates collapse to one text each. Shortcut lists live in the shortcut sheet (Ctrl+/), not in page footers.
- **UX-05 Terms.** A glossary of the app's terms with a one-sentence definition each; a `Term` component underlines a
  term lightly and shows the definition on hover or focus. The palette can search the glossary.
- **UX-06 Plain words.** The renames above; no requirement IDs on screen (a test fails the build on one); status lines
  in plain words ("2 snapshots · OK", rules in a tooltip); event codes in Activity shown as words.
- **UX-07 No dead ends.** Every empty state names the space and offers its action ("Add an image" opens the image
  dialog); a disabled control says why next to it; no page opens on an error (Containers opens on the first host that
  answers, This PC shows "not running" quietly); Templates opens on the first step that isn't done.
- **UX-08 Navigation.** The grouped sidebar and page merges above; shortcuts in sidebar order; the sidebar's status
  rows (vault, Workstation, VirtualBox) show only when something needs attention, since the status bar has them.
- **UX-09 Tips.** One-time tips per page (dismissed per user, kept in the window's local storage), shown where a first
  use needs one (picking several tabs, the selection bar, Customize); Settings resets them.
- **UX-10 Settings.** Sections in a side list with a search box (the existing settings index); one save model:
  changes save at once with a quiet "Saved" and Undo where it matters; the tool paths in one table ("vmrun · found ·
  Change"); Approval rules opens on a summary ("Default rules · 0 changed") with the tier table and the
  dangerous-command patterns under "Advanced".
- **UX-11 Approval dialog.** Summary first: the action, the targets, the tier with one plain reason ("High: db-01 is
  Prod") and a "Why?" popover; the impact table and warnings below, folded when long; one field for the reason or
  change ID (AP-08's rule still requires it for Prod when a workspace says so); the countdown and safety snapshot as
  today.
- **UX-12 Effective environment.** Wherever a session or VM shows its environment, it shows the one that applies, and
  where it comes from when it isn't its own ("Prod · from VM db-01", "Prod · from folder Production"), so a Medium
  approval is never a surprise.
- **UX-13 Visual consistency.** Three button variants (primary, secondary, ghost) and two sizes; one primary per view;
  icons with tooltips; the same tab style everywhere.

## Packages and order (0.6.0)

U1 first, alone: it makes the shared pieces and the navigation every other package uses. U2 to U5 then run at the same
time, each owning its pages.

| # | Package | IDs | After |
| --- | --- | --- | --- |
| U1 | Foundations and navigation | UX-01, UX-04 to UX-06, UX-08, UX-09, UX-13 | now |
| U2 | Machines: VMs, Templates (with Disk images), Schedules | UX-02, UX-03, UX-07 | U1 |
| U3 | Remote: Terminal and Sessions | UX-02, UX-03, UX-07, UX-12 | U1 |
| U4 | Settings, Vault (with Known hosts), approvals, first run | UX-10, UX-11, UX-07 | U1 |
| U5 | Overview and the rest: Dashboard (with Map), Activity, Containers, palette, notifications | UX-02, UX-03, UX-07 | U1 |

### U1: foundations and navigation
- Shared components: `PageHeader`, `HelpTip` and the help registry (`src/lib/help.ts`), `Term` and the glossary
  (`src/lib/glossary.ts`), `SelectionBar`, `RowMenu`, an empty-state pattern on shadcn's, `Tip` (one-time tips).
- The grouped sidebar, the page merges' navigation (Image tools, Map and Known hosts keep their page components, shown
  as tabs of their new homes), shortcuts in sidebar order, old ones mapped.
- The renames and the requirement-ID test across all UI strings; one refresh label; titles that match the sidebar;
  the sidebar status rows only when needed.
- The UI rules written down in CLAUDE.md (Conventions): header, one primary, selection bar, row menu, help budget,
  terms, empty states, button variants and sizes, copy style (sentence case, verb-first buttons, no requirement IDs).

### U2: Machines
- VMs: one header (New VM ▾ for Add, Deploy, Clone and Import; Tools ▾ for Networks and Waste finder), the selection
  bar, a compact table (path in a tooltip and the details panel, Tools in the state badge, a column picker), the More
  menu cut to what applies, grouped (Power, Snapshots, Organise). VM details: about 5 tabs (Overview with System,
  Snapshots, Settings, Log, Activity with Timeline and Schedules), the actions palette without repeats, a resizable
  split.
- Templates: tabs in order (Images, Sizes, Launch templates, Stacks, Disk images), opening on the first step not done;
  empty states with their action; Deploy in one place per row.
- Deploy, Clone, Import and Export dialogs, the Schedules page and stack rows to the same rules.

### U3: Remote
- Terminal: tabs on their own full-width row; about 5 toolbar icons (New, Split, Type in all tabs, Files, ⋯); the rest
  in the ⋯ menu or the pane's right-click menu; one slim bar for typing in all tabs and the picked tabs' actions; Files,
  Compare hosts and Commands share one side panel; the session tree folds while panes are open; no footer.
- Sessions: the session editor's basics first (name, host, port, user, login, folder, environment) and the rest under
  Advanced; the import menu and dialog; folder defaults; UX-12 in the list, the tree and the tab chips.

### U4: Settings, Vault, approvals, first run
- Settings: UX-10 in full; the terminal, presentation, retention, dashboard and update cards to the help budget.
- Vault with a Known hosts tab; one place for the Windows-unlock setting and its warning; one primary action.
- The approval dialog (UX-11), the vault-password dialog, the change ID, the workspace switcher's copy, the first-run
  wizard (correct step count, tools shown as "found ✓ · Change", Finish alone on the last step).

### U5: Overview and the rest
- Dashboard with a Map tab: widgets sized to their content, one time range, the round's timing in a tooltip, the
  "Host key" badge a link to trusting the key.
- Activity: jobs grouped with their audit entries folded, plain event names, filters (target, kind, date), the audit
  log as a second view.
- Containers: UX-07's opening, the selection bar, one "Open a shell".
- The Ctrl+K palette: navigation and "New..." first; bulk destructive actions only when typed for; the glossary.
- The notification centre and status bar to the help budget.

## Features (0.7.0)

Planned in detail when 0.6.0 ships; in scope now, as picked by the owner:

| # | Package | IDs |
| --- | --- | --- |
| F1 | Toolbox and health checks: ping, traceroute, DNS lookup, port check, certificate viewer and expiry, Wake-on-LAN; HTTP, TCP and service checks with history and MO-07 alerts | FD-09, MO-08 |
| F2 | Windows and network gear: RDP through `mstsc` with a generated .rdp file, PowerShell remoting (WinRM), Windows guest metrics, serial (COM) and Telnet consoles | SS-12, MO-05 |
| F3 | Notes and everyday comfort: markdown notes and runbooks per host and VM, favourites and recents, a 30-day trash with restore for sessions, snippets and templates, bulk edit of sessions | FD-06, QL-26 to QL-28 |
| F4 | Handover and reports: a customer handover pack (inventory, topology, what was done, from the audit log, secrets redacted), inventory export to Excel, Ansible inventory export, a support bundle collected from many hosts | FD-08, FD-05, BX-12, FD-04 |

Every 0.7.0 action that changes something goes through the bus with a tier, as always; the plan for 0.7.0 sets them.

## Development safety for 0.6.0

- 0.6.0 changes the UI, not the core's behaviour: a package that finds it must change a core rule (a tier, a step, an
  audit entry) says so in its PR and keeps the existing tests passing unchanged.
- Hand checks use demo data only, as in the 0.5.0 audit: a temp `REMOTELY_DATA_DIR`, a temp `APPDATA` with a demo
  Workstation library, stand-in `vmrun` and `VBoxManage` that answer reads only, and `dev_ssh_server`. Never the
  owner's VMs or hosts. Screenshots stay out of the repo (they show this PC's own details).

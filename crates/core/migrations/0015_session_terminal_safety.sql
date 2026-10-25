-- 0.4.1: what a terminal types into a session's shell by itself (SS-01, SS-08).
--
-- sessions.prompt_hook
--   SS-08: the folder prompt hook typed into bash and zsh. NULL follows Settings (on by default, off for a
--   Prod-labelled session); 1 always, 0 never.
-- sessions.startup_on_reconnect
--   SS-01: type the startup command again after an automatic reconnect. Off by default: it is typed once
--   per connection the user opens, never again by itself.

ALTER TABLE sessions ADD COLUMN prompt_hook INTEGER CHECK (prompt_hook IN (0, 1));
ALTER TABLE sessions ADD COLUMN startup_on_reconnect INTEGER NOT NULL DEFAULT 0 CHECK (startup_on_reconnect IN (0, 1));

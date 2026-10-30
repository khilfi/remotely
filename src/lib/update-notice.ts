// FD-14, UX-04 (0.6.0): the one update notice above the pages, as a pure function (tested in update-notice.test.ts).
// A newer release, a check that failed, and a check that needs the GitHub update token were three banners; they are
// one quiet line now, and at most one shows: a newer release first, then a failed check, then a token needed. "Later"
// hides it until something else is to be said (its key changes).

import type { UpdateCheck, UpdateInfo } from "./api.ts";

export type UpdateNoticeState =
  | { kind: "available"; key: string; update: UpdateInfo }
  | { kind: "problem"; key: string; message: string }
  | { kind: "tokenNeeded"; key: string; repository: string };

export function updateNotice(
  check: UpdateCheck | null,
  problem: { code: string; message: string } | null,
  laterFor: string | null,
): UpdateNoticeState | null {
  const notice: UpdateNoticeState | null =
    check?.status === "available"
      ? { kind: "available", key: check.update.version, update: check.update }
      : problem
        ? { kind: "problem", key: problem.code, message: problem.message }
        : check?.status === "tokenNeeded"
          ? { kind: "tokenNeeded", key: "tokenNeeded", repository: check.repository }
          : null;
  return notice && notice.key !== laterFor ? notice : null;
}

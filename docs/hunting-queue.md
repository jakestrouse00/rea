# Hunting queue

The hunting queue is REA's orchestration plane: a durable list of analysis
units, one admitted per call, with a budget and a history. It is not a second
analyzer. Every unit delegates to the capability that owns the work, and the
queue adds what those lanes do not have on their own — ordering from coverage
and unknowns, budgets, and a queue that survives a restart.

MCP registers six tools:

| Tool                           | Question it answers                                      |
| ------------------------------ | -------------------------------------------------------- |
| `schedule_investigation_batch` | Which work do I want later, and in what order?           |
| `run_scheduled_batch`          | Do the next piece of that work now, within a budget.     |
| `read_hunting_queue`           | What is still queued, blocked, or done?                  |
| `cancel_hunting_batch`         | Drop the work of one batch that has not started.         |
| `start_watch_session`          | Tell me when this tree changes, and queue a re-analysis. |
| `stop_watch_session`           | Stop observing and release the session's timer.          |

## Scheduling and ordering

`schedule_investigation_batch` takes a list of targets and a list of recipes and
queues every target × recipe pair. Each target carries:

- `path` — the investigation target the units advance.
- `coverage` — the completion ledger its verifier produced
  ([Evidence completion ledgers](./reconstruction-obligation-ledgers.md) own the
  same shape). `fail`, `truncated`, and `unknown` claims raise a unit's score;
  `pass` claims do not.
- `unknown_ids` — residual-unknown heads that scope the target. Their severity
  and status order the work; a resolved head adds nothing.

A target without a ledger is _missing_ coverage, never complete coverage, so it
stays eligible at the lowest weight. A missing ledger and an id the registry
does not hold are different outcomes: the first is a fact about coverage, the
second is refused as an input error.

The score is a plain sum of counted reasons, so the same queue always orders the
same way:

| Reason               | Weight                                                       |
| -------------------- | ------------------------------------------------------------ |
| `coverage_fail`      | 40 per failing claim                                         |
| `coverage_truncated` | 20 per truncated claim                                       |
| `coverage_unknown`   | 10 per unknown claim                                         |
| `coverage_missing`   | 5 when no ledger exists                                      |
| `unresolved_unknown` | 80 / 40 / 15 / 5 per head for critical / high / medium / low |
| `coverage_complete`  | 0 (recorded, informational)                                  |
| `resolved_unknown`   | 0 (recorded, informational)                                  |

Queued units are admitted before blocked units; ties break on the recipe order
the caller supplied.

## Recipes this release

| Kind            | Composed capability                                                                                                            |
| --------------- | ------------------------------------------------------------------------------------------------------------------------------ |
| `re-analysis`   | One inspection (`binary_overview`, `list_procedures`, `list_strings`) over the server's **admitted** analysis target.          |
| `fuzz-campaign` | A registered campaign through the fuzz loop (`start_fuzzing_campaign`'s service seam).                                         |
| `probe`         | A learned protocol model against one operator-allowlisted **loopback** lab socket, through the protocol-learning lane's guard. |
| `replay`        | One captured entry through an existing `http_replay_*` or `proxy_replay_send` session.                                         |

A recipe whose owner is not composed in this server is not an error and not a
fabricated result: the unit reports `state: "blocked"` with
`stop.error_tag: "RecipeNotComposed"` and stays in the queue.

`re-analysis` never re-targets the caller's session. Its declared path is a
precondition: when the admitted target is a different file, the unit reports
`state: "blocked"` and the remediation names `open_binary`. A queued unit must
not retire analysis the caller did not ask to lose.

## Units, states, and stops

| State       | Meaning                                                                 |
| ----------- | ----------------------------------------------------------------------- |
| `queued`    | Runnable now, in priority order.                                        |
| `blocked`   | A named precondition is not satisfied; retried after every queued unit. |
| `succeeded` | The composed capability returned an observation.                        |
| `failed`    | The composed capability reported a failure (or threw).                  |
| `cancelled` | The batch was cancelled before this unit started.                       |

A unit that reaches its own deadline, or whose caller aborts the call, reports
`state: "stopped"` in the reply and **stays queued**: the stop names why
(`unit_budget`, `cancelled`), the attempt counter rises, and the next
`run_scheduled_batch` call admits it again. Nothing is retried automatically.

The reply never carries a composed runner's message text: only its tagged error
class and operation name, so a provider's diagnostics cannot smuggle target text
into the queue record.

## Budgets

| Bound              | Where it lives                                                                     |
| ------------------ | ---------------------------------------------------------------------------------- |
| Unit deadline      | `max_unit_seconds` per call, capped by `hunting.max_unit_seconds` (default 300 s). |
| Batch wall clock   | `budget.max_seconds`, capped by `hunting.max_batch_seconds` (default 1800 s).      |
| Batch unit slots   | `budget.max_units`, at most 128 per batch.                                         |
| Units per schedule | 128 (targets × recipes); larger requests are refused, not clamped.                 |

A batch that reaches its unit or wall-clock budget becomes `exhausted`; the
units it never started stay queued, and a later `run_scheduled_batch` call on
that batch reports `stop.kind: "batch_budget"` instead of admitting anything.
Continue with a new batch.

REA stops waiting at a unit's deadline. A composed runner that ignores its
cancellation signal may still finish; its late result is not used, and shutdown
does not block on it.

## Durability

The queue lives in an owner-only SQLite file:

```
$HOME/.rea/state/hunting/queue.sqlite   (0600 on POSIX; DACL on Windows)
```

- The batch, every unit, its recipe, ordering facts, attempt count, stop, and
  observation identity are written before the reply. A restarted REA resumes the
  same queue.
- A unit that was running when the process stopped returns to `queued` with
  `stop.kind: "interrupted"`: REA never claims it completed.
- The file is durable by design, unlike a temporary runtime root. `rea uninstall`
  purges the `state` directory with the rest of REA's managed data.

Watch sessions are **not** durable: their timers belong to this server's
lifetime, exactly like an interception or replay session. The units they already
queued are durable.

## Watch sessions

`start_watch_session` observes one directory tree:

- The baseline is read before the session is issued, so a change that happens
  before the first interval is not lost.
- Each interval reads names, sizes, and modification times only. File content is
  never read and a symbolic link is reported as itself, never followed.
- One re-analysis unit per observed change is appended to a batch the session
  owns, up to `max_triggers`; the session then stops observing and its identity
  is released.
- A tick that is still pending is not overlapped: the next tick is skipped. A
  read that fails is counted and reported at `stop_watch_session`; it does not
  end the session.
- A truncated observation never proves removal, so a bounded walk cannot turn
  into a deletion report.

This release watches directories only. A `device` or `endpoint` source is
refused with a typed `AnalysisCapabilityUnavailableError` rather than silently
watching nothing.

`stop_watch_session` clears the owned timer, aborts an in-flight read, and waits
for it to settle. A failed release keeps the session identity so the call can be
retried; a cancellation that arrives while the release finishes returns typed
cancellation with the partial observation of what was released.

## Sandbox and Evidence

The queue starts no child of its own, so it has no profile to render. Each
composed capability confines its own launch under the deny-default profiles from
[autonomous execution policy](./autonomous-execution.md), and each unit's reply
reports whether `REA_DISABLE_SANDBOX` left this host unconfined. An
uninterpretable `REA_DISABLE_SANDBOX` value blocks the unit instead of guessing.

Every call that changes queue state records Evidence:

- the schedule, with the ordering reasons and the budget it accepted;
- each admitted unit, with its state, attempt, elapsed time, the budget applied,
  the stop (if any), and the queue counters it left behind;
- the composed observation, recorded **separately** and named by its Evidence
  identity and canonical result digest — the unit record does not inline it;
- each cancellation and each watch session's start and release.

A unit that does not complete also records one residual unknown in the `hunting`
domain, scoped to its own unit Evidence, so an unfinished claim stays visible.
When the server has no investigation session, unknown updates are skipped and
the reply says so.

## Boundaries

- Offline tests drive scripted runners over the service seams; they establish
  queue semantics, not real provider, engine, or lab behavior.
- No real `sandbox-exec` launch is observed by this lane, because this lane
  launches nothing.
- A watch session observes a directory on the local filesystem; it makes no
  network request and no device access.

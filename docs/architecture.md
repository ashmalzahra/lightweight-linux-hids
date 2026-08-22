# System Architecture

## 1. Architectural Goal

The system uses a modular pipeline that separates host observation, event
normalisation, rule evaluation, alert generation, and storage. This separation
allows monitors and rules to be tested independently and makes the reason for
each alert inspectable.

The project is a research and educational prototype. Its components are kept
small and transparent so that detection decisions, limitations, and resource
costs can be examined. It is not intended to replace a production security
platform.

## 2. Processing Pipeline

```text
Linux data source
       |
       v
Monitor / collector
       |
       v
Normalised Event --------------------> JSONL event storage
       |
       v
Rule Engine
       |
       v
Structured Alert --------------------> JSONL alert storage
```

An **event** records an observed change or activity. An **alert** is created
only when one or more events satisfy a configured detection rule. An event
that does not generate an alert is not automatically proven benign; it simply
did not match the current rules.

Events and alerts use shared data models so that every monitor produces a
consistent structure. Unique identifiers link each alert to the event or
events that caused it, supporting traceability during testing and analysis.

## 3. Runtime State and Stored Evidence

The `.hids-state` directory stores the previous observation required by each
stateful monitor. This runtime state allows a new scan to determine what has
changed since the preceding observation. It is operational state rather than
experimental evidence and is not committed to version control.

Events are appended to `var/events.jsonl`, and alerts are appended to
`var/alerts.jsonl`. JSON Lines stores one JSON object per line, allowing records
to be appended without rewriting the complete file. These runtime files are
also excluded from version control because experiments generate them locally.

## 4. File-Integrity Monitoring

The file-integrity monitor creates a trusted snapshot of each configured path
during explicit initialization. The snapshot records file content hashes and
selected metadata, including the permission mode. Later scans build a current
snapshot and compare it with that baseline.

The comparison can produce the following event types:

- `file_added`
- `file_deleted`
- `file_modified`
- `file_metadata_changed`

Configured single-event rules `FIM-001` through `FIM-004` convert these events
into alerts. The baseline is not silently replaced after a change because doing
so would make an unreviewed modification become trusted. Separate active-
finding state suppresses identical repeated findings while allowing a
restored file and a later new change to be detected again.

This design provides transparent change detection, but a changed file is not
necessarily malicious. The monitored paths and trusted initialization point
must be chosen carefully, and legitimate changes may generate alerts.

## 5. Authentication Monitoring

The authentication monitor reads `/var/log/auth.log` and currently normalises
supported `sudo` authentication-failure records. Initialization records a byte
cursor at the end of the existing log so that historical entries are treated
as already seen. Each scan reads only newly appended, complete lines.

The cursor includes the log file's device, inode, and byte offset. This allows
the monitor to recognise when the underlying log file has been replaced or
truncated and avoids repeatedly parsing the entire log. The monitor creates an
`authentication_failed` event for each supported failure.

Rule `AUTH-001` is a threshold rule. It generates an alert when three failures
for the same user occur within sixty seconds. Grouping by user prevents
unrelated failures from different accounts from being combined into one
detection. Threshold state is maintained by the running rule engine, so the
continuous `run` command is used for this scenario.

This implementation intentionally covers a limited, testable subset of Linux
authentication activity. Log formats vary between services and Linux
configurations, and a failure may result from user error rather than an attack.

## 6. Process-Activity Monitoring

The process monitor uses `psutil` to collect periodic snapshots of observable
running processes. Each process record includes its PID, creation time, parent
PID, name, executable, command line, and username when those values are
accessible. Processes that disappear during collection or cannot be inspected
are skipped safely.

A process instance is identified using both its PID and creation time. This is
necessary because Linux can reuse a PID after an earlier process exits.
Comparing consecutive snapshots produces `process_started` and
`process_stopped` events. The most recent snapshot is stored in
`.hids-state/processes.json` for the next comparison.

Rule `PROC-001` currently detects the controlled laboratory executable named
`hids-lab-agent`. This rule proves that a process-start observation can travel
through the complete event, rule, alert, and storage pipeline. It is not a
general claim that arbitrary malicious processes can be identified by name.

Polling has an inherent visibility limitation: a process that starts and exits
entirely between two scans might not appear in either snapshot. In addition,
normal Linux operation creates many short-lived user-space and kernel
processes, producing substantial benign event volume.

## 7. Console-Output Policy

Event collection is separated from console presentation. All detected events
are stored and evaluated by the rule engine, but normal continuous operation
does not print every event individually. It displays compact activity summaries
and prints generated alerts so that routine process activity does not obscure
important detections.

Detailed live events can be displayed deliberately with:

```bash
lightweight-hids run --verbose-events
```

Previously stored events can be inspected with commands such as:

```bash
lightweight-hids show-events --source processes --limit 10
```

This policy reduces console clutter without discarding evidence. It does not
classify hidden routine events as benign. Filtering observations at collection
time could lower event volume and computational cost, but could also create
detection blind spots. That trade-off will be considered during evaluation.



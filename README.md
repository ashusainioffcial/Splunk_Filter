# 🕵️‍♂️ The Master Splunk SPL Threat Hunting Cheat Sheet

This reference document tracks the core Search Processing Language (SPL) commands, functions, and advanced logical structures utilized to hunt threats, normalize unstructured logs, and engineer operational security metrics across enterprise data scopes.

---

## 🌐 1. Base Filtering & Data Scoping
Use these entry-level commands to isolate specific data repositories and system folders across your infrastructure.

- `index=*` — Directs the query engine to search across all active data repositories and indexed vaults simultaneously.
- `sourcetype=access_combined_wcookie` — Targets raw server transactions handling external web application traffic and session cookies.
- `sourcetype=secure-2` — Isolates Linux operating system authentication logs to monitor host access vectors.
- `index=* "404"` — Performs a raw string search across all indexes to isolate occurrences of the text string "404", bypassing standard field mapping layers.

---

## 📊 2. Aggregation, Field Normalization & Sorting
Use these commands to group high-volume pattern bursts and organize data tables hierarchically.

- `| top sourcetype` — Calculates and ranks the most frequent data types logging across the enterprise.
- `| top host` — Groups corporate events by server asset names (e.g., `www1`, `mailsv`, `vendor_sales`) to locate active log generators.
- `| sort - count` — Sorts tabular data arrays in descending order to force critical anomalies to the top of the interface.

---

## 🛠️ 3. Advanced Regular Expression Extraction (`| rex`)
A digital scalpel used to extract hidden data parameters out of raw text paragraphs using specific string pattern flags.

- `| rex "Failed password for\s+(invalid user\s+)?(?<username>\S+)"`
  - `\s+` / `\s*` — Handles flexible spacing variations inside raw sentences.
  - `(?<username> ... )` — Extracts the trapped account names and maps them into a new custom column named `username`.
  - `\S+` — Instructs the engine to grab characters continuously until it hits a blank space boundary.
- `| rex "from (?<attacker_ip>\d+\.\d+\.\d+\.\d+)"`
  - `\d+\.\d+\.\d+\.\d+` — Matches four distinct number groups separated by periods to extract raw network IP signatures cleanly.

---

## 📉 4. Chronological Trend Charting (`| timechart`)
Used to automatically bucket events by time increments to track when hackers are most active.

- `| timechart span=1h count by username useother=f limit=5`
  - `span=1h` — Groups traffic spikes into clean, hourly buckets.
  - `useother=f` — **False.** Suppresses rare, background noise usernames so your line graph focuses exclusively on the top priority targets.

---

## 🧠 5. Logic Enrichment & Conditional Engines (`| eval`)
Used to calculate threat metrics, create custom indicators, and assign risk tiers dynamically.

- `| stats count as total_attempts, dc(attacker_ip) as unique_attacker_ips by username`
  - `dc()` — **Distinct Count.** Calculates exactly how many *different* hacking devices are attacking a single user profile to identify distributed botnets.
- `| eval Threat_Severity = if(total_attempts > 100, "🚨 CRITICAL BOTNET", "⚠️ MINOR TYPO")`
  - `if(condition, True, False)` — Evaluates numeric thresholds and slaps visibility labels onto your rows automatically.
- `| eval Network_Zone = case(cidrmatch("192.168.1.0/24", clientip), "INTERNAL", true(), "EXTERNAL")`
  - `case()` — Evaluates multiple rules sequentially to map network zones without relying on external lookup database files.

---

## 🏁 Investigation Workflow Checklist
When responding to a network authentication anomaly:
1. **Scope the Environment:** Use `index=* sourcetype=secure-2` to view raw system access logs.
2. **Apply Rex Scalpels:** Isolate hidden username strings using `| rex` to bypass whitespace parsing issues.
3. **Determine Velocity Trends:** Run a `| timechart span=1h` calculation to identify automated cron-job script behaviors.
4. **Prescribe Triage Actions:** Inject an `| eval` statement using conditional `if` triggers to separate malicious traffic segments from trusted corporate zones.

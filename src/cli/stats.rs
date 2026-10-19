//! `voidgate stats`: read-only aggregates rendered as text tables or JSON.
//!
//! Tables are hand-padded (no table dependency) and JSON is written by hand
//! with a minimal escaping routine, so the report needs nothing beyond the
//! existing `rusqlite` read-only [`Stats`] view.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

use crate::config::AppConfig;
use crate::storage::{now_ms, Action, ClientStat, Stats, StorageError};

use super::CliError;

/// The data behind one `voidgate stats` run.
pub(super) struct StatsReport {
    /// Total queries inside the window.
    total: u64,
    /// Per-action counts, always all four actions in report order.
    by_action: Vec<(Action, u64)>,
    /// The `--top` limit, echoed in the JSON and the table heading.
    top: usize,
    /// Most-blocked domains inside the window.
    top_blocked: Vec<(String, u64)>,
    /// Per-client breakdown inside the window.
    clients: Vec<ClientStat>,
    /// The raw `--since` window, for the "Period" line.
    since: Option<String>,
}

/// Reads the aggregates for `config`, applying `--since` and `--top`.
///
/// Returns [`CliError::Unavailable`] (exit code 1) when there is nothing to
/// read — logging disabled or no database — and [`CliError::Runtime`] (exit
/// code 2) for a database that exists but cannot be read.
pub(super) fn collect(
    config: &AppConfig,
    top: usize,
    since: Option<&str>,
) -> Result<StatsReport, CliError> {
    let storage = &config.storage;
    if !storage.log_queries {
        return Err(CliError::Unavailable(
            "query logging is disabled (`storage.log_queries: false`), so there is nothing to report \
             (hint: enable storage.log_queries and run the server)"
                .to_owned(),
        ));
    }
    if !storage.db_path.exists() {
        return Err(CliError::Unavailable(format!(
            "no query log at `{}` (hint: run `voidgate run` so it creates the log, \
             or point storage.db_path at an existing database)",
            storage.db_path.display()
        )));
    }
    let since_ms = since
        .map(|window| {
            parse_window(window)
                .map(|delta| now_ms() - delta)
                .map_err(|message| {
                    CliError::Unavailable(format!(
                        "invalid --since `{window}`: {message} (hint: use a window like 1h, 24h or 7d)"
                    ))
                })
        })
        .transpose()?;

    let stats = Stats::open(&storage.db_path, storage.busy_timeout_ms).map_err(open_error)?;
    Ok(StatsReport {
        total: stats.total(since_ms).map_err(read_error)?,
        by_action: fill_actions(stats.counts_by_action(since_ms).map_err(read_error)?),
        top,
        top_blocked: stats
            .top_blocked_domains(since_ms, top)
            .map_err(read_error)?,
        clients: stats.per_client(since_ms).map_err(read_error)?,
        since: since.map(str::to_owned),
    })
}

/// Maps a failed read-only open onto a runtime error with a hint.
fn open_error(error: StorageError) -> CliError {
    CliError::Runtime(anyhow::anyhow!(
        "cannot open the query log read-only: {error} \
         (hint: check the permissions on storage.db_path)"
    ))
}

/// Maps a failed aggregate query onto a runtime error.
fn read_error(error: StorageError) -> CliError {
    CliError::Runtime(anyhow::anyhow!("failed to read the query log: {error}"))
}

/// Parses a `--since` window (`30s`, `5m`, `1h`, `24h`, `7d`) into
/// milliseconds.
pub(super) fn parse_window(value: &str) -> Result<i64, String> {
    let value = value.trim();
    let mut chars = value.chars();
    let unit = chars
        .next_back()
        .ok_or_else(|| "the window is empty".to_owned())?;
    let amount: i64 = chars
        .as_str()
        .parse()
        .map_err(|_| format!("`{value}` is not a number followed by s, m, h or d"))?;
    if amount <= 0 {
        return Err("the window must be greater than zero".to_owned());
    }
    let multiplier = match unit {
        's' => 1_000,
        'm' => 60_000,
        'h' => 3_600_000,
        'd' => 86_400_000,
        other => return Err(format!("unknown unit `{other}`")),
    };
    amount
        .checked_mul(multiplier)
        .ok_or_else(|| "the window is too large".to_owned())
}

/// Every action in report order, including zeros for actions with no rows.
fn fill_actions(counts: Vec<(Action, u64)>) -> Vec<(Action, u64)> {
    [
        Action::Allowed,
        Action::Blocked,
        Action::Forwarded,
        Action::Servfail,
    ]
    .into_iter()
    .map(|action| {
        let count = counts
            .iter()
            .find(|(present, _)| *present == action)
            .map_or(0, |(_, count)| *count);
        (action, count)
    })
    .collect()
}

/// `part / whole` as a percentage; `0.0` when `whole` is zero.
fn percent(part: u64, whole: u64) -> f64 {
    if whole == 0 {
        0.0
    } else {
        part as f64 / whole as f64 * 100.0
    }
}

impl StatsReport {
    /// Renders the human-readable tables.
    pub(super) fn render_text(&self) -> String {
        let mut out = String::new();
        out.push_str("voidgate query statistics\n");
        out.push_str("=========================\n");
        match &self.since {
            Some(window) => out.push_str(&format!("Period: last {window}\n")),
            None => out.push_str("Period: all time\n"),
        }
        out.push_str(&format!("\nTotal queries: {}\n", self.total));

        heading(&mut out, "Queries by action");
        let rows: Vec<Vec<String>> = self
            .by_action
            .iter()
            .map(|(action, count)| {
                vec![
                    action.as_str().to_owned(),
                    count.to_string(),
                    format!("{:.1}%", percent(*count, self.total)),
                ]
            })
            .collect();
        out.push_str(&render_table(
            &["action", "count", "percent"],
            &[Align::Left, Align::Right, Align::Right],
            &rows,
        ));

        heading(&mut out, &format!("Top {} blocked domains", self.top));
        if self.top_blocked.is_empty() {
            out.push_str("(none)\n");
        } else {
            let rows: Vec<Vec<String>> = self
                .top_blocked
                .iter()
                .map(|(domain, count)| vec![domain.clone(), count.to_string()])
                .collect();
            out.push_str(&render_table(
                &["domain", "count"],
                &[Align::Left, Align::Right],
                &rows,
            ));
        }

        heading(&mut out, &format!("Clients ({})", self.clients.len()));
        if self.clients.is_empty() {
            out.push_str("(none)\n");
        } else {
            let rows: Vec<Vec<String>> = self
                .clients
                .iter()
                .map(|client| {
                    vec![
                        client.client_ip.clone(),
                        client.total.to_string(),
                        client.blocked.to_string(),
                        format!("{:.1}%", percent(client.blocked, client.total)),
                    ]
                })
                .collect();
            out.push_str(&render_table(
                &["client_ip", "queries", "blocked", "blocked %"],
                &[Align::Left, Align::Right, Align::Right, Align::Right],
                &rows,
            ));
        }

        out
    }

    /// Renders the same data as JSON on one final newline.
    pub(super) fn render_json(&self) -> String {
        let mut out = String::new();
        out.push_str("{\n");
        out.push_str(&format!("  \"total\": {},\n", self.total));
        out.push_str("  \"since\": ");
        match &self.since {
            Some(window) => out.push_str(&format!("\"{}\",\n", escape(window))),
            None => out.push_str("null,\n"),
        }
        out.push_str(&format!("  \"top\": {},\n", self.top));

        out.push_str("  \"by_action\": [\n");
        for (index, (action, count)) in self.by_action.iter().enumerate() {
            out.push_str(&format!(
                "    {{\"action\": \"{}\", \"count\": {}, \"percent\": {:.1}}}{}\n",
                escape(action.as_str()),
                count,
                percent(*count, self.total),
                comma(index, self.by_action.len()),
            ));
        }
        out.push_str("  ],\n");

        out.push_str("  \"top_blocked\": [\n");
        for (index, (domain, count)) in self.top_blocked.iter().enumerate() {
            out.push_str(&format!(
                "    {{\"domain\": \"{}\", \"count\": {}}}{}\n",
                escape(domain),
                count,
                comma(index, self.top_blocked.len()),
            ));
        }
        out.push_str("  ],\n");

        out.push_str("  \"clients\": [\n");
        for (index, client) in self.clients.iter().enumerate() {
            out.push_str(&format!(
                "    {{\"client_ip\": \"{}\", \"queries\": {}, \"blocked\": {}, \
                 \"blocked_percent\": {:.1}}}{}\n",
                escape(&client.client_ip),
                client.total,
                client.blocked,
                percent(client.blocked, client.total),
                comma(index, self.clients.len()),
            ));
        }
        out.push_str("  ]\n}\n");
        out
    }
}

/// Appends a heading followed by a matching `-` underline.
fn heading(out: &mut String, title: &str) {
    out.push('\n');
    out.push_str(title);
    out.push('\n');
    out.push_str(&"-".repeat(title.chars().count()));
    out.push('\n');
}

/// Column alignment for the text tables.
#[derive(Clone, Copy)]
enum Align {
    /// Text is padded on the right.
    Left,
    /// Numbers are padded on the left.
    Right,
}

/// Renders `headers` and `rows` as fixed-width, space-padded columns.
fn render_table(headers: &[&str], aligns: &[Align], rows: &[Vec<String>]) -> String {
    let widths: Vec<usize> = headers
        .iter()
        .enumerate()
        .map(|(column, header)| {
            rows.iter()
                .map(|row| row[column].chars().count())
                .fold(header.chars().count(), usize::max)
        })
        .collect();

    let mut out = String::new();
    let header_row: Vec<String> = headers.iter().map(|header| (*header).to_owned()).collect();
    push_row(&mut out, &header_row, &widths, aligns);
    let separator: Vec<String> = widths.iter().map(|width| "-".repeat(*width)).collect();
    push_row(&mut out, &separator, &widths, aligns);
    for row in rows {
        push_row(&mut out, row, &widths, aligns);
    }
    out
}

/// Appends one padded row, trimming trailing whitespace.
fn push_row(out: &mut String, cells: &[String], widths: &[usize], aligns: &[Align]) {
    let mut line = String::new();
    for (column, cell) in cells.iter().enumerate() {
        if column > 0 {
            line.push_str("  ");
        }
        let padding = widths[column].saturating_sub(cell.chars().count());
        match aligns[column] {
            Align::Left => {
                line.push_str(cell);
                line.push_str(&" ".repeat(padding));
            }
            Align::Right => {
                line.push_str(&" ".repeat(padding));
                line.push_str(cell);
            }
        }
    }
    out.push_str(line.trim_end());
    out.push('\n');
}

/// `""` for the last element, `","` otherwise.
fn comma(index: usize, len: usize) -> &'static str {
    if index + 1 == len {
        ""
    } else {
        ","
    }
}

/// Escapes `value` for a JSON string literal.
fn escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            control if (control as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", control as u32));
            }
            other => out.push(other),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_convert_to_milliseconds() {
        assert_eq!(parse_window("30s").unwrap(), 30_000);
        assert_eq!(parse_window("5m").unwrap(), 300_000);
        assert_eq!(parse_window("1h").unwrap(), 3_600_000);
        assert_eq!(parse_window("24h").unwrap(), 86_400_000);
        assert_eq!(parse_window("7d").unwrap(), 604_800_000);
        assert_eq!(parse_window(" 1h ").unwrap(), 3_600_000);
    }

    #[test]
    fn bad_windows_are_rejected() {
        for value in ["", "0h", "h", "10", "1x", "-1h", "99999999999999999999d"] {
            assert!(parse_window(value).is_err(), "{value:?} should be rejected");
        }
    }

    fn sample() -> StatsReport {
        StatsReport {
            total: 4,
            by_action: vec![
                (Action::Allowed, 1),
                (Action::Blocked, 2),
                (Action::Forwarded, 1),
                (Action::Servfail, 0),
            ],
            top: 10,
            top_blocked: vec![("ads.example".to_owned(), 2)],
            clients: vec![ClientStat {
                client_ip: "10.0.0.1".to_owned(),
                total: 4,
                blocked: 2,
            }],
            since: None,
        }
    }

    #[test]
    fn text_report_contains_counts_and_percentages() {
        let text = sample().render_text();
        assert!(text.contains("Total queries: 4"), "{text}");
        assert!(text.contains("Top 10 blocked domains"), "{text}");
        assert!(text.contains("ads.example"), "{text}");
        assert!(text.contains("blocked"), "{text}");
        assert!(text.contains("50.0%"), "{text}");
        // Zero-count actions still appear.
        assert!(text.contains("servfail"), "{text}");
    }

    #[test]
    fn json_report_is_valid_and_matches_the_totals() {
        let json = sample().render_json();
        let parsed: serde_yaml_ng::Value = serde_yaml_ng::from_str(&json).unwrap();
        assert_eq!(parsed["total"].as_u64(), Some(4));
        assert_eq!(
            parsed["top_blocked"][0]["domain"].as_str(),
            Some("ads.example")
        );
        assert_eq!(parsed["by_action"].as_sequence().unwrap().len(), 4);
        assert_eq!(parsed["clients"][0]["blocked"].as_u64(), Some(2));
    }

    #[test]
    fn json_escapes_special_characters() {
        assert_eq!(escape("a\"b\\c\nd"), "a\\\"b\\\\c\\nd");
    }
}

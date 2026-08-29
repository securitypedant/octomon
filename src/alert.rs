//! Telling someone when nobody is watching the screen.
//!
//! Every other output octomon has assumes a person is looking at it. The
//! intermittent dropout — the 3am ISP flap, the roam that kills a call, the
//! VPN that dies for forty seconds — is exactly the case where nobody is, and
//! by the time they are, the live panels have rolled over.
//!
//! The trigger is the verdict engine's own raise/clear transitions, so an
//! alert is never a raw sample crossing a threshold: it has already been
//! through hysteresis and the flap grace, which is what keeps a notification
//! from firing four times a minute on a lossy link.
//!
//! Three ways out, any combination: the desktop's own notifier, a command, and
//! a webhook. None of them are on unless asked for.

use crate::verdict::{Severity, Transition};

/// Where alerts go, and from what severity up.
#[derive(Clone, Debug)]
pub struct AlertSinks {
    /// One line on stdout — what `--watch` is, and what makes a service's
    /// journal a usable record.
    pub stdout: bool,
    /// Native desktop notification.
    pub desktop: bool,
    /// Shell command run per alert, with the payload in the environment.
    pub command: Option<String>,
    /// Endpoint the payload is POSTed to as JSON.
    pub url: Option<String>,
    /// Findings below this never alert. Info-class notes (a busy CPU, a
    /// weak-but-working radio) are never worth waking someone for, so the
    /// floor is Degraded whatever the settings say.
    pub min_severity: Severity,
}

impl Default for AlertSinks {
    fn default() -> Self {
        Self {
            stdout: false,
            desktop: false,
            command: None,
            url: None,
            min_severity: Severity::Degraded,
        }
    }
}

impl AlertSinks {
    /// Nothing configured means nothing to do — the check every caller makes
    /// before building a payload.
    pub fn is_active(&self) -> bool {
        self.stdout || self.desktop || self.command.is_some() || self.url.is_some()
    }

    fn wants(&self, severity: Severity) -> bool {
        severity >= self.min_severity && severity >= Severity::Degraded
    }
}

/// One thing worth telling someone about.
#[derive(Clone, Debug)]
pub struct Alert {
    /// True when a finding raised; false when it ended.
    pub raised: bool,
    pub severity: Severity,
    /// `Cause::label()` — a stable slug for scripts to match on.
    pub cause: &'static str,
    /// Which target / resolver / interface the finding is about.
    pub subject: String,
    pub summary: String,
    /// What else had just changed when it raised (see
    /// [`crate::verdict::onset_context`]).
    pub onset: Option<String>,
    /// How long it lasted, on a clear.
    pub after_secs: Option<u64>,
    /// The location's name or key, when this network is one octomon knows.
    pub network: Option<String>,
    /// Unix seconds.
    pub at: i64,
}

impl Alert {
    /// A transition as an alert, or `None` when it is not worth one.
    pub fn from_transition(t: &Transition, network: Option<String>) -> Self {
        Self {
            raised: t.raised,
            severity: t.finding.severity,
            cause: t.finding.cause.label(),
            subject: t.finding.subject.clone(),
            summary: t.finding.summary.clone(),
            onset: t.onset.clone(),
            after_secs: t.after.map(|d| d.as_secs()),
            network,
            at: chrono::Utc::now().timestamp(),
        }
    }

    /// The one line a human reads — the notification body, and the `TEXT`
    /// the command gets so a simple hook need not assemble anything.
    pub fn text(&self) -> String {
        let mut s = if self.raised {
            format!("▲ {}", self.summary)
        } else {
            format!("✓ {}", self.summary)
        };
        if let Some(secs) = self.after_secs {
            s.push_str(&format!(
                " — ended after {}",
                crate::verdict::fmt_duration(std::time::Duration::from_secs(secs))
            ));
        }
        if let Some(onset) = &self.onset {
            s.push_str(&format!(" · {onset}"));
        }
        if let Some(net) = &self.network {
            s.push_str(&format!(" · on {net}"));
        }
        s
    }

    fn event(&self) -> &'static str {
        if self.raised { "raised" } else { "cleared" }
    }

    /// The payload as environment variables for a command hook. Handing the
    /// values over this way, rather than substituting them into the command
    /// string, is deliberate: a finding's summary can contain an SSID or a
    /// hostname this machine did not choose, and nothing the network says
    /// should ever reach a shell as syntax.
    fn env(&self) -> Vec<(&'static str, String)> {
        let mut env = vec![
            ("OCTOMON_EVENT", self.event().to_string()),
            ("OCTOMON_SEVERITY", self.severity.label().to_string()),
            ("OCTOMON_CAUSE", self.cause.to_string()),
            ("OCTOMON_SUBJECT", self.subject.clone()),
            ("OCTOMON_SUMMARY", self.summary.clone()),
            ("OCTOMON_TEXT", self.text()),
            ("OCTOMON_AT", self.at.to_string()),
        ];
        if let Some(o) = &self.onset {
            env.push(("OCTOMON_ONSET", o.clone()));
        }
        if let Some(a) = self.after_secs {
            env.push(("OCTOMON_AFTER_SECS", a.to_string()));
        }
        if let Some(n) = &self.network {
            env.push(("OCTOMON_NETWORK", n.clone()));
        }
        env
    }

    fn json(&self) -> serde_json::Value {
        serde_json::json!({
            "event": self.event(),
            "severity": self.severity.label(),
            "cause": self.cause,
            "subject": self.subject,
            "summary": self.summary,
            "text": self.text(),
            "onset": self.onset,
            "after_secs": self.after_secs,
            "network": self.network,
            "at": self.at,
            "source": "octomon",
            "version": crate::util::VERSION,
        })
    }
}

/// Whether an alert has already printed to stdout. `--watch` prints the state
/// it starts from so a silent watchdog is distinguishable from a broken one —
/// but only if the alerts have not already said it, which on a connection
/// that is *already* in trouble they have.
static SPOKE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

pub fn has_printed() -> bool {
    SPOKE.load(std::sync::atomic::Ordering::Relaxed)
}

/// Send one alert down every configured channel. Returns immediately: a
/// notifier that hangs, or a webhook to an unreachable host, must never stall
/// the verdict tick.
pub fn dispatch(sinks: &AlertSinks, alert: Alert) {
    if !sinks.wants(alert.severity) {
        return;
    }
    if sinks.stdout {
        // Timestamped, one line, unbuffered enough for `tee` and journald:
        // this is the whole output of a --watch run.
        println!(
            "{}  {}",
            chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
            alert.text()
        );
        use std::io::Write as _;
        let _ = std::io::stdout().flush();
        SPOKE.store(true, std::sync::atomic::Ordering::Relaxed);
    }
    if sinks.desktop {
        let a = alert.clone();
        tokio::task::spawn_blocking(move || notify_desktop(&a));
    }
    if let Some(cmd) = sinks.command.clone() {
        let a = alert.clone();
        tokio::task::spawn_blocking(move || run_command(&cmd, &a));
    }
    if let Some(url) = sinks.url.clone() {
        tokio::spawn(async move { post_webhook(&url, &alert).await });
    }
}

/// The desktop's own notifier, through whatever this OS ships with — no new
/// dependency, and nothing to install on a stock machine.
fn notify_desktop(alert: &Alert) {
    let title = if alert.raised {
        "octomon — problem"
    } else {
        "octomon — recovered"
    };
    match notify_command(title, &alert.text(), alert.raised).output() {
        Ok(out) if !out.status.success() => crate::errlog::log(
            "alert",
            format!(
                "desktop notification failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            ),
        ),
        Err(e) => crate::errlog::log("alert", format!("desktop notifier not available: {e}")),
        _ => {}
    }
}

/// The notifier invocation for this platform.
///
/// On every one of them the message is *data* — an argument, or an
/// environment variable — and never part of the script or command line being
/// interpreted. That is a safety property (a finding's summary can carry an
/// SSID this machine did not choose) and, on macOS, a correctness one.
fn notify_command(title: &str, body: &str, raised: bool) -> std::process::Command {
    use std::process::Command;
    if cfg!(target_os = "macos") && crate::platform::tools::exists("terminal-notifier") {
        // Preferred when it happens to be installed. A notification posted by
        // `osascript` belongs to Script Editor — that is the app macOS
        // attributes it to, and clicking it opens Script Editor's document
        // chooser, which is a baffling thing to hand someone who just wanted
        // to know why their call dropped. terminal-notifier posts as itself
        // and can hand the click to the terminal octomon is running in.
        let mut c = Command::new("terminal-notifier");
        c.arg("-title")
            .arg(title)
            .arg("-message")
            .arg(body)
            // Both are data, and both after their flags: a summary starting
            // with a dash is still a summary.
            .arg("-sound")
            .arg(if raised { "Basso" } else { "Pop" });
        if let Some(bundle) = host_terminal_bundle() {
            c.arg("-activate").arg(bundle);
        }
        c
    } else if cfg!(target_os = "macos") {
        // Through `on run argv`, not `system attribute`: AppleScript decodes
        // an environment variable as Mac OS Roman, so every ▲, · and — in the
        // text came out as mojibake ("octomon ,Äî problem"). Arguments are
        // decoded as UTF-8 and survive intact — and, like the environment,
        // they keep the message out of the script body, where a network-named
        // string has no business being.
        let mut c = Command::new("osascript");
        c.arg("-e")
            .arg("on run argv")
            .arg("-e")
            .arg("display notification (item 1 of argv) with title (item 2 of argv)")
            .arg("-e")
            .arg("end run")
            .arg("--")
            .arg(body)
            .arg(title);
        c
    } else if cfg!(target_os = "windows") {
        // A balloon tip through WinForms: present on every stock Windows,
        // unlike the toast modules people have to install. The script reads
        // the text from the environment rather than being built around it —
        // Windows hands environment blocks over as UTF-16, so it arrives as
        // written.
        let mut c = Command::new("powershell");
        c.env("OCTOMON_BODY", body)
            .env("OCTOMON_TITLE", title)
            .args(["-NoProfile", "-NonInteractive", "-Command"])
            .arg(WINDOWS_NOTIFY);
        c
    } else {
        let mut c = Command::new("notify-send");
        c.arg("--app-name=octomon")
            .arg(if raised {
                "--urgency=critical"
            } else {
                "--urgency=normal"
            })
            .arg(title)
            .arg(body);
        c
    }
}

/// The notifier this platform needs but does not have, if any.
///
/// macOS and Windows always ship one (`osascript`, `powershell`). A Linux box
/// may not: `notify-send` comes from libnotify, which a desktop has and a
/// server does not. Asking for `--alert` there would otherwise do nothing at
/// all except leave a line in errors.log after the first finding — so this is
/// checked up front and said out loud.
pub fn missing_notifier() -> Option<&'static str> {
    if cfg!(target_os = "linux") && !crate::platform::tools::exists("notify-send") {
        return Some("notify-send");
    }
    None
}

/// The bundle id of the terminal octomon is running in, when it says so — the
/// sensible thing for a click on an alert to bring forward, since that is
/// where the dashboard, the timeline and the session bar are.
///
/// `TERM_PROGRAM` is set by the terminal itself; an unfamiliar one (or a
/// session with none, like a launchd service) simply gets no click target,
/// which is better than guessing at an app that may not exist.
fn host_terminal_bundle() -> Option<&'static str> {
    terminal_bundle(std::env::var("TERM_PROGRAM").ok().as_deref())
}

/// The mapping itself, taking what the environment said rather than reading
/// it — the environment is process-wide, and a test that writes to it can
/// race any other test that reads it.
fn terminal_bundle(term_program: Option<&str>) -> Option<&'static str> {
    match term_program? {
        "Apple_Terminal" => Some("com.apple.Terminal"),
        "iTerm.app" => Some("com.googlecode.iterm2"),
        "ghostty" => Some("com.mitchellh.ghostty"),
        "WezTerm" => Some("com.github.wez.wezterm"),
        "WarpTerminal" => Some("dev.warp.Warp-Stable"),
        "vscode" => Some("com.microsoft.VSCode"),
        "Hyper" => Some("co.zeit.hyper"),
        "kitty" => Some("net.kovidgoyal.kitty"),
        "tabby" => Some("org.tabby"),
        _ => None,
    }
}

const WINDOWS_NOTIFY: &str = "\
[reflection.assembly]::LoadWithPartialName('System.Windows.Forms') | Out-Null; \
$n = New-Object System.Windows.Forms.NotifyIcon; \
$n.Icon = [System.Drawing.SystemIcons]::Information; \
$n.Visible = $true; \
$n.ShowBalloonTip(10000, $env:OCTOMON_TITLE, $env:OCTOMON_BODY, \
[System.Windows.Forms.ToolTipIcon]::Warning); \
Start-Sleep -Seconds 10; $n.Dispose()";

/// Run the user's own hook. The command is theirs; the alert's text is not,
/// so the payload arrives in the environment and the command string is passed
/// to the shell exactly as written.
fn run_command(command: &str, alert: &Alert) {
    use std::process::Command;
    let mut cmd = if cfg!(target_os = "windows") {
        let mut c = Command::new("cmd");
        c.args(["/C", command]);
        c
    } else {
        let mut c = Command::new("sh");
        c.args(["-c", command]);
        c
    };
    for (k, v) in alert.env() {
        cmd.env(k, v);
    }
    match cmd.output() {
        Ok(out) if !out.status.success() => crate::errlog::log(
            "alert",
            format!(
                "alert command exited {}: {}",
                out.status,
                String::from_utf8_lossy(&out.stderr).trim()
            ),
        ),
        Err(e) => crate::errlog::log("alert", format!("alert command failed to start: {e}")),
        _ => {}
    }
}

/// POST the payload as JSON. One attempt, short timeout: a webhook that is
/// down is not worth retrying into a queue nobody drains.
async fn post_webhook(url: &str, alert: &Alert) {
    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .user_agent(crate::util::USER_AGENT)
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            crate::errlog::log("alert", format!("webhook client: {e}"));
            return;
        }
    };
    // Built by hand rather than with reqwest's json feature, which this
    // build does not carry.
    match client
        .post(url)
        .header("content-type", "application/json")
        .body(alert.json().to_string())
        .send()
        .await
    {
        Ok(r) if !r.status().is_success() => {
            crate::errlog::log("alert", format!("webhook {url} answered {}", r.status()))
        }
        Err(e) => crate::errlog::log("alert", format!("webhook {url}: {e}")),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verdict::{Cause, Confidence, Finding};

    fn transition(raised: bool, severity: Severity) -> Transition {
        Transition {
            raised,
            finding: Finding {
                cause: Cause::GatewayLan,
                severity,
                confidence: Confidence::Strong,
                summary: "gateway unresponsive (100% loss)".into(),
                evidence: vec![],
                subject: "192.168.1.1".into(),
                symptom: false,
                since: None,
            },
            after: if raised {
                None
            } else {
                Some(std::time::Duration::from_secs(252))
            },
            onset: raised.then(|| "3s after wifi roam".to_string()),
        }
    }

    #[test]
    fn only_real_problems_reach_a_sink() {
        let sinks = AlertSinks {
            desktop: true,
            min_severity: Severity::Degraded,
            ..Default::default()
        };
        assert!(sinks.is_active());
        assert!(sinks.wants(Severity::Down));
        assert!(sinks.wants(Severity::Degraded));
        // Notes are never worth waking someone for, whatever the floor says.
        assert!(!sinks.wants(Severity::Info));
        let lax = AlertSinks {
            desktop: true,
            min_severity: Severity::Info,
            ..Default::default()
        };
        assert!(!lax.wants(Severity::Info));
        // And with nothing configured there is nothing to send.
        assert!(!AlertSinks::default().is_active());
    }

    #[test]
    fn the_text_reads_as_a_sentence_both_ways() {
        let mut a = Alert::from_transition(&transition(true, Severity::Down), Some("Home".into()));
        assert_eq!(
            a.text(),
            "▲ gateway unresponsive (100% loss) · 3s after wifi roam · on Home"
        );
        a = Alert::from_transition(&transition(false, Severity::Down), None);
        assert_eq!(
            a.text(),
            "✓ gateway unresponsive (100% loss) — ended after 4m 12s"
        );
    }

    /// The notification's text is an argument, never part of the script.
    ///
    /// It was `system attribute "OCTOMON_BODY"` first, which AppleScript
    /// decodes as Mac OS Roman: every ▲, · and — arrived on screen as
    /// mojibake ("octomon ,Äî problem"). Arguments are decoded as UTF-8. The
    /// same shape also keeps a network-chosen string out of a script body, so
    /// folding the text back into the `-e` lines would break both at once.
    #[test]
    #[cfg(target_os = "macos")]
    fn the_notification_text_is_an_argument_not_script() {
        use std::ffi::OsStr;
        if crate::platform::tools::exists("terminal-notifier") {
            return; // a different notifier: see the test below
        }
        let body = "▲ gateway unresponsive (50% loss) · on Home WiFi";
        let cmd = notify_command("octomon — problem", body, true);
        let args: Vec<&OsStr> = cmd.get_args().collect();

        assert!(args.contains(&OsStr::new(body)), "the body is its own arg");
        // Every -e line is fixed script text with no message in it.
        for pair in args.windows(2) {
            if pair[0] == OsStr::new("-e") {
                let script = pair[1].to_string_lossy();
                assert!(
                    !script.contains("gateway") && !script.contains("Home"),
                    "message must not reach the script: {script}"
                );
            }
        }
        // And the message sits after the `--`, where osascript stops looking
        // for options — so a summary starting with a dash is still text.
        let sep = args
            .iter()
            .position(|a| *a == OsStr::new("--"))
            .expect("argument separator");
        assert!(args[sep + 1..].contains(&OsStr::new(body)));
    }

    /// Every sink but the desktop one is platform-neutral, and the desktop
    /// one has an implementation everywhere. What differs is whether the
    /// notifier is actually installed, which is only ever in doubt on Linux.
    #[test]
    fn every_platform_has_a_notifier_to_call() {
        let cmd = notify_command("octomon", "▲ something", true);
        let program = cmd.get_program().to_string_lossy().to_string();
        let expected = if cfg!(target_os = "macos") {
            ["osascript", "terminal-notifier"].as_slice()
        } else if cfg!(target_os = "windows") {
            ["powershell"].as_slice()
        } else {
            ["notify-send"].as_slice()
        };
        assert!(expected.contains(&program.as_str()), "notifier: {program}");

        // And the one platform that can be without it says so up front rather
        // than failing silently on the first finding.
        if cfg!(target_os = "linux") {
            assert_eq!(
                missing_notifier().is_some(),
                !crate::platform::tools::exists("notify-send")
            );
        } else {
            assert_eq!(missing_notifier(), None, "always present here");
        }
    }

    /// Which terminal a click should bring forward, from what the terminal
    /// itself says. An unknown one gets no target rather than a guess: naming
    /// an app that is not installed is how you get a "Where is …?" chooser.
    #[test]
    fn the_click_target_is_the_terminal_or_nothing() {
        assert_eq!(
            terminal_bundle(Some("Apple_Terminal")),
            Some("com.apple.Terminal")
        );
        assert_eq!(
            terminal_bundle(Some("ghostty")),
            Some("com.mitchellh.ghostty")
        );
        assert_eq!(terminal_bundle(Some("SomeNewTerminal")), None);
        assert_eq!(terminal_bundle(None), None, "a service has no terminal");
    }

    /// The payload never becomes shell syntax: a network can name itself
    /// whatever it likes, and that name ends up in a summary.
    #[test]
    fn hostile_text_travels_in_the_environment_not_the_command() {
        let mut t = transition(true, Severity::Down);
        t.finding.summary = "loss to \"; rm -rf ~; echo \"".into();
        let a = Alert::from_transition(&t, None);
        let env = a.env();
        let summary = env
            .iter()
            .find(|(k, _)| *k == "OCTOMON_SUMMARY")
            .map(|(_, v)| v.clone())
            .expect("summary in the environment");
        assert!(summary.contains("rm -rf"), "passed through verbatim");
        // The JSON body is serialised, not concatenated, so the same holds.
        let json = a.json();
        assert_eq!(json["summary"], serde_json::Value::from(summary));
        assert_eq!(json["event"], "raised");
        assert_eq!(json["severity"], "down");
    }
}

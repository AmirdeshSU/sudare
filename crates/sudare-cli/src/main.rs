#![forbid(unsafe_code)]

use clap::{Parser as ClapParser, Subcommand, ValueEnum};
use std::io::{BufRead, IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use sudare_core::parse::{evtx_to_xml, is_evtx};
use sudare_core::{Action, Engine, EntityType, Policy, Prepared, report};
use sudare_egress::cache::Cache;
use sudare_egress::http::ReqwestHttp;
use sudare_egress::llm::{self, ProviderConfig, ProviderKind};
use sudare_egress::pipeline::{self, AnalyzeOptions};
use sudare_egress::ti::TiRunner;

#[derive(ClapParser)]
#[command(
    name = "sudare",
    version,
    about = "Privacy-first, AI-assisted incident analysis. Sensitive values are masked before anything leaves this machine."
)]
struct Cli {
    /// Directory of extra TOML parser mappings.
    #[arg(long, global = true, env = "SUDARE_MAPPINGS_DIR")]
    mappings: Option<PathBuf>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// List the log parsers.
    Parsers,
    /// Dry run: print exactly what would be sent, with values masked.
    Mask(MaskArgs),
    /// Analyse a log file with an LLM.
    Analyze(Box<AnalyzeArgs>),
    /// Fetch an incident's events from a SIEM (read-only), for `sudare mask` / `analyze`.
    Pull(PullArgs),
    /// Run the HTTP API (configured by SUDARE_* environment variables; see README).
    Serve,
    /// Print a new random SUDARE_SECRET_KEY.
    Keygen,
}

#[derive(clap::Args)]
struct Common {
    /// Log file, or - for stdin. Native .evtx files are converted automatically.
    file: PathBuf,
    #[arg(long, value_enum, default_value_t = ModeArg::Default)]
    mode: ModeArg,
    /// Masking policy (see policy.example.toml).
    #[arg(long, env = "SUDARE_POLICY")]
    policy: Option<PathBuf>,
    /// Use this parser instead of auto-detecting one.
    #[arg(long)]
    parser: Option<String>,
}

#[derive(clap::Args)]
struct PullArgs {
    #[arg(value_enum)]
    siem: SiemArg,
    /// Incident ID.
    incident: String,
    /// Write to this file instead of stdout. The file holds unmasked log data.
    #[arg(short, long)]
    out: Option<PathBuf>,
}

/// Configured by SUDARE_FORTISIEM_* environment variables (see README).
#[derive(Clone, Copy, ValueEnum)]
enum SiemArg {
    Fortisiem,
}

#[derive(clap::Args)]
struct MaskArgs {
    #[command(flatten)]
    common: Common,
    /// Show only changed lines, as -/+ pairs.
    #[arg(long)]
    diff: bool,
    /// Also print the token → real value table to stderr (stays on this machine).
    #[arg(long)]
    show_map: bool,
}

#[derive(clap::Args)]
struct AnalyzeArgs {
    #[command(flatten)]
    common: Common,
    #[arg(long, value_enum, default_value_t = ProviderArg::Ollama)]
    provider: ProviderArg,
    #[arg(long)]
    model: Option<String>,
    /// Provider base URL: Ollama on another host, or an OpenAI-compatible server.
    #[arg(long, env = "SUDARE_BASE_URL")]
    base_url: Option<String>,
    /// Hosts that count as local (no confirmation needed), comma-separated.
    #[arg(long, env = "SUDARE_LOCAL_HOSTS", value_delimiter = ',')]
    local_hosts: Vec<String>,
    #[arg(long, value_enum, default_value_t = Format::Md)]
    format: Format,
    /// Skip threat-intel lookups.
    #[arg(long)]
    no_enrich: bool,
    /// Don't read or write the threat-intel cache.
    #[arg(long)]
    no_cache: bool,
    /// Send to a non-local provider without the interactive preview.
    #[arg(long)]
    yes: bool,
    /// Name of the detection rule that fired.
    #[arg(long)]
    rule_name: Option<String>,
    /// Condition / query of that rule.
    #[arg(long, requires = "rule_name")]
    rule_condition: Option<String>,
    /// Character budget for log lines (default: from the provider's context).
    #[arg(long)]
    max_input_chars: Option<usize>,
    /// Ollama context window in tokens. Ollama silently truncates past it.
    #[arg(long, default_value_t = 16_384)]
    num_ctx: u32,
    /// Ask follow-up questions after the report.
    #[arg(long)]
    chat: bool,
}

#[derive(Clone, Copy, ValueEnum)]
enum ModeArg {
    Default,
    Strict,
}

#[derive(Clone, Copy, ValueEnum)]
enum ProviderArg {
    Ollama,
    Openai,
    Anthropic,
    Gemini,
    OpenaiCompatible,
}

#[derive(Clone, Copy, PartialEq, ValueEnum)]
enum Format {
    Md,
    Json,
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<(), String> {
    match cli.cmd {
        Cmd::Parsers => {
            let engine = engine(None, ModeArg::Default, cli.mappings.as_deref())?;
            for p in engine.registry().parsers() {
                println!("{:<20} {}", p.name(), p.description());
            }
            Ok(())
        }
        Cmd::Mask(a) => mask(a, cli.mappings.as_deref()),
        Cmd::Analyze(a) => {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|e| e.to_string())?;
            rt.block_on(analyze(*a, cli.mappings.as_deref()))
        }
        Cmd::Pull(p) => tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| e.to_string())?
            .block_on(pull(p)),
        Cmd::Serve => {
            let cfg = sudare_server::Config::from_env()?;
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .map_err(|e| e.to_string())?
                .block_on(sudare_server::serve(cfg))
        }
        Cmd::Keygen => {
            let mut k = [0u8; 32];
            getrandom::fill(&mut k).map_err(|e| e.to_string())?;
            println!(
                "{}",
                k.iter().map(|b| format!("{b:02x}")).collect::<String>()
            );
            Ok(())
        }
    }
}

async fn pull(p: PullArgs) -> Result<(), String> {
    let SiemArg::Fortisiem = p.siem;
    let f = sudare_egress::siem::FortiSiem::from_lookup(|k| {
        std::env::var(k).ok().filter(|v| !v.trim().is_empty())
    })
    .map_err(|e| e.to_string())?
    .ok_or("FortiSIEM is not configured: set SUDARE_FORTISIEM_URL (see README)")?;
    let http = ReqwestHttp::new().map_err(|e| e.to_string())?;
    let json = f
        .triggering_events(&http, &p.incident)
        .await
        .map_err(|e| e.to_string())?;
    match p.out {
        Some(path) => {
            std::fs::write(&path, json).map_err(|e| format!("{}: {e}", path.display()))?;
            eprintln!(
                "wrote {} (unmasked). Next: sudare analyze {0}",
                path.display()
            );
        }
        None => println!("{json}"),
    }
    Ok(())
}

fn engine(policy: Option<&Path>, mode: ModeArg, mappings: Option<&Path>) -> Result<Engine, String> {
    let mut p = match policy {
        Some(path) => Policy::load(path).map_err(|e| e.to_string())?,
        None => Policy::default(),
    };
    if let ModeArg::Strict = mode {
        p = p.strict();
    }
    let mut engine = Engine::new(p).map_err(|e| e.to_string())?;
    if let Some(dir) = mappings {
        let entries = std::fs::read_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().is_some_and(|x| x == "toml") {
                let text = std::fs::read_to_string(&path)
                    .map_err(|e| format!("{}: {e}", path.display()))?;
                engine
                    .registry_mut()
                    .add_mapping(&text)
                    .map_err(|e| format!("{}: {e}", path.display()))?;
            }
        }
    }
    Ok(engine)
}

fn read_input(path: &Path) -> Result<String, String> {
    let bytes = if path == Path::new("-") {
        let mut b = Vec::new();
        std::io::stdin()
            .read_to_end(&mut b)
            .map_err(|e| e.to_string())?;
        b
    } else {
        std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?
    };
    if is_evtx(&bytes) {
        return evtx_to_xml(&bytes).map_err(|e| format!("{}: {e}", path.display()));
    }
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

fn salt() -> Result<[u8; 32], String> {
    let mut s = [0u8; 32];
    getrandom::fill(&mut s).map_err(|e| format!("no OS randomness: {e}"))?;
    Ok(s)
}

fn prepare(engine: &Engine, c: &Common) -> Result<Prepared, String> {
    let text = read_input(&c.file)?;
    engine
        .prepare(&text, c.parser.as_deref(), salt()?)
        .map_err(|e| e.to_string())
}

fn summary(p: &Prepared) -> String {
    let masked: Vec<String> = p
        .stats
        .masked
        .iter()
        .map(|(k, v)| format!("{k} {v}"))
        .collect();
    let mut s = format!(
        "parser {} · {} events{} · masked: {} · kept {} · {} public indicator(s)",
        p.parser,
        p.events,
        if p.parse_errors > 0 {
            format!(" ({} unparsed)", p.parse_errors)
        } else {
            String::new()
        },
        if masked.is_empty() {
            "nothing".into()
        } else {
            masked.join(", ")
        },
        p.stats.kept,
        p.indicators.len()
    );
    // Domains are only "internal" if the policy or a self-naming field says so. Show
    // the ones being sent as public so a missed internal domain is caught here.
    let kept: Vec<&str> = p
        .decisions
        .iter()
        .filter(|d| d.action == Action::Keep && d.entity.kind == EntityType::Fqdn)
        .map(|d| d.entity.normalized.as_str())
        .collect();
    if !kept.is_empty() {
        s.push_str(&format!(
            "\nkept as public domains: {}\n(if any are yours, add them to [classify] internal_domains in your policy)",
            kept.join(", ")
        ));
    }
    s
}

fn mask(a: MaskArgs, mappings: Option<&Path>) -> Result<(), String> {
    let engine = engine(a.common.policy.as_deref(), a.common.mode, mappings)?;
    let p = prepare(&engine, &a.common)?;
    let mut out = std::io::stdout().lock();
    if a.diff {
        for (n, (orig, masked)) in p.normalized.lines().zip(p.input.text().lines()).enumerate() {
            if orig != masked {
                let _ = writeln!(out, "L{:04} - {orig}\nL{:04} + {masked}", n + 1, n + 1);
            }
        }
    } else {
        let _ = write!(out, "{}", p.input.text());
        if !p.input.text().ends_with('\n') {
            let _ = writeln!(out);
        }
    }
    eprintln!("{}", summary(&p));
    if a.show_map {
        eprintln!("token → value (local only, never sent):");
        for (token, kind, _) in p.map.tokens() {
            eprintln!(
                "  {token:<28} {:<10} {}",
                kind.label(),
                p.map.original(token).unwrap_or("")
            );
        }
    }
    Ok(())
}

fn confirm(question: &str) -> bool {
    eprint!("{question} [y/N] ");
    let _ = std::io::stderr().flush();
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line).is_ok() && matches!(line.trim(), "y" | "Y" | "yes")
}

async fn analyze(a: AnalyzeArgs, mappings: Option<&Path>) -> Result<(), String> {
    let engine = engine(a.common.policy.as_deref(), a.common.mode, mappings)?;
    let mut p = prepare(&engine, &a.common)?;

    let kind = match a.provider {
        ProviderArg::Ollama => ProviderKind::Ollama,
        ProviderArg::Openai => ProviderKind::OpenAi,
        ProviderArg::Anthropic => ProviderKind::Anthropic,
        ProviderArg::Gemini => ProviderKind::Gemini,
        ProviderArg::OpenaiCompatible => ProviderKind::OpenAiCompatible,
    };
    let mut cfg = ProviderConfig::new(kind);
    cfg.model = a.model.clone();
    cfg.base_url = a.base_url.clone();
    cfg.num_ctx = a.num_ctx;
    cfg.local_hosts = a.local_hosts.clone();
    cfg.max_input_chars = a.max_input_chars;
    let provider = llm::build(cfg).map_err(|e| e.to_string())?;
    let interactive = std::io::stdin().is_terminal() && a.common.file != Path::new("-");

    eprintln!("{}", summary(&p));
    if !provider.is_local() && !a.yes {
        if !interactive {
            return Err(format!(
                "refusing to send to {} ({}) without review. Inspect with `sudare mask {}`, then re-run with --yes.",
                provider.name(),
                provider.base_url(),
                a.common.file.display()
            ));
        }
        eprintln!(
            "\n--- preview: first 30 masked lines (full view: sudare mask {}) ---",
            a.common.file.display()
        );
        for line in p.input.text().lines().take(30) {
            eprintln!("{line}");
        }
        eprintln!("---");
        if !confirm(&format!(
            "Send this masked input to {} at {}?",
            provider.name(),
            provider.base_url()
        )) {
            return Err("cancelled; nothing was sent".into());
        }
    }

    let http = ReqwestHttp::new().map_err(|e| e.to_string())?;
    let mut enrichment = vec![Vec::new(); p.indicators.len()];
    if !a.no_enrich && !p.indicators.is_empty() {
        let mut runner = TiRunner::from_env();
        let configured = runner.configured().join(", ");
        if configured.is_empty() {
            eprintln!("threat intel: no SUDARE_*_KEY set, skipping lookups");
        } else {
            if !a.no_cache
                && let Some(path) = Cache::default_path()
            {
                match Cache::open(&path, Duration::from_secs(24 * 3600)) {
                    Ok(c) => runner = runner.with_cache(c),
                    Err(e) => eprintln!("threat intel cache disabled: {e}"),
                }
            }
            eprintln!(
                "threat intel: checking {} public indicator(s) with {configured}",
                p.indicators.len()
            );
            enrichment = pipeline::enrich(&p, &runner, &http).await;
        }
    }

    eprintln!(
        "analysing with {} / {} ...",
        provider.name(),
        provider.model()
    );
    let opts = AnalyzeOptions {
        rule: a
            .rule_name
            .clone()
            .map(|n| (n, a.rule_condition.clone().unwrap_or_default())),
        max_input_chars: a.max_input_chars,
        now_unix: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs()),
    };
    let result = pipeline::analyze(
        &engine,
        &mut p,
        &enrichment,
        provider.as_ref(),
        &http,
        &opts,
    )
    .await
    .map_err(|e| match (kind, &e) {
        (ProviderKind::Ollama, llm::LlmError::Http { .. }) => {
            format!(
                "{e}\nIs Ollama running at {}? Start it with `ollama serve` and `ollama pull {}`.",
                provider.base_url(),
                provider.model()
            )
        }
        _ => e.to_string(),
    })?;
    match a.format {
        Format::Md => println!("{}", report::render_markdown(&result.report)),
        Format::Json => println!(
            "{}",
            serde_json::to_string_pretty(&result.report).map_err(|e| e.to_string())?
        ),
    }

    if a.chat {
        if !interactive {
            return Err("--chat needs an interactive terminal".into());
        }
        let mut history = Vec::new();
        loop {
            eprint!("\nask (empty line to quit)> ");
            let _ = std::io::stderr().flush();
            let mut q = String::new();
            if std::io::stdin()
                .lock()
                .read_line(&mut q)
                .map_err(|e| e.to_string())?
                == 0
                || q.trim().is_empty()
            {
                break;
            }
            let answer = pipeline::chat(
                &engine,
                &mut p,
                &result.masked_output,
                &mut history,
                q.trim(),
                provider.as_ref(),
                &http,
                a.max_input_chars,
            )
            .await
            .map_err(|e| e.to_string())?;
            println!("\n{answer}");
        }
    }
    Ok(())
}

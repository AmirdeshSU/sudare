//! Property tests: masking hides every generated sensitive value, unmasking restores
//! the input exactly, and no input or parser can panic.

use proptest::prelude::*;
use sudare_core::parse::Registry;
use sudare_core::{Engine, Policy};

fn engine() -> Engine {
    let policy = Policy::from_toml(
        "[classify]\ninternal_networks = [\"192.0.2.0/24\"]\ninternal_domains = [\"corp.example.com\"]",
    )
    .unwrap();
    Engine::new(policy).unwrap()
}

/// `w` occurs in `text` as a whole word (case-insensitive).
fn has_word(text: &str, w: &str) -> bool {
    let (t, w) = (text.to_lowercase(), w.to_lowercase());
    let glued = |c: Option<char>| c.is_some_and(|c| c.is_alphanumeric() || c == '_' || c == '-');
    t.match_indices(&w)
        .any(|(i, _)| !glued(t[..i].chars().next_back()) && !glued(t[i + w.len()..].chars().next()))
}

fn line((user, host, n, shape): &(String, String, u8, u8)) -> String {
    match shape {
        0 => format!("login user={user} host={host} src=192.0.2.{n}\n"),
        1 => format!(
            "{host}.corp.example.com connected to 198.51.100.{n} as {user}@corp.example.com\n"
        ),
        2 => format!("CORP\\{user} ran C:\\Users\\{user}\\tool.exe on host={host}\n"),
        _ => format!("user={user} password=p{n}x{user}q from 192.0.2.{n}\n"),
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn mask_hides_and_unmask_restores(
        lines in prop::collection::vec(("[a-z]{3,10}", "[a-z]{2,6}-[0-9]{2}", 1u8..=254, 0u8..4), 1..20)
    ) {
        let text: String = lines.iter().map(line).collect();
        let p = engine().prepare(&text, None, [9; 32]).unwrap();
        let masked = p.input.text();
        for (user, host, n, _) in &lines {
            prop_assert!(!has_word(masked, user), "user {} survived:\n{}", user, masked);
            prop_assert!(!has_word(masked, host), "host {} survived:\n{}", host, masked);
            prop_assert!(!has_word(masked, &format!("192.0.2.{n}")), "IP survived:\n{}", masked);
        }
        prop_assert_eq!(p.map.unmask(masked).text, p.normalized.clone());
    }

    #[test]
    fn any_input_never_panics(s in any::<String>()) {
        let p = engine().prepare(&s, None, [1; 32]).unwrap();
        let _ = p.map.unmask(p.input.text());
    }

    #[test]
    fn every_parser_survives_log_shaped_noise(s in r"(<[0-9]{1,3}>|CEF:0\||LEEF:2\.0\||\{|\[|<Event>|[ -~\t\n\\|=:]){0,80}") {
        for p in Registry::builtin().parsers() {
            let _ = p.parse(&s);
        }
    }
}

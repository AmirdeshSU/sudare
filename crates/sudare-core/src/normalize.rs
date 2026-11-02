//! Input normalization. Runs before anything else so look-alike characters can't
//! smuggle a value past the extractors (fullwidth digits, zero-width joiners inside
//! an IP, bidi overrides). Every span in the pipeline refers to the normalized text.

use unicode_normalization::UnicodeNormalization;

pub fn normalize(input: &str) -> String {
    input
        .replace("\r\n", "\n")
        .replace('\r', "\n")
        .nfkc()
        .filter(|c| !is_format_char(*c))
        .collect()
}

/// Unicode format characters (category Cf) and other invisible code points.
fn is_format_char(c: char) -> bool {
    matches!(c,
        '\u{00AD}' | '\u{034F}' | '\u{061C}' | '\u{115F}' | '\u{1160}' | '\u{17B4}' | '\u{17B5}'
        | '\u{180B}'..='\u{180F}'
        | '\u{200B}'..='\u{200F}'
        | '\u{202A}'..='\u{202E}'
        | '\u{2060}'..='\u{2064}'
        | '\u{2066}'..='\u{206F}'
        | '\u{3164}' | '\u{FE00}'..='\u{FE0F}' | '\u{FEFF}' | '\u{FFA0}'
        | '\u{FFF9}'..='\u{FFFB}'
        | '\u{1D173}'..='\u{1D17A}'
        | '\u{E0000}'..='\u{E007F}'
        | '\u{E0100}'..='\u{E01EF}')
}

/// Byte offset → 1-based line number.
pub struct LineIndex {
    starts: Vec<usize>,
    count: u32,
}

impl LineIndex {
    pub fn new(text: &str) -> Self {
        let mut starts = vec![0];
        starts.extend(text.match_indices('\n').map(|(i, _)| i + 1));
        let mut count = starts.len() as u32;
        if text.is_empty() {
            count = 0;
        } else if text.ends_with('\n') {
            count -= 1;
        }
        Self { starts, count }
    }

    pub fn line(&self, offset: usize) -> u32 {
        self.starts.partition_point(|&s| s <= offset) as u32
    }

    pub fn count(&self) -> u32 {
        self.count
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_invisible_and_folds_fullwidth() {
        assert_eq!(normalize("192.0.2\u{200B}.7"), "192.0.2.7");
        assert_eq!(
            normalize("\u{FF57}\u{FF45}\u{FF42}\u{FF10}\u{FF11}"),
            "web01"
        );
        assert_eq!(normalize("a\r\nb\rc"), "a\nb\nc");
    }

    #[test]
    fn line_index() {
        let li = LineIndex::new("a\nbb\nc\n");
        assert_eq!(li.count(), 3);
        assert_eq!(li.line(0), 1);
        assert_eq!(li.line(2), 2);
        assert_eq!(li.line(5), 3);
    }
}

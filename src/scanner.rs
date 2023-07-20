pub use regex::Regex;

#[derive(PartialEq, Debug)]
pub struct Scanner {
    cursor: usize,
    characters: Vec<char>,
}

#[derive(PartialEq, Debug)]
pub enum ScanError {
    EndOfLine,                     // end of line reached during parsing
    InvalidRegexCaptureConversion, // regex with capture groups could not be converted
}

impl From<regex::Error> for ScanError {
    fn from(_err: regex::Error) -> ScanError {
        ScanError::InvalidRegexCaptureConversion
    }
}

#[derive(Eq, Debug, Clone)]
pub struct ScannerPos {
    pub cursor: usize,
}

impl From<ScannerPos> for usize {
    fn from(value: ScannerPos) -> Self {
        value.cursor
    }
}

impl PartialEq for ScannerPos {
    fn eq(&self, other: &Self) -> bool {
        self.cursor == other.cursor
    }
}

impl PartialOrd for ScannerPos {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for ScannerPos {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.cursor.cmp(&other.cursor)
    }
}

pub struct ErrorContext {
    pub context: String,
    pub line: u32,
    pub column: u32,
}

#[derive(Debug)]
pub struct LineIterator<'a> {
    cursor: usize,
    characters: &'a [char],
}

impl<'a> LineIterator<'a> {
    pub fn take_while_peek<P>(&self, predicate: P) -> (Vec<String>, usize)
    where
        Self: Sized,
        P: Fn(&str) -> bool,
    {
        let len = self.characters.len();
        let mut cursor = self.cursor;
        let mut peek_cursor = self.cursor;

        let mut lines: Vec<String> = Vec::new();

        loop {
            if peek_cursor >= len {
                break;
            }
            if self.characters[peek_cursor] == '\n' {
                let line = &self.characters[cursor..peek_cursor];
                let line = line.iter().collect::<String>();
                if !predicate(&line) {
                    return (lines, cursor);
                }
                lines.push(line);
                cursor = peek_cursor + 1;
            }

            peek_cursor += 1;
        }

        (lines, cursor)
    }
}

impl<'a> Iterator for LineIterator<'a> {
    type Item = String;
    fn next(&mut self) -> Option<Self::Item> {
        let len: usize = self.characters.len();
        if self.cursor >= len {
            return None;
        }
        let mut peek_cursor: usize = self.cursor;
        loop {
            if peek_cursor >= len || self.characters[peek_cursor] == '\n' {
                let result = self.characters[self.cursor..peek_cursor]
                    .iter()
                    .collect::<String>();
                self.cursor = peek_cursor;
                return Some(result);
            }
            peek_cursor += 1;
        }
    }
}

// whitespace character which are not newlines
pub const WS_CHARS: [char; 4] = [' ', '\t', '\r', '\u{000C}'];

impl Scanner {
    pub fn new(string: &str) -> Scanner {
        Scanner {
            cursor: 0,
            characters: string.chars().collect(),
        }
    }

    pub fn iter_at_pos(&mut self) -> LineIterator {
        LineIterator {
            characters: &self.characters[..],
            cursor: self.cursor,
        }
    }

    pub fn set_pos<T: Into<usize>>(&mut self, position: T) {
        self.cursor = position.into();
    }

    pub fn get_pos(&self) -> ScannerPos {
        ScannerPos {
            cursor: self.cursor,
        }
    }

    pub fn get_cursor(&self) -> usize {
        self.cursor
    }

    pub fn get_error_context(&self, start_pos: usize, end_pos: Option<usize>) -> ErrorContext {
        let mut line = 0;
        let mut last_newline_pos = 0;
        for (index, char) in self.characters[..start_pos].iter().enumerate() {
            if char == &'\n' {
                line += 1;
                last_newline_pos = index;
            }
        }

        let column = start_pos - last_newline_pos;

        let context = if let Some(end_pos) = end_pos {
            self.characters[start_pos..end_pos]
                .iter()
                .collect::<String>()
        } else {
            self.characters[last_newline_pos..start_pos]
                .iter()
                .collect::<String>()
        };

        ErrorContext {
            line,
            column: column as u32,
            context,
        }
    }

    pub fn get_from_to<S: Into<usize>, E: Into<usize>>(&self, start: S, end: E) -> String {
        let start: usize = start.into();
        let end = end.into();
        if start == end {
            return String::new();
        }
        self.characters[start..end].iter().collect::<String>()
    }

    // Return the character under the cursor without advancing
    pub fn peek(&self) -> Option<&char> {
        self.characters.get(self.cursor)
    }

    // Return the next n characters or none if not enough characters are present
    pub fn peek_n(&self, num: usize) -> Option<Vec<char>> {
        if self.cursor + num > self.characters.len() {
            return None;
        }
        Some(self.characters[self.cursor..(self.cursor + num)].to_vec())
    }

    // Checks if we scanned the whole file
    pub fn is_done(&self) -> bool {
        self.cursor >= self.characters.len()
    }

    // Get the character under the cursor and advance. None is returned if we are at the end of the
    // file.
    pub fn next_char(&mut self) -> Option<&char> {
        match self.characters.get(self.cursor) {
            Some(character) => {
                self.cursor += 1;
                Some(character)
            }
            None => None,
        }
    }

    // Advance the cursor if the supplied character matches. Returns true if a match and advance
    // occurred, false otherwise
    pub fn take(&mut self, character: &char) -> bool {
        match self.characters.get(self.cursor) {
            Some(current) => {
                if current == character {
                    self.cursor += 1;
                    true
                } else {
                    false
                }
            }
            None => false,
        }
    }

    /// Get the next non whitespace character under the cursor without advancing.
    /// Following characters are skipped: space, tab, form feed, carriage return
    #[allow(dead_code)]
    pub fn peek_skip_ws(&self) -> Option<char> {
        let mut peek_cursor = self.cursor;
        // whitespace is regular space, tab, carriage return and form feed
        loop {
            if peek_cursor >= self.characters.len() {
                return None;
            }
            let char: char = self.characters[peek_cursor];
            if !WS_CHARS.iter().any(|ch| *ch == char) {
                return Some(self.characters[peek_cursor]);
            }
            peek_cursor += 1;
        }
    }

    /// Skip whitespace characters which are not new lines. Following characters are skipped: space, tab, form feed, carriage return
    pub fn skip_ws(&mut self) {
        loop {
            if self.cursor >= self.characters.len() {
                return;
            }
            let char: char = self.characters[self.cursor];

            if !WS_CHARS.iter().any(|ch| *ch == char) {
                return;
            }
            self.cursor += 1;
        }
    }

    // Skip empty lines, lines containing whitespace are not skipped
    pub fn skip_empty_lines(&mut self) {
        loop {
            match self.peek() {
                Some('\n') => {
                    self.next_char();
                }
                _ => return,
            }
        }
    }

    /// Tries to match the given string and if successful moves the cursor to the next
    /// position after the strings and returns if matched or not
    /// If cursor is at the end of the file, nothing can be matched and always false will be
    /// returned.
    /// matching the empty string "" will always return in a match without moving the cursor
    /// forward.
    pub fn match_str_forward(&mut self, str: &str) -> bool {
        let chars = str.chars().collect::<Vec<char>>();
        let sequence = chars.as_slice();

        let mut peek_cursor = self.cursor;
        let mut sequence_cursor = 0;
        let seq_len = sequence.len();
        let end_index = self.characters.len();

        let matches_str = loop {
            if sequence_cursor >= seq_len {
                break true;
            }
            if peek_cursor >= end_index {
                break false;
            }
            let current_char: char = self.characters[peek_cursor];
            if current_char != sequence[sequence_cursor] {
                break false;
            }
            sequence_cursor += 1;
            peek_cursor += 1;
        };
        if matches_str {
            self.cursor = peek_cursor;
        }
        matches_str
    }

    pub fn seek_return(&mut self, character: &char) -> Result<String, ScanError> {
        let start: usize = self.cursor;
        loop {
            if self.cursor >= self.characters.len() {
                return Err(ScanError::EndOfLine);
            }
            if self.characters[self.cursor] == *character {
                let string = self.characters[start..self.cursor].iter().collect();
                self.cursor += 1;
                return Ok(string);
            }
            self.cursor += 1;
        }
    }

    // Tries to match a regex from the current position of the scanner (cursor) forward
    // if it matches Ok result is returned with a list of matches. If the string contained capture groups then
    // a list of captured strings is returned, an empty list otherwise if the regex matched but no
    // capture groups were present. If the regex does not contain a regex that starts at the
    // beginning of the string then the `^` symbol is added. If a match occurs the cursor is moved
    // forward. If no match occurs None is returned (no matter if capture groups were provided).
    pub fn match_regex_forward(
        &mut self,
        user_regex_str: &str,
    ) -> Result<Option<Vec<String>>, ScanError> {
        if self.cursor >= self.characters.len() {
            return Err(ScanError::EndOfLine);
        }

        // we only want to match from the current position forward, therefore add regex start of
        // string symbol ^
        let mut regex_str: String = user_regex_str.to_owned();
        if !regex_str.starts_with('^') {
            regex_str = format!("^{}", user_regex_str);
        }
        let regex = regex::bytes::Regex::new(&regex_str)?;

        let string_tmp = self.characters[self.cursor..].iter().collect::<String>();
        let bytes = string_tmp.as_bytes();
        return match regex.captures(bytes) {
            Some(comment_captures) => {
                let mut str_captures: Vec<String> = Vec::new();

                for (i, capture) in comment_captures.iter().enumerate() {
                    // first match is full string
                    // if we got a match we adjust the cursor otherwise we don't
                    if i == 0 {
                        let matched_str = std::str::from_utf8(capture.unwrap().as_bytes()).unwrap();
                        let num_chars = matched_str.chars().count();
                        self.cursor += num_chars;
                    } else {
                        let capture_bytes: Vec<u8> = capture.unwrap().as_bytes().to_owned();
                        match String::from_utf8(capture_bytes) {
                            Ok(string) => {
                                str_captures.push(string);
                            }
                            Err(_) => return Err(ScanError::InvalidRegexCaptureConversion),
                        }
                    }
                }
                return Ok(Some(str_captures));
            }
            None => Ok(None),
        };
    }

    /// Get the current line (excluding the new line character) and advance to the next.
    pub fn get_line_and_advance(&mut self) -> Option<String> {
        let mut peek_cursor = self.cursor;
        let num_chars = self.characters.len();
        if self.is_done() {
            return None;
        }

        let line = loop {
            if peek_cursor >= num_chars || self.characters[peek_cursor] == '\n' {
                break self.characters[self.cursor..peek_cursor]
                    .iter()
                    .collect::<String>();
            }
            peek_cursor += 1;
        };

        // skip \n character
        if peek_cursor < num_chars {
            peek_cursor += 1;
        }

        self.cursor = peek_cursor;

        Some(line)
    }

    pub fn peek_line(&mut self) -> Option<String> {
        if self.is_done() {
            return None;
        }

        let mut peek_cursor = self.cursor;
        let len = self.characters.len();

        while peek_cursor < len && self.characters[peek_cursor] != '\n' {
            peek_cursor += 1;
        }

        Some(
            self.characters[self.cursor..peek_cursor]
                .iter()
                .collect::<String>(),
        )
    }

    pub fn skip_to_next_line(&mut self) {
        loop {
            if self.is_done() {
                return;
            }
            if self.characters[self.cursor] == '\n' {
                self.cursor += 1;
                return;
            }
            self.cursor += 1;
        }
    }

    pub fn get_tokens(&self) -> Vec<String> {
        // @TODO check whitespace
        self.characters
            .iter()
            .collect::<String>()
            .split_whitespace()
            .map(|s| s.to_string())
            .collect()
    }

    /// Return the previous line's bounds (start and end position)
    fn get_prev_line_bounds(&self) -> Option<(usize, usize)> {
        if self.cursor == 0 {
            return None;
        }
        let mut line_end = self.cursor - 1;
        loop {
            // no previous line found
            if line_end == 0 {
                return None;
            }
            // found marker for previous line
            if self.characters[line_end] == '\n' {
                break;
            }

            line_end -= 1;
        }

        let mut line_start = line_end - 1;
        loop {
            if line_start == 0 {
                break;
            }
            if self.characters[line_start] == '\n' {
                // we found the previous line but move cursor after newline character
                line_start += 1;
                break;
            }
            line_start -= 1;
        }
        if line_start > line_end {
            line_start = line_end;
        }

        Some((line_start, line_end))
    }

    /// Return the previous line without moving the cursor position
    pub fn get_prev_line(&self) -> Option<String> {
        let (line_start, line_end) = self.get_prev_line_bounds()?;
        if line_start == line_end {
            return Some("".to_string());
        }
        return Some(
            self.characters[line_start..line_end]
                .iter()
                .collect::<String>(),
        );
    }

    /// Change the position to the start of the new line if exists, otherwise do nothing
    pub fn step_to_previous_line_start(&mut self) {
        if let Some((line_start, _)) = self.get_prev_line_bounds() {
            self.cursor = line_start;
        }
    }
}

// only for debugging
#[allow(dead_code)]
#[cfg(debug_assertions)]
impl Scanner {
    pub fn debug_string(&self) -> String {
        let before: String = self.characters[..self.cursor].iter().collect();

        let current: String = self
            .characters
            .get(self.cursor)
            .map_or("".to_string(), |c| c.to_string());

        let after: String = if self.cursor >= self.characters.len() - 1 {
            String::new()
        } else {
            self.characters[self.cursor + 1..].iter().collect()
        };
        format!("{}[{}]{}", before, current, after)
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    pub fn seek_return() {
        let string = "abc def    ghi\n\n next line";
        let mut scanner = Scanner::new(string);

        match scanner.seek_return(&'\n') {
            Ok(result) => {
                assert_eq!(result, "abc def    ghi");
                assert_eq!(
                    scanner.cursor, 15,
                    "position should be right after new line"
                );
            }
            err => panic!("invalid result: {:?}", err),
        }

        match scanner.seek_return(&'\n') {
            Ok(result) => {
                assert_eq!(result, "");
                assert_eq!(scanner.cursor, 16);
            }
            err => panic!("invalid result: {:?}", err),
        }
    }

    #[test]
    pub fn seek_return_missing() {
        let string = "abc def    ghi";
        let mut scanner = Scanner::new(string);

        match scanner.seek_return(&'\n') {
            Ok(_) => panic!("should not have found missing new line"),

            Err(err) => {
                assert_eq!(err, ScanError::EndOfLine);
            }
        }
    }

    #[test]
    pub fn get_line_and_advance() {
        let string = "First line\n    Next Line  \n";
        let mut scanner = Scanner::new(string);

        let line = scanner.get_line_and_advance();
        assert_eq!(line, Some("First line".to_string()));
        assert_eq!(scanner.cursor, 11);

        let next = scanner.get_line_and_advance();
        assert_eq!(next, Some("    Next Line  ".to_string()));
        assert!(scanner.is_done());
        assert_eq!(scanner.cursor, string.len());

        // at the end, None is returned
        let next = scanner.get_line_and_advance();
        assert!(next.is_none());
        assert!(scanner.is_done());
        assert!(scanner.cursor == string.len());
    }

    #[test]
    pub fn skip_to_next_line() {
        let string = "First line\nSecond Line\n\n";
        let mut scanner = Scanner::new(string);
        assert_eq!(scanner.cursor, 0);

        scanner.skip_to_next_line();
        assert_eq!(scanner.cursor, 11);
        scanner.skip_to_next_line();
        assert_eq!(scanner.cursor, 23);
        scanner.skip_to_next_line();
        assert_eq!(scanner.cursor, 24);
        assert_eq!(scanner.cursor, string.len());
        assert!(scanner.is_done());
    }

    #[test]
    pub fn skip_empty_lines() {
        let string = "0\n\n\n4";
        let mut scanner = Scanner::new(string);

        scanner.skip_empty_lines();
        assert_eq!(scanner.cursor, 0);

        scanner.next_char();
        assert_eq!(scanner.cursor, 1);

        scanner.skip_empty_lines();
        assert_eq!(scanner.cursor, 4);
    }

    #[test]
    pub fn skip_ws() {
        let string = "0     \r \t \u{000C}  1";
        let mut scanner = Scanner::new(string);

        // don't skip non whitespace
        scanner.skip_ws();
        assert_eq!(scanner.cursor, 0);

        scanner.next_char();
        scanner.skip_ws();
        let last_char = scanner.peek().unwrap();
        assert_eq!(*last_char, '1');
    }

    #[test]
    pub fn match_str_forward() {
        let string = "012   \nTest line";
        let mut scanner = Scanner::new(string);

        // don't skip non whitespace
        assert!(scanner.match_str_forward("012"));
        assert_eq!(scanner.cursor, 3);

        assert!(scanner.match_str_forward("   \n"));
        assert_eq!(scanner.cursor, 7);

        assert!(!scanner.match_str_forward("No match"));
        assert_eq!(scanner.cursor, 7);

        assert!(scanner.match_str_forward("Test line"));
        assert!(scanner.is_done());

        assert!(!scanner.match_str_forward("No match"));

        assert!(scanner.match_str_forward(""));
    }

    #[test]
    pub fn take() {
        let string = "0 \n";
        let mut scanner = Scanner::new(string);

        assert_eq!(scanner.cursor, 0);
        assert!(scanner.take(&'0'));
        assert_eq!(scanner.cursor, 1);
        assert!(scanner.take(&' '));
        assert_eq!(scanner.cursor, 2);
        assert!(scanner.take(&'\n'));
        assert_eq!(scanner.cursor, 3);
        assert!(scanner.is_done());
        assert!(!scanner.take(&' '));
    }

    #[test]
    pub fn peek() {
        let string = "0 \n";
        let mut scanner = Scanner::new(string);

        assert_eq!(scanner.peek(), Some(&'0'));
        assert_eq!(scanner.cursor, 0);

        scanner.next_char();
        assert_eq!(scanner.peek(), Some(&' '));
        assert_eq!(scanner.cursor, 1);

        scanner.next_char();
        assert_eq!(scanner.peek(), Some(&'\n'));
        assert_eq!(scanner.cursor, 2);

        scanner.next_char();

        // we are at the end
        assert_eq!(scanner.peek(), None);
        assert!(scanner.is_done());
    }

    #[test]
    pub fn match_regex_forward_only_at_start() {
        let string = "### 000 123 456 ";
        let mut scanner = Scanner::new(string);

        // the regex should only match from the beginning of the string and not within
        // no match should return None
        let matches = scanner.match_regex_forward("123").unwrap();
        assert_eq!(matches, None);
        let mut scanner = Scanner::new(string);
        let matches = scanner.match_regex_forward("^123").unwrap();
        assert_eq!(matches, None);

        // here we match the regex but no capture group was provided, so return should be
        // Ok(Some([]))
        let mut scanner = Scanner::new(string);
        let matches = scanner.match_regex_forward("###").unwrap().unwrap();
        assert_eq!(matches.len(), 0);

        let mut scanner = Scanner::new(string);
        let matches = scanner.match_regex_forward("^###").unwrap().unwrap();
        assert_eq!(matches.len(), 0);

        // we match and have a capture group
        let mut scanner = Scanner::new(string);
        let matches = scanner
            .match_regex_forward("### (\\d\\d\\d)")
            .unwrap()
            .unwrap();
        assert_eq!(matches, vec!["000"]);

        // we move the cursor forward and should only match from the current position and not the
        // start!
        let mut scanner = Scanner::new(string);
        scanner.match_str_forward("### ");
        let matches = scanner.match_regex_forward("###").unwrap();
        assert_eq!(matches, None);
        // no matches from the start as the cursor has been moved forward
        let matches = scanner.match_regex_forward("###").unwrap();
        assert_eq!(matches, None);
        // now we match from the current cursor forward
        let matches = scanner.match_regex_forward("(000)").unwrap().unwrap();
        assert_eq!(matches, vec!["000"]);
    }

    #[test]
    pub fn match_regex_forward_no_captures() {
        let string = "000 123 456 | abc def ghi | \n\t\r\n end";
        let mut scanner = Scanner::new(string);

        // we should get ok, and an empty list of matches as we have no capture groups
        let mut matches = scanner
            .match_regex_forward("[0-9]{3} [0-9]{3} 456")
            .unwrap()
            .unwrap();
        let empty: Vec<String> = Vec::new();
        assert_eq!(matches, empty);

        _ = scanner.match_regex_forward(" \\| ");

        matches = scanner
            .match_regex_forward("(abc) [a-z]{3} (ghi)")
            .unwrap()
            .unwrap();
        assert_eq!(matches, vec!["abc", "ghi"]);

        _ = scanner.match_regex_forward(" \\| ");

        matches = scanner.match_regex_forward("\n(\t\r)\n ").unwrap().unwrap();

        assert_eq!(matches, ["\t\r".to_string()]);
    }

    #[test]
    pub fn get_prev_line_bounds() {
        let string = "abc\ndef\n\n\n";
        let mut scanner = Scanner::new(string);
        assert_eq!(scanner.get_prev_line_bounds(), None);

        scanner.skip_to_next_line();
        assert_eq!(scanner.get_prev_line_bounds(), Some((0, 3)));
        scanner.skip_to_next_line();
        assert_eq!(scanner.get_prev_line_bounds(), Some((4, 7)));
    }
}

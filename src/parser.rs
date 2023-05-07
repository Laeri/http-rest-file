pub use crate::scanner::Scanner;

use std::str::FromStr;

use crate::{
    model::model,
    model::model::ParseErrorType,
    parser::model::HttpMethod,
    scanner::{LineIterator, WS_CHARS},
};

pub use http::Uri;

use self::model::{Multipart, RequestTarget};

pub struct Parser {}

impl Parser {
    pub const REST_FILE_EXTENSIONS: [&str; 2] = ["http", "rest"];
    pub fn has_valid_extension<T: AsRef<std::path::Path>>(path: &T) -> bool {
        let extension = path.as_ref().extension();
        match extension {
            Some(extension) => Parser::REST_FILE_EXTENSIONS.contains(&extension.to_str().unwrap()),
            _ => false,
        }
    }

    pub fn parse_name_comment(
        scanner: &mut Scanner,
    ) -> Result<Option<model::Name>, ParseErrorType> {
        scanner.skip_empty_lines();
        scanner.skip_ws();

        let name_regex = "\\s*#\\s*@name\\s*=\\s*(.*)[$\n]";
        if let Ok(Some(captures)) = scanner.match_regex_forward(name_regex) {
            let name = captures.first().unwrap().trim().to_string();
            Ok(Some(model::Name { value: name }))
        } else {
            Ok(None)
        }
    }

    /// match a comment line after '###', '//' or '##' has been stripped from it
    pub fn parse_comment_line(
        scanner: &mut Scanner,
    ) -> Result<Option<model::Comment>, ParseErrorType> {
        scanner.skip_ws();
        match scanner.seek_return(&'\n') {
            Ok(value) => Ok(Some(model::Comment { value })),
            Err(_) => Err(ParseErrorType::Unspecified),
        }
    }

    // @TODO: create a macro that generates a match statement for each enum variant
    pub fn match_request_method(str: &str) -> model::HttpMethod {
        match str {
            "GET" => HttpMethod::GET,
            "PUT" => HttpMethod::PUT,
            "POST" => HttpMethod::POST,
            "PATCH" => HttpMethod::PATCH,
            "DELETE" => HttpMethod::DELETE,
            "HEAD" => HttpMethod::HEAD,
            "OPTIONS" => HttpMethod::OPTIONS,
            "CONNECT " => HttpMethod::CONNECT,
            "TRACE" => HttpMethod::TRACE,
            custom => HttpMethod::CUSTOM(custom.to_string()),
        }
    }

    pub fn parse_request_target(
        target_str: &str,
    ) -> Result<Option<model::RequestTarget>, ParseErrorType> {
        let target = RequestTarget::from(target_str);
        if let RequestTarget::InvalidTarget(value) = target {
            return Err(ParseErrorType::InvalidTargetUrl(value));
        }

        Ok(Some(target))
    }

    // [method required-whitespace] request-target [required-whitespace http-version]
    // @TODO errors are ignored for now!
    pub fn parse_request_line(
        scanner: &mut Scanner,
    ) -> Result<Option<model::RequestLine>, ParseErrorType> {
        let mut line = match scanner.get_line_and_advance() {
            Some(line) => line,
            _ => String::new(),
        };

        // request line can be split over multiple lines but all lines following need to be
        // indented
        let line_iterator: LineIterator = scanner.iter_at_pos();
        let (indented_lines, cursor): (Vec<String>, usize) =
            line_iterator.take_while_peek(|line| {
                line.len() > 0 && WS_CHARS.contains(&line.chars().next().unwrap())
            });

        scanner.set_pos(cursor);

        if indented_lines.len() > 0 {
            line.push_str(
                &indented_lines
                    .iter()
                    .map(|l| l.trim().to_owned())
                    .collect::<Vec<String>>()
                    .join(""),
            );
        }

        let line_scanner = Scanner::new(&line);
        let tokens: Vec<String> = line_scanner.get_tokens();

        // @TODO: still keep error around but also return 'patched up' model?
        let (request_line, _err) = match &tokens[..] {
            [target_str] => {
                // @TODO: why can't we pass target_str or &(*target_str) directly?
                let str: &str = target_str;
                (
                    Some(model::RequestLine {
                        target: RequestTarget::from(str),
                        method: HttpMethod::GET,
                        http_version: None,
                    }),
                    None,
                )
            }
            [method, target_str] => {
                // @TODO: why can't we pass target_str or &(*target_str) directly?
                let str: &str = target_str;

                (
                    Some(model::RequestLine {
                        target: RequestTarget::from(str),
                        method: Parser::match_request_method(method),
                        http_version: None,
                    }),
                    None,
                )
            }

            [method, target_str, http_version_str] => {
                let result = model::HttpVersion::from_str(http_version_str);
                let (http_version, err) = match result {
                    Ok(version) => (Some(version), None),
                    Err(_) => (None, None),
                };

                // @TODO: why can't we pass target_str or &(*target_str) directly?
                let str: &str = target_str;
                (
                    Some(model::RequestLine {
                        target: RequestTarget::from(str),
                        method: Parser::match_request_method(method),
                        http_version,
                    }),
                    err,
                )
            }
            // we are missing at least the url
            [] => (
                None,
                Some(ParseErrorType::MissingRequestTargetUrl(String::from(
                    "The request line should have at least a target url.",
                ))),
            ),
            // @TODO: ERROR

            // on a request line only method, target and http_version should be present
            [method, target_str, http_version_str, ..] => {
                /* if let Err(parse_error) = Parser::validate_http_version(http_version) {
                    parse_errs.push(parse_error);
                } */
                // @TODO: why can't we pass target_str or &(*target_str) directly?
                let result = model::HttpVersion::from_str(http_version_str);
                let http_version = match result {
                    Ok(version) => Some(version),
                    Err(_) => None,
                };

                let str: &str = target_str;
                (
                    Some(model::RequestLine {
                        target: RequestTarget::from(str),
                        method: Parser::match_request_method(method),
                        http_version,
                    }),
                    Some(ParseErrorType::TooManyElementsOnRequestLine(format!(
                        "There are too many elements on this line for a request.
There should only be method, target url and http version.
You have additional elements: '{}'",
                        tokens[3..].join(",")
                    ))),
                )
            } // @TODO: ERROR
        };

        // @TODO: validate target, http_version
        Ok(request_line)
    }

    pub fn parse_comment(scanner: &mut Scanner) -> Result<Option<model::Comment>, ParseErrorType> {
        scanner.skip_empty_lines();
        // comments can be indented
        scanner.skip_ws();

        // a regular comment either starts with '###' or with '//'
        // note that '###' can also be a request separator
        // apparently '##' is also accepted as a comment within intellij idea as long as there is
        // no '@name' somewhere within the line which would be the case for a name comment '#
        // @name=<yourRequestName>'
        if scanner.match_str_forward("###") || scanner.match_str_forward("//") {
            return Parser::parse_comment_line(scanner);
        }

        if scanner.match_str_forward("##") {
            return Parser::parse_comment_line(scanner);
        }

        // @TODO: is single comment allowed if not a name comment line?
        if scanner.match_str_forward("#") {
            return Parser::parse_comment_line(scanner);
        }

        Ok(None)
    }

    pub fn parse_multipart_part(
        scanner: &mut Scanner,
        boundary: &str,
    ) -> Result<model::Multipart, ParseErrorType> {
        let boundary_line = format!("--{}", boundary);
        let multipart_end_line = format!("--{}--", boundary);

        let escaped_boundary = regex::escape(&boundary_line);
        let first_boundary = scanner.match_regex_forward(&escaped_boundary);
        if first_boundary.is_err() {
            return Err(ParseErrorType::InvalidMultipart(
                "Multipart requires a first starting boundary before first part content."
                    .to_string(),
            ));
        }

        scanner.skip_to_next_line(); // @TODO: nothing else should be here

        let part_headers = Parser::parse_headers(scanner).map_err(|_err| {
            ParseErrorType::InvalidMultipart("Multipart headers could not be parsed".to_string())
        })?;

        let (mut fields, part_headers) = match &part_headers[..] {
            [] => {
                return Err(ParseErrorType::InvalidMultipart(
                    "Multipart part is missing 'Content-Disposition' header".to_string(),
                ));
            }
            [disposition_part, part_headers @ ..] => {
                if disposition_part.key != "Content-Disposition" {
                    return Err(ParseErrorType::InvalidMultipart(format!(
                        "First Multipart header should be 'Content-Disposition', found: {}",
                        disposition_part.key
                    )));
                }
                let parts: Vec<&str> = disposition_part.value.split(';').collect();
                let mut parts_iter = parts.iter();
                let disposition_type = parts_iter.next().unwrap().trim();
                if disposition_type != "form-data" {
                    // only form-data is valid in http context, other disposition types may exist
                    // for other applications (email mime types...)
                    return Err(ParseErrorType::InvalidMultipart(format!(
                        "Multipart Content-Disposition should have type 'form-data', found: {}",
                        disposition_type
                    )));
                }
                let mut fields: Vec<model::DispositionField> = Vec::new();
                for disposition_field in parts_iter {
                    match disposition_field.split('=').map(|p| p.trim()).collect::<Vec<&str>>()[..] {
                        [key, mut value] => {
                            if value.starts_with('"') && value.ends_with('"') {
                                value = &value[1..(value.len()-1)];
                            }
                            let field = model::DispositionField {key: key.to_string(), value: value.to_string()};
                            fields.push(field);
                        },
                            _ => {
                            return Err(ParseErrorType::InvalidMultipart(format!("Expected content disposition values in form <key>=<value> or <key>=\"<value>\" but found: '{}'", disposition_field)))
                        }

                    }
                }
                (fields, part_headers)
            }
        };

        let name_index = fields.iter().position(|field| field.key == "name");
        if name_index.is_none() {
            return Err(ParseErrorType::InvalidMultipart(format!(
                "Content-Disposition requires field 'name', found only: {:?}",
                fields
            )));
        }

        let name = fields.remove(name_index.unwrap());

        if !scanner.match_str_forward("\n") {
            println!("SCANNER: {}", scanner.debug_string());
            return Err(ParseErrorType::InvalidMultipart(
                "Requires empty line in multipart after Content-Disposition and other headers"
                    .to_string(),
            ));
        }

        println!("{}", scanner.debug_string());
        let peek_line = dbg!(scanner.peek_line());

        if peek_line.is_none() {
            return Err(ParseErrorType::InvalidMultipart(
                "Multipart should be ended with --<boundary>--. End of file encountered."
                    .to_string(),
            ));
        }

        let peek_line = dbg!(peek_line.unwrap());

        // < means content of multipart is read from file
        // should only have one line to parse
        // @TODO only read in file depending on the content type -> how is this not ambigous?
        // @TODO can we have multiple files added here?
        if peek_line.starts_with('<') {
            let mut line = scanner.get_line_and_advance().unwrap();
            line = line.trim().to_string();

            let file_path = &line[1..].trim();
            // @TODO is name expected?
            Ok(Multipart {
                name: name.value,
                from_filepath: Some(file_path.to_string()),
                fields,
                headers: part_headers.to_vec(),
                data: None, // @TODO: when to read in data from file?
            })
        } else {
            let mut text = String::new();

            loop {
                let peek_line = scanner.peek_line();
                if peek_line.is_none() {
                    return Err(ParseErrorType::InvalidMultipart(
                        "Multipart should be ended with --<boundary>--. Encountered end of file. "
                            .to_string(),
                    ));
                };
                let peek_line = peek_line.unwrap();
                if peek_line == boundary_line || peek_line == multipart_end_line {
                    return Ok(Multipart {
                        name: name.value,
                        from_filepath: None,
                        fields,
                        headers: part_headers.to_owned(),
                        data: Some(text),
                    });
                }
                let next = scanner.get_line_and_advance().unwrap();
                text += &next;
                // only add a new line if more text will appear
                if !scanner
                    .peek_line()
                    .map_or(false, |pl| pl.starts_with(&boundary_line))
                {
                    text += "\n";
                }
            }
        }
    }

    pub fn parse_multipart_body(
        scanner: &mut Scanner,
        boundary: &str,
    ) -> Result<model::RequestBody, ParseErrorType> {
        scanner.skip_empty_lines();

        // parse multipart @TODO check content type is a-ok!
        let mut parts: Vec<Multipart> = Vec::new();

        let mut errors: Vec<ParseErrorType> = Vec::new();
        loop {
            let multipart = dbg!(Parser::parse_multipart_part(scanner, boundary));
            if let Err(err) = multipart {
                // @TODO what to do with the error?
                errors.push(err);
                break;
            }
            let multipart = multipart.unwrap();
            parts.push(multipart);
            if scanner.is_done() {
                break;
            }
            // end of multipart
            let end_boundary = regex::escape(&format!("--{}--", boundary));
            if scanner.match_str_forward(&end_boundary) {
                break;
            }

            let next_boundary = format!("--{}", boundary);
            if !scanner.match_str_forward(&next_boundary) {
                // @TDOO: return error and parsed rest...
                // @TODO: better error message
                return Err(ParseErrorType::InvalidMultipart(format!(
                    "Expected next boundary: {}. ",
                    &next_boundary
                )));
            }
        }
        Ok(model::RequestBody::Multipart {
            boundary: boundary.to_string(),
            parts,
        })
    }

    pub fn parse_headers(scanner: &mut Scanner) -> Result<Vec<model::Header>, ParseErrorType> {
        let mut headers: Vec<model::Header> = Vec::new();

        let header_regex = regex::Regex::from_str("^([^:]+):\\s*(.+)\\s*").unwrap();

        loop {
            if scanner.is_done() {
                return Ok(headers);
            }

            // newline after requestline and headers ends header section
            if let Some(&'\n') = scanner.peek() {
                return Ok(headers);
            }

            let line = scanner.get_line_and_advance().unwrap();
            let captures = header_regex.captures(&line);

            let err_msg = format!(
                "Expected header in the form of <Key>: <Value>. Found line: {}",
                line
            );
            if captures.is_none() {
                return Err(ParseErrorType::InvalidHeaderFields(err_msg));
            }
            let captures = captures.unwrap();
            match (captures.get(1), captures.get(2)) {
                (Some(key_match), Some(value_match)) => {
                    //@TODO: validate header fields
                    headers.push(model::Header {
                        key: key_match.as_str().to_string(),
                        value: value_match.as_str().to_string(),
                    })
                }
                _ => {
                    return Err(ParseErrorType::InvalidHeaderFields(err_msg));
                }
            }
        }
    }

    // TODO:
    // https://www.rfc-editor.org/rfc/rfc2046#section-5.1.1
    pub fn is_multipart_boundary_valid(boundary: &str) -> Result<(), ParseErrorType> {
        let boundary_len = boundary.len();
        if !(1..=70).contains(&boundary_len) {
            return Err(ParseErrorType::InvalidHeaderFields(
                "Boundary within multipart content type is required to be 1-70 characters long."
                    .to_string(),
            ));
        }

        let bytes = boundary.as_bytes();
        for byte in bytes {
            match byte {
                b'0'..=b'9'
                | b'a'..=b'z'
                | b'A'..=b'Z'
                | b'\''
                | b'('
                | b')'
                | b'.'
                | b','
                | b'-'
                | b'_'
                | b'+'
                | b'/'
                | b':'
                | b'?'
                | b'=' => continue,
                invalid_byte => {
                    return Err(ParseErrorType::InvalidHeaderFields(
                        "Invalid character found for multipart boundary: ".to_string()
                            + &(String::from_utf8(vec![invalid_byte.to_owned()]).unwrap()),
                    ));
                }
            }
        }
        Ok(())
    }

    pub fn parse_body(
        scanner: &mut Scanner,
        headers: &[model::Header],
    ) -> (model::RequestBody, Vec<ParseErrorType>) {
        let mut body = model::RequestBody::None;
        let mut parse_errs: Vec<ParseErrorType> = Vec::new();
        if let Some(multipart_header) = headers.iter().find(|header| {
            header.key == "Content-Type" && header.value.starts_with("multipart/form-data")
        }) {
            // @TODO check what can be part within Content-Type header...
            let boundary_regex =
                regex::Regex::from_str("multipart/form-data\\s*;\\s*boundary\\s*=\\s*(.+)")
                    .unwrap();
            let captures = boundary_regex.captures(&multipart_header.value);

            if let Some(captures) = captures {
                let boundary_match = captures.get(1);

                // either with or without quotes
                if boundary_match.is_none() {
                    let msg = format!("Found header field with key 'Content-Type' and value 'multipart/form-data' but missing the boundary for the multipart content. Value: {}", multipart_header.value);
                    parse_errs.push(ParseErrorType::InvalidHeaderFields(msg));
                }
                let mut boundary = boundary_match.unwrap().as_str();
                if boundary.starts_with('"') && boundary.ends_with('"') {
                    boundary = &boundary[1..(boundary.len() - 1)];
                }
                // @TODO validate boundary string
                if let Err(boundary_err) = Parser::is_multipart_boundary_valid(boundary) {
                    parse_errs.push(boundary_err);
                }
                match dbg!(Parser::parse_multipart_body(scanner, boundary)) {
                    Ok(multipart_body) => body = multipart_body,
                    Err(err) => parse_errs.push(err),
                };
            } else {
                let msg = format!("Found header field with key 'Content-Type' and value 'multipart/form-data' but missing the boundary for the multipart content. Value: {}", multipart_header.value);
                parse_errs.push(ParseErrorType::InvalidHeaderFields(msg))
            }
        } else {
            // body is text
            // @TODO: parse non multipart body!
        }
        (body, parse_errs)
    }

    pub fn parse_request(
        scanner: &mut Scanner,
    ) -> Result<Option<(model::Request, Vec<ParseErrorType>)>, ParseErrorType> {
        let mut comments = Vec::new();
        let mut name: Option<model::Name> = None;
        let mut parse_errs: Vec<ParseErrorType> = Vec::new();

        loop {
            if let Ok(Some(name_node)) = Parser::parse_name_comment(scanner) {
                name = Some(name_node);
            }
            match Parser::parse_comment(scanner) {
                Ok(Some(comment_node)) => {
                    comments.push(comment_node);
                }
                Ok(None) => {
                    break;
                }
                Err(parse_error) => {
                    parse_errs.push(parse_error);
                    break;
                }
            }
        }

        let request_line = match Parser::parse_request_line(scanner) {
            Ok(Some(line)) => line,
            Ok(None) => model::RequestLine::default(),
            Err(parse_error) => {
                parse_errs.push(parse_error);
                model::RequestLine::default()
            }
        };

        let headers = match Parser::parse_headers(scanner) {
            Ok(headers) => headers,
            Err(parse_err) => {
                parse_errs.push(parse_err);
                Vec::<model::Header>::new()
            }
        };

        scanner.skip_empty_lines();

        //@TODO body
        let (body, mut body_parse_errs) = Parser::parse_body(scanner, &headers);
        parse_errs.append(&mut body_parse_errs);

        if name.is_none() {
            name = Some(model::Name {
                value: String::new(),
            });
        }

        let name_box = match name {
            Some(name) => Box::new(name),
            None => Box::new(model::Name {
                value: String::new(),
            }),
        };

        let mut request_node = model::Request {
            name: name_box,
            comments,
            request_line,
            headers,
            body,
        };

        // if no name set we use the first comment as name @TODO: only ### comment is accepted?
        #[allow(clippy::comparison_to_empty)]
        if request_node.name.value == "" && !request_node.comments.is_empty() {
            let first_comment = request_node.comments.remove(0);
            request_node.name.value = first_comment.value;
        }
        Ok(Some((request_node, parse_errs)))
    }

    pub fn parse(
        string: &str,
    ) -> Result<Option<(model::Request, Vec<ParseErrorType>)>, ParseErrorType> {
        let mut scanner = Scanner::new(string);

        Parser::parse_request(&mut scanner)
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        model::model::DispositionField,
        parser::model::{Header, HttpVersion},
    };

    use super::*;

    #[test]
    pub fn name_triple_tag() {
        let str = "
### test name

https://httpbin.org
";
        let parsed = Parser::parse(str);

        let expected = model::Request {
            name: Box::new(model::Name {
                value: String::from("test name"),
            }),
            comments: Vec::new(),
            request_line: model::RequestLine {
                method: HttpMethod::GET,
                target: RequestTarget::from("https://httpbin.org"),
                http_version: None,
            },
            headers: Vec::new(),
            body: model::RequestBody::None,
        };

        match parsed {
            Ok(Some((parse_tree, errs))) => {
                assert!(errs.is_empty());
                assert_eq!(parse_tree, expected)
            }
            _ => panic!("no valid parse result {:?}", parsed),
        }
    }

    #[test]
    pub fn name_with_at() {
        let str = "
# @name=test name

https://httpbin.org
";
        let parsed = Parser::parse(str);

        let expected = model::Request {
            name: Box::new(model::Name {
                value: String::from("test name"),
            }),
            comments: Vec::new(),
            request_line: model::RequestLine {
                method: HttpMethod::GET,
                target: RequestTarget::from("https://httpbin.org"),
                http_version: None,
            },
            headers: Vec::new(),
            body: model::RequestBody::None,
        };

        match parsed {
            Ok(Some((parse_tree, errs))) => {
                assert!(errs.is_empty());
                assert_eq!(parse_tree, expected)
            }
            _ => panic!("no valid parse result {:?}", parsed),
        }
    }

    #[test]
    pub fn comment_and_name_tag() {
        let str = "
### Just a comment
## invalid comment but still parsed
# @name=actual request name

GET https://test.com
";
        // if there is a ### comment and a @name section use the @name section as name
        let (parsed, errs) = Parser::parse(str).unwrap().unwrap();
        assert!(errs.len() == 0);
        assert_eq!(parsed.name.value, "actual request name");
        assert_eq!(parsed.comments.len(), 2);
        assert_eq!(parsed.comments[0].value, "Just a comment");
        assert_eq!(parsed.comments[1].value, "invalid comment but still parsed");
    }

    #[test]
    pub fn custom_method() {
        let str = "
# @name=test name

CUSTOMVERB https://httpbin.org
";
        let parsed = Parser::parse(str);

        let expected = model::Request {
            name: Box::new(model::Name {
                value: String::from("test name"),
            }),
            comments: Vec::new(),
            request_line: model::RequestLine {
                method: HttpMethod::CUSTOM("CUSTOMVERB".to_string()),
                target: RequestTarget::from("https://httpbin.org"),
                http_version: None,
            },
            headers: Vec::new(),
            body: model::RequestBody::None,
        };

        match parsed {
            Ok(Some((parse_tree, errs))) => {
                assert!(errs.is_empty());
                assert_eq!(parse_tree, expected)
            }
            _ => panic!("no valid parse result {:?}", parsed),
        }
    }

    #[test]
    pub fn no_body_post() {
        let str = "
# @name=test name

POST https://httpbin.org
";
        let parsed = Parser::parse(str);

        let expected = model::Request {
            name: Box::new(model::Name {
                value: String::from("test name"),
            }),
            comments: Vec::new(),
            request_line: model::RequestLine {
                method: HttpMethod::POST,
                target: RequestTarget::from("https://httpbin.org"),
                http_version: None,
            },
            headers: Vec::new(),
            body: model::RequestBody::None,
        };

        match parsed {
            Ok(Some((parse_tree, errs))) => {
                assert!(errs.is_empty());
                assert_eq!(parse_tree, expected)
            }
            _ => panic!("no valid parse result {:?}", parsed),
        }
    }

    #[test]
    pub fn name_with_whitespace() {
        let str = "
# @name  =  test name    

POST https://httpbin.org
";
        let parsed = Parser::parse(str);

        let expected = model::Request {
            name: Box::new(model::Name {
                value: String::from("test name"),
            }),
            comments: Vec::new(),
            request_line: model::RequestLine {
                method: HttpMethod::POST,
                target: RequestTarget::from("https://httpbin.org"),
                http_version: None,
            },
            headers: Vec::new(),
            body: model::RequestBody::None,
        };

        match parsed {
            Ok(Some((parse_tree, errs))) => {
                assert_eq!(
                    parse_tree.name.value, "test name",
                    "whitespace before or after name should be removed"
                );
                assert!(errs.is_empty());
                assert_eq!(parse_tree, expected)
            }
            _ => panic!("no valid parse result {:?}", parsed),
        }
    }

    #[test]
    pub fn multiple_comments() {
        let str = "
### Comment one
### Comment line two    
// This comment type is also allowed      
# @name  =  test name    

POST https://httpbin.org
";
        let parsed = Parser::parse(str);

        match parsed {
            Ok(Some((parse_tree, errs))) => {
                assert!(errs.is_empty());
                assert_eq!(
                    parse_tree.get_comment_text(),
                    "Comment one\nComment line two    \nThis comment type is also allowed      ",
                    "parsed: {:?}, {:?}",
                    parse_tree,
                    errs
                )
            }
            _ => panic!("no valid parse result {:?}", parsed),
        }
    }

    #[test]
    pub fn request_target_asterisk() {
        let (request, errs) = Parser::parse("*").unwrap().unwrap();
        assert_eq!(request.request_line.target, RequestTarget::Asterisk);
        assert_eq!(errs, vec![]);

        // @TODO: is asterisk form only for OPTIONS request?
        let (request, errs) = Parser::parse("GET *").unwrap().unwrap();
        assert_eq!(request.request_line.target, RequestTarget::Asterisk);
        assert_eq!(request.request_line.method, HttpMethod::GET);
        assert_eq!(request.request_line.http_version, None);
        assert_eq!(errs, vec![]);

        let (request, errs) = Parser::parse("CUSTOMMETHOD * HTTP/1.1").unwrap().unwrap();
        assert_eq!(request.request_line.target, RequestTarget::Asterisk);
        assert_eq!(
            request.request_line.method,
            HttpMethod::CUSTOM(String::from("CUSTOMMETHOD"))
        );
        assert_eq!(
            request.request_line.http_version,
            Some(model::HttpVersion { major: 1, minor: 1 })
        );
        assert_eq!(errs, vec![]);
    }

    #[test]
    pub fn request_target_absolute() {
        let (request, errs) = Parser::parse("https://test.com/api/v1/user?show_all=true&limit=10")
            .unwrap()
            .unwrap();

        // only with relative url
        let expected_target = RequestTarget::Absolute {
            string: "https://test.com/api/v1/user?show_all=true&limit=10".to_string(),
            uri: "https://test.com/api/v1/user?show_all=true&limit=10"
                .parse::<Uri>()
                .unwrap(),
        };
        assert_eq!(request.request_line.target, expected_target);

        match request.request_line.target {
            RequestTarget::Absolute {
                ref uri,
                ref string,
            } => {
                assert_eq!(uri.path(), "/api/v1/user");
                assert_eq!(*uri.scheme().unwrap(), http::uri::Scheme::HTTPS);
                assert_eq!(uri.authority().unwrap().host(), "test.com");
                assert_eq!(uri.authority().unwrap().port(), None);
                assert_eq!(uri.query(), Some("show_all=true&limit=10"));
                assert_eq!(
                    string,
                    "https://test.com/api/v1/user?show_all=true&limit=10"
                );
            }
            _ => panic!("not expected target found"),
        }

        assert!(request.request_line.target.has_scheme());
        assert_eq!(errs, vec![]);

        // method and URL
        let (request, errs) =
            Parser::parse("GET https://test.com/api/v1/user?show_all=true&limit=10")
                .unwrap()
                .unwrap();
        assert_eq!(request.request_line.target, expected_target);
        assert_eq!(request.request_line.method, HttpMethod::GET);
        assert_eq!(request.request_line.http_version, None);
        assert_eq!(errs, vec![]);

        // method and URL and http version
        let (request, errs) =
            Parser::parse("GET https://test.com/api/v1/user?show_all=true&limit=10    HTTP/1.1")
                .unwrap()
                .unwrap();
        assert_eq!(request.request_line.target, expected_target);
        assert_eq!(request.request_line.method, HttpMethod::GET);
        assert_eq!(
            request.request_line.http_version,
            Some(model::HttpVersion { major: 1, minor: 1 })
        );
        assert_eq!(errs, vec![]);
    }

    #[test]
    pub fn request_target_no_scheme_with_host_no_path() {
        let (request, errs) = Parser::parse("test.com").unwrap().unwrap();
        assert_eq!(errs, vec![]);
        match request.request_line.target {
            RequestTarget::Absolute {
                ref uri,
                ref string,
            } => {
                assert_eq!(uri.scheme(), None);
                assert_eq!(uri.host().unwrap(), "test.com");
                assert_eq!(uri.query(), None);
                //@TODOassert_eq!(uri.path(), "");
                assert_eq!(string, "test.com");
            }
            kind => panic!("!request target is not absolute kind, it is: {:?}", kind),
        }
    }

    #[test]
    pub fn request_target_no_scheme_with_host_and_path() {
        let (request, errs) = Parser::parse("test.com/api/v1/test").unwrap().unwrap();
        assert_eq!(errs, vec![]);
        match request.request_line.target {
            RequestTarget::Absolute {
                ref uri,
                ref string,
            } => {
                // @TODO: with uri parser we cannot have
                // authority and path without a scheme, add http as default in this case if no
                // scheme is present

                assert_eq!(*uri.scheme().unwrap(), http::uri::Scheme::HTTP);
                assert_eq!(uri.host().unwrap(), "test.com");
                assert_eq!(uri.query(), None);
                assert_eq!(uri.path(), "/api/v1/test");
                assert_eq!(string, "test.com/api/v1/test");
            }
            kind => panic!("!request target is not absolute kind, it is: {:?}", kind),
        }
    }

    #[test]
    pub fn request_target_relative() {
        let (request, errs) = Parser::parse("/api/v1/user?show_all=true&limit=10")
            .unwrap()
            .unwrap();

        // only with relative url
        let expected_target = RequestTarget::RelativeOrigin {
            string: "/api/v1/user?show_all=true&limit=10".to_string(),
            uri: "/api/v1/user?show_all=true&limit=10"
                .parse::<Uri>()
                .unwrap(),
        };
        assert_eq!(request.request_line.target, expected_target);

        match request.request_line.target {
            RequestTarget::RelativeOrigin {
                ref uri,
                ref string,
            } => {
                assert_eq!(uri.path(), "/api/v1/user");
                assert_eq!(uri.scheme(), None);
                assert_eq!(uri.authority(), None);
                assert_eq!(uri.query(), Some("show_all=true&limit=10"));
                assert_eq!(string, "/api/v1/user?show_all=true&limit=10");
            }
            _ => panic!("not expected target found"),
        }

        assert!(!request.request_line.target.has_scheme());
        assert_eq!(errs, vec![]);

        // method and URL
        let (request, errs) = Parser::parse("GET /api/v1/user?show_all=true&limit=10")
            .unwrap()
            .unwrap();
        assert_eq!(request.request_line.target, expected_target);
        assert_eq!(request.request_line.method, HttpMethod::GET);
        assert_eq!(request.request_line.http_version, None);
        assert_eq!(errs, vec![]);

        // method and URL and http version
        let (request, errs) = Parser::parse("GET /api/v1/user?show_all=true&limit=10    HTTP/1.1")
            .unwrap()
            .unwrap();
        assert_eq!(request.request_line.target, expected_target);
        assert_eq!(request.request_line.method, HttpMethod::GET);
        assert_eq!(
            request.request_line.http_version,
            Some(model::HttpVersion { major: 1, minor: 1 })
        );
        assert_eq!(errs, vec![]);
    }

    #[test]
    pub fn validate_http_version() {
        let version = model::HttpVersion::from_str("HTTP/1.1").expect("Version 1.1 to be valid");
        assert_eq!(version, model::HttpVersion { major: 1, minor: 1 });

        let version = model::HttpVersion::from_str("HTTP/1.2").expect("Version 1.2 to be valid");
        assert_eq!(version, model::HttpVersion { major: 1, minor: 2 });

        let version = model::HttpVersion::from_str("HTTP/2.0").expect("Version 2.0 to be valid");
        assert_eq!(version, model::HttpVersion { major: 2, minor: 0 });

        let version = model::HttpVersion::from_str("HTTP/2.1").expect("Version 2.1 to be valid");
        assert_eq!(version, model::HttpVersion { major: 2, minor: 1 });

        assert!(model::HttpVersion::from_str("invalid").is_err());
    }

    #[test]
    pub fn request_target_multiline() {
        let str = r#####"
GET https://test.com:8080
    /get
    /html
    ?id=123
    &value=test

        "#####;
        let (request, errs) = Parser::parse(str).unwrap().unwrap();
        assert_eq!(errs, vec![]);
        let expected_uri = "https://test.com:8080/get/html?id=123&value=test"
            .parse()
            .unwrap();
        assert_eq!(
            request.request_line.target,
            RequestTarget::Absolute {
                uri: expected_uri,
                string: "https://test.com:8080/get/html?id=123&value=test".to_owned()
            }
        );
        assert_eq!(request.request_line.http_version, None);
        assert_eq!(request.request_line.method, HttpMethod::GET);
    }

    #[test]
    pub fn request_target_multiline_no_method() {
        let str = r#####"
https://test.com:8080
    /get
    /html
    ?id=123
    &value=test

        "#####;
        let (request, errs) = Parser::parse(str).unwrap().unwrap();
        assert_eq!(errs, vec![]);
        let expected_uri = "https://test.com:8080/get/html?id=123&value=test"
            .parse()
            .unwrap();
        assert_eq!(
            request.request_line.target,
            RequestTarget::Absolute {
                uri: expected_uri,
                string: "https://test.com:8080/get/html?id=123&value=test".to_owned()
            }
        );
        assert_eq!(request.request_line.http_version, None);
        assert_eq!(request.request_line.method, HttpMethod::GET);
    }

    #[test]
    pub fn request_target_multiline_with_version() {
        let str = r#####"
GET https://test.com:8080
    /get
    /html
    ?id=123
    &value=test HTTP/2.1

        "#####;
        let (request, errs) = Parser::parse(str).unwrap().unwrap();
        assert_eq!(errs, vec![]);
        let expected_uri = "https://test.com:8080/get/html?id=123&value=test"
            .parse()
            .unwrap();
        assert_eq!(
            request.request_line.target,
            RequestTarget::Absolute {
                uri: expected_uri,
                string: "https://test.com:8080/get/html?id=123&value=test".to_owned()
            }
        );
        assert_eq!(
            request.request_line.http_version,
            Some(HttpVersion { major: 2, minor: 1 })
        );
        assert_eq!(request.request_line.method, HttpMethod::GET);
    }

    #[test]
    pub fn parse_simple_headers() {
        let str = "Key1: Value1
Key2: Value2
Key3: Value3
";
        let mut scanner = Scanner::new(str);
        let parsed = Parser::parse_headers(&mut scanner);

        let parsed = parsed.expect("No error for simple headers");

        assert_eq!(parsed.len(), 3);
        assert_eq!(parsed[0], Header::new("Key1", "Value1"));
        assert_eq!(parsed[1], Header::new("Key2", "Value2"));
        assert_eq!(parsed[2], Header::new("Key3", "Value3"));
    }

    #[test]
    pub fn parse_headers_with_colon() {
        let str = r###"Host: localhost:8080
Custom: ::::::

        "###;
        let mut scanner = Scanner::new(str);
        let parsed = Parser::parse_headers(&mut scanner).unwrap();

        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0], Header::new("Host", "localhost:8080"));
        assert_eq!(parsed[1], Header::new("Custom", "::::::"));
    }

    #[test]
    pub fn parse_with_multipart_body_file() {
        let str = r####"
# With Multipart Body
POST https://test.com/multipart
Content-Type: multipart/form-data; boundary="--test_boundary"

----test_boundary
Content-Disposition: form-data; name="part1_name"

< path/to/file
----test_boundary--
"####;

        let (parsed, errs) = Parser::parse(str)
            .expect("Parsing should be successful")
            .expect("There should be a parsed request");
        assert_eq!(errs, vec![]);

        assert_eq!(
            parsed.headers,
            vec![Header::new(
                "Content-Type",
                "multipart/form-data; boundary=\"--test_boundary\""
            )]
        );

        assert_eq!(
            parsed.body,
            model::RequestBody::Multipart {
                boundary: "--test_boundary".to_string(),
                parts: vec![Multipart {
                    name: "part1_name".to_string(),
                    from_filepath: Some("path/to/file".to_string()),
                    data: None,
                    fields: vec![],
                    headers: vec![]
                }]
            }
        )
    }

    #[test]
    pub fn parse_with_multipart_body_text() {
        let str = r####"
# With Multipart Body
POST https://test.com/multipart
Content-Type: multipart/form-data; boundary="--test.?)()test"

----test.?)()test
Content-Disposition: form-data; name="text"

some text

----test.?)()test
Content-Disposition: form-data; name="text"

more content


----test.?)()test--
"####;

        let (parsed, errs) = Parser::parse(str)
            .expect("Parsing should be successful")
            .expect("There should be a parsed request");
        assert_eq!(errs, vec![]);

        assert_eq!(
            parsed.headers,
            vec![Header::new(
                "Content-Type",
                "multipart/form-data; boundary=\"--test.?)()test\""
            )]
        );

        assert_eq!(
            parsed.body,
            model::RequestBody::Multipart {
                boundary: "--test.?)()test".to_string(),
                parts: vec![
                    Multipart {
                        name: "text".to_string(),
                        fields: vec![],
                        headers: vec![],
                        data: Some("some text\n".to_string()),
                        from_filepath: None
                    },
                    Multipart {
                        name: "text".to_string(),
                        fields: vec![],
                        headers: vec![],
                        data: Some("more content\n\n".to_string()),
                        from_filepath: None
                    }
                ]
            }
        )
    }

    #[test]
    pub fn parse_multipart_with_content_types() {
        let str = r#####"
### Send a form with the text and file fields
POST https://httpbin.org/post
Content-Type: multipart/form-data; boundary=WebAppBoundary

--WebAppBoundary
Content-Disposition: form-data; name="element-name"
Content-Type: text/plain

Name
--WebAppBoundary
Content-Disposition: form-data; name="data"; filename="data.json"
Content-Type: application/json

< ./request-form-data.json
--WebAppBoundary--
        "#####;

        let (parsed, errs) = Parser::parse(str)
            .expect("Parsing should be successful")
            .expect("There should be a parsed request");
        assert_eq!(errs, vec![]);

        assert_eq!(
            parsed.headers,
            vec![Header::new(
                "Content-Type",
                "multipart/form-data; boundary=WebAppBoundary"
            )]
        );

        assert_eq!(
            parsed.body,
            model::RequestBody::Multipart {
                boundary: "WebAppBoundary".to_string(),
                parts: vec![
                    Multipart {
                        data: Some("Name".to_string()),
                        name: "element-name".to_string(),
                        fields: vec![],
                        from_filepath: None,
                        headers: vec![Header {
                            key: "Content-Type".to_string(),
                            value: "text/plain".to_string()
                        }]
                    },
                    Multipart {
                        name: "data".to_string(), // @TODO
                        data: None,
                        // @TODO: check within fields, filename: Some("data.json".to_string()),
                        from_filepath: Some("./request-form-data.json".to_string()),
                        fields: vec![DispositionField {
                            key: "filename".to_string(),
                            value: "data.json".to_string()
                        }],
                        headers: vec![Header {
                            key: "Content-Type".to_string(),
                            value: "application/json".to_string()
                        }]
                    }
                ]
            }
        )
    }

    #[test]
    pub fn parse_multipart_binary() {
        let str = r#####"
POST /upload HTTP/1.1
Host: localhost:8080
Content-Type: multipart/form-data; boundary=/////////////////////////////
Content-Length: 676

--/////////////////////////////
Content-Disposition: form-data; name="file"; filename="binaryfile.tar.gz"
Content-Type: application/x-gzip
Content-Transfer-Encoding: base64

H4sIAGiNIU8AA+3R0W6CMBQGYK59iobLZantRDG73osUOGqnFNJWM2N897UghG1ZdmWWLf93U/jP4bRAq8q92hJ/dY1J7kQEqyyLq8yXYrp2ltkqkTKXYiEykYc++ZTLVcLEvQ40dXReWcYSV1pdnL/v+6n+R11mjKVG1ZQ+s3TT2FpXqjhQ+hjzE1mnGxNLkgu+7tOKWjIVmVKTC6XL9ZaeXj4VQhwKWzL+cI4zwgQuuhkh3mhTad/Hkssh3im3027X54JnQ360R/M19OT8kC7SEN7Ooi2VvrEfznHQRWzl83gxttZKmzGehzPRW/+W8X+3fvL8sFet9sS6m3EIma02071MU3Uf9KHrmV1/+y8DAAAAAAAAAAAAAAAAAAAAAMB/9A6txIuJACgAAA==
--/////////////////////////////--
        "#####;

        let (parsed, errs) = Parser::parse(str)
            .expect("Parsing should be successful")
            .expect("There should be a parsed request");
        assert_eq!(errs, vec![]);

        assert_eq!(
            parsed.headers,
            vec![
                Header::new("Host", "localhost:8080"),
                Header::new(
                    "Content-Type",
                    r#"multipart/form-data; boundary=/////////////////////////////"#
                ),
                Header::new("Content-Length", "676")
            ]
        );

        // @TODO check content
        assert_eq!(
            parsed.body,
            model::RequestBody::Multipart {
                boundary: r#"/////////////////////////////"#.to_string(),
                parts: vec![model::Multipart {
                    name: "file".to_string(),
                    from_filepath: None,
                    fields: vec![DispositionField {
                        key: "filename".to_string(),
                        value: "binaryfile.tar.gz".to_string()
                    }],
                    headers: vec![
                        Header {
                            key: "Content-Type".to_string(),
                            value: "application/x-gzip".to_string()
                        },
                        Header {
                            key: "Content-Transfer-Encoding".to_string(),
                            value: "base64".to_string()
                        }
                    ],
                    data: Some("H4sIAGiNIU8AA+3R0W6CMBQGYK59iobLZantRDG73osUOGqnFNJWM2N897UghG1ZdmWWLf93U/jP4bRAq8q92hJ/dY1J7kQEqyyLq8yXYrp2ltkqkTKXYiEykYc++ZTLVcLEvQ40dXReWcYSV1pdnL/v+6n+R11mjKVG1ZQ+s3TT2FpXqjhQ+hjzE1mnGxNLkgu+7tOKWjIVmVKTC6XL9ZaeXj4VQhwKWzL+cI4zwgQuuhkh3mhTad/Hkssh3im3027X54JnQ360R/M19OT8kC7SEN7Ooi2VvrEfznHQRWzl83gxttZKmzGehzPRW/+W8X+3fvL8sFet9sS6m3EIma02071MU3Uf9KHrmV1/+y8DAAAAAAAAAAAAAAAAAAAAAMB/9A6txIuJACgAAA==".to_string())
                }]
            }
        )
    }
    #[test]
    pub fn has_valid_extension() {
        // ok
        assert!(Parser::has_valid_extension(&"test.rest"));
        assert!(Parser::has_valid_extension(&"rest.http"));

        assert!(Parser::has_valid_extension(&"C:\\folder\\test.rest"));
        assert!(Parser::has_valid_extension(&"/home/user/test.rest"));

        assert!(Parser::has_valid_extension(&std::path::Path::new(
            "test.rest"
        )));

        assert!(Parser::has_valid_extension(&std::path::Path::new(
            "test.http"
        )));

        assert!(Parser::has_valid_extension(&std::path::Path::new(
            "C:\\folder\\test.rest"
        )));

        assert!(Parser::has_valid_extension(&std::path::Path::new(
            "/home/usr/folder/test.rest"
        )));

        // nok
        assert!(!Parser::has_valid_extension(&"test"));
        assert!(!Parser::has_valid_extension(&"/home/user/test"));
        assert!(!Parser::has_valid_extension(&""));
    }

    #[test]
    // https://www.rfc-editor.org/rfc/rfc2046#section-5.1.1
    pub fn is_multipart_boundary_valid() {
        // at least one character is required
        let boundary = "";
        assert_eq!(Parser::is_multipart_boundary_valid(boundary).is_err(), true);

        // no more than 70 characters
        let boundary = "a".repeat(71);
        assert_eq!(
            Parser::is_multipart_boundary_valid(&boundary).is_err(),
            true
        );

        // at least one character is required
        let boundary = "a";

        assert_eq!(
            Parser::is_multipart_boundary_valid(&boundary).is_err(),
            false
        );

        // up to 70 characters is ok
        let boundary = "a".repeat(70);
        assert_eq!(
            Parser::is_multipart_boundary_valid(&boundary).is_err(),
            false
        );

        // no spaces within allowed
        let boundary = "a b";
        assert_eq!(
            Parser::is_multipart_boundary_valid(&boundary).is_err(),
            true
        );

        // these characters are allowed
        let boundary = "0123456789abcdefghijklmnopqrstuvwyxz";
        assert_eq!(
            Parser::is_multipart_boundary_valid(&boundary).is_err(),
            false
        );

        let boundary = "ABCDEFGHIJKLMNOPQRSTUVWXYZ'()+_,-./:=?";
        assert_eq!(
            Parser::is_multipart_boundary_valid(&boundary).is_err(),
            false
        );
    }
}

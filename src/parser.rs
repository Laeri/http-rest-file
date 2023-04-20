pub use crate::scanner::Scanner;
pub use http::Uri;

use self::node::RequestTarget;

#[derive(PartialEq, Debug)]
pub enum HttpMethod {
    GET,
    POST,
    PUT,
    PATCH,
    DELETE,
    HEAD,
    TRACE,
    OPTIONS,
    CONNECT,
    CUSTOM(String),
}

#[derive(PartialEq, Debug)]
pub enum ParseErrorType {
    Unspecified,
    NoNameFound,
    InvalidHttpMethod, // @TODO: validate if either predefined or check if custom needs specific
    InvalidTargetUrl(String), // @TODO: url is not valid
    InvalidHttpVersion(String),
    MissingRequestTargetUrl(String),
    TooManyElementsOnRequestLine(String),
}

mod node {

    #[derive(PartialEq, Debug)]
    pub enum RequestTarget {
        RelativeOrigin { uri: http::Uri, string: String },
        Absolute { uri: http::Uri, string: String },
        Asterisk,
        InvalidTarget(String),
    }

    impl RequestTarget {
        pub fn has_scheme(&self) -> bool {
            match self {
                RequestTarget::Asterisk => false,
                RequestTarget::Absolute { uri, .. } => uri.scheme().is_some(),
                RequestTarget::RelativeOrigin { uri, .. } => uri.scheme().is_some(),
                RequestTarget::InvalidTarget(_) => false,
            }
        }

        pub fn get_string(&self) -> String {
            match self {
                RequestTarget::Asterisk => String::from("*"),
                RequestTarget::Absolute { string, .. } => string.to_string(),
                RequestTarget::RelativeOrigin { string, .. } => string.to_string(),
                RequestTarget::InvalidTarget(string) => string.clone(),
            }
        }

        pub fn parse(value: &str) -> Result<RequestTarget, super::ParseErrorType> {
            if value == "*" {
                return Ok(RequestTarget::Asterisk);
            }
            match value.parse::<http::Uri>() {
                Ok(uri) => {
                    // if we have the authority (host:port) then it is an absolute url
                    if let Some(_authority) = uri.authority() {
                        Ok(RequestTarget::Absolute {
                            uri,
                            string: value.to_string(),
                        })
                    } else {
                        Ok(RequestTarget::RelativeOrigin {
                            uri,
                            string: value.to_string(),
                        })
                    }
                }
                // the http::uri crate cannot parse urls without scheme *but* with url, it can
                // however parse urls without a scheme if no path is present
                // @TODO eithr write the parser myself or use a different library. for now we add
                // the default scheme http if this occurs and try to parse again.
                Err(_err) => {
                    let fixed_value = format!("http://{}", value);
                    match fixed_value.parse::<http::Uri>() {
                        Ok(uri) => Ok(RequestTarget::Absolute {
                            uri,
                            string: value.to_string(),
                        }),
                        _ => Err(super::ParseErrorType::InvalidTargetUrl(value.to_string())),
                    }
                }
            }
        }
    }

    impl From<&str> for RequestTarget {
        fn from(value: &str) -> RequestTarget {
            match RequestTarget::parse(value) {
                Ok(t) => t,
                Err(_err) => RequestTarget::InvalidTarget(value.to_string()),
            }
            // @TODO: only
            // return a single error from parse and create conversion to parse error
        }
    }

    #[derive(PartialEq, Debug)]
    pub struct Request {
        pub name: Box<Name>,
        pub comments: Vec<Box<Comment>>,
        pub request_line: RequestLine,
    }

    #[derive(PartialEq, Debug)]
    pub struct Comment {
        pub value: String,
    }

    #[derive(PartialEq, Debug)]
    pub struct Name {
        pub value: String,
    }

    #[derive(PartialEq, Debug)]
    pub struct UriTarget {}

    #[derive(PartialEq, Debug)]
    pub struct RequestLine {
        pub method: super::HttpMethod,
        pub target: RequestTarget,
        pub http_version: Option<String>, // @TODO: use enum and validate
    }

    impl RequestLine {
        pub fn new() -> RequestLine {
            RequestLine {
                method: super::HttpMethod::GET,
                target: RequestTarget::from(""),
                http_version: None,
            }
        }
    }

    #[derive(PartialEq, Debug)]
    pub struct UrlTarget {
        //@TODO: url, path, query, fragment
    }

    impl Request {
        pub fn get_comment_text(&self) -> String {
            self.comments
                .iter()
                .map(|b| b.value.clone())
                .collect::<Vec<String>>()
                .join("\n")
        }
    }
}

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

    pub fn parse_name_comment(scanner: &mut Scanner) -> Result<Option<node::Name>, ParseErrorType> {
        scanner.skip_empty_lines();
        scanner.skip_ws();

        let name_regex = "\\s*#\\s*@name\\s*=\\s*(.*)[$\n]";
        if let Ok(Some(captures)) = scanner.match_regex_forward(name_regex) {
            let name = captures.first().unwrap().trim().to_string();
            Ok(Some(node::Name { value: name }))
        } else {
            Ok(None)
        }
    }

    /// match a comment line after '###', '//' or '##' has been stripped from it
    pub fn parse_comment_line(
        scanner: &mut Scanner,
    ) -> Result<Option<node::Comment>, ParseErrorType> {
        scanner.skip_ws();
        return match scanner.seek_return(&'\n') {
            Ok(value) => Ok(Some(node::Comment { value })),
            Err(_) => Err(ParseErrorType::Unspecified),
        };
    }

    // @TODO: create a macro that generates a match statement for each enum variant
    pub fn match_request_method(str: &str) -> HttpMethod {
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

    pub fn validate_http_version(version: &str) -> Result<bool, ParseErrorType> {
        // @ http version ‘HTTP/’ (digit)+ ‘.’ (digit)+
        let version_regex = regex::Regex::new("HTTP/\\d+.\\d+").unwrap();
        if version_regex.is_match(version) {
            return Ok(true);
        } else {
            return Err(ParseErrorType::InvalidHttpVersion(String::from("Http version requires format: 'HTTP/\\d+.\\d+'. 
For example 'HTTP/2.1'. You can also omit the version and only specify the url target of the request or the http method and the url target.
                ")));
        }
    }

    pub fn parse_request_target(
        target_str: &str,
    ) -> Result<Option<node::RequestTarget>, ParseErrorType> {
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
    ) -> Result<Option<node::RequestLine>, ParseErrorType> {
        let line = match scanner.get_line_and_advance() {
            Some(line) => line,
            _ => String::new(),
        };

        let line_scanner = Scanner::new(&line);
        let tokens: Vec<String> = line_scanner.get_tokens();

        // @TODO: still keep error around but also return 'patched up' model?
        let (request_line, _err) = match &tokens[..] {
            [target_str] => {
                // @TODO: why can't we pass target_str or &(*target_str) directly?
                let str: &str = &(*target_str);
                (
                    Some(node::RequestLine {
                        target: RequestTarget::from(str),
                        method: HttpMethod::GET,
                        http_version: None,
                    }),
                    None,
                )
            }
            [method, target_str] => {
                // @TODO: why can't we pass target_str or &(*target_str) directly?
                let str: &str = &(*target_str);

                (
                    Some(node::RequestLine {
                        target: RequestTarget::from(str),
                        method: Parser::match_request_method(method),
                        http_version: None,
                    }),
                    None,
                )
            }

            [method, target_str, http_version] => {
                // @TODO: why can't we pass target_str or &(*target_str) directly?
                let str: &str = &(*target_str);
                (
                    Some(node::RequestLine {
                        target: RequestTarget::from(str),
                        method: Parser::match_request_method(method),
                        http_version: Some(http_version.to_string()),
                    }),
                    None,
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
            [method, target_str, http_version, ..] => {
                /* if let Err(parse_error) = Parser::validate_http_version(http_version) {
                    parse_errs.push(parse_error);
                } */
                // @TODO: why can't we pass target_str or &(*target_str) directly?
                let str: &str = &(*target_str);
                (
                    Some(node::RequestLine {
                        target: RequestTarget::from(str),
                        method: Parser::match_request_method(method),
                        http_version: Some(String::from(http_version)),
                    }),
                    Some(ParseErrorType::TooManyElementsOnRequestLine(format!(
                        "There are too many elements on this line for a request.
There should only be method, target url and http version.
You have additional elements: '{}'",
                        (&tokens[3..]).join(",")
                    ))),
                )
            } // @TODO: ERROR
        };

        // @TODO: validate target, http_version
        return Ok(request_line);
    }

    pub fn parse_comment(scanner: &mut Scanner) -> Result<Option<node::Comment>, ParseErrorType> {
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
        } else if scanner.match_str_forward("##") {
            return Parser::parse_comment_line(scanner);
        }

        return Ok(None);
    }

    pub fn parse(
        string: &str,
    ) -> Result<Option<(node::Request, Vec<ParseErrorType>)>, ParseErrorType> {
        let mut scanner = Scanner::new(string);

        let mut comments = Vec::new();
        let mut name: Option<node::Name> = None;
        let mut parse_errs: Vec<ParseErrorType> = Vec::new();

        loop {
            if let Ok(Some(name_node)) = Parser::parse_name_comment(&mut scanner) {
                name = Some(name_node);
            }
            match Parser::parse_comment(&mut scanner) {
                Ok(Some(comment_node)) => {
                    comments.push(Box::new(comment_node));
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
        let request_line = match Parser::parse_request_line(&mut scanner) {
            Ok(Some(line)) => line,
            Ok(None) => node::RequestLine::new(),
            Err(parse_error) => {
                parse_errs.push(parse_error);
                node::RequestLine::new()
            }
        };

        if let None = name {
            name = Some(node::Name {
                value: String::new(),
            });
        }

        let name_box = match name {
            Some(name) => Box::new(name),
            None => Box::new(node::Name {
                value: String::new(),
            }),
        };

        let mut file_node = node::Request {
            name: name_box,
            comments,
            request_line,
        };

        // if no name set we use the first comment as name @TODO: only ### comment is accepted?
        if file_node.name.value == "" {
            if file_node.comments.len() > 0 {
                let first_comment = file_node.comments.remove(0);
                file_node.name.value = first_comment.value;
            }
        }
        Ok(Some((file_node, parse_errs)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    pub fn name_triple_tag() {
        let str = "
### test name

https://httpbin.org
";
        let parsed = Parser::parse(str);

        let expected = node::Request {
            name: Box::new(node::Name {
                value: String::from("test name"),
            }),
            comments: Vec::new(),
            request_line: node::RequestLine {
                method: HttpMethod::GET,
                target: RequestTarget::from("https://httpbin.org"),
                http_version: None,
            },
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

        let expected = node::Request {
            name: Box::new(node::Name {
                value: String::from("test name"),
            }),
            comments: Vec::new(),
            request_line: node::RequestLine {
                method: HttpMethod::GET,
                target: RequestTarget::from("https://httpbin.org"),
                http_version: None,
            },
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

        let expected = node::Request {
            name: Box::new(node::Name {
                value: String::from("test name"),
            }),
            comments: Vec::new(),
            request_line: node::RequestLine {
                method: HttpMethod::CUSTOM("CUSTOMVERB".to_string()),
                target: RequestTarget::from("https://httpbin.org"),
                http_version: None,
            },
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

        let expected = node::Request {
            name: Box::new(node::Name {
                value: String::from("test name"),
            }),
            comments: Vec::new(),
            request_line: node::RequestLine {
                method: HttpMethod::POST,
                target: RequestTarget::from("https://httpbin.org"),
                http_version: None,
            },
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

        let expected = node::Request {
            name: Box::new(node::Name {
                value: String::from("test name"),
            }),
            comments: Vec::new(),
            request_line: node::RequestLine {
                method: HttpMethod::POST,
                target: RequestTarget::from("https://httpbin.org"),
                http_version: None,
            },
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
            Some(String::from("HTTP/1.1"))
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
            Some(String::from("HTTP/1.1"))
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
            Some(String::from("HTTP/1.1"))
        );
        assert_eq!(errs, vec![]);
    }

    #[test]
    pub fn validate_http_version() {
        assert!(Parser::validate_http_version("HTTP/1.1").unwrap());
        assert!(Parser::validate_http_version("HTTP/1.2").unwrap());
        assert!(Parser::validate_http_version("HTTP/2.0").unwrap());
        assert!(Parser::validate_http_version("invalid").is_err());
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
}

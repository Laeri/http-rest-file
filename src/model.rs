pub mod model {

    #[derive(PartialEq, Debug, Clone)]
    pub enum ParseErrorType {
        Unspecified,
        NoNameFound,
        InvalidHttpMethod,
        InvalidTargetUrl(String),
        InvalidHttpVersion(String),
        MissingRequestTargetUrl(String),
        TooManyElementsOnRequestLine(String),
        InvalidMultipart(String),
        InvalidHeaderFields(String),
    }

    #[derive(PartialEq, Debug)]
    #[allow(clippy::upper_case_acronyms)]
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
    pub enum RequestTarget {
        RelativeOrigin { uri: http::Uri, string: String },
        Absolute { uri: http::Uri, string: String },
        Asterisk,
        InvalidTarget(String),
    }

    #[derive(PartialEq, Debug, Clone)]
    pub struct DispositionField {
        pub key: String,
        pub value: String,
    }

    #[derive(PartialEq, Debug, Clone)]
    pub struct Multipart {
        pub name: String,
        pub from_filepath: Option<String>,
        pub data: Option<String>,
        pub fields: Vec<DispositionField>,
        pub headers: Vec<Header>,
    }

    #[derive(Debug, Clone, PartialEq)]
    pub enum RequestBody {
        None,
        Multipart {
            boundary: String,
            parts: Vec<Multipart>,
        },
        //@TODO
        Text(String),
    }

    impl RequestTarget {
        pub fn parse(value: &str) -> Result<RequestTarget, ParseErrorType> {
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
                        _ => Err(ParseErrorType::InvalidTargetUrl(value.to_string())),
                    }
                }
            }
        }

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
    }

    #[derive(PartialEq, Debug, Clone)]
    pub struct Header {
        pub key: String,
        pub value: String,
    }

    impl Header {
        pub fn new<S: Into<String>, T: Into<String>>(key: S, value: T) -> Self {
            Header {
                key: key.into(),
                value: value.into(),
            }
        }
    }

    #[derive(PartialEq, Debug)]
    pub struct Request {
        pub name: Box<Name>,
        pub comments: Vec<Comment>,
        pub request_line: RequestLine,
        pub headers: Vec<Header>,
        pub body: RequestBody,
    }

    #[derive(PartialEq, Debug)]
    pub struct Comment {
        pub value: String,
    }

    #[derive(PartialEq, Debug)]
    pub struct Name {
        pub value: String,
    }

    #[derive(PartialEq, Debug, Clone)]
    pub struct HttpVersion {
        pub major: u32,
        pub minor: u32,
    }

    impl std::str::FromStr for HttpVersion {
        type Err = ParseErrorType;
        fn from_str(s: &str) -> Result<Self, Self::Err> {
            let err =  ParseErrorType::InvalidHttpVersion(String::from("Http version requires format: 'HTTP/\\d+.\\d+'. 
For example 'HTTP/2.1'. You can also omit the version and only specify the url target of the request or the http method and the url target.
                "));
            if !s.starts_with("HTTP/") {
                return Err(err);
            }
            let rest = &s[5..].to_string();
            let mut split = rest.split('.');
            let major = split.next().map(|v| v.parse::<u32>());
            let minor = split.next().map(|v| v.parse::<u32>());
            match (major, minor) {
                (Some(Ok(major)), Some(Ok(minor))) => Ok(HttpVersion { major, minor }),
                _ => Err(err),
            }
        }
    }

    impl std::fmt::Display for HttpVersion {
        fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            write!(f, "HTTP/{}.{}", self.major, self.minor)
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
    pub struct RequestLine {
        pub method: HttpMethod,
        pub target: RequestTarget,
        pub http_version: Option<HttpVersion>, // @TODO: use enum and validate
    }

    impl RequestTarget {}
    impl Default for RequestLine {
        fn default() -> RequestLine {
            RequestLine {
                method: HttpMethod::GET,
                target: RequestTarget::from(""),
                http_version: None,
            }
        }
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

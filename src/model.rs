#[derive(PartialEq, Debug, Clone)]
pub enum ParseErrorType {
    // General error
    General,
    NoNameFound,
    // Http method has to be one of the Http verbs or a custom string
    InvalidHttpMethod,
    // The target url on the request line is invalid
    InvalidTargetUrl(String),
    // Http version of the request line is not valid, valid are HTTP/<num>.<num>
    InvalidHttpVersion(String),
    // Request line requires at least an url
    MissingRequestTargetUrl(String),
    // Request line should have form <url> | <method> <url> | <method> <url> <version>
    TooManyElementsOnRequestLine(String),
    // Some multipart is invalid
    InvalidMultipart(String),
    // A header of a request is invalid
    InvalidHeaderFields(String),
    // We expect requests to be separated by '###'
    InvalidRequestBoundary(String),

    // only certain characters tart a comment such as '//', '#', '###'
    CommentTypeNotRecognized(String),

    // pre request scripts < {% %}
    InvalidPreRequestScript(String),

    // response handler '> <path>' or '> {% <your_script> %}' is not valid
    InvalidResponseHandler(String),

    // redirect to file requires a path
    RedirectMissingPath(String),
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

impl ToString for HttpMethod {
    fn to_string(&self) -> String {
        let result = match self {
            HttpMethod::GET => "GET",
            HttpMethod::POST => "POST",
            HttpMethod::PUT => "PUT",
            HttpMethod::PATCH => "PATCH",
            HttpMethod::DELETE => "DELETE",
            HttpMethod::HEAD => "HEAD",
            HttpMethod::TRACE => "TRACE",
            HttpMethod::OPTIONS => "OPTIONS",
            HttpMethod::CONNECT => "CONNECT",
            HttpMethod::CUSTOM(string) => &string,
        };
        result.to_string()
    }
}

#[derive(PartialEq, Debug)]
pub enum RequestTarget {
    RelativeOrigin { uri: http::Uri, string: String },
    Absolute { uri: http::Uri, string: String },
    Asterisk,
    InvalidTarget(String),
}

#[derive(PartialEq, Debug, Clone)]
pub enum SettingsEntry {
    NoRedirect,
    NoLog,
    NoCookieJar,
    UseOsCredentials,
    NameEntry(String),
}

#[derive(PartialEq, Debug, Clone)]
pub struct RequestSettings {
    pub no_redirect: Option<bool>,
    pub no_log: Option<bool>,
    pub no_cookie_jar: Option<bool>,
    pub use_os_credentials: Option<bool>,
}

impl Default for RequestSettings {
    fn default() -> Self {
        RequestSettings {
            no_redirect: Some(false),
            no_log: Some(false),
            no_cookie_jar: Some(false),
            use_os_credentials: Some(false),
        }
    }
}

impl RequestSettings {
    pub fn set_entry(&mut self, entry: &SettingsEntry) {
        match entry {
            SettingsEntry::NoLog => self.no_log = Some(true),
            SettingsEntry::NoRedirect => self.no_redirect = Some(true),
            SettingsEntry::NoCookieJar => self.no_cookie_jar = Some(true),
            SettingsEntry::UseOsCredentials => self.use_os_credentials = Some(true),
            // do nothing with name, is stored directly on the request
            SettingsEntry::NameEntry(_name) => (),
        }
    }

    pub fn serialized(&self) -> String {
        let mut result = String::new();
        if let Some(true) = self.no_redirect {
            result.push_str("# @no-redirect\n");
        }
        if let Some(true) = self.no_log {
            result.push_str("# @no-log\n");
        }
        if let Some(true) = self.no_cookie_jar {
            result.push_str("# @no-cookie-jar\n");
        }
        if let Some(true) = self.use_os_credentials {
            result.push_str("# @use-os-credentials\n");
        }
        result
    }
}

#[derive(PartialEq, Debug, Clone)]
pub struct DispositionField {
    pub key: String,
    pub value: String,
}

#[derive(PartialEq, Debug, Clone)]
pub struct Multipart {
    pub name: String,
    pub data: DataSource<String>,
    pub fields: Vec<DispositionField>,
    pub headers: Vec<Header>,
}

#[derive(PartialEq, Debug, Clone)]
pub enum DataSource<T> {
    Raw(T),
    FromFilepath(T),
}

impl ToString for DataSource<String> {
    fn to_string(&self) -> String {
        match self {
            Self::Raw(str) => str.to_string(),
            Self::FromFilepath(path) => format!("< {}", path),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum RequestBody {
    None,
    Multipart {
        boundary: String,
        parts: Vec<Multipart>,
    },
    //@TODO
    Text {
        data: DataSource<String>,
    },
}

impl RequestBody {
    pub fn is_present(&self) -> bool {
        if let RequestBody::None = self {
            return false;
        }
        true
    }
}

impl ToString for RequestBody {
    fn to_string(&self) -> String {
        match self {
            RequestBody::None => "".to_string(),
            RequestBody::Multipart { boundary, parts } => {
                let mut multipart_res = String::new();

                // TODO
                for part in parts.iter() {
                    multipart_res.push_str(&format!("--{}\n", boundary));
                    multipart_res.push_str(&format!(
                        "Content-Disposition: form-data; name=\"{}\"",
                        part.name
                    ));
                    let fields_string = part
                        .fields
                        .iter()
                        .map(|field| format!("{}=\"{}\"", field.key, field.value))
                        .collect::<Vec<String>>()
                        .join(";");
                    if !fields_string.is_empty() {
                        multipart_res.push_str("; ");
                    }
                    multipart_res.push_str(&fields_string);
                    multipart_res.push('\n');
                    for header in part.headers.iter() {
                        multipart_res.push_str(&format!("{}: {}", header.key, header.value));
                        multipart_res.push('\n');
                    }
                    multipart_res.push('\n');
                    let content = match part.data {
                        DataSource::Raw(ref str) => str.to_string(),
                        DataSource::FromFilepath(ref path) => format!("< {}", path),
                    };
                    multipart_res.push_str(&content);
                    multipart_res.push('\n');
                }
                multipart_res.push_str(&format!("--{}--", boundary));
                return multipart_res;
            }
            RequestBody::Text { data } => data.to_string(),
        }
    }
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

impl ToString for Header {
    fn to_string(&self) -> String {
        format!("{}: {}", self.key, self.value)
    }
}

#[derive(PartialEq, Debug)]
pub enum HttpRestFileExtension {
    Http,
    Rest,
}

#[derive(PartialEq, Debug)]
pub struct HttpRestFile {
    requests: Vec<Request>,
    path: Box<std::path::Path>,
    extension: HttpRestFileExtension,
}

#[derive(PartialEq, Debug, Clone)]
pub enum PreRequestScript {
    FromFilepath(String),
    Script(String),
}

impl ToString for PreRequestScript {
    fn to_string(&self) -> String {
        match self {
            PreRequestScript::FromFilepath(path) => format!("< {}", path),
            PreRequestScript::Script(script) => {
                format!("< {{%{}%}}", script)
            }
        }
    }
}

#[derive(PartialEq, Debug, Clone)]
pub enum ResponseHandler {
    FromFilepath(String),
    Script(String),
}

#[derive(PartialEq, Debug, Clone)]
pub enum Redirect {
    NewFileIfExists(String),
    RewriteFile(String),
}

#[derive(PartialEq, Debug)]
pub struct RequestFile {
    pub path: String,
    pub requests: Vec<Request>,
}

#[derive(PartialEq, Debug)]
pub struct Request {
    pub name: Option<String>,
    pub comments: Vec<Comment>,
    pub request_line: RequestLine,
    pub headers: Vec<Header>,
    pub body: RequestBody,
    pub settings: RequestSettings,
    pub pre_request_script: Option<PreRequestScript>,
    pub response_handler: Option<ResponseHandler>,
    pub redirect: Option<Redirect>,
}

#[derive(PartialEq, Debug, Clone)]
pub enum CommentKind {
    // //
    DoubleSlash,
    // ###
    RequestSeparator,
    // #
    SingleTag,
}

impl CommentKind {
    pub fn string_repr(&self) -> &str {
        match self {
            Self::DoubleSlash => "//",
            Self::RequestSeparator => "###",
            Self::SingleTag => "#",
        }
    }
}

impl std::str::FromStr for CommentKind {
    type Err = ParseErrorType;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "//" => Ok(Self::DoubleSlash),
            "###" => Ok(Self::RequestSeparator),
            "#" => Ok(Self::SingleTag),
            _ => {
                let msg = format!("Invalid start characters for comment: {}", s);
                Err(ParseErrorType::CommentTypeNotRecognized(msg))
            }
        }
    }
}

#[derive(PartialEq, Debug)]
pub struct Comment {
    pub value: String,
    pub kind: CommentKind,
}

impl ToString for Comment {
    fn to_string(&self) -> String {
        match self.kind {
            CommentKind::SingleTag => format!("# {}", self.value),
            CommentKind::DoubleSlash => format!("// {}", self.value),
            CommentKind::RequestSeparator => format!("### {}", self.value),
        }
    }
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
    pub method: Option<HttpMethod>,
    pub target: RequestTarget,
    pub http_version: Option<HttpVersion>, // @TODO: use enum and validate
}

impl RequestTarget {}

impl Default for RequestLine {
    fn default() -> RequestLine {
        RequestLine {
            method: Some(HttpMethod::GET),
            target: RequestTarget::from(""),
            http_version: None,
        }
    }
}

impl ToString for RequestTarget {
    fn to_string(&self) -> String {
        match self {
            RequestTarget::Asterisk => "*",
            RequestTarget::Absolute { string, .. } => string,
            RequestTarget::RelativeOrigin { string, .. } => string,
            RequestTarget::InvalidTarget(target) => target,
        }
        .to_string()
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

#[derive(PartialEq, Debug)]
pub struct FileParseResult {
    pub requests: Vec<Request>,
    pub errs: Vec<ParseErrorType>,
}

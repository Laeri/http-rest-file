#[derive(PartialEq, Debug, Clone)]
pub enum ParseErrorKind {
    // General error
    General,
    // The target url on the request line is invalid
    InvalidTargetUrl,
    // Http version of the request line is not valid, valid are HTTP/<num>.<num>
    InvalidHttpVersion,
    // Request line requires at least an url
    MissingRequestTargetUrl,
    // Request line should have form <url> | <method> <url> | <method> <url> <version>
    TooManyElementsOnRequestLine,
    // Some multipart is invalid
    InvalidMultipart,
    // A header of a request is invalid
    InvalidHeaderFields,
    // We expect requests to be separated by '###'
    InvalidRequestBoundary,
    // only certain characters tart a comment such as '//', '#', '###'
    CommentTypeNotRecognized,
    // pre request scripts < {% %}
    InvalidPreRequestScript,
    // response handler '> <path>' or '> {% <your_script> %}' is not valid
    InvalidResponseHandler,
    // redirect to file requires a path
    RedirectMissingPath,
    // if read file errors
    FileReadError,
    // file does not contain any request
    NoRequestFoundInFile,
    // path to read file from is not valid
    InvalidFilePath,
}

#[derive(PartialEq, Debug, Clone)]
pub struct ParseError {
    pub kind: ParseErrorKind,
    pub message: String,
    pub start_pos: Option<usize>,
    pub end_pos: Option<usize>,
}

impl Default for ParseError {
    fn default() -> Self {
        ParseError {
            kind: ParseErrorKind::General,
            message: String::new(),
            start_pos: None,
            end_pos: None,
        }
    }
}
impl ParseError {
    pub fn new<S: Into<String>>(kind: ParseErrorKind, msg: S) -> Self {
        ParseError {
            kind,
            message: msg.into(),
            start_pos: None,
            end_pos: None,
        }
    }

    pub fn new_with_position<S, T, U>(
        kind: ParseErrorKind,
        msg: S,
        start_pos: T,
        end_pos: Option<U>,
    ) -> ParseError
    where
        S: Into<String>,
        T: Into<usize>,
        U: Into<usize>,
    {
        ParseError {
            kind,
            message: msg.into(),
            start_pos: Some(start_pos.into()),
            end_pos: end_pos.map(|p| p.into()),
        }
    }
}

#[allow(dead_code)]
pub enum WithDefault<T> {
    Some(T),
    Default(T),
    DefaultFn(Box<dyn Fn() -> T>),
}

impl<T: std::fmt::Debug> std::fmt::Debug for WithDefault<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WithDefault::Some(value) => f.debug_tuple("Some").field(value).finish(),
            WithDefault::Default(value) => f.debug_tuple("Default").field(value).finish(),
            WithDefault::DefaultFn(fun) => {
                let result = fun();
                let type_name = std::any::type_name::<T>();
                f.debug_tuple("DefaultFn")
                    .field(&format_args!("{}: {:?}", type_name, result))
                    .finish()
            }
        }
    }
}

impl<T> WithDefault<T> {
    #[allow(dead_code)]
    fn default_fn(f: Box<dyn Fn() -> T>) -> Self {
        WithDefault::DefaultFn(f)
    }
}

impl<T> From<Option<T>> for WithDefault<T>
where
    WithDefault<T>: Default,
{
    fn from(value: Option<T>) -> Self {
        match value {
            Some(t) => WithDefault::Some(t),
            _ => WithDefault::default(),
        }
    }
}

impl<T> Default for WithDefault<T>
where
    T: Default + std::fmt::Debug,
{
    fn default() -> Self {
        WithDefault::Default(T::default())
    }
}

impl Default for WithDefault<HttpVersion> {
    fn default() -> Self {
        WithDefault::Default(HttpVersion { major: 1, minor: 1 })
    }
}

impl Default for WithDefault<HttpMethod> {
    fn default() -> Self {
        WithDefault::Default(HttpMethod::GET)
    }
}

impl<T> WithDefault<T> {
    #[allow(dead_code)]
    pub fn is_default(&self) -> bool {
        !matches!(self, WithDefault::Some(_))
    }

    #[allow(dead_code)]
    pub fn unwrap_or_default(self) -> T {
        match self {
            WithDefault::Some(value) => value,
            WithDefault::Default(default) => default,
            WithDefault::DefaultFn(f) => f(),
        }
    }
}

impl<T: Clone> WithDefault<T> {
    pub fn get_or_default(&self) -> T {
        match self {
            WithDefault::Some(value) => value.clone(),
            WithDefault::Default(default) => default.clone(),
            WithDefault::DefaultFn(f) => f(),
        }
    }
}

impl<T: std::cmp::PartialEq> PartialEq for WithDefault<T> {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (WithDefault::Some(value), WithDefault::Some(other_value)) => value.eq(other_value),
            (WithDefault::Default(value), WithDefault::Default(other_value)) => {
                value.eq(other_value)
            }
            (WithDefault::DefaultFn(f), WithDefault::DefaultFn(f_other)) => (f()).eq(&f_other()),
            _ => false,
        }
    }
}

#[allow(clippy::upper_case_acronyms)]
#[derive(PartialEq, Debug, Clone)]
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
            HttpMethod::CUSTOM(string) => string,
        };
        result.to_string()
    }
}

#[derive(PartialEq, Debug)]
pub enum RequestTarget {
    RelativeOrigin { uri: String },
    Absolute { uri: String },
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

    #[allow(dead_code)]
    // lsp plugin does not recognize that this method is used
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
    #[allow(dead_code)]
    // error in lsp plugin, does not recognize this method is used
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
                multipart_res
            }
            RequestBody::Text { data } => data.to_string(),
        }
    }
}

impl RequestTarget {
    pub fn parse(value: &str) -> Result<RequestTarget, ParseError> {
        if value == "*" {
            return Ok(RequestTarget::Asterisk);
        }
        match value.parse::<http::Uri>() {
            Ok(uri) => {
                // if we have the authority (host:port) then it is an absolute url
                if let Some(_authority) = uri.authority() {
                    Ok(RequestTarget::Absolute {
                        uri: value.to_string(),
                    })
                } else {
                    Ok(RequestTarget::RelativeOrigin {
                        uri: value.to_string(),
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
                    Ok(_uri) => Ok(RequestTarget::Absolute {
                        uri: value.to_string(),
                    }),
                    _ => Err(ParseError::new(
                        ParseErrorKind::InvalidTargetUrl,
                        value.to_string(),
                    )),
                }
            }
        }
    }

    #[allow(dead_code)]
    // bug in lsp does not recognize this method is used
    pub fn has_scheme(&self) -> bool {
        match self {
            RequestTarget::Asterisk => false,
            RequestTarget::Absolute { uri, .. } | RequestTarget::RelativeOrigin { uri, .. } => uri
                .parse::<http::Uri>()
                .map_or(false, |uri| uri.scheme().is_some()),
            RequestTarget::InvalidTarget(_) => false,
        }
    }
}

#[derive(PartialEq, Debug, Clone)]
pub struct Header {
    pub key: String,
    pub value: String,
}

impl Header {
    #[allow(dead_code)]
    // bug in lsp does not recognize this method is used
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

impl HttpRestFileExtension {
    pub fn from_path(path: &std::path::Path) -> Option<Self> {
        match path.extension().and_then(|os_str| os_str.to_str()) {
            Some("http") => Some(HttpRestFileExtension::Http),
            Some("rest") => Some(HttpRestFileExtension::Rest),
            _ => None,
        }
    }
}

#[derive(PartialEq, Debug)]
pub struct HttpRestFile {
    pub requests: Vec<Request>,
    pub errs: Vec<ParseError>,
    pub path: Box<std::path::PathBuf>,
    pub extension: Option<HttpRestFileExtension>,
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

impl Default for Request {
    fn default() -> Self {
        Request {
            name: None,
            comments: vec![],
            request_line: RequestLine::default(),
            headers: vec![],
            body: RequestBody::None,
            settings: RequestSettings::default(),
            pre_request_script: None,
            response_handler: None,
            redirect: None,
        }
    }
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
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "//" => Ok(Self::DoubleSlash),
            "###" => Ok(Self::RequestSeparator),
            "#" => Ok(Self::SingleTag),
            _ => {
                let msg = format!("Invalid start characters for comment: {}", s);
                Err(ParseError::new(
                    ParseErrorKind::CommentTypeNotRecognized,
                    msg,
                ))
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
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let err =  ParseError::new(ParseErrorKind::InvalidHttpVersion,String::from("Http version requires format: 'HTTP/\\d+.\\d+'. 
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

#[derive(PartialEq, Debug)]
pub struct RequestLine {
    pub method: WithDefault<HttpMethod>,
    pub target: RequestTarget,
    pub http_version: WithDefault<HttpVersion>,
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

impl Default for RequestLine {
    fn default() -> RequestLine {
        RequestLine {
            method: WithDefault::Default(HttpMethod::GET),
            target: RequestTarget::from(""),
            http_version: WithDefault::Default(HttpVersion { major: 1, minor: 1 }),
        }
    }
}

impl ToString for RequestTarget {
    fn to_string(&self) -> String {
        match self {
            RequestTarget::Asterisk => "*",
            RequestTarget::Absolute { uri, .. } => uri,
            RequestTarget::RelativeOrigin { uri, .. } => uri,
            RequestTarget::InvalidTarget(target) => target,
        }
        .to_string()
    }
}

impl Request {
    #[allow(dead_code)]
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
    pub errs: Vec<ParseError>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    pub fn test_with_default() {
        assert_eq!(
            WithDefault::<HttpVersion>::default(),
            WithDefault::<HttpVersion>::default()
        );

        assert_eq!(
            WithDefault::<HttpMethod>::default(),
            WithDefault::<HttpMethod>::default()
        );

        assert_eq!(
            WithDefault::DefaultFn(Box::new(|| HttpVersion { major: 2, minor: 1 })),
            WithDefault::DefaultFn(Box::new(|| HttpVersion { major: 2, minor: 1 }))
        );

        assert_eq!(
            WithDefault::Some(HttpMethod::CUSTOM("CustomVerb".to_string())),
            WithDefault::Some(HttpMethod::CUSTOM("CustomVerb".to_string()))
        );

        assert!(WithDefault::<HttpVersion>::default().is_default());
        assert_eq!(
            WithDefault::Some(HttpVersion { major: 1, minor: 1 }).is_default(),
            false
        );
        assert!(WithDefault::default_fn(Box::new(|| 1)).is_default());
        assert!(
            WithDefault::DefaultFn(Box::new(|| HttpVersion { major: 1, minor: 1 })).is_default()
        );

        assert_eq!(WithDefault::Some(1).unwrap_or_default(), 1);
        assert_eq!(WithDefault::Default(1).unwrap_or_default(), 1);
        assert_eq!(
            WithDefault::DefaultFn(Box::new(|| 1)).unwrap_or_default(),
            1
        );
    }
}

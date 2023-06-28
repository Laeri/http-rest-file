#[cfg(feature = "rspc")]
use rspc::Type;

use serde::{Deserialize, Serialize};

use std::borrow::Cow;

#[derive(PartialEq, Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
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
    // Response redirect should have form '>> <some/path>' or '>>! <some/path>'
    InvalidSaveResponseRedirect,
}

#[derive(PartialEq, Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
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
    pub fn new_default_fn(f: Box<dyn Fn() -> T>) -> Self {
        WithDefault::DefaultFn(f)
    }

    pub fn with_default(value: Option<T>, default: T) -> Self {
        match value {
            Some(value) => WithDefault::Some(value),
            None => WithDefault::Default(default),
        }
    }

    pub fn with_default_fn(value: Option<T>, default_fn: Box<dyn Fn() -> T>) -> Self {
        match value {
            Some(value) => WithDefault::Some(value),
            None => WithDefault::DefaultFn(default_fn),
        }
    }
}

impl<T> From<T> for WithDefault<T> {
    fn from(value: T) -> Self {
        WithDefault::Some(value)
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

impl<T> From<WithDefault<T>> for Option<T> {
    fn from(value: WithDefault<T>) -> Option<T> {
        match value {
            WithDefault::Some(val) => Some(val),
            _ => None,
        }
    }
}

impl<T> Default for WithDefault<T>
where
    T: Default,
{
    fn default() -> Self {
        WithDefault::Default(T::default())
    }
}

impl<T: ToOwned<Owned = T>> WithDefault<T> {
    #[allow(dead_code)]
    pub fn get_cloned_or_computed(&self) -> T {
        match self {
            WithDefault::Some(val) => val.to_owned(),
            WithDefault::Default(val) => val.to_owned(),
            WithDefault::DefaultFn(func) => func(),
        }
    }
}

impl<T: Clone> WithDefault<T> {
    #[allow(dead_code)]
    pub fn get_ref_or_default<'a>(&'a self) -> Cow<'a, T> {
        match self {
            WithDefault::Some(val) => Cow::Borrowed(val),
            WithDefault::Default(val) => Cow::Borrowed(val),
            WithDefault::DefaultFn(func) => Cow::Owned(func()),
        }
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

impl<T: std::cmp::PartialOrd> PartialOrd for WithDefault<T> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        let first_computed;
        let second_computed;

        let first_ref = match self {
            WithDefault::Default(default) => default,
            WithDefault::Some(value) => value,
            WithDefault::DefaultFn(default_fn) => {
                first_computed = Some(default_fn());
                first_computed.as_ref().unwrap()
            }
        };

        let second_ref = match other {
            WithDefault::Default(default) => default,
            WithDefault::Some(value) => value,
            WithDefault::DefaultFn(default_fn) => {
                second_computed = Some(default_fn());
                second_computed.as_ref().unwrap()
            }
        };

        first_ref.partial_cmp(second_ref)
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
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "rspc", derive(Type))]
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

impl HttpMethod {
    pub fn new(s: &str) -> Self {
        match s {
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
}

impl Default for HttpMethod {
    fn default() -> Self {
        HttpMethod::GET
    }
}

#[derive(PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "rspc", derive(Type))]
pub enum RequestTarget {
    RelativeOrigin { uri: String },
    Absolute { uri: String },
    Asterisk,
    InvalidTarget(String),
    Missing,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "rspc", derive(Type))]
pub enum SettingsEntry {
    NoRedirect,
    NoLog,
    NoCookieJar,
    NameEntry(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "rspc", derive(Type))]
pub struct RequestSettings {
    pub no_redirect: Option<bool>,
    pub no_log: Option<bool>,
    pub no_cookie_jar: Option<bool>,
}

impl Default for RequestSettings {
    fn default() -> Self {
        RequestSettings {
            no_redirect: Some(false),
            no_log: Some(false),
            no_cookie_jar: Some(false),
        }
    }
}

impl RequestSettings {
    pub fn set_entry(&mut self, entry: &SettingsEntry) {
        match entry {
            SettingsEntry::NoLog => self.no_log = Some(true),
            SettingsEntry::NoRedirect => self.no_redirect = Some(true),
            SettingsEntry::NoCookieJar => self.no_cookie_jar = Some(true),
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
        result
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "rspc", derive(Type))]
pub struct DispositionField {
    pub name: String,
    pub filename: Option<String>,
    pub filename_star: Option<String>,
}

impl DispositionField {
    pub fn new<S>(name: S) -> Self
    where
        S: Into<String>,
    {
        DispositionField {
            name: name.into(),
            filename: None,
            filename_star: None,
        }
    }
    pub fn new_with_filename<S, T>(name: S, filename: Option<T>) -> Self
    where
        S: Into<String>,
        T: Into<String>,
    {
        DispositionField {
            name: name.into(),
            filename: filename.map(|t| t.into()),
            filename_star: None,
        }
    }
}

#[derive(PartialEq, Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "rspc", derive(Type))]
pub struct Multipart {
    pub data: DataSource<String>,
    pub disposition: DispositionField,
    pub headers: Vec<Header>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "rspc", derive(Type))]
pub enum DataSource<T> {
    Raw(T),
    FromFilepath(String),
}

impl ToString for DataSource<String> {
    fn to_string(&self) -> String {
        match self {
            Self::Raw(str) => str.to_string(),
            Self::FromFilepath(path) => format!("< {}", path),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "rspc", derive(Type))]
pub struct UrlEncodedParam {
    pub key: String,
    pub value: String,
}

impl UrlEncodedParam {
    pub fn new<S, T>(key: S, value: T) -> Self
    where
        S: Into<String>,
        T: Into<String>,
    {
        UrlEncodedParam {
            key: key.into(),
            value: value.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "rspc", derive(Type))]
pub enum RequestBody {
    None,

    Multipart {
        boundary: String,
        parts: Vec<Multipart>,
    },

    UrlEncoded {
        url_encoded_params: Vec<UrlEncodedParam>,
    },

    Raw {
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
            RequestBody::UrlEncoded { url_encoded_params } => {
                let mut serializer = url::form_urlencoded::Serializer::new(String::new());
                url_encoded_params.iter().for_each(|param| {
                    serializer.append_pair(&param.key, &param.value);
                });
                serializer.finish()
            }
            RequestBody::Multipart { boundary, parts } => {
                let mut multipart_res = String::new();

                // TODO
                for part in parts.iter() {
                    multipart_res.push_str(&format!("--{}\n", boundary));
                    multipart_res.push_str(&format!(
                        "Content-Disposition: form-data; name=\"{}\"",
                        part.disposition.name
                    ));

                    if let Some(ref filename) = part.disposition.filename {
                        multipart_res.push_str(&format!("; filename=\"{}\"", filename));
                    }

                    if let Some(ref filename_star) = part.disposition.filename_star {
                        multipart_res.push_str(&format!("; filename*=\"{}\"", filename_star));
                    }
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
            RequestBody::Raw { data } => data.to_string(),
        }
    }
}

impl RequestTarget {
    pub fn is_missing(&self) -> bool {
        return matches!(self, RequestTarget::Missing);
    }

    pub fn parse(value: &str) -> Result<RequestTarget, ParseError> {
        if value == "" {
            return Ok(RequestTarget::Missing);
        }

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
            RequestTarget::Missing => false,
        }
    }
}

#[derive(PartialEq, Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "rspc", derive(Type))]
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

#[derive(PartialEq, Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "rspc", derive(Type))]
pub enum HttpRestFileExtension {
    Http,
    Rest,
}

impl HttpRestFileExtension {
    pub fn get_extension(&self) -> String {
        match self {
            HttpRestFileExtension::Http => ".http".to_string(),
            HttpRestFileExtension::Rest => ".rest".to_string(),
        }
    }
}

impl std::fmt::Display for HttpRestFileExtension {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HttpRestFileExtension::Http => f.write_str("http"),
            HttpRestFileExtension::Rest => f.write_str("rest"),
        }
    }
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
#[cfg_attr(feature = "rspc", derive(Type))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
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
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "rspc", derive(Type))]
pub enum ResponseHandler {
    FromFilepath(String),
    Script(String),
}

#[derive(PartialEq, Debug, Clone, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "rspc", derive(Type))]
///https://www.jetbrains.com/help/idea/http-client-in-product-code-editor.html#redirect-output-to-a-custom-file-or-directory
pub enum SaveResponse {
    // save the response into a new file if there exists already an existing save (use incremental
    // numbering for filename)
    NewFileIfExists(std::path::PathBuf),
    // save the response to a file and overwrite it if present
    RewriteFile(std::path::PathBuf),
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
    pub save_response: Option<SaveResponse>,
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
            save_response: None,
        }
    }
}

#[derive(PartialEq, Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "rspc", derive(Type))]
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
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "rspc", derive(Type))]
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

#[derive(PartialEq, Debug, Clone, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "rspc", derive(Type))]
pub struct HttpVersion {
    pub major: u32,
    pub minor: u32,
}

impl Default for HttpVersion {
    fn default() -> Self {
        HttpVersion { major: 1, minor: 1 }
    }
}

impl std::str::FromStr for HttpVersion {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        println!("STRING: {}", s);
        let err =  ParseError::new(ParseErrorKind::InvalidHttpVersion,String::from("Http version requires format: 'HTTP/\\d+.\\d+' or 'HTTP/\\d+'. 
For example 'HTTP/2.1'. You can also omit the version and only specify the url target of the request or the http method and the url target.
                "));
        if !s.starts_with("HTTP/") {
            return Err(err);
        }
        // @TODO: string can also have form HTTP/2 200, at least returned from the client, maybe
        // check if we can remove it there already...
        let s = if s.contains(" ") {
            s.split(" ").next().unwrap_or("")
        } else {
            s
        };
        let rest = &s[5..].to_string();
        let mut split = dbg!(rest).split('.');
        let major = dbg!(split.next()).map(|v| v.parse::<u32>());
        // if no minor version is present, then we assume it is 2.0 --> @TODO: is this ok?
        let minor = split.next().map(|v| v.parse::<u32>()).unwrap_or(Ok(0));
        println!("MAJOR: {:?}", major);
        println!("MINOR: {:?}", minor);
        match (major, minor) {
            (Some(Ok(major)), Ok(minor)) => Ok(HttpVersion { major, minor }),
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
            http_version: WithDefault::Default(HttpVersion::default()),
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
            RequestTarget::Missing => "",
        }
        .to_string()
    }
}

impl Request {
    #[allow(dead_code)]
    pub fn get_comment_text(&self) -> Option<String> {
        if self.comments.is_empty() {
            return None;
        }
        Some(
            self.comments
                .iter()
                .map(|b| b.value.clone())
                .collect::<Vec<String>>()
                .join("\n"),
        )
    }

    pub fn get_url(&self) -> String {
        self.request_line.target.to_string()
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
        assert!(WithDefault::new_default_fn(Box::new(|| 1)).is_default());
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

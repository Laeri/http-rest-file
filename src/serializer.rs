use crate::model::{self, CommentKind, RequestFile, ResponseHandler};

#[derive(PartialEq, Debug, Clone)]
pub enum SerializeError {
    InvalidFilePath,
    IoError(String),
}

pub struct Serializer {}

impl Serializer {
    pub fn serialize_to_file(file_model: &RequestFile) -> Result<(), SerializeError> {
        let content = Serializer::serialize_requests(
            &file_model.requests.iter().collect::<Vec<&model::Request>>()[..],
        );
        let path = std::path::PathBuf::from(&file_model.path);

        match std::fs::write(path, content) {
            Ok(_) => Ok(()),
            Err(io_err) => Err(SerializeError::IoError(io_err.to_string())),
        }
    }

    pub fn serialize_requests(requests: &[&model::Request]) -> String {
        let mut result = String::new();
        let num_requests = requests.len();
        for (index, request) in requests.iter().enumerate() {
            // if no request separator is present between the requests then create one
            if index > 0
                && !request.comments.first().map_or(false, |comment| {
                    comment.kind == CommentKind::RequestSeparator
                })
            {
                result.push_str("###");
            }
            result.push_str(&Serializer::serialize_request(request));

            // insert new line between requests
            if num_requests > 1 && index != num_requests - 1 {
                result.push('\n');
            }
        }
        result
    }

    pub fn serialize_request(request: &model::Request) -> String {
        let mut result = String::new();
        let comments_string = request
            .comments
            .iter()
            .map(|comment| comment.to_string())
            .collect::<Vec<String>>()
            .join("\n");

        if !comments_string.is_empty() {
            result.push_str(&comments_string);
            result.push('\n');
        }

        if let Some(ref name) = request.name {
            result.push_str(&format!("# @name={}\n", name));
        }

        result.push_str(&request.settings.serialized());

        if let Some(pre_request_script) = &request.pre_request_script {
            result.push_str(&pre_request_script.to_string());
            result.push('\n');
        }

        // @TODO Option type for method
        if let Some(method) = &request.request_line.method {
            result.push_str(&method.to_string());
            result.push(' ');
        }
        result.push_str(&request.request_line.target.to_string());

        if let Some(ref http_version) = request.request_line.http_version {
            result.push(' ');
            result.push_str(&http_version.to_string());
        }

        if !request.headers.is_empty() {
            result.push('\n');
            let headers = request
                .headers
                .iter()
                .map(|header| header.to_string())
                .collect::<Vec<String>>()
                .join("\n");
            result.push_str(&headers);
            // an empty newline is required after the headers
            result.push('\n')
        }

        if request.body.is_present() {
            result.push('\n');
            result.push_str(&request.body.to_string());
        }

        if let Some(response_handler) = &request.response_handler {
            result.push_str("\n\n");
            let string = match response_handler {
                ResponseHandler::FromFilepath(path) => format!("> {}", path),
                ResponseHandler::Script(script) => format!("> {{%{}%}}", script),
            };
            result.push_str(&string);
        }

        if let Some(redirect) = &request.redirect {
            result.push_str("\n\n");
            let string = match redirect {
                model::Redirect::RewriteFile(path) => format!(">>! {}", path),
                model::Redirect::NewFileIfExists(path) => format!(">> {}", path),
            };
            result.push_str(&string);
        }

        result
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{model::*, Parser};
    use pretty_assertions::assert_eq;

    #[test]
    pub fn serialize_comments() {
        let request = Request {
            name: Some("RequestName".to_string()),
            headers: vec![],
            comments: vec![Comment {
                value: "The Request".to_string(),
                kind: CommentKind::RequestSeparator,
            }],
            settings: RequestSettings {
                no_redirect: Some(true),
                no_log: Some(true),
                no_cookie_jar: Some(true),
                use_os_credentials: Some(true),
            },
            request_line: RequestLine {
                method: Some(HttpMethod::GET),
                target: RequestTarget::from("https://httpbin.org"),
                http_version: None,
            },
            body: RequestBody::None,
            pre_request_script: None,
            response_handler: None,
            redirect: None,
        };
        let expected = r"### The Request
# @name=RequestName
# @no-redirect
# @no-log
# @no-cookie-jar
# @use-os-credentials
GET https://httpbin.org";

        let serialized = Serializer::serialize_requests(&[&request]);
        assert_eq!(serialized, expected);
    }

    #[test]
    pub fn serialize_only_url() {
        let request = Request {
            name: None,
            headers: vec![],
            comments: vec![],
            settings: RequestSettings {
                no_redirect: None,
                no_log: None,
                no_cookie_jar: None,
                use_os_credentials: None,
            },
            request_line: RequestLine {
                method: None,
                target: RequestTarget::from("https://httpbin.org"),
                http_version: None,
            },
            body: RequestBody::None,
            pre_request_script: None,
            response_handler: None,
            redirect: None,
        };
        let expected = r"https://httpbin.org";

        let serialized = Serializer::serialize_requests(&[&request]);
        assert_eq!(serialized, expected);
    }

    #[test]
    pub fn serialize_method_url() {
        let request = Request {
            name: None,
            headers: vec![],
            comments: vec![],
            settings: RequestSettings {
                no_redirect: None,
                no_log: None,
                no_cookie_jar: None,
                use_os_credentials: None,
            },
            request_line: RequestLine {
                method: Some(HttpMethod::GET),
                target: RequestTarget::from("https://httpbin.org"),
                http_version: None,
            },
            body: RequestBody::None,
            pre_request_script: None,
            response_handler: None,
            redirect: None,
        };
        let expected = r"GET https://httpbin.org";

        let serialized = Serializer::serialize_requests(&[&request]);
        assert_eq!(serialized, expected);
    }

    #[test]
    pub fn serialize_method_url_http_version() {
        let request = Request {
            name: None,
            headers: vec![],
            comments: vec![],
            settings: RequestSettings {
                no_redirect: None,
                no_log: None,
                no_cookie_jar: None,
                use_os_credentials: None,
            },
            request_line: RequestLine {
                method: Some(HttpMethod::GET),
                target: RequestTarget::from("https://httpbin.org"),
                http_version: Some(HttpVersion { major: 1, minor: 1 }),
            },
            body: RequestBody::None,
            pre_request_script: None,
            response_handler: None,
            redirect: None,
        };
        let expected = r"GET https://httpbin.org HTTP/1.1";

        let serialized = Serializer::serialize_requests(&[&request]);
        assert_eq!(serialized, expected);
    }

    #[test]
    pub fn serialize_custom_method() {
        let request = Request {
            name: None,
            headers: vec![],
            comments: vec![],
            settings: RequestSettings {
                no_redirect: None,
                no_log: None,
                no_cookie_jar: None,
                use_os_credentials: None,
            },
            request_line: RequestLine {
                method: Some(HttpMethod::CUSTOM("CustomMethod".to_string())),
                target: RequestTarget::from("https://httpbin.org"),
                http_version: Some(HttpVersion { major: 2, minor: 1 }),
            },
            body: RequestBody::None,
            pre_request_script: None,
            response_handler: None,
            redirect: None,
        };
        let expected = r"CustomMethod https://httpbin.org HTTP/2.1";
        let serialized = Serializer::serialize_requests(&[&request]);
        assert_eq!(serialized, expected);
    }

    #[test]
    pub fn serialize_with_text_body() {
        let request = Request {
            name: None,
            headers: vec![Header::new("Content-Type", "application/json")],
            comments: vec![],
            settings: RequestSettings {
                no_redirect: None,
                no_log: None,
                no_cookie_jar: None,
                use_os_credentials: None,
            },
            request_line: RequestLine {
                method: Some(HttpMethod::POST),
                target: RequestTarget::from("https://httpbin.org/post"),
                http_version: None,
            },
            body: RequestBody::Text {
                data: DataSource::Raw(
                    r####"{
  "name": "John Doe",
  "age": 30,
  "email": "johndoe@example.com",
  "address": {
    "street": "123 Main St",
    "city": "Anytown",
    "state": "CA",
    "zip": "12345"
  },
  "phoneNumbers": [
    {
      "type": "home",
      "number": "555-555-1234"
    },
    {
      "type": "work",
      "number": "555-555-5678"
    }
  ],
  "isActive": true
}"####
                        .to_string(),
                ),
            },
            pre_request_script: None,
            response_handler: None,
            redirect: None,
        };
        let expected = r####"POST https://httpbin.org/post
Content-Type: application/json

{
  "name": "John Doe",
  "age": 30,
  "email": "johndoe@example.com",
  "address": {
    "street": "123 Main St",
    "city": "Anytown",
    "state": "CA",
    "zip": "12345"
  },
  "phoneNumbers": [
    {
      "type": "home",
      "number": "555-555-1234"
    },
    {
      "type": "work",
      "number": "555-555-5678"
    }
  ],
  "isActive": true
}"####;

        let serialized = Serializer::serialize_requests(&[&request]);
        assert_eq!(serialized, expected);
    }

    #[test]
    pub fn serialize_with_file() {
        let request = Request {
            name: None,
            headers: vec![Header::new("Content-Type", "application/json")],
            comments: vec![],
            settings: RequestSettings {
                no_redirect: None,
                no_log: None,
                no_cookie_jar: None,
                use_os_credentials: None,
            },
            request_line: RequestLine {
                method: Some(HttpMethod::POST),
                target: RequestTarget::from("https://httpbin.org/post"),
                http_version: None,
            },
            body: RequestBody::Text {
                data: DataSource::Raw("< /path/to/file.json".to_string()),
            },
            pre_request_script: None,
            response_handler: None,
            redirect: None,
        };
        let expected = r####"POST https://httpbin.org/post
Content-Type: application/json

< /path/to/file.json"####;

        let serialized = Serializer::serialize_requests(&[&request]);
        assert_eq!(serialized, expected);
    }

    #[test]
    pub fn serialize_with_redirect() {
        let request = Request {
            name: None,
            headers: vec![Header::new("Content-Type", "application/json")],
            comments: vec![],
            settings: RequestSettings {
                no_redirect: None,
                no_log: None,
                no_cookie_jar: None,
                use_os_credentials: None,
            },
            request_line: RequestLine {
                method: Some(HttpMethod::POST),
                target: RequestTarget::from("https://httpbin.org/post"),
                http_version: None,
            },
            body: RequestBody::Text {
                data: DataSource::Raw("< /path/to/file.json".to_string()),
            },
            pre_request_script: None,
            response_handler: None,
            redirect: Some(Redirect::NewFileIfExists("./path/to/out.json".to_string())),
        };
        let expected = r####"POST https://httpbin.org/post
Content-Type: application/json

< /path/to/file.json

>> ./path/to/out.json"####;

        let serialized = Serializer::serialize_requests(&[&request]);
        assert_eq!(serialized, expected);
    }

    #[test]
    pub fn serialize_with_headers() {
        let request = Request {
            name: None,
            headers: vec![Header::new("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/93.0.4577.63 Safari/537.36")
, Header::new("Accept-Language", "en-US,en;q=0.9,es;q=0.8"),
                // fake token
                Header::new("Authorization", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"),
Header::new("Cache-Control", "max-age=3600")
            ],
            comments: vec![],
            settings: RequestSettings {
                no_redirect: None,
                no_log: None,
                no_cookie_jar: None,
                use_os_credentials: None,
            },
            request_line: RequestLine {
                method: Some(HttpMethod::POST),
                target: RequestTarget::from("https://httpbin.org/post"),
                http_version: None,
            },
            body: RequestBody::None,
            pre_request_script: None,
            response_handler: None,
            redirect: None,
        };
        // we expect a newline after the headers
        let expected = r"POST https://httpbin.org/post
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/93.0.4577.63 Safari/537.36
Accept-Language: en-US,en;q=0.9,es;q=0.8
Authorization: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
Cache-Control: max-age=3600
";
        let serialized = Serializer::serialize_requests(&[&request]);
        assert_eq!(serialized, expected);
    }

    #[test]
    pub fn serialize_all() {
        let request = Request {
            name: Some("RequestName".to_string()),
            headers: vec![Header::new("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/93.0.4577.63 Safari/537.36")
, Header::new("Accept-Language", "en-US,en;q=0.9,es;q=0.8"),
                // fake token
                Header::new("Authorization", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"),
Header::new("Cache-Control", "max-age=3600"),
                Header::new("Content-Type", "application/json")
            ],
comments: vec![Comment {
                value: "The Request".to_string(),
                kind: CommentKind::RequestSeparator,
            }],
            settings: RequestSettings {
                no_redirect: Some(true),
                no_log: Some(true),
                no_cookie_jar: Some(true),
                use_os_credentials: Some(true),
            },
            request_line: RequestLine {
                method: Some(HttpMethod::POST),
                target: RequestTarget::from("https://httpbin.org/post"),
                http_version: Some(HttpVersion { major: 2, minor: 1 }),
            },
            body: RequestBody::Text { data: DataSource::Raw(r####"{
  "name": "John Doe",
  "age": 30,
  "email": "johndoe@example.com",
  "address": {
    "street": "123 Main St",
    "city": "Anytown",
    "state": "CA",
    "zip": "12345"
  },
  "phoneNumbers": [
    {
      "type": "home",
      "number": "555-555-1234"
    },
    {
      "type": "work",
      "number": "555-555-5678"
    }
  ],
  "isActive": true
}"####.to_string() )},
            pre_request_script: Some(PreRequestScript::Script(r####" request.variables.set("firstname", "John") "####.to_string())),
            response_handler: Some(ResponseHandler::FromFilepath(r####"/path/to/responseHandler.js"####.to_string())),
            redirect: Some(Redirect::RewriteFile("/path/to/out_file".to_string())),
        };

        // we expect a newline after the headers
        let expected = r####"### The Request
# @name=RequestName
# @no-redirect
# @no-log
# @no-cookie-jar
# @use-os-credentials
< {% request.variables.set("firstname", "John") %}
POST https://httpbin.org/post HTTP/2.1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/93.0.4577.63 Safari/537.36
Accept-Language: en-US,en;q=0.9,es;q=0.8
Authorization: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
Cache-Control: max-age=3600
Content-Type: application/json

{
  "name": "John Doe",
  "age": 30,
  "email": "johndoe@example.com",
  "address": {
    "street": "123 Main St",
    "city": "Anytown",
    "state": "CA",
    "zip": "12345"
  },
  "phoneNumbers": [
    {
      "type": "home",
      "number": "555-555-1234"
    },
    {
      "type": "work",
      "number": "555-555-5678"
    }
  ],
  "isActive": true
}

> /path/to/responseHandler.js

>>! /path/to/out_file"####;
        let serialized = Serializer::serialize_requests(&[&request]);
        assert_eq!(serialized, expected);

        // reparsing should return the same model
        let file_parse_result = Parser::parse(&serialized, false);
        assert_eq!(file_parse_result.errs, vec![]);
        assert_eq!(file_parse_result.requests.len(), 1);
        assert_eq!(
            file_parse_result.requests.iter().collect::<Vec<&Request>>(),
            vec![&request]
        );
    }

    #[test]
    pub fn serialize_all_multipart() {
        let request = Request {
            name: Some("RequestName".to_string()),
            headers: vec![Header::new("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/93.0.4577.63 Safari/537.36")
, Header::new("Accept-Language", "en-US,en;q=0.9,es;q=0.8"),
                // fake token
                Header::new("Authorization", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"),
Header::new("Cache-Control", "max-age=3600"),
                Header::new("Content-Type", "multipart/form-data; boundary=WebAppBoundary")
            ],
comments: vec![Comment {
                value: "The Request".to_string(),
                kind: CommentKind::RequestSeparator,
            }],
            settings: RequestSettings {
                no_redirect: Some(true),
                no_log: Some(true),
                no_cookie_jar: Some(true),
                use_os_credentials: Some(true),
            },
            request_line: RequestLine {
                method: Some(HttpMethod::POST),
                target: RequestTarget::from("https://httpbin.org/post"),
                http_version: Some(HttpVersion { major: 2, minor: 1 }),
            },
            body: model::RequestBody::Multipart {
                boundary: "WebAppBoundary".to_string(),
                parts: vec![
                    Multipart {
                        name: "element-name".to_string(),
                        data: DataSource::Raw("Name".to_string()),
                        fields: vec![],
                        headers: vec![Header {
                            key: "Content-Type".to_string(),
                            value: "text/plain".to_string()
                        }]
                    },
                    Multipart {
                        name: "data".to_string(), 
                        data: DataSource::FromFilepath("./request-form-data.json".to_string()),
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
            },

            pre_request_script: Some(PreRequestScript::Script("\nrequest.variables.set(\"firstname\", \"John\")\n".to_string())),
            response_handler: Some(ResponseHandler::Script("\n    client.global.set(\"my_cookie\", response.headers.valuesOf(\"Set-Cookie\")[0]);\n".to_string())),
            redirect: Some(Redirect::NewFileIfExists("/path/to/out_file".to_string())),
        };

        // we expect a newline after the headers
        let expected = r####"### The Request
# @name=RequestName
# @no-redirect
# @no-log
# @no-cookie-jar
# @use-os-credentials
< {%
request.variables.set("firstname", "John")
%}
POST https://httpbin.org/post HTTP/2.1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/93.0.4577.63 Safari/537.36
Accept-Language: en-US,en;q=0.9,es;q=0.8
Authorization: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
Cache-Control: max-age=3600
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

> {%
    client.global.set("my_cookie", response.headers.valuesOf("Set-Cookie")[0]);
%}

>> /path/to/out_file"####;
        let serialized = Serializer::serialize_requests(&[&request]);
        assert_eq!(serialized, expected);

        // reparsing should return the same model
        let file_parse_result = Parser::parse(&serialized, false);
        assert_eq!(file_parse_result.errs, vec![]);
        assert_eq!(file_parse_result.requests.len(), 1);
        assert_eq!(
            file_parse_result.requests.iter().collect::<Vec<&Request>>(),
            vec![&request]
        );
    }
}

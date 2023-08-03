# Http Rest File

This project is a recursive descent parser and generator for the `.http` and `.rest` file format written in Rust.
The http rest file format describes a request with target, headers and body that can be performed by a api client
for testing purposes.

JetBrains has an inbuilt http client within their editor that can perform these specified requests.
See here for more information: [Intellij Http Syntax](https://www.jetbrains.com/help/idea/exploring-http-syntax.html)

## What is the .http/.rest format
With the http file format you can specify requests given 
- an HTTP method such as (GET, POST, PUT, ..)
- an URL
- optionally the HTTP version
- headers
- body

Such a request could look like this:

```
GET https://httpbin.org/get
```

or using a POST and some additional meta information in the comments:

```
### Some comment describing the request 
# @name=Request Name
# @no-log @no-follow
POST https://httpbin.org/post
Content-Type: application/json

< path/to/json/file.json

>>! save_response_output.json
```


JetBrains also specified the request in editor in the following github project.
[http-request-in-editor-spec](https://github.com/JetBrains/http-request-in-editor-spec)
The content of the specification seems to be somewhat outdated but still describes the format quite well.


## Add Library Using Cargo
`cargo add http-rest-file`

## Usage
If you are using this crate you want to either parse the content of a .http/.rest file into a model or do the
vice versa and create the file content from an existing model.

### Model
The request model looks like this:

```rust
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
```

Some parts of it are contained within the comments (meta information) such as the `name` as well as the `settings` (`@no-log`, `@no-cookie-jar`, `@no-follow`).
The `request_line` contains the http method type, url as well as optionally the http version.
The pre-request scripts and response handler are optional and do not need to be present.
Optionally, the result of a respones can be sent to a file specified by the `SaveResponse` type.

### Parsing Text -> Model

Parse a file given a file path:
```rust
use http_rest_file::Parser;
use std::path::PathBuf;

fn main() {
  let model = Parser::parse_file(PathBuf::from("./your/path/request.http")).expect(jj)
}
```

Parse string content

```rust
let str = r#####"
POST http://example.com/api/add
Content-Type: application/json

< ./input.json
###

GET https://example.com/first
###
GET https://example.com/second


###
        "#####;

        let FileParseResult { requests, errs } = dbg!(Parser::parse(str, false));
        println!("errs: {:?}", errs);
        assert_eq!(errs.len(), 1);
        assert_eq!(requests.len(), 3);

        // @TODO check content
        assert_eq!(
            requests,
            vec![
                model::Request {
                    name: None,
                    comments: vec![],
                    headers: vec![Header {
                        key: "Content-Type".to_string(),
                        value: "application/json".to_string()
                    }],
                    body: model::RequestBody::Raw {
                        data: DataSource::FromFilepath("./input.json".to_string())
                    },
                    request_line: model::RequestLine {
                        http_version: WithDefault::default(),
                        method: WithDefault::Some(HttpMethod::POST),
                        target: model::RequestTarget::Absolute {
                            uri: "http://example.com/api/add".to_string()
                        }
                    },
                    settings: RequestSettings::default(),
                    pre_request_script: None,
                    response_handler: None,
                    save_response: None,
                },
                model::Request {
                    name: None,
                    comments: vec![],
                    headers: vec![],
                    body: model::RequestBody::None,
                    request_line: model::RequestLine {
                        http_version: WithDefault::default(),
                        method: WithDefault::Some(HttpMethod::GET),
                        target: model::RequestTarget::Absolute {
                            uri: "https://example.com/first".to_string()
                        }
                    },
                    settings: RequestSettings::default(),
                    pre_request_script: None,
                    response_handler: None,
                    save_response: None,
                },
                model::Request {
                    name: None,
                    comments: vec![],
                    headers: vec![],
                    body: model::RequestBody::None,
                    request_line: model::RequestLine {
                        http_version: WithDefault::default(),
                        method: WithDefault::Some(HttpMethod::GET),
                        target: model::RequestTarget::Absolute {
                            uri: "https://example.com/second".to_string()
                        }
                    },
                    settings: RequestSettings::default(),
                    pre_request_script: None,
                    response_handler: None,
                    save_response: None
                }
            ],
        );
}
```

### Serialization Model -> Text
Either serialize to a file given a `HttpRestFile` model:
`http_rest_file::Serializer::serialize_to_file(rest_file_model)`

Or serialize to a string given a list of request models, each will be serialized and requests are separated by the request
separator which are three tags: `###`

`http_rest_file::Serializer::serialize_requests(requests)`

Full example:
```rust
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
            },
            request_line: RequestLine {
                method: WithDefault::Some(HttpMethod::POST),
                target: RequestTarget::from("https://httpbin.org/post"),
                http_version: WithDefault::default(),
            },
            body: RequestBody::None,
            pre_request_script: None,
            response_handler: None,
            save_response: None,
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
```

### Error Handling And Recovery
During parsing errors can occur. See the `ParseError` enum type for a display of the kind of errors that can occur and what kind
of messages are displayed if they do. 

If a request can be parsed partially then the `ErrorWithPartial` will be returned which contains a `PartialRequest` with all
parts that could be parsed before the error occurred. From a `PartialRequest` you can if you want create a `Request` model where
all successfully parsed parts are present and the rest is filled up with the defaults.

For more detailed information where the error occurred the `ParseErrorDetails` type contains the cursor position within the parsed string.

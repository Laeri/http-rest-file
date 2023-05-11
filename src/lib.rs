//! This library provides a parser `parser::Parser` for parsing http client request files (.http or .rest
//! extension). In addition, the `serializer::Serializer` allows to generate http client files given an existing model. 
//! These request files are also commonly used in the JetBrains integrated http client.
//! JetBrains has a lose specification (not entirely up to date) here:
//! https://github.com/JetBrains/http-request-in-editor-spec
//! They also have some documentation about their http client here: https://www.jetbrains.com/help/idea/http-client-in-product-code-editor.html#creating-http-request-files

mod model;
mod parser;
mod scanner;
mod serializer;
pub use parser::Parser;
pub use parser::Scanner;
pub use serializer::Serializer;

use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::model::Request;

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Error, Debug, PartialEq, Eq, Clone)]
pub enum ParseError {
    #[error("No request has been found in the given file: '{0}'.")]
    NoRequestFoundInFile(PathBuf),
    #[error("Could not read the file: '{0}'.")]
    CouldNotReadRequestFile(PathBuf),

    #[error("Invalid comment start characters: '{0}', comments before the request url should start with '//', '#' or '###'.")]
    InvalidCommentStart(String),

    #[error("Invalid request URL found: '{0}'. The URL should either be in the form of an URL using host with optional schemes 'http://', 'https://' or it should be a relative url starting with a slash and the 'Host:' header defined.")]
    InvalidRequestUrl(String),

    #[error("The HTTP version: '{0}' is not valid. A valid HTTP version requires format: 'HTTP/\\d+.\\d+' or 'HTTP/\\d+'.\nFor example 'HTTP/2.1'. You can also omit the version and only specify the url target of the request or the HTTP method and the url target.")]
    InvalidHttpVersion(String),

    #[error("Expected either a prerequest script within '{{% %}}' blocks or a filepath to a pre-request script after matching '<' character.")]
    MissingPreRequestScript,
    #[error("A pre-request script should be ended with '%}}' characters but none were found.")]
    MissingPreRequestScriptClose,

    #[error("Missing request target line.")]
    MissingRequestTargetLine,
    #[error("The request target line containing the url for the request contains too many elements. There should only be a method, the URL and HTTP version. You have additional elements: {0}")]
    TooManyElementsOnRequestLine(String),

    #[error("Expected header in the form of '<Key>: <Value>'. Found line: {0}")]
    InvalidHeaderField(String),

    #[error("Missing multipart boundary in 'Content-Type' for 'multipart/form-data'. Using default boundary '{0}' instead.")]
    MissingMultipartHeaderBoundaryDefinition(String),
    #[error("Within multipart body expected either a new boundary starting with '{next_boundary}' or finishing a multipart with '{end_boundary}' but none were found.")]
    MissingMultipartBoundary {
        next_boundary: String,
        end_boundary: String,
    },
    #[error("Multipart requires a first starting boundary before any content.")]
    MissingMultipartStartingBoundary,
    #[error("Could not parse the headers of the given part of a multipart body. Error during parsing: {error_msg}.")]
    InvalidSingleMultipartHeaders {
        header_parse_err: Box<ParseError>,
        error_msg: String,
    },

    // first header of a single multipart should be 'Content-Disposition', this error occurs if
    // none are present
    #[error("Missing 'Content-Disposition' header of the multipart part.")]
    MissingSingleMultipartContentDispositionHeader,
    // If there are headers but the first isn't the 'Content-Disposition' one
    #[error("First header of a multipart part should be the 'Content-Disposition' header, found '{0}' instead.")]
    WrongMultipartContentDispositionHeader(String),
    // 'form-data' is missing, should be the first part of the 'Content-Disposition' header
    #[error("Multipart Content-Disposition should have type 'form-data', found: {0}.")]
    InvalidMultipartContentDispositionFormData(String),
    // The 'Content-Disposition' header is in some way malformed
    #[error("Expected content disposition values in form <key>=<value> or <key>=\"<value>\" but found: '{0}'")]
    MalformedContentDispositionEntries(String),
    // Same as for the request, after the headers an empty line has to occur before the body begins
    // for every single multipart
    #[error("Requires empty line in single multipart after Content-Disposition and other headers before the body begins!")]
    SingleMultipartMissingEmptyLine,
    #[error("Multipart should be ended with boundary '{0}'. End of file encountered instead.")]
    MultipartShouldBeEndedWithBoundary(String),
    #[error("Boundary within multipart content type is required to be 1-70 characters long.")]
    InvalidMultipartBoundaryLength,
    #[error("Invalid character: '{0}' found in multipart boundary.")]
    InvalidMultipartBoundaryCharacter(String),
    #[error("Content disposition header of a multipart (multipart/formdata) requires a name field, found only {0}")]
    SingleMultipartNameMissing(String),
    // response handler opened with '> {% should be closed again
    #[error("Expected closing '%}}' characters for response handler when opened with '{{%', response handler script is malformed.")]
    MissingResponseHandlerClose,

    #[error("Missing filepath for response after redirecting file using '>>', or '>>!'")]
    MissingRedirectResponsePath,

    //let msg = "Expected pre request starting characters '{%' after a matching '<', or a filepath to a handler script above the request.".to_string();
    #[error("unknown parse error")]
    Unknown,
}

#[derive(Debug, PartialEq)]
pub struct ParseErrorDetails {
    pub error: ParseError,
    pub details: Option<String>,
    pub start_pos: Option<usize>,
    pub end_pos: Option<usize>,
    pub partial_request: Option<Request>,
}

impl Default for ParseErrorDetails {
    fn default() -> Self {
        ParseErrorDetails {
            error: ParseError::Unknown,
            details: None,
            start_pos: None,
            end_pos: None,
            partial_request: None,
        }
    }
}

impl ParseErrorDetails {
    pub fn new_with_position(error: ParseError, position: (usize, Option<usize>)) -> Self {
        ParseErrorDetails {
            error,
            details: None,
            start_pos: Some(position.0),
            end_pos: position.1,
            partial_request: None,
        }
    }
}

impl From<ParseError> for ParseErrorDetails {
    fn from(parse_error: ParseError) -> Self {
        ParseErrorDetails {
            error: parse_error,
            ..Default::default()
        }
    }
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Error, Debug, PartialEq, Eq)]
pub enum SerializeError {
    #[error("IoError occurred during serialization: {0}")]
    IoError(String),
}

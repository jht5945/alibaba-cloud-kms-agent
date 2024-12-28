#[derive(Debug)]
pub(crate) struct HttpError(pub u16, pub String);

impl From<url::ParseError> for HttpError {
    fn from(e: url::ParseError) -> Self {
        HttpError(400, e.to_string())
    }
}

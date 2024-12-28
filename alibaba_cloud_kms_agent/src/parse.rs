use std::borrow::Borrow;

use url::Url;

use crate::error::HttpError;

#[derive(Debug)]
pub(crate) struct GSVQuery {
    pub secret_id: String,
    pub version_id: Option<String>,
    pub version_stage: Option<String>,
}

impl GSVQuery {
    pub(crate) fn try_from_query(s: &str) -> Result<Self, HttpError> {
        // url library can only parse complete URIs. The host/port/scheme used is irrelevant since it is not used
        let complete_uri = format!("http://localhost{}", s);

        let url = Url::parse(&complete_uri)?;

        let mut query = GSVQuery {
            secret_id: "".into(),
            version_id: None,
            version_stage: None,
        };

        for (k, v) in url.query_pairs() {
            match k.borrow() {
                "secretId" => query.secret_id = v.into(),
                "versionId" => query.version_id = Some(v.into()),
                "versionStage" => query.version_stage = Some(v.into()),
                p => return Err(HttpError(400, format!("unknown parameter: {}", p))),
            }
        }

        if query.secret_id.is_empty() {
            return Err(HttpError(400, "missing parameter secretId".to_string()));
        }

        Ok(query)
    }

    pub(crate) fn try_from_path_query(s: &str, path_prefix: &str) -> Result<Self, HttpError> {
        // url library can only parse complete URIs. The host/port/scheme used is irrelevant since it gets stripped
        let complete_uri = format!("http://localhost{}", s);

        let url = Url::parse(&complete_uri)?;

        let secret_id = match url.path().get(path_prefix.len()..) {
            Some(s) if !s.is_empty() => s.to_string(),
            _ => return Err(HttpError(400, "missing secret ID".to_string())),
        };

        let mut query = GSVQuery {
            secret_id,
            version_id: None,
            version_stage: None,
        };

        for (k, v) in url.query_pairs() {
            match k.borrow() {
                "versionId" => query.version_id = Some(v.into()),
                "versionStage" => query.version_stage = Some(v.into()),
                p => return Err(HttpError(400, format!("unknown parameter: {}", p))),
            }
        }

        Ok(query)
    }
}

use alibaba_cloud_kms::AliyunClientError;

pub fn is_transient_error(e: &AliyunClientError) -> bool {
    match e {
        AliyunClientError::Reqwest(_) => true,
        AliyunClientError::InvalidHeader(_) => false,
        AliyunClientError::InvalidRequest(_) => false,
        AliyunClientError::InvalidResponse {
            request_id: _,
            error_code,
            error_message: _,
        } => {
            // FIXME check more error codes @see alibaba_cloud_kms_agent/src/cache_manager.rs
            match error_code.as_str() {
                "Rejected.Throttling" => true,
                error if error.contains("Temporary") || error.contains("InternalError") => true,
                _ => false,
            }
        }
    }
}

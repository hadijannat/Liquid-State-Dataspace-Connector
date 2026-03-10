use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;

pub type ApiResult<T> = std::result::Result<T, ApiError>;

pub struct ApiError {
    status: StatusCode,
    message: String,
    headers: HeaderMap,
}

impl ApiError {
    pub fn bad_request(err: impl ToString) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: err.to_string(),
            headers: HeaderMap::new(),
        }
    }

    pub fn internal(err: impl ToString) -> Self {
        tracing::error!(error = %err.to_string(), "internal server error");
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: "internal server error".to_string(),
            headers: HeaderMap::new(),
        }
    }

    pub fn unauthorized() -> Self {
        let mut headers = HeaderMap::new();
        headers.insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
        Self {
            status: StatusCode::UNAUTHORIZED,
            message: "unauthorized".to_string(),
            headers,
        }
    }

    pub fn not_found(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            message: message.into(),
            headers: HeaderMap::new(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let mut response = (
            self.status,
            Json(serde_json::json!({ "error": self.message })),
        )
            .into_response();
        response.headers_mut().extend(self.headers);
        response
    }
}

#[cfg(test)]
mod tests {
    use super::ApiError;
    use axum::http::{header, StatusCode};
    use axum::response::IntoResponse;

    #[test]
    fn test_unauthorized_response_includes_bearer_challenge() {
        let response = ApiError::unauthorized().into_response();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            response.headers().get(header::WWW_AUTHENTICATE).unwrap(),
            "Bearer"
        );
    }
}

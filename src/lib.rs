use axum::{body::Body, http::header::HeaderName, response::Response};
use futures_util::StreamExt;

/// agentrouter.org's WAF rejects requests whose User-Agent is not an allowed
/// agent (curl, bare reqwest, etc.). Always spoof an allowed client upstream,
/// since callers send their own UA (e.g. curl) that the WAF would block.
const ALLOWED_CLIENT_USER_AGENT: &str = "opencode/0.11.0";

pub fn app(client: reqwest::Client, target: String) -> axum::Router {
    axum::Router::new().fallback(move |request| proxy(client.clone(), target.clone(), request))
}

async fn proxy(
    client: reqwest::Client,
    target: String,
    request: axum::extract::Request,
) -> Response {
    let (parts, body) = request.into_parts();
    let url = format!(
        "{target}{}",
        parts
            .uri
            .path_and_query()
            .map_or("/", |value| value.as_str())
    );
    let mut builder = client.request(parts.method, url);

    for (name, value) in &parts.headers {
        if name != axum::http::header::HOST
            && name != axum::http::header::USER_AGENT
            && name != axum::http::header::CONTENT_LENGTH
            && !is_hop_by_hop(name)
        {
            builder = builder.header(name, value);
        }
    }

    builder = builder.header(axum::http::header::USER_AGENT, ALLOWED_CLIENT_USER_AGENT);

    let body_bytes = match axum::body::to_bytes(body, usize::MAX).await {
        Ok(bytes) => bytes,
        Err(error) => {
            let mut response = Response::new(Body::from(error.to_string()));
            *response.status_mut() = axum::http::StatusCode::BAD_REQUEST;
            return response;
        }
    };
    let body_bytes = sanitize_tool_schemas(&body_bytes);

    let upstream = match builder.body(body_bytes).send().await {
        Ok(response) => response,
        Err(error) => {
            let mut response = Response::new(Body::from(error.to_string()));
            *response.status_mut() = axum::http::StatusCode::BAD_GATEWAY;
            return response;
        }
    };

    let status = upstream.status();
    let headers = upstream.headers().clone();
    let stream = upstream
        .bytes_stream()
        .map(|chunk| chunk.map_err(std::io::Error::other));
    let mut response = Response::new(Body::from_stream(stream));
    *response.status_mut() = status;
    for (name, value) in &headers {
        if !is_hop_by_hop(name) {
            response.headers_mut().insert(name, value.clone());
        }
    }
    response
}

fn is_hop_by_hop(name: &HeaderName) -> bool {
    matches!(
        name.as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

/// Strict upstreams (e.g. DeepSeek) reject schemas where dirge serializes
/// omitted tool parameters as `"required": null`. Coerce those to empty
/// arrays/objects inside tool definitions only, leaving messages untouched.
fn sanitize_tool_schemas(body: &[u8]) -> Vec<u8> {
    let Ok(mut value) = serde_json::from_slice::<serde_json::Value>(body) else {
        return body.to_vec();
    };
    let mut changed = false;
    if let Some(object) = value.as_object_mut() {
        for key in ["tools", "functions"] {
            if let Some(items) = object
                .get_mut(key)
                .and_then(|section| section.as_array_mut())
            {
                for item in items {
                    changed |= sanitize_schema(item);
                }
            }
        }
    }
    if changed {
        serde_json::to_vec(&value).expect("Value round-trips through JSON")
    } else {
        body.to_vec()
    }
}

fn sanitize_schema(schema: &mut serde_json::Value) -> bool {
    let mut changed = false;
    if let Some(object) = schema.as_object_mut() {
        if object.get("required") == Some(&serde_json::Value::Null) {
            object.insert("required".to_owned(), serde_json::json!([]));
            changed = true;
        }
        if object.get("properties") == Some(&serde_json::Value::Null) {
            object.insert("properties".to_owned(), serde_json::json!({}));
            changed = true;
        }
        for child in object.values_mut() {
            changed |= sanitize_schema(child);
        }
    } else if let Some(array) = schema.as_array_mut() {
        for child in array {
            changed |= sanitize_schema(child);
        }
    }
    changed
}

#[cfg(test)]
mod tests {
    use axum::{
        Router,
        body::Body,
        extract::Request,
        http::{Response, StatusCode, header},
    };
    use reqwest::Client;
    use tokio::net::TcpListener;

    async fn spawn_upstream() -> (tokio::task::JoinHandle<()>, std::net::SocketAddr) {
        let upstream = Router::new().fallback(|request: Request| async move {
            let (parts, body) = request.into_parts();
            let received_body =
                String::from_utf8_lossy(&axum::body::to_bytes(body, usize::MAX).await.unwrap())
                    .into_owned();
            let mut resp_headers = vec![
                ("x-upstream".to_owned(), "present".to_owned()),
                ("content-type".to_owned(), "text/event-stream".to_owned()),
                ("x-received-body".to_owned(), received_body),
            ];
            for (k, v) in &parts.headers {
                if k.as_str().starts_with("x-stainless") {
                    resp_headers.push((k.as_str().to_owned(), v.to_str().unwrap().to_owned()));
                }
            }
            if let Some(ua) = parts.headers.get(axum::http::header::USER_AGENT) {
                resp_headers.push(("x-received-ua".to_owned(), ua.to_str().unwrap().to_owned()));
            }
            for name in ["content-length", "connection", "te"] {
                if let Some(value) = parts.headers.get(name) {
                    resp_headers.push((
                        format!("x-received-{name}"),
                        value.to_str().unwrap().to_owned(),
                    ));
                }
            }
            let mut builder = Response::builder().status(StatusCode::OK);
            for (k, v) in &resp_headers {
                builder = builder.header(k.as_str(), v.as_str());
            }
            builder.body(Body::from("data: upstream body\n\n")).unwrap()
        });
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            axum::serve(listener, upstream.into_make_service())
                .await
                .unwrap();
        });
        (handle, addr)
    }

    #[tokio::test]
    async fn proxy_sanitizes_null_required_and_properties_in_tool_schemas() {
        let (_upstream_handle, upstream_addr) = spawn_upstream().await;

        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();
        let app = crate::app(Client::new(), format!("http://{upstream_addr}"));
        tokio::spawn(async move {
            axum::serve(proxy_listener, app.into_make_service())
                .await
                .unwrap();
        });

        let body = r#"{"model":"deepseek-chat","messages":[{"role":"user","content":"keep literal \"required\": null"}],"tools":[{"type":"function","function":{"name":"list_symbols","parameters":{"type":"object","properties":{},"required":null}}},{"type":"function","function":{"name":"make_chart","parameters":{"type":"object","properties":{"chart":{"type":"object","properties":null,"required":null}},"required":null}}}],"functions":[{"name":"legacy_fn","parameters":{"type":"object","properties":null,"required":null}}]}"#;

        let response = Client::new()
            .post(format!("http://{proxy_addr}/v1/chat/completions"))
            .header(header::AUTHORIZATION, "Bearer test-key")
            .body(body)
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let forwarded: serde_json::Value =
            serde_json::from_str(response.headers()["x-received-body"].to_str().unwrap()).unwrap();
        assert_eq!(
            forwarded["tools"][0]["function"]["parameters"]["required"],
            serde_json::json!([])
        );
        assert_eq!(
            forwarded["tools"][1]["function"]["parameters"]["required"],
            serde_json::json!([])
        );
        assert_eq!(
            forwarded["tools"][1]["function"]["parameters"]["properties"]["chart"]["required"],
            serde_json::json!([])
        );
        assert_eq!(
            forwarded["tools"][1]["function"]["parameters"]["properties"]["chart"]["properties"],
            serde_json::json!({})
        );
        assert_eq!(
            forwarded["functions"][0]["parameters"]["required"],
            serde_json::json!([])
        );
        assert_eq!(
            forwarded["messages"][0]["content"],
            "keep literal \"required\": null"
        );
    }

    #[tokio::test]
    async fn proxy_forwards_bodies_without_schema_nulls_byte_for_byte() {
        let (_upstream_handle, upstream_addr) = spawn_upstream().await;

        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();
        let app = crate::app(Client::new(), format!("http://{upstream_addr}"));
        tokio::spawn(async move {
            axum::serve(proxy_listener, app.into_make_service())
                .await
                .unwrap();
        });

        let client = Client::new();
        let url = format!("http://{proxy_addr}/v1/chat/completions");

        let non_json = "request body";
        let response = client
            .post(&url)
            .header(header::AUTHORIZATION, "Bearer test-key")
            .body(non_json)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["x-received-body"], non_json);

        let valid_tools = r#"{"model":"gpt-4","tools":[{"type":"function","function":{"name":"ok_fn","parameters":{"type":"object","properties":{},"required":["a"]}}}]}"#;
        let response = client
            .post(&url)
            .header(header::AUTHORIZATION, "Bearer test-key")
            .body(valid_tools)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["x-received-body"], valid_tools);
    }

    #[tokio::test]
    async fn proxy_forwards_authorization_and_upstream_response() {
        let (_upstream_handle, upstream_addr) = spawn_upstream().await;

        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();
        let app = crate::app(Client::new(), format!("http://{upstream_addr}"));
        tokio::spawn(async move {
            axum::serve(proxy_listener, app.into_make_service())
                .await
                .unwrap();
        });

        let response = Client::new()
            .post(format!("http://{proxy_addr}/v1/chat/completions"))
            .header(header::AUTHORIZATION, "Bearer test-key")
            .body("request body")
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["x-upstream"], "present");
        assert_eq!(response.headers()["content-type"], "text/event-stream");
        assert_eq!(response.text().await.unwrap(), "data: upstream body\n\n");
    }

    #[tokio::test]
    async fn model_endpoints_proxy_to_upstream() {
        let (_upstream_handle, upstream_addr) = spawn_upstream().await;

        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();
        let app = crate::app(Client::new(), format!("http://{upstream_addr}"));
        tokio::spawn(async move {
            axum::serve(proxy_listener, app.into_make_service())
                .await
                .unwrap();
        });

        let client = Client::new();
        for path in ["/v1/models", "/models"] {
            let resp = client
                .get(format!("http://{proxy_addr}{path}"))
                .send()
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
            assert_eq!(resp.headers()["x-upstream"], "present");
            assert_eq!(resp.text().await.unwrap(), "data: upstream body\n\n");
        }
    }

    #[tokio::test]
    async fn messages_endpoints_proxy_to_upstream() {
        let (_upstream_handle, upstream_addr) = spawn_upstream().await;

        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();
        let app = crate::app(Client::new(), format!("http://{upstream_addr}"));
        tokio::spawn(async move {
            axum::serve(proxy_listener, app.into_make_service())
                .await
                .unwrap();
        });

        let client = Client::new();
        for path in ["/v1/messages", "/messages"] {
            let resp = client
                .post(format!("http://{proxy_addr}{path}"))
                .header(header::AUTHORIZATION, "Bearer test-key")
                .body("request body")
                .send()
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
            assert_eq!(resp.headers()["x-upstream"], "present");
        }
    }

    #[tokio::test]
    async fn proxy_forwards_x_stainless_headers() {
        let (_upstream_handle, upstream_addr) = spawn_upstream().await;

        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();
        let app = crate::app(Client::new(), format!("http://{upstream_addr}"));
        tokio::spawn(async move {
            axum::serve(proxy_listener, app.into_make_service())
                .await
                .unwrap();
        });

        let response = Client::new()
            .post(format!("http://{proxy_addr}/v1/messages"))
            .header("x-stainless-lang", "python")
            .header("x-stainless-runtime", "cpython")
            .header(header::AUTHORIZATION, "Bearer test-key")
            .body("{}")
            .send()
            .await
            .unwrap();

        assert_eq!(response.headers()["x-stainless-lang"], "python");
        assert_eq!(response.headers()["x-stainless-runtime"], "cpython");
    }

    #[tokio::test]
    async fn non_message_non_model_routes_are_proxied() {
        let (_upstream_handle, upstream_addr) = spawn_upstream().await;

        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();
        let app = crate::app(Client::new(), format!("http://{upstream_addr}"));
        tokio::spawn(async move {
            axum::serve(proxy_listener, app.into_make_service())
                .await
                .unwrap();
        });

        let response = Client::new()
            .get(format!("http://{proxy_addr}/some/other/path"))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["x-upstream"], "present");
    }

    #[tokio::test]
    async fn proxy_strips_content_length_and_hop_by_hop_request_headers() {
        let (_upstream_handle, upstream_addr) = spawn_upstream().await;

        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();
        let app = crate::app(Client::new(), format!("http://{upstream_addr}"));
        tokio::spawn(async move {
            axum::serve(proxy_listener, app.into_make_service())
                .await
                .unwrap();
        });

        let response = Client::new()
            .post(format!("http://{proxy_addr}/v1/messages"))
            .header(header::AUTHORIZATION, "Bearer test-key")
            .header(header::CONNECTION, "keep-alive")
            .header(header::TE, "trailers")
            .body("request body")
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        // The caller's content-length is stripped; reqwest recomputes it from
        // the buffered body ("request body" is non-JSON and forwarded as-is).
        assert_eq!(response.headers()["x-received-content-length"], "12");
        assert!(!response.headers().contains_key("x-received-connection"));
        assert!(!response.headers().contains_key("x-received-te"));
    }

    #[tokio::test]
    async fn proxy_forces_allowed_user_agent_upstream() {
        let (_upstream_handle, upstream_addr) = spawn_upstream().await;

        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();
        let app = crate::app(Client::new(), format!("http://{upstream_addr}"));
        tokio::spawn(async move {
            axum::serve(proxy_listener, app.into_make_service())
                .await
                .unwrap();
        });

        // Callers send their own User-Agent (e.g. curl) which the upstream
        // WAF rejects; the proxy must override it with an allowed client.
        let response = Client::new()
            .post(format!("http://{proxy_addr}/v1/messages"))
            .header(header::USER_AGENT, "curl/8.21.0")
            .header(header::AUTHORIZATION, "Bearer test-key")
            .body("{}")
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["x-received-ua"], "opencode/0.11.0");
    }
}

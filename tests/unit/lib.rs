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

async fn serve(app: Router) -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    addr
}

#[tokio::test]
async fn proxy_supplies_required_for_optional_only_tools() {
    let upstream = serve(Router::new().fallback(
        |axum::Json(body): axum::Json<serde_json::Value>| async move {
            let schema = body
                .pointer("/tools/0/function/parameters")
                .or_else(|| body.pointer("/tools/0/input_schema"))
                .or_else(|| body.pointer("/tools/0/parameters"))
                .or_else(|| body.pointer("/functions/0/parameters"))
                .unwrap();
            let status = if schema
                .get("required")
                .is_some_and(serde_json::Value::is_array)
                && schema["properties"]["filter"]
                    .get("required")
                    .is_some_and(serde_json::Value::is_array)
            {
                StatusCode::OK
            } else {
                StatusCode::BAD_REQUEST
            };
            (status, axum::Json(body))
        },
    ))
    .await;
    let proxy = serve(crate::app(Client::new(), format!("http://{upstream}"))).await;
    let schema = serde_json::json!({
        "type": "object",
        "properties": {"filter": {"type": "object", "properties": {"kind": {"type": "string"}}}}
    });
    for (path, body) in [
        (
            "/v1/chat/completions",
            serde_json::json!({"tools": [{"type": "function", "function": {"name": "list_symbols", "parameters": schema}}]}),
        ),
        (
            "/v1/messages",
            serde_json::json!({"tools": [{"name": "list_symbols", "input_schema": schema}]}),
        ),
        (
            "/v1/responses",
            serde_json::json!({"tools": [{"type": "function", "name": "list_symbols", "parameters": schema}]}),
        ),
        (
            "/v1/chat/completions",
            serde_json::json!({"functions": [{"name": "list_symbols", "parameters": schema}]}),
        ),
    ] {
        let response = Client::new()
            .post(format!("http://{proxy}{path}"))
            .header(header::CONTENT_TYPE, "application/json")
            .body(body.to_string())
            .send()
            .await
            .unwrap();
        let status = response.status();
        let forwarded = response.text().await.unwrap();
        assert_eq!(status, StatusCode::OK, "{path}: {forwarded}");
    }
}

#[tokio::test]
async fn schema_repairs_leave_literal_values_and_messages_untouched() {
    let (_handle, upstream) = spawn_upstream().await;
    let proxy = serve(crate::app(Client::new(), format!("http://{upstream}"))).await;
    let literal = serde_json::json!({"type": "object", "required": null, "properties": null});
    let body = serde_json::json!({
        "messages": [{"role": "user", "content": literal.to_string()}],
        "tools": [{"type": "function", "function": {"name": "list_symbols", "parameters": {
            "type": "object", "required": null,
            "properties": {
                "required": {"type": "string", "default": null},
                "value": {"anyOf": [{"type": "object", "required": null, "properties": null}, {"type": "null"}],
                    "default": literal, "const": literal, "enum": [literal], "examples": [literal]}
            }
        }}}]
    });
    let response = Client::new()
        .post(format!("http://{proxy}/v1/chat/completions"))
        .body(body.to_string())
        .send()
        .await
        .unwrap();
    let forwarded: serde_json::Value =
        serde_json::from_str(response.headers()["x-received-body"].to_str().unwrap()).unwrap();
    let value = &forwarded["tools"][0]["function"]["parameters"]["properties"]["value"];
    for key in ["default", "const"] {
        assert_eq!(value[key], literal);
    }
    for key in ["enum", "examples"] {
        assert_eq!(value[key], serde_json::json!([literal]));
    }
    assert_eq!(value["anyOf"][0]["required"], serde_json::json!([]));
    assert_eq!(value["anyOf"][0]["properties"], serde_json::json!({}));
    assert_eq!(forwarded["messages"], body["messages"]);
    assert_eq!(
        forwarded["tools"][0]["function"]["parameters"]["properties"]["required"],
        body["tools"][0]["function"]["parameters"]["properties"]["required"]
    );
}

async fn assert_thinking_round_trip(
    path: &str,
    response_body: String,
    content_type: &'static str,
    assistant: serde_json::Value,
    continuation: serde_json::Value,
) {
    let expected_body = response_body.clone();
    let upstream = serve(Router::new().fallback(
        move |headers: axum::http::HeaderMap, axum::Json(body): axum::Json<serde_json::Value>| {
            let response_body = response_body.clone();
            let assistant = assistant.clone();
            async move {
                assert_eq!(headers[header::ACCEPT_ENCODING], "identity");
                if body["messages"].as_array().unwrap().len() == 1 {
                    let chunks: Vec<_> = response_body
                        .as_bytes()
                        .chunks(3)
                        .map(|chunk| {
                            Ok::<_, std::io::Error>(axum::body::Bytes::copy_from_slice(chunk))
                        })
                        .collect();
                    let mut response =
                        Response::builder().header(header::CONTENT_TYPE, content_type);
                    if content_type == "application/json" {
                        response = response.header(header::CONTENT_LENGTH, response_body.len());
                    }
                    response
                        .body(Body::from_stream(futures_util::stream::iter(chunks)))
                        .unwrap()
                } else if body["messages"][1] == assistant {
                    Response::new(Body::from("accepted"))
                } else {
                    Response::builder().status(StatusCode::BAD_REQUEST).body(Body::from(
                    "The `content[].thinking` in the thinking mode must be passed back to the API."
                )).unwrap()
                }
            }
        },
    ))
    .await;
    let proxy = serve(crate::app(Client::new(), format!("http://{upstream}"))).await;
    let client = Client::new();
    let url = format!("http://{proxy}{path}");
    let first = serde_json::json!({
        "model": "deepseek-v4-pro", "messages": [{"role": "user", "content": "List symbols"}],
        "stream": content_type == "text/event-stream"
    });
    let response = client
        .post(&url)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::AUTHORIZATION, "Bearer test-key")
        .header(header::ACCEPT_ENCODING, "gzip, br")
        .body(first.to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.text().await.unwrap(), expected_body);
    let mut wrong_model = continuation.clone();
    wrong_model["model"] = serde_json::json!("another-model");
    let mut wrong_context = continuation.clone();
    wrong_context["messages"][0]["content"] = serde_json::json!("Another conversation");
    for (key, body) in [
        ("Bearer another-key", continuation.clone()),
        ("Bearer test-key", wrong_model),
        ("Bearer test-key", wrong_context),
    ] {
        let response = client
            .post(&url)
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::AUTHORIZATION, key)
            .body(body.to_string())
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
    let response = client
        .post(&url)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::AUTHORIZATION, "Bearer test-key")
        .body(continuation.to_string())
        .send()
        .await
        .unwrap();
    let status = response.status();
    let body = response.text().await.unwrap();
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body, "accepted");
}

#[tokio::test]
async fn proxy_replays_anthropic_thinking_in_json_and_fragmented_sse() {
    let thinking = serde_json::json!({"type": "thinking", "thinking": "Inspect λ\ncarefully.", "signature": "signed-original"});
    let redacted = serde_json::json!({"type": "redacted_thinking", "data": "opaque-original"});
    let tool = serde_json::json!({"type": "tool_use", "id": "tool-1", "name": "list_symbols", "input": {"path": "src/lib.rs"}});
    let assistant = serde_json::json!({"role": "assistant", "content": [thinking, redacted, tool]});
    let continuation = serde_json::json!({
        "model": "deepseek-v4-pro", "thinking": {"type": "enabled", "budget_tokens": 1024},
        "messages": [
            {"role": "user", "content": "List symbols"},
            {"role": "assistant", "content": [tool]},
            {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "tool-1", "content": "found"}]}
        ]
    });
    let json = serde_json::json!({"type": "message", "role": "assistant", "content": assistant["content"]}).to_string();
    assert_thinking_round_trip(
        "/v1/messages",
        json,
        "application/json",
        assistant.clone(),
        continuation.clone(),
    )
    .await;
    let events = [
        serde_json::json!({"type": "message_start", "message": {"role": "assistant", "content": []}}),
        serde_json::json!({"type": "content_block_start", "index": 0, "content_block": {"type": "thinking", "thinking": "", "signature": ""}}),
        serde_json::json!({"type": "content_block_delta", "index": 0, "delta": {"type": "thinking_delta", "thinking": "Inspect λ\n"}}),
        serde_json::json!({"type": "content_block_delta", "index": 0, "delta": {"type": "thinking_delta", "thinking": "carefully."}}),
        serde_json::json!({"type": "content_block_delta", "index": 0, "delta": {"type": "signature_delta", "signature": "signed-"}}),
        serde_json::json!({"type": "content_block_delta", "index": 0, "delta": {"type": "signature_delta", "signature": "original"}}),
        serde_json::json!({"type": "content_block_stop", "index": 0}),
        serde_json::json!({"type": "content_block_start", "index": 1, "content_block": redacted}),
        serde_json::json!({"type": "content_block_stop", "index": 1}),
        serde_json::json!({"type": "content_block_start", "index": 2, "content_block": {"type": "tool_use", "id": "tool-1", "name": "list_symbols", "input": {}}}),
        serde_json::json!({"type": "content_block_delta", "index": 2, "delta": {"type": "input_json_delta", "partial_json": "{\"path\":\"src/"}}),
        serde_json::json!({"type": "content_block_delta", "index": 2, "delta": {"type": "input_json_delta", "partial_json": "lib.rs\"}"}}),
        serde_json::json!({"type": "content_block_stop", "index": 2}),
        serde_json::json!({"type": "message_delta", "delta": {"stop_reason": "tool_use"}}),
        serde_json::json!({"type": "message_stop"}),
    ];
    for newline in ["\n", "\r\n"] {
        let sse = events
            .iter()
            .map(|event| {
                format!(
                    "event: {}{newline}data: {event}{newline}{newline}",
                    event["type"].as_str().unwrap()
                )
            })
            .collect();
        assert_thinking_round_trip(
            "/messages",
            sse,
            "text/event-stream",
            assistant.clone(),
            continuation.clone(),
        )
        .await;
    }
}

#[tokio::test]
async fn proxy_replays_openai_reasoning_in_json_and_fragmented_sse() {
    let tool = serde_json::json!({"id": "call-1", "type": "function", "function": {"name": "list_symbols", "arguments": "{\"path\":\"src/lib.rs\"}"}});
    let assistant = serde_json::json!({"role": "assistant", "content": null, "reasoning_content": "Inspect λ\ncarefully.", "tool_calls": [tool]});
    let continuation = serde_json::json!({
        "model": "deepseek-v4-pro",
        "messages": [
            {"role": "user", "content": "List symbols"},
            {"role": "assistant", "content": null, "tool_calls": [tool]},
            {"role": "tool", "tool_call_id": "call-1", "content": "found"}
        ]
    });
    let json = serde_json::json!({"choices": [{"index": 0, "message": assistant, "finish_reason": "tool_calls"}]}).to_string();
    assert_thinking_round_trip(
        "/v1/chat/completions",
        json,
        "application/json",
        assistant.clone(),
        continuation.clone(),
    )
    .await;
    let events = [
        serde_json::json!({"choices": [{"index": 0, "delta": {"role": "assistant", "reasoning_content": "Inspect λ\n"}, "finish_reason": null}]}),
        serde_json::json!({"choices": [{"index": 0, "delta": {"reasoning_content": "carefully."}, "finish_reason": null}]}),
        serde_json::json!({"choices": [{"index": 0, "delta": {"tool_calls": [{"index": 0, "id": "call-1", "type": "function", "function": {"name": "list_symbols", "arguments": "{\"path\":\"src/"}}]}, "finish_reason": null}]}),
        serde_json::json!({"choices": [{"index": 0, "delta": {"tool_calls": [{"index": 0, "function": {"arguments": "lib.rs\"}"}}]}, "finish_reason": null}]}),
        serde_json::json!({"choices": [{"index": 0, "delta": {}, "finish_reason": "tool_calls"}]}),
    ];
    let mut sse: String = events
        .iter()
        .map(|event| format!("data: {event}\n\n"))
        .collect();
    sse.push_str("data: [DONE]\n\n");
    assert_thinking_round_trip(
        "/v1/chat/completions",
        sse,
        "text/event-stream",
        assistant,
        continuation,
    )
    .await;
}

#[tokio::test]
async fn proxy_retries_only_missing_thinking_errors_without_fabricating_history() {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    let calls = Arc::new(AtomicUsize::new(0));
    let upstream_calls = calls.clone();
    let upstream = serve(Router::new().fallback(move |axum::Json(body): axum::Json<serde_json::Value>| {
        let calls = upstream_calls.clone();
        async move {
            calls.fetch_add(1, Ordering::SeqCst);
            if body.get("thinking") == Some(&serde_json::json!({"type": "disabled"})) {
                (StatusCode::OK, axum::Json(body))
            } else {
                (StatusCode::BAD_REQUEST, axum::Json(serde_json::json!({"error": {
                    "message": "The `content[].thinking` in the thinking mode must be passed back to the API.",
                    "type": "invalid_request_error"
                }})))
            }
        }
    })).await;
    let proxy = serve(crate::app(Client::new(), format!("http://{upstream}"))).await;
    let body = serde_json::json!({
        "model": "deepseek-v4-pro", "thinking": {"type": "enabled", "budget_tokens": 1024},
        "messages": [{"role": "assistant", "content": [{"type": "tool_use", "id": "old-call", "name": "list_symbols", "input": {}}]}]
    });
    let response = Client::new()
        .post(format!("http://{proxy}/v1/messages"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(body.to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let forwarded: serde_json::Value =
        serde_json::from_str(&response.text().await.unwrap()).unwrap();
    assert_eq!(forwarded["messages"], body["messages"]);
    assert_eq!(calls.load(Ordering::SeqCst), 2);

    let calls = Arc::new(AtomicUsize::new(0));
    let upstream_calls = calls.clone();
    let error = r#"{"error":{"message":"Invalid API key","type":"authentication_error"}}"#;
    let upstream = serve(Router::new().fallback(move || {
        upstream_calls.fetch_add(1, Ordering::SeqCst);
        async move { (StatusCode::BAD_REQUEST, [("x-error-id", "original")], error) }
    }))
    .await;
    let proxy = serve(crate::app(Client::new(), format!("http://{upstream}"))).await;
    let response = Client::new()
        .post(format!("http://{proxy}/v1/messages"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(body.to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(response.headers()["x-error-id"], "original");
    assert_eq!(response.text().await.unwrap(), error);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn proxy_does_not_retry_missing_thinking_more_than_once() {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    let calls = Arc::new(AtomicUsize::new(0));
    let upstream_calls = calls.clone();
    let error = r#"{"error":{"message":"The `reasoning_content` in the thinking mode must be passed back to the API.","type":"invalid_request_error"}}"#;
    let upstream = serve(Router::new().fallback(move || {
        upstream_calls.fetch_add(1, Ordering::SeqCst);
        async move { (StatusCode::BAD_REQUEST, [("x-error-id", "original")], error) }
    }))
    .await;
    let proxy = serve(crate::app(Client::new(), format!("http://{upstream}"))).await;
    for thinking in [
        serde_json::Value::Null,
        serde_json::json!({"type": "disabled"}),
    ] {
        calls.store(0, Ordering::SeqCst);
        let body = serde_json::json!({"model": "test", "thinking": thinking, "messages": [{"role": "assistant", "content": "old answer"}]});
        let response = Client::new()
            .post(format!("http://{proxy}/v1/chat/completions"))
            .header(header::CONTENT_TYPE, "application/json")
            .body(body.to_string())
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(response.headers()["x-error-id"], "original");
        assert_eq!(response.text().await.unwrap(), error);
        assert_eq!(
            calls.load(Ordering::SeqCst),
            if thinking.is_null() { 2 } else { 1 }
        );
    }
}

#[test]
fn thinking_cache_isolated_and_preserves_existing_thinking() {
    use super::{Protocol, ThinkingCache, visible_message};
    let original = serde_json::json!({"role": "assistant", "content": [
        {"type": "thinking", "thinking": "unchanged\nλ", "signature": "signed"},
        {"type": "text", "text": "answer"}
    ]});
    let stripped = serde_json::json!({"role": "assistant", "content": "answer"});
    let visible = visible_message(&stripped);
    let mut cache = ThinkingCache::default();
    cache.remember(1, Protocol::Messages, 2, original.clone());
    for (scope, protocol, context) in [
        (9, Protocol::Messages, 2),
        (1, Protocol::Chat, 2),
        (1, Protocol::Messages, 9),
    ] {
        let mut message = stripped.clone();
        assert!(!cache.restore(scope, protocol, context, &visible, &mut message));
        assert_eq!(message, stripped);
    }
    let mut message = stripped;
    assert!(cache.restore(1, Protocol::Messages, 2, &visible, &mut message));
    assert_eq!(message, original);
    assert!(!cache.restore(1, Protocol::Messages, 2, &visible, &mut message));
    message["content"][0]
        .as_object_mut()
        .unwrap()
        .remove("signature");
    assert!(cache.restore(1, Protocol::Messages, 2, &visible, &mut message));
    assert_eq!(message, original);
    message["content"][0]["thinking"] = serde_json::json!("client thinking");
    let unchanged = message.clone();
    assert!(!cache.restore(1, Protocol::Messages, 2, &visible, &mut message));
    assert_eq!(message, unchanged);
}

#[test]
fn request_scope_separates_credentials_models_and_users() {
    use super::{RandomState, request_scope};
    let hasher = RandomState::new();
    let headers = axum::http::HeaderMap::new();
    let body = serde_json::json!({"model": "one", "user": "alice"});
    let original = request_scope(&headers, &body, &hasher);
    assert_eq!(request_scope(&headers, &body, &hasher), original);
    for key in ["authorization", "x-api-key"] {
        let mut headers = headers.clone();
        headers.insert(
            axum::http::header::HeaderName::from_static(key),
            "secret".parse().unwrap(),
        );
        assert_ne!(request_scope(&headers, &body, &hasher), original);
    }
    for key in ["model", "system", "user"] {
        let mut body = body.clone();
        body[key] = serde_json::json!("other");
        assert_ne!(request_scope(&headers, &body, &hasher), original);
    }
}

#[test]
fn thinking_capture_handles_byte_boundaries_and_rejects_incomplete_streams() {
    use super::{Protocol, ResponseCapture, ThinkingCache};
    use std::sync::{Arc, Mutex};
    let events = [
        serde_json::json!({"type": "content_block_start", "index": 0, "content_block": {"type": "thinking", "thinking": "", "signature": ""}}),
        serde_json::json!({"type": "content_block_delta", "index": 0, "delta": {"type": "thinking_delta", "thinking": "λ\ntext"}}),
        serde_json::json!({"type": "content_block_delta", "index": 0, "delta": {"type": "signature_delta", "signature": "signed"}}),
        serde_json::json!({"type": "content_block_stop", "index": 0}),
        serde_json::json!({"type": "content_block_start", "index": 1, "content_block": {"type": "text", "text": "answer"}}),
        serde_json::json!({"type": "content_block_stop", "index": 1}),
    ];
    for newline in ["\n", "\r\n", "\r"] {
        let cache = Arc::new(Mutex::new(ThinkingCache::default()));
        let mut capture = ResponseCapture::new(cache.clone(), 1, Protocol::Messages, 2);
        capture.sse = true;
        for event in &events {
            let data = format!(": ping{newline}data: {event}{newline}{newline}");
            for byte in data.as_bytes().chunks(1) {
                capture.push(byte);
            }
        }
        capture.finish();
        assert!(cache.lock().unwrap().entries.is_empty());
        for byte in format!("data: {{\"type\":{newline}data: \"message_stop\"}}{newline}{newline}")
            .as_bytes()
            .chunks(1)
        {
            capture.push(byte);
        }
        let cache = cache.lock().unwrap();
        assert_eq!(cache.entries.len(), 1);
        assert_eq!(
            cache.entries[0].message["content"][0],
            serde_json::json!({"type": "thinking", "thinking": "λ\ntext", "signature": "signed"})
        );
    }
}

#[test]
fn thinking_cache_and_capture_are_bounded() {
    use super::{
        MAX_CACHE_BYTES, MAX_CACHE_ENTRIES, MAX_CAPTURE_BYTES, Protocol, ResponseCapture,
        ThinkingCache,
    };
    use std::sync::{Arc, Mutex};
    let mut cache = ThinkingCache::default();
    for index in 0..=MAX_CACHE_ENTRIES {
        cache.remember(1, Protocol::Chat, index as u64, serde_json::json!({"role": "assistant", "content": index.to_string(), "reasoning_content": "original"}));
    }
    assert_eq!(cache.entries.len(), MAX_CACHE_ENTRIES);
    assert_eq!(cache.entries[0].context, 1);
    assert!(cache.bytes <= MAX_CACHE_BYTES);
    let cache = Arc::new(Mutex::new(ThinkingCache::default()));
    let mut capture = ResponseCapture::new(cache.clone(), 1, Protocol::Chat, 2);
    capture.push(&vec![b' '; MAX_CAPTURE_BYTES + 1]);
    assert!(capture.disabled);
    assert!(capture.pending.is_empty());
    capture.push(br#"{"choices":[{"message":{"role":"assistant","content":"answer","reasoning_content":"original"}}]}"#);
    capture.finish();
    assert!(cache.lock().unwrap().entries.is_empty());
}

#[tokio::test]
async fn proxy_streams_before_upstream_finishes() {
    let (release, released) = tokio::sync::oneshot::channel::<()>();
    let released = std::sync::Arc::new(std::sync::Mutex::new(Some(released)));
    let upstream = serve(Router::new().fallback(move || {
        let released = released.lock().unwrap().take().unwrap();
        async move {
            let first = futures_util::stream::once(async {
                Ok::<_, std::io::Error>(axum::body::Bytes::from_static(b"data: first\n\n"))
            });
            Response::builder()
                .header(header::CONTENT_TYPE, "text/event-stream")
                .body(Body::from_stream(futures_util::StreamExt::chain(
                    first,
                    futures_util::stream::once(async move {
                        released.await.unwrap();
                        Ok::<_, std::io::Error>(axum::body::Bytes::from_static(b"data: [DONE]\n\n"))
                    }),
                )))
                .unwrap()
        }
    }))
    .await;
    let proxy = serve(crate::app(Client::new(), format!("http://{upstream}"))).await;
    let mut response = Client::new()
        .post(format!("http://{proxy}/v1/chat/completions"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(r#"{"model":"test","messages":[],"stream":true}"#)
        .send()
        .await
        .unwrap();
    let first = tokio::time::timeout(std::time::Duration::from_secs(2), response.chunk())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(first.as_ref(), b"data: first\n\n");
    release.send(()).unwrap();
    assert_eq!(response.text().await.unwrap(), "data: [DONE]\n\n");
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

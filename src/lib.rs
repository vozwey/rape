use std::{
    collections::{
        BTreeMap, VecDeque,
        hash_map::{DefaultHasher, RandomState},
    },
    hash::{BuildHasher, Hash, Hasher},
    sync::{Arc, Mutex},
};

use axum::{
    body::Body,
    http::{HeaderMap, header::HeaderName},
    response::Response,
};
use futures_util::StreamExt;
use serde_json::{Value, json};

/// agentrouter.org's WAF rejects requests whose User-Agent is not an allowed
/// agent (curl, bare reqwest, etc.). Always spoof an allowed client upstream,
/// since callers send their own UA (e.g. curl) that the WAF would block.
const ALLOWED_CLIENT_USER_AGENT: &str = "opencode/0.11.0";

pub fn app(client: reqwest::Client, target: String) -> axum::Router {
    let history = Arc::new(Mutex::new(ThinkingCache::default()));
    let scope_hasher = RandomState::new();
    axum::Router::new().fallback(move |request| {
        proxy(
            client.clone(),
            target.clone(),
            history.clone(),
            scope_hasher.clone(),
            request,
        )
    })
}

async fn proxy(
    client: reqwest::Client,
    target: String,
    history: Arc<Mutex<ThinkingCache>>,
    scope_hasher: RandomState,
    request: axum::extract::Request,
) -> Response {
    let (parts, body) = request.into_parts();
    let protocol = Protocol::from_path(parts.uri.path());
    let capture_thinking = matches!(protocol, Some(Protocol::Messages | Protocol::Chat));
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
            && (!capture_thinking || name != axum::http::header::ACCEPT_ENCODING)
            && !is_hop_by_hop(name)
        {
            builder = builder.header(name, value);
        }
    }

    builder = builder.header(axum::http::header::USER_AGENT, ALLOWED_CLIENT_USER_AGENT);
    if capture_thinking {
        // Capture the upstream JSON/SSE without adding compression dependencies.
        builder = builder.header(axum::http::header::ACCEPT_ENCODING, "identity");
    }

    let body_bytes = match axum::body::to_bytes(body, usize::MAX).await {
        Ok(bytes) => bytes,
        Err(error) => {
            let mut response = Response::new(Body::from(error.to_string()));
            *response.status_mut() = axum::http::StatusCode::BAD_REQUEST;
            return response;
        }
    };
    let mut capture = None;
    let body_bytes = if let Some(protocol) = protocol
        && let Ok(mut value) = serde_json::from_slice::<Value>(&body_bytes)
    {
        let scope = request_scope(&parts.headers, &value, &scope_hasher);
        let mut changed = sanitize_tool_schemas(&mut value);
        if capture_thinking
            && let Some(messages) = value.get_mut("messages").and_then(Value::as_array_mut)
        {
            let mut context = DefaultHasher::new();
            {
                let cache = history.lock().expect("thinking cache lock");
                for message in messages {
                    let visible = visible_message(message);
                    changed |= cache.restore(scope, protocol, context.finish(), &visible, message);
                    visible.hash(&mut context);
                }
            }
            capture = Some(ResponseCapture::new(
                history,
                scope,
                protocol,
                context.finish(),
            ));
        }
        if changed {
            serde_json::to_vec(&value).expect("Value round-trips through JSON")
        } else {
            body_bytes.to_vec()
        }
    } else {
        body_bytes.to_vec()
    };

    let body_bytes = axum::body::Bytes::from(body_bytes);
    let retry = if capture_thinking {
        builder.try_clone()
    } else {
        None
    };
    let mut upstream = match builder.body(body_bytes.clone()).send().await {
        Ok(response) => response,
        Err(error) => {
            let mut response = Response::new(Body::from(error.to_string()));
            *response.status_mut() = axum::http::StatusCode::BAD_GATEWAY;
            return response;
        }
    };

    if upstream.status() == axum::http::StatusCode::BAD_REQUEST
        && let Some(retry) = retry
    {
        let headers = upstream.headers().clone();
        let error_bytes = match upstream.bytes().await {
            Ok(bytes) => bytes,
            Err(error) => {
                let mut response = Response::new(Body::from(error.to_string()));
                *response.status_mut() = axum::http::StatusCode::BAD_GATEWAY;
                return response;
            }
        };
        let missing_thinking = serde_json::from_slice::<Value>(&error_bytes)
            .ok()
            .and_then(|body| {
                body.pointer("/error/message")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            })
            .is_some_and(|message| {
                (message.contains("content[].thinking") || message.contains("reasoning_content"))
                    && message.contains("must be passed back to the API")
            });
        if missing_thinking
            && let Ok(mut body) = serde_json::from_slice::<Value>(&body_bytes)
            && let Some(object) = body.as_object_mut()
            && object
                .get("thinking")
                .and_then(|value| value.get("type"))
                .and_then(Value::as_str)
                != Some("disabled")
        {
            // A restarted proxy cannot recover signed thinking it has never seen.
            object.insert("thinking".to_owned(), json!({"type": "disabled"}));
            upstream = match retry
                .body(serde_json::to_vec(&body).expect("Value round-trips through JSON"))
                .send()
                .await
            {
                Ok(response) => response,
                Err(error) => {
                    let mut response = Response::new(Body::from(error.to_string()));
                    *response.status_mut() = axum::http::StatusCode::BAD_GATEWAY;
                    return response;
                }
            };
        } else {
            let mut response = Response::new(Body::from(error_bytes));
            *response.status_mut() = axum::http::StatusCode::BAD_REQUEST;
            for (name, value) in &headers {
                if !is_hop_by_hop(name) {
                    response.headers_mut().insert(name, value.clone());
                }
            }
            return response;
        }
    }
    let status = upstream.status();
    let headers = upstream.headers().clone();
    if !status.is_success() {
        capture = None;
    }
    if let Some(capture) = &mut capture {
        capture.expected_bytes = upstream.content_length();
        capture.sse = headers
            .get(axum::http::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.split(';').next() == Some("text/event-stream"));
    }
    let stream = upstream
        .bytes_stream()
        .map(Some)
        .chain(futures_util::stream::once(async { None }))
        .filter_map(move |chunk| {
            match &chunk {
                Some(Ok(bytes)) => {
                    if let Some(capture) = &mut capture {
                        capture.push(bytes);
                    }
                }
                Some(Err(_)) => capture = None,
                None => {
                    if let Some(capture) = &mut capture {
                        capture.finish();
                    }
                }
            }
            std::future::ready(chunk.map(|chunk| chunk.map_err(std::io::Error::other)))
        });
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

fn sanitize_tool_schemas(value: &mut Value) -> bool {
    let mut changed = false;
    for key in ["tools", "functions"] {
        if let Some(items) = value.get_mut(key).and_then(Value::as_array_mut) {
            for item in items {
                let definition = if item.get("function").is_some() {
                    &mut item["function"]
                } else {
                    item
                };
                for key in ["parameters", "input_schema"] {
                    if let Some(schema) = definition.get_mut(key) {
                        changed |= sanitize_schema(schema);
                    }
                }
            }
        }
    }
    changed
}

fn sanitize_schema(schema: &mut Value) -> bool {
    let Some(object) = schema.as_object_mut() else {
        return false;
    };
    let is_object = object.get("type").is_some_and(|kind| {
        kind == "object"
            || kind
                .as_array()
                .is_some_and(|types| types.iter().any(|kind| kind == "object"))
    }) || object.contains_key("properties");
    let mut changed = false;
    // Some relays decode an omitted required list to nil, then forward it as null.
    for (key, empty) in [("required", json!([])), ("properties", json!({}))] {
        if object.get(key) == Some(&Value::Null) || (is_object && !object.contains_key(key)) {
            object.insert(key.to_owned(), empty);
            changed = true;
        }
    }
    for key in [
        "properties",
        "patternProperties",
        "$defs",
        "definitions",
        "dependentSchemas",
        "dependencies",
    ] {
        if let Some(children) = object.get_mut(key).and_then(Value::as_object_mut) {
            for child in children.values_mut() {
                changed |= sanitize_schema(child);
            }
        }
    }
    for key in [
        "items",
        "additionalItems",
        "additionalProperties",
        "contains",
        "propertyNames",
        "not",
        "if",
        "then",
        "else",
        "unevaluatedItems",
        "unevaluatedProperties",
    ] {
        if let Some(child) = object.get_mut(key) {
            if let Some(children) = child.as_array_mut() {
                for child in children {
                    changed |= sanitize_schema(child);
                }
            } else {
                changed |= sanitize_schema(child);
            }
        }
    }
    for key in ["allOf", "anyOf", "oneOf", "prefixItems"] {
        if let Some(children) = object.get_mut(key).and_then(Value::as_array_mut) {
            for child in children {
                changed |= sanitize_schema(child);
            }
        }
    }
    changed
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Protocol {
    Messages,
    Chat,
    Responses,
}

impl Protocol {
    fn from_path(path: &str) -> Option<Self> {
        match path {
            "/messages" | "/v1/messages" => Some(Self::Messages),
            "/chat/completions" | "/v1/chat/completions" => Some(Self::Chat),
            "/responses" | "/v1/responses" => Some(Self::Responses),
            _ => None,
        }
    }
}

fn request_scope(headers: &HeaderMap, body: &Value, hasher: &RandomState) -> u64 {
    // Only a process-keyed fingerprint is retained, never the API credentials.
    hasher.hash_one((
        headers.get("authorization").map(|value| value.as_bytes()),
        headers.get("x-api-key").map(|value| value.as_bytes()),
        body.get("model"),
        body.get("system"),
        body.get("user"),
    ))
}

fn is_thinking(block: &Value) -> bool {
    matches!(
        block.get("type").and_then(Value::as_str),
        Some("thinking" | "redacted_thinking")
    )
}

fn visible_message(message: &Value) -> Value {
    if message.get("role").and_then(Value::as_str) != Some("assistant") {
        return message.clone();
    }
    let mut visible = json!({"role": "assistant", "content": message.get("content")});
    if let Some(content) = visible["content"].as_array_mut() {
        content.retain(|block| !is_thinking(block));
        if content.len() == 1 && content[0]["type"] == "text" {
            visible["content"] = content[0]["text"].clone();
        } else if content.is_empty() {
            visible["content"] = Value::Null;
        }
    }
    if visible["content"] == "" {
        visible["content"] = Value::Null;
    }
    for key in ["tool_calls", "function_call"] {
        if let Some(value) = message.get(key).filter(|value| !value.is_null()) {
            visible[key] = value.clone();
        }
    }
    if let Some(tools) = visible.get_mut("tool_calls").and_then(Value::as_array_mut) {
        for tool in tools {
            if let Some(arguments) = tool.pointer_mut("/function/arguments")
                && let Some(text) = arguments.as_str()
                && let Ok(parsed) = serde_json::from_str::<Value>(text)
            {
                *arguments = parsed;
            }
        }
    }
    visible
}

const REASONING_FIELDS: [&str; 3] = ["reasoning_content", "reasoning", "reasoning_details"];
const MAX_CAPTURE_BYTES: usize = 8 * 1024 * 1024;
const MAX_CACHE_BYTES: usize = 64 * 1024 * 1024;
const MAX_CACHE_ENTRIES: usize = 256;

struct ThinkingEntry {
    scope: u64,
    protocol: Protocol,
    context: u64,
    visible: Value,
    message: Value,
    bytes: usize,
}

#[derive(Default)]
struct ThinkingCache {
    entries: VecDeque<ThinkingEntry>,
    bytes: usize,
}

impl ThinkingCache {
    fn remember(&mut self, scope: u64, protocol: Protocol, context: u64, message: Value) {
        if message.get("role").and_then(Value::as_str) != Some("assistant")
            || (!message
                .get("content")
                .and_then(Value::as_array)
                .is_some_and(|blocks| blocks.iter().any(is_thinking))
                && !REASONING_FIELDS
                    .iter()
                    .any(|key| message.get(key).is_some_and(|value| !value.is_null())))
        {
            return;
        }
        let visible = visible_message(&message);
        let bytes = message.to_string().len() + visible.to_string().len();
        if bytes > MAX_CAPTURE_BYTES {
            return;
        }
        while self.entries.len() >= MAX_CACHE_ENTRIES || self.bytes + bytes > MAX_CACHE_BYTES {
            if let Some(entry) = self.entries.pop_front() {
                self.bytes -= entry.bytes;
            }
        }
        self.bytes += bytes;
        self.entries.push_back(ThinkingEntry {
            scope,
            protocol,
            context,
            visible,
            message,
            bytes,
        });
    }

    fn restore(
        &self,
        scope: u64,
        protocol: Protocol,
        context: u64,
        visible: &Value,
        message: &mut Value,
    ) -> bool {
        let Some(entry) = self.entries.iter().rev().find(|entry| {
            entry.scope == scope
                && entry.protocol == protocol
                && entry.context == context
                && entry.visible == *visible
        }) else {
            return false;
        };
        let mut changed = false;
        if let Some(original) = entry.message.get("content").and_then(Value::as_array)
            && original.iter().any(is_thinking)
        {
            let current = message.get("content").and_then(Value::as_array);
            if current != Some(original)
                && current.is_none_or(|blocks| {
                    blocks
                        .iter()
                        .filter(|block| is_thinking(block))
                        .all(|block| {
                            original.iter().any(|saved| {
                                block == saved
                                    || (block["type"] == "thinking"
                                        && block["thinking"] == saved["thinking"]
                                        && block.get("signature").is_none_or(|signature| {
                                            signature.is_null() || signature == ""
                                        }))
                            })
                        })
                })
            {
                message["content"] = Value::Array(original.clone());
                changed = true;
            }
        }
        for key in REASONING_FIELDS {
            if let Some(original) = entry.message.get(key).filter(|value| !value.is_null())
                && message
                    .get(key)
                    .is_none_or(|value| value.is_null() || value == "")
            {
                message[key] = original.clone();
                changed = true;
            }
        }
        changed
    }
}

struct ResponseCapture {
    cache: Arc<Mutex<ThinkingCache>>,
    scope: u64,
    protocol: Protocol,
    context: u64,
    sse: bool,
    disabled: bool,
    bytes: usize,
    expected_bytes: Option<u64>,
    carriage_return: bool,
    pending: Vec<u8>,
    data: Vec<u8>,
    blocks: BTreeMap<u64, Value>,
    inputs: BTreeMap<u64, String>,
    choices: BTreeMap<u64, Value>,
    tools: BTreeMap<(u64, u64), Value>,
}

impl ResponseCapture {
    fn new(cache: Arc<Mutex<ThinkingCache>>, scope: u64, protocol: Protocol, context: u64) -> Self {
        Self {
            cache,
            scope,
            protocol,
            context,
            sse: false,
            disabled: false,
            bytes: 0,
            expected_bytes: None,
            carriage_return: false,
            pending: Vec::new(),
            data: Vec::new(),
            blocks: BTreeMap::new(),
            inputs: BTreeMap::new(),
            choices: BTreeMap::new(),
            tools: BTreeMap::new(),
        }
    }

    fn remember(&self, message: Value) {
        self.cache.lock().expect("thinking cache lock").remember(
            self.scope,
            self.protocol,
            self.context,
            message,
        );
    }

    fn push(&mut self, bytes: &[u8]) {
        if self.disabled {
            return;
        }
        self.bytes += bytes.len();
        if self.bytes > MAX_CAPTURE_BYTES {
            self.disabled = true;
            self.pending.clear();
            self.data.clear();
            self.blocks.clear();
            self.inputs.clear();
            self.choices.clear();
            self.tools.clear();
            return;
        }
        if !self.sse {
            self.pending.extend_from_slice(bytes);
            if self.expected_bytes == Some(self.bytes as u64) {
                self.finish();
            }
            return;
        }
        for byte in bytes {
            if *byte == b'\n' && self.carriage_return {
                self.carriage_return = false;
                continue;
            }
            self.carriage_return = *byte == b'\r';
            if !matches!(*byte, b'\n' | b'\r') {
                self.pending.push(*byte);
                continue;
            }
            let line = std::mem::take(&mut self.pending);
            if line.is_empty() {
                let data = std::mem::take(&mut self.data);
                if data == b"[DONE]\n" {
                    for index in self.choices.keys().copied().collect::<Vec<_>>() {
                        self.finish_choice(index);
                    }
                } else if let Ok(event) = serde_json::from_slice::<Value>(&data) {
                    self.event(event);
                }
            } else if let Some(data) = line.strip_prefix(b"data:") {
                self.data
                    .extend_from_slice(data.strip_prefix(b" ").unwrap_or(data));
                self.data.push(b'\n');
            }
        }
    }

    fn event(&mut self, event: Value) {
        if self.disabled {
            return;
        }
        match self.protocol {
            Protocol::Messages => {
                let index = event.get("index").and_then(Value::as_u64).unwrap_or(0);
                match event.get("type").and_then(Value::as_str) {
                    Some("message_start") => {
                        if let Some(blocks) =
                            event.pointer("/message/content").and_then(Value::as_array)
                        {
                            self.blocks.extend(
                                blocks
                                    .iter()
                                    .cloned()
                                    .enumerate()
                                    .map(|(index, block)| (index as u64, block)),
                            );
                        }
                    }
                    Some("content_block_start") => {
                        if let Some(block) =
                            event.get("content_block").filter(|block| block.is_object())
                        {
                            self.blocks.insert(index, block.clone());
                        }
                    }
                    Some("content_block_delta") => {
                        if let Some(block) = self.blocks.get_mut(&index) {
                            let delta = &event["delta"];
                            for key in ["thinking", "signature", "text"] {
                                append_field(block, key, &delta[key]);
                            }
                            if let Some(part) = delta.get("partial_json").and_then(Value::as_str) {
                                self.inputs.entry(index).or_default().push_str(part);
                            }
                        }
                    }
                    Some("content_block_stop") => {
                        if let Some(input) = self.inputs.remove(&index)
                            && let Some(block) = self.blocks.get_mut(&index)
                        {
                            match serde_json::from_str::<Value>(&input) {
                                Ok(input) => block["input"] = input,
                                Err(_) => self.disabled = true,
                            }
                        }
                    }
                    Some("message_stop") if self.inputs.is_empty() => {
                        let content: Vec<_> =
                            std::mem::take(&mut self.blocks).into_values().collect();
                        self.remember(json!({"role": "assistant", "content": content}));
                    }
                    Some("error") => self.disabled = true,
                    _ => {}
                }
            }
            Protocol::Chat => {
                if let Some(choices) = event.get("choices").and_then(Value::as_array) {
                    for choice in choices {
                        let index = choice.get("index").and_then(Value::as_u64).unwrap_or(0);
                        let message = self
                            .choices
                            .entry(index)
                            .or_insert_with(|| json!({"role": "assistant", "content": null}));
                        let delta = &choice["delta"];
                        for key in ["content", "reasoning_content", "reasoning"] {
                            append_field(message, key, &delta[key]);
                        }
                        for key in ["content", "reasoning_details"] {
                            if let Some(parts) = delta.get(key).and_then(Value::as_array) {
                                if !message[key].is_array() {
                                    message[key] = json!([]);
                                }
                                message[key]
                                    .as_array_mut()
                                    .expect("array assigned above")
                                    .extend(parts.iter().cloned());
                            }
                        }
                        if let Some(tools) = delta.get("tool_calls").and_then(Value::as_array) {
                            for tool in tools {
                                let tool_index =
                                    tool.get("index").and_then(Value::as_u64).unwrap_or(0);
                                let entry = self
                                    .tools
                                    .entry((index, tool_index))
                                    .or_insert_with(|| json!({"type": "function", "function": {}}));
                                append_field(entry, "id", &tool["id"]);
                                for key in ["name", "arguments"] {
                                    append_field(
                                        &mut entry["function"],
                                        key,
                                        &tool["function"][key],
                                    );
                                }
                            }
                        }
                        if choice
                            .get("finish_reason")
                            .is_some_and(|value| !value.is_null())
                        {
                            self.finish_choice(index);
                        }
                    }
                }
            }
            Protocol::Responses => {}
        }
    }

    fn finish_choice(&mut self, index: u64) {
        if let Some(mut message) = self.choices.remove(&index) {
            let tools: Vec<_> = self
                .tools
                .iter()
                .filter(|((choice, _), _)| *choice == index)
                .map(|(_, tool)| tool.clone())
                .collect();
            self.tools.retain(|(choice, _), _| *choice != index);
            if !tools.is_empty() {
                message["tool_calls"] = Value::Array(tools);
            }
            self.remember(message);
        }
    }

    fn finish(&mut self) {
        if self.disabled || self.sse {
            return;
        }
        let Ok(value) = serde_json::from_slice::<Value>(&std::mem::take(&mut self.pending)) else {
            return;
        };
        match self.protocol {
            Protocol::Messages
                if value.get("role").and_then(Value::as_str) == Some("assistant") =>
            {
                self.remember(value)
            }
            Protocol::Chat => {
                if let Some(choices) = value.get("choices").and_then(Value::as_array) {
                    for choice in choices {
                        if let Some(message) = choice.get("message") {
                            self.remember(message.clone());
                        }
                    }
                }
            }
            _ => {}
        }
    }
}

fn append_field(value: &mut Value, key: &str, part: &Value) {
    if let Some(part) = part.as_str()
        && let Some(object) = value.as_object_mut()
    {
        let field = object.entry(key).or_insert(Value::Null);
        if field.is_null() {
            *field = Value::String(String::new());
        }
        if let Value::String(field) = field {
            field.push_str(part);
        }
    }
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
        let upstream = serve(Router::new().fallback(move |headers: axum::http::HeaderMap, axum::Json(body): axum::Json<serde_json::Value>| {
            let response_body = response_body.clone();
            let assistant = assistant.clone();
            async move {
                assert_eq!(headers[header::ACCEPT_ENCODING], "identity");
                if body["messages"].as_array().unwrap().len() == 1 {
                    let chunks: Vec<_> = response_body.as_bytes().chunks(3)
                        .map(|chunk| Ok::<_, std::io::Error>(axum::body::Bytes::copy_from_slice(chunk)))
                        .collect();
                    let mut response = Response::builder().header(header::CONTENT_TYPE, content_type);
                    if content_type == "application/json" {
                        response = response.header(header::CONTENT_LENGTH, response_body.len());
                    }
                    response.body(Body::from_stream(futures_util::stream::iter(chunks))).unwrap()
                } else if body["messages"][1] == assistant {
                    Response::new(Body::from("accepted"))
                } else {
                    Response::builder().status(StatusCode::BAD_REQUEST).body(Body::from(
                        "The `content[].thinking` in the thinking mode must be passed back to the API."
                    )).unwrap()
                }
            }
        })).await;
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
        let assistant =
            serde_json::json!({"role": "assistant", "content": [thinking, redacted, tool]});
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
            for byte in
                format!("data: {{\"type\":{newline}data: \"message_stop\"}}{newline}{newline}")
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
                            Ok::<_, std::io::Error>(axum::body::Bytes::from_static(
                                b"data: [DONE]\n\n",
                            ))
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
}

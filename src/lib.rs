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
#[path = "../tests/unit/lib.rs"]
mod tests;

//! WebSocket client for real-time IOTA event subscriptions.
//!
//! Provides persistent WebSocket connections to IOTA full nodes for:
//! - Real-time transaction monitoring (incoming/outgoing)
//! - Event subscriptions with filters
//! - Balance change notifications
//!
//! Native from day one — no polling, no HTTP fallback for streaming.

#[cfg(feature = "wallet")]
use anyhow::{Context, Result};
#[cfg(feature = "wallet")]
use futures_util::{SinkExt, StreamExt};
#[cfg(feature = "wallet")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "wallet")]
use tokio_tungstenite::{connect_async, tungstenite::Message};

/// WebSocket endpoints for IOTA networks.
pub const TESTNET_WS: &str = "wss://api.testnet.iota.cafe:443";
#[allow(dead_code)]
pub const DEVNET_WS: &str = "wss://api.devnet.iota.cafe:443";

/// Event filter types for subscriptions.
#[cfg(feature = "wallet")]
#[derive(Debug, Clone, Serialize)]
#[serde(untagged)]
pub enum EventFilter {
    /// Filter by sender address.
    Sender {
        #[serde(rename = "Sender")]
        sender: String,
    },
    /// Filter by recipient address.
    Recipient {
        #[serde(rename = "Recipient")]
        recipient: String,
    },
    /// Filter by transaction digest.
    Transaction {
        #[serde(rename = "Transaction")]
        transaction: String,
    },
    /// All events (no filter).
    All(Vec<serde_json::Value>),
}

/// A parsed on-chain event from the WebSocket stream.
#[cfg(feature = "wallet")]
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IotaEvent {
    /// Event ID containing tx digest and sequence.
    pub id: serde_json::Value,
    /// Package that emitted the event.
    pub package_id: Option<String>,
    /// Module that performed the transaction.
    pub transaction_module: Option<String>,
    /// Address that triggered the event.
    pub sender: Option<String>,
    /// Event type.
    #[serde(rename = "type")]
    pub event_type: Option<String>,
    /// Parsed JSON payload.
    pub parsed_json: Option<serde_json::Value>,
    /// Timestamp in milliseconds.
    pub timestamp_ms: Option<String>,
}

/// WebSocket JSON-RPC subscription request.
#[cfg(feature = "wallet")]
#[derive(Serialize)]
struct WsSubscribeRequest {
    jsonrpc: String,
    id: u64,
    method: String,
    params: Vec<serde_json::Value>,
}

/// WebSocket JSON-RPC notification (event delivery).
#[cfg(feature = "wallet")]
#[derive(Deserialize, Debug)]
struct WsNotification {
    #[allow(dead_code)]
    jsonrpc: String,
    method: Option<String>,
    params: Option<WsNotificationParams>,
}

#[cfg(feature = "wallet")]
#[derive(Deserialize, Debug)]
struct WsNotificationParams {
    #[allow(dead_code)]
    subscription: u64,
    result: serde_json::Value,
}

/// IOTA WebSocket client for real-time event streaming.
#[cfg(feature = "wallet")]
pub struct IotaWsClient {
    ws_url: String,
}

#[cfg(feature = "wallet")]
impl IotaWsClient {
    /// Create a new WebSocket client for testnet.
    pub fn testnet() -> Self {
        Self {
            ws_url: TESTNET_WS.to_string(),
        }
    }

    /// Create a new WebSocket client for devnet.
    #[allow(dead_code)]
    pub fn devnet() -> Self {
        Self {
            ws_url: DEVNET_WS.to_string(),
        }
    }

    /// Create a WebSocket client for a custom endpoint.
    #[allow(dead_code)]
    pub fn custom(ws_url: &str) -> Self {
        Self {
            ws_url: ws_url.to_string(),
        }
    }

    /// Subscribe to events matching the given filter.
    ///
    /// Calls `callback` for each event received. The callback returns
    /// `true` to continue listening, `false` to stop.
    ///
    /// This is the core streaming primitive — everything else builds on it.
    pub async fn subscribe_events<F>(&self, filter: EventFilter, mut callback: F) -> Result<()>
    where
        F: FnMut(IotaEvent) -> bool,
    {
        let (mut ws_stream, _) = connect_async(&self.ws_url)
            .await
            .context("Failed to connect to IOTA WebSocket")?;

        // Send subscription request
        let subscribe_msg = WsSubscribeRequest {
            jsonrpc: "2.0".to_string(),
            id: 1,
            method: "iota_subscribeEvent".to_string(),
            params: vec![serde_json::to_value(&filter)?],
        };

        let msg_text = serde_json::to_string(&subscribe_msg)?;
        ws_stream
            .send(Message::Text(msg_text.into()))
            .await
            .context("Failed to send subscription request")?;

        // Read subscription confirmation
        if let Some(Ok(msg)) = ws_stream.next().await {
            let text = msg.to_text().unwrap_or("");
            // Check for error in subscription response
            if text.contains("\"error\"") {
                anyhow::bail!("Subscription failed: {}", text);
            }
        }

        // Stream events
        while let Some(msg_result) = ws_stream.next().await {
            match msg_result {
                Ok(Message::Text(text)) => {
                    if let Ok(notification) = serde_json::from_str::<WsNotification>(&text) {
                        if notification.method.as_deref() == Some("iota_subscribeEvent") {
                            if let Some(params) = notification.params {
                                if let Ok(event) =
                                    serde_json::from_value::<IotaEvent>(params.result)
                                {
                                    if !callback(event) {
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
                Ok(Message::Ping(data)) => {
                    let _ = ws_stream.send(Message::Pong(data)).await;
                }
                Ok(Message::Close(_)) => break,
                Err(e) => {
                    anyhow::bail!("WebSocket error: {}", e);
                }
                _ => {}
            }
        }

        // Clean close
        let _ = ws_stream.close(None).await;
        Ok(())
    }

    /// Watch all transactions involving a specific address (sent or received).
    ///
    /// This opens TWO subscriptions — one for sender, one for recipient —
    /// and merges them into a single stream.
    pub async fn watch_address<F>(&self, address: &str, mut callback: F) -> Result<()>
    where
        F: FnMut(IotaEvent, &str) -> bool + Send,
    {
        let (mut ws_stream, _) = connect_async(&self.ws_url)
            .await
            .context("Failed to connect to IOTA WebSocket")?;

        // Subscribe to events where this address is the sender
        let sender_sub = WsSubscribeRequest {
            jsonrpc: "2.0".to_string(),
            id: 1,
            method: "iota_subscribeEvent".to_string(),
            params: vec![serde_json::json!({"Sender": address})],
        };
        ws_stream
            .send(Message::Text(serde_json::to_string(&sender_sub)?.into()))
            .await?;

        // Read confirmation
        let _ = ws_stream.next().await;

        // Subscribe to events where this address is the recipient
        let recipient_sub = WsSubscribeRequest {
            jsonrpc: "2.0".to_string(),
            id: 2,
            method: "iota_subscribeEvent".to_string(),
            params: vec![serde_json::json!({"Recipient": address})],
        };
        ws_stream
            .send(Message::Text(serde_json::to_string(&recipient_sub)?.into()))
            .await?;

        // Read confirmation
        let _ = ws_stream.next().await;

        // Stream merged events
        while let Some(msg_result) = ws_stream.next().await {
            match msg_result {
                Ok(Message::Text(text)) => {
                    if let Ok(notification) = serde_json::from_str::<WsNotification>(&text) {
                        if notification.method.as_deref() == Some("iota_subscribeEvent") {
                            if let Some(params) = notification.params {
                                let direction = if params.subscription == 1 {
                                    "outgoing"
                                } else {
                                    "incoming"
                                };
                                if let Ok(event) =
                                    serde_json::from_value::<IotaEvent>(params.result)
                                {
                                    if !callback(event, direction) {
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
                Ok(Message::Ping(data)) => {
                    let _ = ws_stream.send(Message::Pong(data)).await;
                }
                Ok(Message::Close(_)) => break,
                Err(e) => {
                    anyhow::bail!("WebSocket error: {}", e);
                }
                _ => {}
            }
        }

        let _ = ws_stream.close(None).await;
        Ok(())
    }

    /// Query historical events (HTTP, not WebSocket — but included here
    /// for API completeness since it's the read-side complement to subscribe).
    pub async fn query_events(
        &self,
        filter: &EventFilter,
        limit: u32,
    ) -> Result<Vec<serde_json::Value>> {
        // Use HTTP for historical queries (WebSocket is for streaming)
        let http_url = self
            .ws_url
            .replace("wss://", "https://")
            .replace("ws://", "http://");
        let client = reqwest::Client::new();

        let req = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "iotax_queryEvents",
            "params": [filter, null, limit, false]
        });

        let resp = client
            .post(&http_url)
            .json(&req)
            .send()
            .await
            .context("Failed to query events")?;
        let body: serde_json::Value = resp
            .json()
            .await
            .context("Failed to parse events response")?;

        if let Some(err) = body.get("error") {
            anyhow::bail!("Query events error: {}", err);
        }

        let data = body
            .get("result")
            .and_then(|r| r.get("data"))
            .and_then(|d| d.as_array())
            .cloned()
            .unwrap_or_default();

        Ok(data)
    }
}

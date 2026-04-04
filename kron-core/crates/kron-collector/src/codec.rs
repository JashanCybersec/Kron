//! JSON-over-gRPC codec for agent→collector communication (server side).
//!
//! Mirror of `kron-agent`'s `transport::codec` module. Uses `serde_json` to
//! serialize/deserialize gRPC messages without requiring `protoc` or generated
//! code. The agent and collector must use identical codec configuration.
//!
//! # Wire format
//!
//! ```text
//! [1 byte:  compressed flag (always 0)]
//! [4 bytes: message length, big-endian u32]
//! [N bytes: UTF-8 JSON body]
//! ```

use std::marker::PhantomData;

use bytes::{Buf, BufMut};
use serde::{de::DeserializeOwned, Serialize};
use tonic::codec::{Codec, DecodeBuf, Decoder, EncodeBuf, Encoder};
use tonic::Status;

/// JSON-based gRPC codec parameterised by request and response types.
///
/// - `Req` — outbound message type (server response). Must be `Serialize`.
/// - `Res` — inbound message type (client request). Must be `DeserializeOwned`.
#[derive(Debug, Clone, Default)]
pub struct JsonCodec<Req, Res> {
    _phantom: PhantomData<(Req, Res)>,
}

impl<Req, Res> JsonCodec<Req, Res> {
    /// Creates a new `JsonCodec`.
    #[must_use]
    pub fn new() -> Self {
        Self {
            _phantom: PhantomData,
        }
    }
}

impl<Req, Res> Codec for JsonCodec<Req, Res>
where
    Req: Serialize + Send + 'static,
    Res: DeserializeOwned + Send + 'static,
{
    type Encode = Req;
    type Decode = Res;
    type Encoder = JsonEncoder<Req>;
    type Decoder = JsonDecoder<Res>;

    fn encoder(&mut self) -> Self::Encoder {
        JsonEncoder(PhantomData)
    }

    fn decoder(&mut self) -> Self::Decoder {
        JsonDecoder(PhantomData)
    }
}

// ─── Encoder ─────────────────────────────────────────────────────────────────

/// JSON encoder for gRPC response messages.
#[derive(Debug, Clone)]
pub struct JsonEncoder<T>(PhantomData<T>);

impl<T: Serialize> Encoder for JsonEncoder<T> {
    type Item = T;
    type Error = Status;

    fn encode(&mut self, item: Self::Item, dst: &mut EncodeBuf<'_>) -> Result<(), Self::Error> {
        serde_json::to_writer(dst.writer(), &item)
            .map_err(|e| Status::internal(format!("JSON encode error: {e}")))?;
        Ok(())
    }
}

// ─── Decoder ─────────────────────────────────────────────────────────────────

/// JSON decoder for gRPC request messages.
#[derive(Debug, Clone)]
pub struct JsonDecoder<T>(PhantomData<T>);

impl<T: DeserializeOwned> Decoder for JsonDecoder<T> {
    type Item = T;
    type Error = Status;

    fn decode(&mut self, src: &mut DecodeBuf<'_>) -> Result<Option<Self::Item>, Self::Error> {
        if !src.has_remaining() {
            return Ok(None);
        }
        let body = src.chunk();
        let item: T = serde_json::from_slice(body)
            .map_err(|e| Status::internal(format!("JSON decode error: {e}")))?;
        let len = body.len();
        src.advance(len);
        Ok(Some(item))
    }
}

// ─── Convenience type aliases ─────────────────────────────────────────────────

/// Codec for the `Register` RPC: server sends `RegisterResponse`, receives `RegisterRequest`.
pub type RegisterCodec = JsonCodec<kron_types::RegisterResponse, kron_types::RegisterRequest>;

/// Codec for the `SendEvents` RPC: server sends `EventAck`, receives `EventBatch`.
pub type EventBatchCodec = JsonCodec<kron_types::EventAck, kron_types::EventBatch>;

/// Codec for the `Heartbeat` RPC: server sends `HeartbeatResponse`, receives `HeartbeatRequest`.
pub type HeartbeatCodec = JsonCodec<kron_types::HeartbeatResponse, kron_types::HeartbeatRequest>;

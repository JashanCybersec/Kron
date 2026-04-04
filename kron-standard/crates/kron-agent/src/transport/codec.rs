//! JSON-over-gRPC codec for agent→collector communication.
//!
//! Implements [`tonic::codec::Codec`] using `serde_json` for serialization.
//! This avoids `protoc` and generated code while remaining compatible with
//! any gRPC framework that supports custom codecs.
//!
//! # Wire format
//!
//! Each gRPC message is a length-prefixed `application/grpc+json` frame:
//! ```text
//! [1 byte: compressed flag (always 0)]
//! [4 bytes: message length, big-endian u32]
//! [N bytes: UTF-8 JSON body]
//! ```
//!
//! This follows the gRPC framing spec with `Content-Type: application/grpc+json`.

use std::marker::PhantomData;

use bytes::{Buf, BufMut};
use serde::{de::DeserializeOwned, Serialize};
use tonic::codec::{Codec, DecodeBuf, Decoder, EncodeBuf, Encoder};
use tonic::Status;

/// JSON-based gRPC codec.
///
/// Type parameters:
/// - `Req`: the request message type (must be `Serialize`)
/// - `Res`: the response message type (must be `DeserializeOwned`)
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

/// JSON encoder for gRPC messages.
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

/// JSON decoder for gRPC responses.
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

/// Convenience alias for the codec used on outbound batches.
pub type EventBatchCodec = JsonCodec<kron_types::EventBatch, kron_types::EventAck>;

/// Convenience alias for the codec used on heartbeat RPCs.
pub type HeartbeatCodec = JsonCodec<kron_types::HeartbeatRequest, kron_types::HeartbeatResponse>;

/// Convenience alias for the codec used on registration RPCs.
pub type RegisterCodec = JsonCodec<kron_types::RegisterRequest, kron_types::RegisterResponse>;

/// The `Content-Type` header value required by gRPC for JSON payloads.
#[allow(dead_code)]
pub const GRPC_JSON_CONTENT_TYPE: &str = "application/grpc+json";

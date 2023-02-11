// Copyright 2017-2020 Parity Technologies (UK) Ltd.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.

//! Future that drives a QUIC connection until is has performed its TLS handshake.

use crate::{Connection, Error};

use futures::{prelude::*, future::Either};
use futures_timer::Delay;
use libp2p_core::PeerId;
use std::{
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

/// A QUIC connection currently being negotiated.
#[derive(Debug)]
pub struct Connecting {
    connecting: futures::future::Select<quinn::Connecting, Delay>,
    //timeout: Delay,
}

impl Connecting {
    pub(crate) fn new(connection: quinn::Connecting, timeout: Duration) -> Self {
        Connecting {
            connecting: futures::future::select(connection, Delay::new(timeout)),
            //timeout: Delay::new(timeout),
        }
    }
}

impl Connecting {
    /// Returns the address of the node we're connected to.
    /// Panics if the connection is still handshaking.
    fn remote_peer_id(connection: &quinn::Connection) -> PeerId {
        //debug_assert!(!connection.handshake_data().is_some());
        let identity = connection
            .peer_identity()
            .expect("connection got identity because it passed TLS handshake; qed");
        let certificates: Box<Vec<rustls::Certificate>> =
            identity.downcast().expect("we rely on rustls feature; qed");
        let end_entity = certificates
            .get(0)
            .expect("there should be exactly one certificate; qed");
        let p2p_cert = libp2p_tls::certificate::parse(end_entity)
            .expect("the certificate was validated during TLS handshake; qed");
        p2p_cert.peer_id()
    }
}

impl Future for Connecting {
    type Output = Result<(PeerId, Connection), Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let connecting = Pin::new(&mut self.get_mut().connecting);

        let connection = match futures::ready!(connecting.poll(cx)) {
            Either::Right(_) => return Poll::Ready(Err(Error::HandshakeTimedOut)),
            Either::Left((connection, _)) => connection.map_err(crate::ConnectionError)?,
        };

        let peer_id = Self::remote_peer_id(&connection);
        let connection_c = connection.clone();
        let incoming = Box::pin(async move { connection_c.accept_bi().await });
        let connection_c = connection.clone();
        let outgoing = Box::pin(async move { connection_c.open_bi().await });
        let muxer = Connection {
            connection,
            incoming,
            outgoing,
        };
        Poll::Ready(Ok((peer_id, muxer)))
    }
}

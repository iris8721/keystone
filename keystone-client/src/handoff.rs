//! Delivering a [`HandoffToken`] to a child process over its stdin. The
//! child reads it with [`HandoffToken::read_from`] on stdin and redeems it
//! through [`crate::PendingSession::from_handoff`].

use std::io;
use std::process::{Child, Command, Stdio};

use keystone_core::HandoffToken;

/// Spawn `command` with a piped stdin, write `token` as one line, and close
/// stdin. If the token cannot be written the child is killed and reaped
/// before the error is returned.
pub fn spawn_with_handoff(command: &mut Command, token: &HandoffToken) -> io::Result<Child> {
    let mut child = command.stdin(Stdio::piped()).spawn()?;
    let written = match child.stdin.take() {
        // Dropping the pipe closes the child's stdin.
        Some(mut stdin) => token.write_to(&mut stdin),
        None => Err(io::Error::other("child stdin was not piped")),
    };
    if let Err(e) = written {
        let _ = child.kill();
        let _ = child.wait();
        return Err(e);
    }
    Ok(child)
}

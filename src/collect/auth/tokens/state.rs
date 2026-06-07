/// Module containing the shared state for a service token.
use crate::collect::auth::tokens::entity::Token;

use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};

/// Shared state for a single service's authentication token.
/// Uses a `RwLock` for the token itself to allow concurrent reads,
/// and a `Mutex` to synchronize refresh operations and prevent the thundering herd.
pub struct TokenState {
    pub token: RwLock<Token>,
    pub refresh_lock: Mutex<()>,
}

impl TokenState {
    pub fn new(token: Token) -> Self {
        Self {
            token: RwLock::new(token),
            refresh_lock: Mutex::new(()),
        }
    }
}

pub type SharedTokenState = Arc<TokenState>;

use std::cell::RefCell;
use std::sync::Arc;
use tokio::runtime::{Builder, Runtime};
use crate::util::Shared;
use crate::util::shared::Shareable;

#[derive(Clone, Debug)]
pub struct NetworkContext {
    // pub runtime: RefCell<Runtime>,
}

// impl Shareable for NetworkContext {}

// shareable!(NetworkContext);

impl Default for NetworkContext {
    fn default() -> Self {
        Self {
            // runtime: RefCell::new(Builder::new_multi_thread()
            //     .worker_threads(1)
            //     .build()
            //     .unwrap())
        }
    }
}

impl NetworkContext {
    pub fn new() -> Self {
        Self {
            // runtime: RefCell::new(Builder::new_multi_thread()
            //     .worker_threads(1)
            //     .build()
            //     .unwrap())
        }
    }
}


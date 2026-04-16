use std::cell::RefCell;

use sia_storage::{
    ApprovedState, Builder as StorageBuilder, DisconnectedState, RequestingApprovalState,
};
use wasm_bindgen::prelude::*;

use crate::app_key::AppKey;
use crate::helpers::{make_app_metadata, to_js_err};
use crate::run_local;
use crate::sdk::Sdk;
use crate::types::AppMetadata;

enum BuilderState {
    Disconnected(StorageBuilder<DisconnectedState>),
    RequestingApproval(StorageBuilder<RequestingApprovalState>),
    Approved(StorageBuilder<ApprovedState>),
    Finalized,
}

/// SDK Builder — handles the connection and registration flow with an indexer.
#[wasm_bindgen]
pub struct Builder {
    state: RefCell<Option<BuilderState>>,
}

#[wasm_bindgen]
impl Builder {
    #[wasm_bindgen(constructor)]
    pub fn new(indexer_url: &str, app: AppMetadata) -> Result<Builder, JsError> {
        let meta = make_app_metadata(
            &app.app_id,
            &app.name,
            &app.description,
            &app.service_url,
            app.logo_url,
            app.callback_url,
        )?;
        let builder = StorageBuilder::new(indexer_url, meta).map_err(to_js_err)?;
        Ok(Builder {
            state: RefCell::new(Some(BuilderState::Disconnected(builder))),
        })
    }

    /// Attempts to connect using an existing AppKey.
    /// Returns a Sdk if the key is valid, or undefined if not registered.
    pub async fn connected(&self, app_key: &AppKey) -> Result<Option<Sdk>, JsError> {
        let state = self.state.borrow_mut().take();
        let ak = app_key.0.clone();

        let (next_state, result) = run_local(async move {
            match state {
                Some(BuilderState::Disconnected(builder)) => match builder.connected(&ak).await {
                    Ok(Some(sdk)) => (Some(BuilderState::Finalized), Ok(Some(Sdk::new(sdk)))),
                    Ok(None) => (Some(BuilderState::Disconnected(builder)), Ok(None)),
                    Err(e) => (Some(BuilderState::Disconnected(builder)), Err(to_js_err(e))),
                },
                other => (other, Err(JsError::new("must be in disconnected state"))),
            }
        })
        .await;

        *self.state.borrow_mut() = next_state;
        result
    }

    /// Requests connection approval from the indexer.
    #[wasm_bindgen(js_name = "requestConnection")]
    pub async fn request_connection(&self) -> Result<(), JsError> {
        let state = self.state.borrow_mut().take();

        let (next_state, result) = run_local(async move {
            match state {
                Some(BuilderState::Disconnected(builder)) => {
                    match builder.request_connection().await {
                        Ok(pending) => (Some(BuilderState::RequestingApproval(pending)), Ok(())),
                        Err(e) => (None, Err(to_js_err(e))),
                    }
                }
                other => (other, Err(JsError::new("must be in disconnected state"))),
            }
        })
        .await;

        *self.state.borrow_mut() = next_state;
        result
    }

    /// Returns the approval URL the user must visit.
    #[wasm_bindgen(js_name = "responseUrl")]
    pub fn response_url(&self) -> Result<String, JsError> {
        let state = self.state.borrow();
        match state.as_ref() {
            Some(BuilderState::RequestingApproval(builder)) => {
                Ok(builder.response_url().to_owned())
            }
            _ => Err(JsError::new("must be in requesting_approval state")),
        }
    }

    /// Waits for the user to approve the connection request.
    #[wasm_bindgen(js_name = "waitForApproval")]
    pub async fn wait_for_approval(&self) -> Result<(), JsError> {
        let state = self.state.borrow_mut().take();

        let (next_state, result) = run_local(async move {
            match state {
                Some(BuilderState::RequestingApproval(builder)) => {
                    match builder.wait_for_approval().await {
                        Ok(approved) => (Some(BuilderState::Approved(approved)), Ok(())),
                        Err(e) => (None, Err(to_js_err(e))),
                    }
                }
                other => (
                    other,
                    Err(JsError::new("must be in requesting_approval state")),
                ),
            }
        })
        .await;

        *self.state.borrow_mut() = next_state;
        result
    }

    /// Completes registration and returns a Sdk instance.
    pub async fn register(&self, mnemonic: &str) -> Result<Sdk, JsError> {
        let state = self.state.borrow_mut().take();
        let mnemonic = mnemonic.to_string();

        let (next_state, result) = run_local(async move {
            match state {
                Some(BuilderState::Approved(builder)) => match builder.register(&mnemonic).await {
                    Ok(sdk) => (Some(BuilderState::Finalized), Ok(Sdk::new(sdk))),
                    Err(e) => (None, Err(to_js_err(e))),
                },
                other => (other, Err(JsError::new("must be in approved state"))),
            }
        })
        .await;

        *self.state.borrow_mut() = next_state;
        result
    }
}

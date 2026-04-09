use std::cell::RefCell;

use sia_storage::{ApprovedState, Builder, DisconnectedState, RequestingApprovalState};
use wasm_bindgen::prelude::*;

use crate::app_key::AppKey;
use crate::helpers::{make_app_metadata, run_local, to_js_err};
use crate::sdk::Sdk;

enum BuilderState {
    Disconnected(Builder<DisconnectedState>),
    RequestingApproval(Builder<RequestingApprovalState>),
    Approved(Builder<ApprovedState>),
    Finalized,
}

/// SDK Builder — handles the connection and registration flow with an indexer.
#[wasm_bindgen]
pub struct SdkBuilder {
    state: RefCell<Option<BuilderState>>,
}

#[wasm_bindgen]
impl SdkBuilder {
    #[wasm_bindgen(constructor)]
    pub fn new(
        indexer_url: &str,
        app_id_hex: &str,
        name: &str,
        description: &str,
        service_url: &str,
        logo_url: Option<String>,
        callback_url: Option<String>,
    ) -> Result<SdkBuilder, JsValue> {
        let meta = make_app_metadata(
            app_id_hex,
            name,
            description,
            service_url,
            logo_url,
            callback_url,
        )?;
        let builder = Builder::new(indexer_url, meta).map_err(to_js_err)?;
        Ok(SdkBuilder {
            state: RefCell::new(Some(BuilderState::Disconnected(builder))),
        })
    }

    /// Attempts to connect using an existing AppKey.
    /// Returns a Sdk if the key is valid, or null if not registered.
    pub async fn connected(&self, app_key: &AppKey) -> Result<JsValue, JsValue> {
        let state = self.state.borrow_mut().take();

        match state {
            Some(BuilderState::Disconnected(builder)) => {
                let result = run_local(builder.connected(&app_key.0)).await;

                match result {
                    Ok(Some(sdk)) => {
                        // Key was recognized — we have a fully initialized SDK.
                        // Transition to Finalized so the builder can't be reused.
                        *self.state.borrow_mut() = Some(BuilderState::Finalized);
                        Ok(Sdk::new(sdk).into())
                    }
                    Ok(None) => {
                        // Key was not registered with this indexer. Put the builder
                        // back into Disconnected so the caller can try a different
                        // key or proceed with the registration flow instead.
                        *self.state.borrow_mut() = Some(BuilderState::Disconnected(builder));
                        Ok(JsValue::NULL)
                    }
                    Err(e) => {
                        // Network or indexer error. Restore Disconnected state
                        // so the caller can retry.
                        *self.state.borrow_mut() = Some(BuilderState::Disconnected(builder));
                        Err(to_js_err(e))
                    }
                }
            }
            other => {
                // Not in Disconnected state (already connecting, approved, or
                // finalized). Put the state back and return an error.
                *self.state.borrow_mut() = other;
                Err(JsValue::from_str("must be in disconnected state"))
            }
        }
    }

    /// Requests connection approval from the indexer.
    #[wasm_bindgen(js_name = "requestConnection")]
    pub async fn request_connection(&self) -> Result<(), JsValue> {
        let state = self.state.borrow_mut().take();
        match state {
            Some(BuilderState::Disconnected(builder)) => {
                let pending = builder.request_connection().await.map_err(to_js_err)?;
                *self.state.borrow_mut() = Some(BuilderState::RequestingApproval(pending));
                Ok(())
            }
            other => {
                *self.state.borrow_mut() = other;
                Err(JsValue::from_str("must be in disconnected state"))
            }
        }
    }

    /// Returns the approval URL the user must visit.
    #[wasm_bindgen(js_name = "responseUrl")]
    pub fn response_url(&self) -> Result<String, JsValue> {
        let state = self.state.borrow();
        match state.as_ref() {
            Some(BuilderState::RequestingApproval(builder)) => {
                Ok(builder.response_url().to_owned())
            }
            _ => Err(JsValue::from_str("must be in requesting_approval state")),
        }
    }

    /// Waits for the user to approve the connection request.
    #[wasm_bindgen(js_name = "waitForApproval")]
    pub async fn wait_for_approval(&self) -> Result<(), JsValue> {
        let state = self.state.borrow_mut().take();
        match state {
            Some(BuilderState::RequestingApproval(builder)) => {
                let approved = builder.wait_for_approval().await.map_err(to_js_err)?;
                *self.state.borrow_mut() = Some(BuilderState::Approved(approved));
                Ok(())
            }
            other => {
                *self.state.borrow_mut() = other;
                Err(JsValue::from_str("must be in requesting_approval state"))
            }
        }
    }

    /// Completes registration and returns a StorageSdk instance.
    pub async fn register(&self, mnemonic: &str) -> Result<Sdk, JsValue> {
        let state = self.state.borrow_mut().take();
        match state {
            Some(BuilderState::Approved(builder)) => {
                let sdk = run_local(builder.register(mnemonic))
                    .await
                    .map_err(to_js_err)?;
                *self.state.borrow_mut() = Some(BuilderState::Finalized);
                Ok(Sdk::new(sdk))
            }
            other => {
                *self.state.borrow_mut() = other;
                Err(JsValue::from_str("must be in approved state"))
            }
        }
    }
}

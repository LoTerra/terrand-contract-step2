use crate::state::State;
use cosmwasm_std::{Binary, CanonicalAddr};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct InitMsg {}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum QueryMsg {
    /// Get the config state
    Config {},
    /// Not used to be call directly
    VerifyCallBack {
        round: u64,
        randomness: Binary,
        valid: bool,
        worker: CanonicalAddr,
    },
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum HandleMsg {
    Verify {
        signature: Binary,
        msg_g2: Binary,
        worker: CanonicalAddr,
        round: u64,
    },
}
// We define a custom struct for each query response
pub type ConfigResponse = State;

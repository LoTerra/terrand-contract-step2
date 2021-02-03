use cosmwasm_std::{to_binary, Binary, Deps, DepsMut, Env, HandleResponse, InitResponse, MessageInfo, attr};

use crate::error::ContractError;
use crate::msg::{
    ConfigResponse, HandleMsg, InitMsg, QueryMsg,
};
use crate::state::{
    config, config_read, State,
};
use paired::bls12_381::{G2Affine, G1Affine, Fq12, Bls12};
use groupy::{CurveAffine};
use paired::{PairingCurveAffine, Engine};
use fff::Field;

use drand_verify::{g2_from_variable, VerificationError, g1_from_variable};

// Note, you can use StdResult in some functions where you do not
// make use of the custom errors
pub fn init(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    _msg: InitMsg,
) -> Result<InitResponse, ContractError> {
    let state = State {
        drand_public_key: vec![
            134, 143, 0, 94, 184, 230, 228, 202, 10, 71, 200, 167, 124, 234, 165, 48, 154, 71, 151,
            138, 124, 113, 188, 92, 206, 150, 54, 107, 93, 122, 86, 153, 55, 197, 41, 238, 218,
            102, 199, 41, 55, 132, 169, 64, 40, 1, 175, 49,
        ]
        .into(),
    };
    config(deps.storage).save(&state)?;

    Ok(InitResponse::default())
}

pub fn handle(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    msg: HandleMsg,
) -> Result<HandleResponse, ContractError> {
    match msg {
        HandleMsg::Verify {
            previous_signature,
            msg_g2,
        } => verify(deps, previous_signature, msg_g2),
    }
}

fn fast_pairing_equality(p: &G1Affine, q: &G2Affine, r: &G1Affine, s: &G2Affine) -> bool {
    fn e_prime(p: &G1Affine, q: &G2Affine) -> Fq12 {
        Bls12::miller_loop([(&(p.prepare()), &(q.prepare()))].iter())
    }

    let minus_p = {
        let mut out = *p;
        out.negate();
        out
    };
    let mut tmp = e_prime(&minus_p, &q);
    tmp.mul_assign(&e_prime(r, &s));
    match Bls12::final_exponentiation(&tmp) {
        Some(value) => value == Fq12::one(),
        None => false,
    }
}

fn verify_step2(
    pk: &G1Affine,
    signature: &[u8],
    msg_on_g2: &G2Affine,
) -> Result<bool, VerificationError> {
    let g1 = G1Affine::one();
    let sigma = match g2_from_variable(signature) {
        Ok(sigma) => sigma,
        Err(err) => {
            return Err(VerificationError::InvalidPoint {
                field: "signature".into(),
                msg: err.to_string()
            })
        }
    };
    Ok(fast_pairing_equality(&g1, &sigma, pk, msg_on_g2))
}

pub fn verify(deps: DepsMut,
              signature: Binary,
              msg_g2: Binary,
) -> Result<HandleResponse, ContractError>{
    // Load state
    let state = config(deps.storage).load()?;
    // To affine
    let pk_to_g1affine = g1_from_variable(&state.drand_public_key.to_vec()).unwrap();
    let msg_to_g2affine = g2_from_variable(&msg_g2.to_vec()).unwrap();
    // Verify
    let is_valid = verify_step2(&pk_to_g1affine, &signature,  &msg_to_g2affine).unwrap();

    Ok(HandleResponse {
            messages: vec![],
            attributes: vec![attr("valid", is_valid.to_string())],
            data: None
        })
}

pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> Result<Binary, ContractError> {
    let response = match msg {
        QueryMsg::Config {} => to_binary(&query_config(deps)?)?,
    };
    Ok(response)
}

fn query_config(deps: Deps) -> Result<ConfigResponse, ContractError> {
    let state = config_read(deps.storage).load()?;
    Ok(state)
}


#[cfg(test)]
mod tests {
    use super::*;
    use cosmwasm_std::testing::{mock_dependencies, mock_env, mock_info};
    use cosmwasm_std::{coins, Api, HumanAddr};
    use hex;
    use paired::bls12_381::{Fq, G1, Fq2, G1Uncompressed};
    use serde::de::IntoDeserializer;


    #[test]
    fn verify_test() {
        let mut deps = mock_dependencies(&[]);
        let info = mock_info(HumanAddr::from("creator"), &[]);
        let init_msg = InitMsg {};
        init(deps.as_mut(), mock_env(), info, init_msg).unwrap();

        let signature: Binary = hex::decode("a75c1b05446c28e9babb078b5e4887761a416b52a2f484bcb388be085236edacc72c69347cb533da81e01fe26f1be34708855b48171280c6660e2eb736abe214740ce696042879f01ba5613808a041b54a80a43dadb5a6be8ed580be7e3f546e").unwrap().into();
        let g2Binary = hex::decode("8332743e3c325954435e289d757183e9d3d0b64055cf7f8610b0823d6fd2c0ec2a9ce274fd2eec85875225f89dcdda710fb11cce31d0fa2b4620bbb2a2147502f921ceb95d29b402b55b69b609e51bb759f94c32b7da12cb91f347b12740cb52").unwrap();

        let msg = HandleMsg::Verify {
            previous_signature: signature,
            msg_g2: Binary::from(g2Binary)
        };
        let info = mock_info(HumanAddr::from("address"), &[]);
        let res = handle(deps.as_mut(), mock_env(), info, msg.clone()).unwrap();
        assert_eq!(1, res.attributes.len());
    }
}

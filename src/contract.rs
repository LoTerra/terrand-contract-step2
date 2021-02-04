use cosmwasm_std::{
    to_binary, Api, Binary, Env, Extern, HandleResponse, InitResponse, LogAttribute, Querier,
    StdResult, Storage,
};

use crate::msg::{ConfigResponse, HandleMsg, InitMsg, QueryMsg};
use crate::state::{config, config_read, State};
use fff::Field;
use groupy::CurveAffine;
use paired::bls12_381::{Bls12, Fq12, G1Affine, G2Affine};
use paired::{Engine, PairingCurveAffine};

use drand_verify::{g1_from_variable, g2_from_variable, VerificationError};

// Note, you can use StdResult in some functions where you do not
// make use of the custom errors
pub fn init<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    _env: Env,
    _msg: InitMsg,
) -> StdResult<InitResponse> {
    let state = State {
        drand_public_key: vec![
            134, 143, 0, 94, 184, 230, 228, 202, 10, 71, 200, 167, 124, 234, 165, 48, 154, 71, 151,
            138, 124, 113, 188, 92, 206, 150, 54, 107, 93, 122, 86, 153, 55, 197, 41, 238, 218,
            102, 199, 41, 55, 132, 169, 64, 40, 1, 175, 49,
        ]
        .into(),
    };
    config(&mut deps.storage).save(&state)?;

    Ok(InitResponse::default())
}

pub fn handle<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    _env: Env,
    msg: HandleMsg,
) -> StdResult<HandleResponse> {
    match msg {
        HandleMsg::Verify { signature, msg_g2 } => verify(deps, signature, msg_g2),
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
                msg: err.to_string(),
            })
        }
    };
    Ok(fast_pairing_equality(&g1, &sigma, pk, msg_on_g2))
}

pub fn verify<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    signature: Binary,
    msg_g2: Binary,
) -> StdResult<HandleResponse> {
    // Load state
    let state = config(&mut deps.storage).load()?;
    // To affine
    let pk_to_g1affine = g1_from_variable(state.drand_public_key.as_slice()).unwrap();
    let msg_to_g2affine = g2_from_variable(&msg_g2.as_slice()).unwrap();
    // Verify
    let is_valid = verify_step2(&pk_to_g1affine, &signature.as_slice(), &msg_to_g2affine).unwrap();

    Ok(HandleResponse {
        messages: vec![],
        data: None,
        log: vec![LogAttribute {
            key: "valid".to_string(),
            value: is_valid.to_string(),
        }],
    })
}

pub fn query<S: Storage, A: Api, Q: Querier>(
    deps: &Extern<S, A, Q>,
    msg: QueryMsg,
) -> StdResult<Binary> {
    let response = match msg {
        QueryMsg::Config {} => to_binary(&query_config(deps)?)?,
    };
    Ok(response)
}

fn query_config<S: Storage, A: Api, Q: Querier>(
    deps: &Extern<S, A, Q>,
) -> StdResult<ConfigResponse> {
    let state = config_read(&deps.storage).load()?;
    Ok(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use cosmwasm_std::testing::{mock_dependencies, mock_env};
    use hex;

    #[test]
    fn verify_test() {
        let mut deps = mock_dependencies(0, &[]);

        let init_msg = InitMsg {};
        init(&mut deps, mock_env("creator", &[]), init_msg).unwrap();

        let signature: Binary = hex::decode("a75c1b05446c28e9babb078b5e4887761a416b52a2f484bcb388be085236edacc72c69347cb533da81e01fe26f1be34708855b48171280c6660e2eb736abe214740ce696042879f01ba5613808a041b54a80a43dadb5a6be8ed580be7e3f546e").unwrap().into();
        let g2_binary = hex::decode("8332743e3c325954435e289d757183e9d3d0b64055cf7f8610b0823d6fd2c0ec2a9ce274fd2eec85875225f89dcdda710fb11cce31d0fa2b4620bbb2a2147502f921ceb95d29b402b55b69b609e51bb759f94c32b7da12cb91f347b12740cb52").unwrap();

        let msg = HandleMsg::Verify {
            signature: signature,
            msg_g2: Binary::from(g2_binary),
        };

        let res = handle(&mut deps, mock_env("address", &[]), msg.clone()).unwrap();
        assert_eq!(1, res.log.len());
    }
}

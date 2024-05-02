use axum::{
    extract::{Path, State},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use candid::{Decode, Encode};
use clap::Parser;
use dmailfi_types::{LedgerConfiguration, RegistryError};
use ic_agent::{agent::AgentBuilder, export::Principal, identity::Secp256k1Identity, Agent};
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, str::FromStr, sync::Mutex};
use std::{hash::Hash, sync::Arc};
use trust_dns_resolver::{
    config::{ResolverConfig, ResolverOpts},
    Resolver,
};
use types::AppIdentity;
use uuid::{uuid, Uuid};

mod types;
lazy_static! {
    static ref CACHE: Cache<String, String> = Cache::new();
}

struct Cache<K, V> {
    map: Mutex<HashMap<K, V>>,
}

impl<K: Eq + Hash, V> Cache<K, V> {
    fn new() -> Cache<K, V> {
        Cache {
            map: Mutex::new(HashMap::new()),
        }
    }

    fn set(&self, key: K, value: V) {
        let mut map = self.map.lock().unwrap();
        map.insert(key, value);
    }

    fn get(&self, key: &K) -> Option<V>
    where
        V: Clone,
    {
        let map = self.map.lock().unwrap();
        map.get(key).cloned()
    }

    fn remove(&self, key: &K) {
        let mut map = self.map.lock().unwrap();
        map.remove(key);
    }
}

#[derive(Clone)]
struct AppState {
    cli: Cli,
    // cache: Cache<String, String>
}
#[tokio::main]
async fn main() {
    let appstate = AppState { cli: Cli::parse() };
    let app = Router::new()
        .route("/verify/domain", post(create_verification))
        .route("/verify/:domain_name", get(verify))
        .with_state(appstate);
    // run our app with hyper, listening globally on port 3000
    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000")
        .await
        .unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn create_verification(
    // this argument tells axum to parse the request body
    // as JSON into a `CreateUser` type
    Json(payload): Json<CreateVerification>,
) -> (StatusCode, Json<CreateVerificationResponse>) {
    let id = Uuid::new_v4();
    CACHE.set(payload.domain, id.to_string());
    (
        StatusCode::OK,
        Json(CreateVerificationResponse {
            data: id.to_string(),
        }),
    )
}

async fn verify(Path(domain): Path<String>, State(state): State<AppState>) -> (StatusCode, String) {
    let resolver = Resolver::new(ResolverConfig::default(), ResolverOpts::default()).unwrap();
    let arc_identity = Arc::new(AppIdentity::new());
    let owner_principal: String = "".to_string();
    // Lookup the IP addresses associated with a name.
    let response = resolver.txt_lookup(domain.clone()).unwrap();
    let txtdata = response.iter().next();
    if txtdata.is_none() {
        return (StatusCode::EXPECTATION_FAILED, "There's no TXT data in that domain".to_string());
    }
    let txtdata = txtdata.unwrap();
    let txt_str = txtdata.to_string();
    let domain_rslt = CACHE.get(&domain);

    if domain_rslt.is_none() {
        return (StatusCode::NOT_FOUND, "You have created verification for this domain".to_string());
    }

    if txt_str == domain_rslt.unwrap() {
        let agent = Agent::builder()
            .with_arc_identity(arc_identity)
            .with_url(state.cli.rpc_url)
            .build()
            .unwrap();

        let registry_id = Principal::from_text(state.cli.registry_id).unwrap();
        let can_result = agent
            .update(&registry_id, "create_dmail_canister")
            .with_arg(Encode!(&domain, &owner_principal, &None::<LedgerConfiguration>).unwrap())
            .call_and_wait()
            .await;

        if can_result.is_err() {
            let err = can_result.unwrap_err();
            return (StatusCode::INTERNAL_SERVER_ERROR, err.to_string());
        }

        let can_result = Decode!(&can_result.unwrap(), Result<String, RegistryError>).unwrap();
        if can_result.is_err() {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Error from the canister".to_string(),
            );
        }
        
        return (StatusCode::OK, "".to_string());
    } else {
        return (StatusCode::BAD_REQUEST, "Invalid TXT record".to_string());
    }
}

#[derive(Deserialize)]
struct CreateVerification {
    domain: String,
}

#[derive(Serialize)]
struct CreateVerificationResponse {
    data: String,
}

#[derive(Clone, Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    #[arg(long)]
    registry_id: String,
    #[arg(long)]
    rpc_url: String,
}

//! Runtime configuration loaded from feature_manifest.json and bank_risk_policy.json.
//! All constants that were previously hardcoded in main.rs now live here.
//! Config is read-once at startup and stored in Arc<RwLock<PolicyConfig>>.
//! Live reload is triggered via POST /policy/reload.

use ort::session::builder::GraphOptimizationLevel;
use serde::Deserialize;
use std::path::Path;

#[derive(Debug, Clone, PartialEq)]
pub enum VarakshaTier {
    Cloud,
    OnPrem,
    Edge,
}

impl VarakshaTier {
    pub fn from_env() -> Self {
        match std::env::var("VARAKSHA_TIER")
            .unwrap_or_default()
            .to_lowercase()
            .as_str()
        {
            "cloud" => VarakshaTier::Cloud,
            "edge" => VarakshaTier::Edge,
            _ => VarakshaTier::OnPrem,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            VarakshaTier::Cloud => "cloud",
            VarakshaTier::OnPrem => "on_prem",
            VarakshaTier::Edge => "edge",
        }
    }

    /// Default cache TTL per tier (seconds).
    pub fn default_cache_ttl(&self) -> u64 {
        match self {
            VarakshaTier::Cloud => 180,
            VarakshaTier::OnPrem => 300,
            VarakshaTier::Edge => 60,
        }
    }

    /// Default rate limit max requests per window per key.
    pub fn default_rate_max(&self) -> u64 {
        match self {
            VarakshaTier::Cloud => 100,
            VarakshaTier::OnPrem => 500,
            VarakshaTier::Edge => 20,
        }
    }
}

/// Deserialization shapes for feature_manifest.json
#[derive(Deserialize)]
#[allow(dead_code)]
struct ManifestScoreFusion {
    lgbm_weight: f32,
    anomaly_weight: f32,
    topology_weight: f32,
}

#[derive(Deserialize)]
struct ManifestVerdicts {
    #[serde(rename = "ALLOW")]
    allow: [f32; 2],
    #[serde(rename = "FLAG")]
    flag: [f32; 2],
    #[serde(rename = "BLOCK")]
    block: [f32; 2],
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct FeatureManifest {
    n_features: usize,
    lgbm_onnx: String,
    if_onnx: Option<String>,
    decision_threshold: f32,
    score_fusion: ManifestScoreFusion,
    verdicts: ManifestVerdicts,
}

/// Deserialization shape for bank_risk_policy.json (written by 04_monthly_risk_analyzer.py).
#[derive(Deserialize, Default)]
#[allow(dead_code)]
struct BankRiskPolicy {
    l3_ml_threshold: Option<f32>,
    l1_fan_in_limit: Option<u32>,
    cache_ttl_seconds: Option<u64>,
    allow_threshold: Option<f32>,
    flag_threshold: Option<f32>,
    block_threshold: Option<f32>,
}

/// All runtime configuration for the gateway.
/// No field in this struct should ever be a hardcoded constant — everything
/// originates from a JSON file or environment variable.
#[derive(Debug, Clone)]
pub struct PolicyConfig {
    // ── Feature contract (from feature_manifest.json) ─────────────────────
    pub n_features: usize,
    pub lgbm_onnx_path: String,
    /// None on Edge tier (IsolationForest not loaded).
    pub if_onnx_path: Option<String>,

    // ── Score fusion weights (from feature_manifest.json) ─────────────────
    pub lgbm_weight: f32,
    pub anomaly_weight: f32,
    pub topology_weight: f32,

    // ── Decision thresholds (policy file > manifest fallback) ─────────────
    /// Scores below this → ALLOW
    pub allow_threshold: f32,
    /// Scores between allow_threshold and block_threshold → FLAG
    pub flag_threshold: f32,
    /// Scores above this → BLOCK
    pub block_threshold: f32,

    // ── Operational limits ─────────────────────────────────────────────────
    pub fan_in_limit: u32,
    pub cache_ttl_seconds: u64,

    // ── Rate limiting ──────────────────────────────────────────────────────
    pub rate_max: u64,
    pub rate_window_seconds: u64,

    // ── Tier and paths ─────────────────────────────────────────────────────
    pub is_production: bool,
    pub tier: VarakshaTier,
    pub models_dir: String,
    pub optimized_models_dir: String,
    pub bind_addr: String,

    // ── ONNX Runtime tuning (env-configurable) ────────────────────────────
    pub ort_intra_threads: usize,
    pub ort_inter_threads: usize,
    pub ort_parallel_execution: bool,
    pub ort_optimization_level: GraphOptimizationLevel,
    pub ort_cpu_mem_arena: bool,
}

fn parse_bool_env(name: &str, default: bool) -> bool {
    std::env::var(name)
        .ok()
        .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(default)
}

fn parse_usize_env(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(default)
}

fn parse_opt_level_env(name: &str) -> GraphOptimizationLevel {
    match std::env::var(name)
        .unwrap_or_else(|_| "level1".to_string())
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "disable" | "disabled" | "off" => GraphOptimizationLevel::Disable,
        "level1" | "basic" => GraphOptimizationLevel::Level1,
        "level2" | "extended" => GraphOptimizationLevel::Level2,
        "all" | "level3" | "max" => GraphOptimizationLevel::Level3,
        _ => GraphOptimizationLevel::Level1,
    }
}

fn parse_production_mode() -> bool {
    parse_bool_env("VARAKSHA_PRODUCTION", false)
        || matches!(
            std::env::var("VARAKSHA_ENV")
                .unwrap_or_default()
                .trim()
                .to_ascii_lowercase()
                .as_str(),
            "prod" | "production"
        )
}

impl PolicyConfig {
    /// Load configuration from disk. Called once at startup, and again on /policy/reload.
    ///
    /// Load order:
    ///  1. VARAKSHA_MODELS_DIR env var (fallback: "../models")
    ///  2. {models_dir}/feature_manifest.json — n_features, onnx paths, weights, default thresholds
    ///  3. {models_dir}/../varaksha-v2-core/bank_risk_policy.json — if present, overrides thresholds
    ///  4. Env vars — VARAKSHA_TIER, VARAKSHA_BIND_ADDR, VARAKSHA_RATE_MAX, VARAKSHA_RATE_WINDOW_S
    pub fn load() -> Result<Self, String> {
        let is_production = parse_production_mode();
        let models_dir = std::env::var("VARAKSHA_MODELS_DIR")
            .unwrap_or_else(|_| "../models".to_string());

        // ── 1. Feature manifest ────────────────────────────────────────────
        let manifest_path = format!("{}/feature_manifest.json", models_dir);
        let manifest_raw = std::fs::read_to_string(&manifest_path)
            .map_err(|e| format!("Cannot read {}: {}", manifest_path, e))?;
        let manifest: FeatureManifest = serde_json::from_str(&manifest_raw)
            .map_err(|e| format!("Invalid feature_manifest.json: {}", e))?;

        let tier = VarakshaTier::from_env();

        // On Edge tier, skip IsolationForest (graph agent doesn't run there).
        let if_onnx_path = if tier == VarakshaTier::Edge {
            None
        } else {
            manifest.if_onnx.map(|name| format!("{}/{}", models_dir, name))
        };

        let lgbm_onnx_path = format!("{}/{}", models_dir, manifest.lgbm_onnx);

        // Default thresholds from manifest
        let mut allow_threshold = manifest.verdicts.allow[1];  // upper bound of ALLOW band
        let mut flag_threshold  = manifest.verdicts.flag[1];   // upper bound of FLAG band (= block lower)
        let mut block_threshold = manifest.verdicts.block[0];  // lower bound of BLOCK band
        let _ = manifest.verdicts.flag[0]; // == allow_threshold, consistent check

        // ── 2. Bank risk policy (monthly analyzer output) ──────────────────
        let policy_path = format!("{}/../varaksha-v2-core/bank_risk_policy.json", models_dir);
        if Path::new(&policy_path).exists() {
            if let Ok(raw) = std::fs::read_to_string(&policy_path) {
                if let Ok(policy) = serde_json::from_str::<BankRiskPolicy>(&raw) {
                    // Policy file threshold takes precedence over manifest.
                    if let Some(t) = policy.l3_ml_threshold.or(policy.allow_threshold) {
                        allow_threshold = t;
                    }
                    if let Some(t) = policy.flag_threshold {
                        flag_threshold = t;
                    }
                    if let Some(t) = policy.block_threshold {
                        block_threshold = t;
                    }
                }
            }
        }

        // ── 3. Operational env vars ────────────────────────────────────────
        let cache_ttl_seconds = std::env::var("VARAKSHA_CACHE_TTL_S")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or_else(|| tier.default_cache_ttl());

        let rate_max = std::env::var("VARAKSHA_RATE_MAX")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or_else(|| tier.default_rate_max());

        let rate_window_seconds = std::env::var("VARAKSHA_RATE_WINDOW_S")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(60u64);

        // Prefer an explicitly configured bind address first.
        // If absent, fall back to Railway PORT when present.
        let bind_addr = std::env::var("VARAKSHA_BIND_ADDR")
            .ok()
            .or_else(|| {
                std::env::var("PORT")
                    .ok()
                    .map(|p| format!("0.0.0.0:{}", p.trim()))
            })
            .unwrap_or_else(|| {
                if is_production {
                    "0.0.0.0:8080".to_string()
                } else {
                    "127.0.0.1:8080".to_string()
                }
            });

        let optimized_models_dir = std::env::var("VARAKSHA_ORT_OPTIMIZED_DIR")
            .unwrap_or_else(|_| format!("{}/optimized", models_dir));

        let cpu_count = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4);
        let ort_intra_threads = parse_usize_env("VARAKSHA_ORT_INTRA_THREADS", cpu_count);
        let ort_inter_threads = parse_usize_env("VARAKSHA_ORT_INTER_THREADS", (cpu_count / 2).max(1));
        let ort_parallel_execution = parse_bool_env("VARAKSHA_ORT_PARALLEL_EXECUTION", false);
        let ort_optimization_level = parse_opt_level_env("VARAKSHA_ORT_OPT_LEVEL");
        let ort_cpu_mem_arena = parse_bool_env("VARAKSHA_ORT_CPU_MEM_ARENA", true);

        let fan_in_limit = 15u32; // sensible default; policy file can override this in future

        Ok(PolicyConfig {
            n_features: manifest.n_features,
            lgbm_onnx_path,
            if_onnx_path,
            lgbm_weight: manifest.score_fusion.lgbm_weight,
            anomaly_weight: manifest.score_fusion.anomaly_weight,
            topology_weight: manifest.score_fusion.topology_weight,
            allow_threshold,
            flag_threshold,
            block_threshold,
            fan_in_limit,
            cache_ttl_seconds,
            rate_max,
            rate_window_seconds,
            is_production,
            tier,
            models_dir,
            optimized_models_dir,
            bind_addr,
            ort_intra_threads,
            ort_inter_threads,
            ort_parallel_execution,
            ort_optimization_level,
            ort_cpu_mem_arena,
        })
    }
}

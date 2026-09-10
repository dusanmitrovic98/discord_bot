use crate::gatekeeper::{TextGatekeeper, ThreatVerdict};
use crate::whitelist::WhitelistRegistry;

#[derive(Debug, PartialEq, Eq)]
pub struct NameEvaluation {
    pub verdict: ThreatVerdict,
    pub offending_name: String,
}

/// Evaluates Username, Global Display Name, and Server Nickname symmetrically
pub async fn evaluate_member_names(
    gatekeeper: &TextGatekeeper,
    whitelist: &WhitelistRegistry,
    user_id: u64,
    username: &str,
    global_name: &str,
    nickname: &str,
) -> NameEvaluation {
    let v_user = gatekeeper.evaluate_threat(username);
    let v_glob = gatekeeper.evaluate_threat(global_name);
    let v_nick = gatekeeper.evaluate_threat(nickname);

    let raw_highest = [v_user, v_glob, v_nick]
        .into_iter()
        .max_by_key(|v| match v {
            ThreatVerdict::InstantBan => 2,
            ThreatVerdict::DeleteOnly => 1,
            ThreatVerdict::Safe => 0,
        })
        .unwrap_or(ThreatVerdict::Safe);

    let offending_name = if v_nick == raw_highest {
        nickname.to_string()
    } else if v_glob == raw_highest {
        global_name.to_string()
    } else {
        username.to_string()
    };

    // Whitelist check: Exempt users bypass Tier 2 DeleteOnly (InstantBan is NEVER bypassed)
    let final_verdict = match raw_highest {
        ThreatVerdict::DeleteOnly => {
            if whitelist.is_user_exempt(user_id, username).await {
                ThreatVerdict::Safe
            } else {
                ThreatVerdict::DeleteOnly
            }
        }
        other => other,
    };

    NameEvaluation {
        verdict: final_verdict,
        offending_name,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_name_evaluation_hierarchy_and_whitelist() {
        let gatekeeper = TextGatekeeper::new();
        let whitelist = WhitelistRegistry::new();

        // 1. Predatory attack triggers InstantBan regardless of whitelist
        whitelist.add_user("hacker").await;
        let eval =
            evaluate_member_names(&gatekeeper, &whitelist, 123, "hacker", "HOT 🔥 LINK", "").await;
        assert_eq!(eval.verdict, ThreatVerdict::InstantBan);
        assert_eq!(eval.offending_name, "HOT 🔥 LINK");

        // 2. Soft link rule without whitelist triggers DeleteOnly
        let dynamic_rules = vec![r"(?i)l+i+n+k+".to_string()];
        gatekeeper.reload_dynamic_patterns(&dynamic_rules).unwrap();

        let eval_soft =
            evaluate_member_names(&gatekeeper, &whitelist, 456, "normal_guy", "steam_link", "")
                .await;
        assert_eq!(eval_soft.verdict, ThreatVerdict::DeleteOnly);

        // 3. Soft link rule with whitelisted user demotes to Safe
        whitelist.add_user("normal_guy").await;
        let eval_exempt =
            evaluate_member_names(&gatekeeper, &whitelist, 456, "normal_guy", "steam_link", "")
                .await;
        assert_eq!(eval_exempt.verdict, ThreatVerdict::Safe);
    }
}

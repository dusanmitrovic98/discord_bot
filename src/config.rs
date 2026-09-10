use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuildConfig {
    pub authorized_guild_id: u64,
    pub welcome_channel_id: u64,
    pub mod_channel_id: u64,
    pub logs_channel_id: u64,
    pub owner_user_id: u64,
    pub admin_role_id: u64,
    pub moderator_role_id: u64,
    pub sapphire_bot_id: u64,
    pub nsfw_auto_delete_threshold: f64,
    pub max_download_size_bytes: usize,
}

impl Default for GuildConfig {
    fn default() -> Self {
        Self {
            authorized_guild_id: 1385636051330142369, // "The Chill Zone"
            welcome_channel_id: 1385636052374520014,
            mod_channel_id: 1424824152417767628,
            logs_channel_id: 1492554211118809319,
            owner_user_id: 1015600709724557434,
            admin_role_id: 1491379177180626974,
            moderator_role_id: 1492192888426201351,
            sapphire_bot_id: 678344927997853742,
            nsfw_auto_delete_threshold: 70.0,
            max_download_size_bytes: 15 * 1024 * 1024, // 15MB safety ceiling (NASA Rule 2)
        }
    }
}

impl GuildConfig {
    pub fn is_authorized_guild(&self, guild_id: u64) -> bool {
        self.authorized_guild_id == guild_id
    }

    pub fn is_owner(&self, user_id: u64) -> bool {
        self.owner_user_id == user_id
    }

    pub fn is_staff(&self, user_id: u64, roles: &[u64]) -> bool {
        if self.is_owner(user_id) {
            return true;
        }
        roles
            .iter()
            .any(|&r| r == self.admin_role_id || r == self.moderator_role_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_authorization_rules() {
        let config = GuildConfig::default();

        // Guild boundary assertion
        assert!(config.is_authorized_guild(1385636051330142369));
        assert!(!config.is_authorized_guild(999999999999999999));

        // Sovereign Owner assertion
        assert!(config.is_owner(1015600709724557434));
        assert!(!config.is_owner(123456789));

        // Staff RBAC assertion
        let admin_roles = vec![1491379177180626974];
        let mod_roles = vec![1492192888426201351];
        let random_roles = vec![111111111, 222222222];

        assert!(config.is_staff(999, &admin_roles));
        assert!(config.is_staff(999, &mod_roles));
        assert!(!config.is_staff(999, &random_roles));
        // Owner is staff regardless of roles
        assert!(config.is_staff(1015600709724557434, &random_roles));
    }
}

"""Configuration management for nginx-doctor server profiles."""

import keyring

from nginx_doctor.connector.ssh import SSHConfig


class ConfigManager:
    """Manages server profiles stored in YAML format with secure keyring for passwords."""

    def __init__(self, config_dir: Path | None = None) -> None:
        if config_dir is None:
            # Check for environment variable override
            env_config = os.getenv("NGINX_DOCTOR_CONFIG")
            if env_config:
                config_dir = Path(env_config).expanduser().resolve()
            else:
                # Default to ~/.nginx-doctor
                config_dir = Path.home() / ".nginx-doctor"
        
        self.config_dir = config_dir
        self.profiles_file = config_dir / "profiles.yaml"
        self._ensure_config_dir()
        self.service_id = "nginx-doctor"

    def _ensure_config_dir(self) -> None:
        """Create config directory if it doesn't exist."""
        self.config_dir.mkdir(parents=True, exist_ok=True)
        if not self.profiles_file.exists():
            self._save_profiles({})

    def _load_profiles(self) -> dict[str, Any]:
        """Load all profiles from the YAML file."""
        if not self.profiles_file.exists():
            return {}
        
        try:
            with open(self.profiles_file, "r") as f:
                return yaml.safe_load(f) or {}
        except Exception:
            return {}

    def _save_profiles(self, profiles: dict[str, Any]) -> None:
        """Save profiles to the YAML file with proper permissions."""
        self.profiles_file.touch(mode=0o600)
        with open(self.profiles_file, "w") as f:
            yaml.safe_dump(profiles, f)

    def add_profile(self, name: str, config: SSHConfig) -> None:
        """Add or update a server profile."""
        profiles = self._load_profiles()
        
        # Handle password via keyring
        password_ref = None
        if config.password:
            try:
                keyring.set_password(self.service_id, name, config.password)
                password_ref = "__keyring__"
            except Exception:
                # Fallback to plain text if keyring fails (e.g. headless without backend)
                password_ref = config.password

        profiles[name] = {
            "host": config.host,
            "user": config.user,
            "port": config.port,
            "key_path": config.key_path,
            "use_sudo": config.use_sudo,
            "password": password_ref,
        }
        self._save_profiles(profiles)

    def get_profile(self, name: str) -> SSHConfig | None:
        """Get an SSHConfig by profile name."""
        profiles = self._load_profiles()
        data = profiles.get(name)
        if not data:
            return None
        
        # Resolve password from keyring if needed
        password = data.get("password")
        if password == "__keyring__":
            try:
                password = keyring.get_password(self.service_id, name)
            except Exception:
                password = None
        
        return SSHConfig(
            host=data["host"],
            user=data.get("user", "root"),
            port=data.get("port", 22),
            key_path=data.get("key_path"),
            use_sudo=data.get("use_sudo", True),
            password=password,
        )

    def list_profiles(self) -> dict[str, Any]:
        """List all available profiles."""
        return self._load_profiles()

    def remove_profile(self, name: str) -> bool:
        """Remove a server profile."""
        profiles = self._load_profiles()
        if name in profiles:
            # Clean up keyring
            if profiles[name].get("password") == "__keyring__":
                try:
                    keyring.delete_password(self.service_id, name)
                except Exception:
                    pass
            
            del profiles[name]
            self._save_profiles(profiles)
            return True
        return False

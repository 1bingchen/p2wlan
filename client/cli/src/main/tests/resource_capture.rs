#[test]
fn resource_capture_config_and_status_use_explicit_opt_in() {
    let mut config = Config::generate_default("https://control.example.com", "resources").unwrap();
    assert!(!config.diagnostics.resource_capture);
    assert!(set_config_value(&mut config, "resource-capture", "enabled").is_err());
    assert!(!config.diagnostics.resource_capture);
    set_config_value(&mut config, "resource-capture", "true").unwrap();
    assert!(config.diagnostics.resource_capture && config.diagnostics.enabled);
    let saved = serde_json::to_vec(&config).unwrap();
    let loaded: Config = serde_json::from_slice(&saved).unwrap();
    assert!(loaded.diagnostics.resource_capture);
    set_config_value(&mut config, "resource-capture", "false").unwrap();
    assert!(!config.diagnostics.resource_capture);
    assert!(config.diagnostics.enabled);
    assert!(matches!(
        Cli::try_parse_from(["p2wlan", "status", "--resources"])
            .unwrap()
            .command,
        Commands::Status {
            resources: true,
            json: false
        }
    ));
    assert!(Cli::try_parse_from(["p2wlan", "status", "--resources", "--json"]).is_err());
}

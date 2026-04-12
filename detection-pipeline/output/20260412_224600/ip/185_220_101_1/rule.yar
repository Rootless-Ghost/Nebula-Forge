rule detect_ip_185_220_101_1
{
    meta:
        description = "Detect threat intel ip indicator: 185.220.101.1. Risk: MEDIUM (47/100)."
        author = "detection-pipeline"
        category = "network"
        date = "2026-04-12"
        yaraforge_generated = true

    strings:
        $ip_ioc = "185.220.101.1"

    condition:
        any of them
}
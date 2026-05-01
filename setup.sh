#!/usr/bin/env bash

cd "$(dirname "${BASH_SOURCE[0]}")"

BASE="https://github.com/Rootless-Ghost"

clone_if_missing() {
    local repo=$1 dir=${2:-$1}
    if [ -d "$dir" ]; then
        echo "  $dir already exists — skipping"
    else
        echo "  Cloning $repo..."
        git clone "$BASE/$repo" "$dir"
    fi
}

clone_if_missing SigmaForge
clone_if_missing YaraForge
clone_if_missing SnortForge
clone_if_missing EndpointForge
clone_if_missing SIREN
clone_if_missing Threat-Intel-Dashboard threat-intel-dashboard
clone_if_missing LogNorm
clone_if_missing HuntForge
clone_if_missing DriftWatch
clone_if_missing ClusterIQ
clone_if_missing AtomicLoop
clone_if_missing VulnForge
clone_if_missing WifiForge

echo ""
echo "Done. Run 'docker compose up -d' to start the full stack."

#!/bin/bash

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_REPORT_DIR="$SCRIPT_DIR/reports"
DATE=$(date +%Y%m%d_%H%M)

# UI Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# Required Docker images
REQUIRED_IMAGES=(
    "ghcr.io/hadolint/hadolint:latest"
    "aquasec/trivy:latest"
    "docker/docker-bench-security:latest"
    "falcosecurity/falco:latest"
)

# Display a progress spinner
show_spinner() {
    local pid=$1
    local delay=0.1
    local spinstr='|/-\'
    while [ "$(ps a | awk '{print $1}' | grep $pid)" ]; do
        local temp=${spinstr#?}
        printf " [%c]  " "$spinstr"
        local spinstr=$temp${spinstr%"$temp"}
        sleep $delay
        printf "\b\b\b\b\b\b"
    done
    printf "    \b\b\b\b"
}

# Check if docker is running and setup directories
check_env() {
    if ! docker ps > /dev/null 2>&1; then
        echo -e "${RED}[!] Error: Docker daemon is not running or insufficient permissions.${NC}"
        exit 1
    fi
    mkdir -p "$BASE_REPORT_DIR"
}

# Pull required security images
install_dependencies() {
    local all_installed=true
    
    for image in "${REQUIRED_IMAGES[@]}"; do
        if ! docker image inspect "$image" > /dev/null 2>&1; then
            echo -ne "${CYAN}[i] Installing ${image}...${NC}"
            
            if docker pull "$image" > /dev/null 2>&1; then
                echo -e "\r${GREEN}[V] ${image} installed.${NC}"
            else
                echo -e "\r${RED}[X] Error installing ${image}${NC}"
                all_installed=false
            fi
        fi
    done
    
    if [ "$all_installed" = true ]; then
        return 0
    else
        echo -e "${RED}[!] Some dependencies failed to install${NC}"
        return 1
    fi
}

# Standard docker execution with redirection
simple_docker_run() {
    local image=$1
    local output_file=$2
    shift 2
    
    docker run --rm "$image" "$@" > "$output_file" 2> /tmp/audit_err.log
    return $?
}

# Docker execution with volume mounting
docker_run_with_mount() {
    local image=$1
    local mount_arg=$2
    local output_file=$3
    shift 3
    
    docker run --rm -v "$mount_arg" "$image" "$@" > "$output_file" 2> /tmp/audit_err.log
    return $?
}

##### Falco #####
# Detect architecture and kernel capabilities for Falco driver
detect_infrastructure() {
    local arch=$(uname -m)
    local kernel=$(uname -r)

    # WSL2 requires specific compatibility
    if [[ "$kernel" == *"microsoft"* ]]; then
        echo "-o engine.name=ebpf"
    # ARM architectures (AWS Graviton / Apple Silicon)
    elif [[ "$arch" == "aarch64" ]]; then
        echo "-o engine.name=modern_ebpf"
    # X86_64 with modern kernels (>= 5.8)
    else
        echo "-o engine.name=modern_ebpf"
    fi
}

# Parse Falco JSON logs into a readable text report
parse_falco_logs() {
    local log_file="/tmp/falco_events.json"
    local output_file="$BASE_REPORT_DIR/runtime/falco_$(date +%Y%m%d_%H%M).txt"
    mkdir -p "$(dirname "$output_file")"

    if [[ ! -s "$log_file" ]]; then
        echo -e "${ORANGE}[!] No Falco events found to parse.${NC}"
        return
    fi

    python3 -c "
import json
import sys

try:
    with open('$log_file', 'r') as f:
        with open('$output_file', 'w') as out:
            out.write('RUNTIME SECURITY EVENT REPORT (FALCO)\n' + '='*60 + '\n\n')
            for line in f:
                try:
                    data = json.loads(line)
                    if 'priority' in data:
                        prio = data.get('priority', 'UNKNOWN')
                        time = data.get('time', 'N/A')
                        rule = data.get('rule', 'N/A')
                        msg = data.get('output', 'N/A')
                        
                        out.write(f'[{prio}] {time}\n')
                        out.write(f' RULE: {rule}\n')
                        out.write(f' EVENT: {msg}\n')
                        out.write('-'*40 + '\n')
                except: continue
    print(f'   {GREEN}[V] Report parsed: $output_file{NC}')
except Exception as e:
    print(f'   {RED}Error parsing Falco logs: {str(e)}{NC}')
"
}

# Main Falco management function
run_falco() {
    echo -e "\n${BLUE}${BOLD}─── RUNTIME SECURITY: INTRUSION DETECTION (FALCO) ───${NC}"
    echo "1) 📊 Sensor Status"
    echo "2) 📝 Generate Alert Report (.txt)"
    echo "3) 🚀 Deploy/Restart Sensor"
    echo "4) 👁️  Live Monitor (Streaming)"
    read -p "Option [1-4]: " fopt
    
    case $fopt in
        1) 
            if [ "$(docker ps -q -f name=falco)" ]; then
                echo -e "${GREEN}[V] Falco is active.${NC}"
                docker ps --filter "name=falco" --format "table {{.Names}}\t{{.Status}}\t{{.Image}}"
            else
                echo -e "${RED}[!] Falco is not running.${NC}"
            fi
            ;;
        2) 
            echo -e "${YELLOW}[*] Extracting events from container...${NC}"
            docker logs falco 2>&1 | grep "{" > /tmp/falco_events.json
            parse_falco_logs
            ;;
        3) 
            local driver_flag=$(detect_infrastructure) 
            echo -e "${BLUE}[*] Deploying Falco with engine: ${driver_flag}...${NC}"
            docker rm -f falco > /dev/null 2>&1
            
            docker run -d --name falco \
                --privileged \
                --restart always \
                -v /var/run/docker.sock:/host/var/run/docker.sock \
                -v /dev:/host/dev \
                -v /proc:/host/proc:ro \
                -v /boot:/host/boot:ro \
                -v /lib/modules:/host/lib/modules:ro \
                -v /usr:/host/usr:ro \
                -v /run:/host/run:ro \
                falcosecurity/falco:latest \
                falco -o "json_output=true" -o "log_stderr=true" $driver_flag
            
            echo -e "${YELLOW}[i] Waiting for initialization...${NC}"
            sleep 5
            if docker logs falco 2>&1 | grep -q "Loaded event sources: syscall"; then
                echo -e "${GREEN}[V] Kernel sensor operational.${NC}"
            else
                echo -e "${RED}[X] Error: Sensor failed to load eBPF driver.${NC}"
                echo -e "${GRAY}Tip: Run 'sudo apt install linux-headers-\$(uname -r)' on your host.${NC}"
            fi
            ;;
        4)
            if [ ! "$(docker ps -q -f name=falco)" ]; then
                echo -e "${RED}[!] Error: Falco is not running.${NC}"
            else
                echo -e "${RED}${BOLD}[!] LIVE MONITOR (Press Ctrl+C to return to menu)${NC}"
                # Only show lines with priority (actual security alerts)
                docker logs -f falco 2>&1 | grep -E "Notice|Warning|Error|Critical" --color=always
            fi
            ;;
    esac
}


##### Hadolint ####

# Parse Hadolint raw output into a formatted terminal view
parse_hadolint() {
    local report=$1
    echo -e "${BLUE}--- Hadolint Security Analysis ---${NC}"
    
    if [ ! -s "$report" ]; then
        echo -e "${YELLOW}[!] No issues found.${NC}"
        return
    fi
    
    while IFS= read -r line; do
        # Extract rule code (DLxxxx or SCxxxx)
        local code=$(echo "$line" | grep -oE '(DL|SC)[0-9]+' || echo "UNKNOWN")
        local line_num=$(echo "$line" | cut -d':' -f2)
        local message=$(echo "$line" | sed 's/.*: //')

        if [[ "$line" == *"error"* ]]; then
            echo -e "${RED}[✘] Line $line_num | $code - ERROR:${NC} $message"
        elif [[ "$line" == *"warning"* ]]; then
            echo -e "${YELLOW}[!] Line $line_num | $code - WARNING:${NC} $message"
        elif [[ "$line" == *"info"* ]]; then
            echo -e "${CYAN}[i] Line $line_num | $code - INFO:${NC} $message"
        else
            echo -e "    $line"
        fi
    done < "$report"
}

# Analyze Dockerfiles for best practices and security smells
run_hadolint() {
    local file=$1

    if [ -z "$file" ]; then
        echo -e "${CYAN}[*] Searching for Dockerfiles...${NC}"
        
        # Find Dockerfiles up to 3 levels deep
        mapfile -t dockerfiles < <(find . -maxdepth 3 -type f \( -name "Dockerfile*" -o -name "*.dockerfile" \) 2>/dev/null)

        if [ ${#dockerfiles[@]} -gt 0 ]; then
            echo -e "${YELLOW}[?] Select a file to audit:${NC}"
            for i in "${!dockerfiles[@]}"; do 
                echo -e "  $((i+1))) ${dockerfiles[$i]}"
            done
            echo -e "  m) Manual path"
            
            read -p "Selection: " choice
            
            if [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -le "${#dockerfiles[@]}" ]; then
                file="${dockerfiles[$((choice-1))]}"
            elif [[ "$choice" == "m" ]]; then
                read -p "Enter manual path: " file
            else
                echo -e "${RED}[!] Invalid selection.${NC}"
                return
            fi
        else 
            echo -e "${ORANGE}[!] No Dockerfiles found.${NC}"
            read -p "Enter manual path: " file
        fi
    fi

    if [ -f "$file" ]; then
        local safe_name=$(basename "$file" | sed 's/[\.\/]/_/g')
        local abs_path=$(realpath "$file")
        local target_dir="$BASE_REPORT_DIR/linter"
        local report_path="$target_dir/${safe_name}_$DATE.log"

        mkdir -p "$target_dir"
        
        echo -ne "${YELLOW}[>] Analyzing $file...${NC}"
        
        # Run Hadolint via Docker
        docker run --rm -v "$abs_path:/Dockerfile:ro" ghcr.io/hadolint/hadolint:latest hadolint /Dockerfile > "$report_path" 2> /tmp/audit_err.log &
        
        local pid=$!
        show_spinner "$pid"
        wait $pid
        local res=$?

        if [ -s "$report_path" ]; then
            echo -e "\r${GREEN}[V] Analysis completed:${NC} $report_path"
            parse_hadolint "$report_path"
        elif [ $res -eq 0 ]; then
            echo -e "\r${GREEN}[V] Perfect! No issues were found.${NC}"
        else
            echo -e "\r${RED}[X] Analysis error.${NC}"
            [[ -f /tmp/audit_err.log ]] && cat /tmp/audit_err.log
        fi
    else
        echo -e "${RED}[!] File not found: $file${NC}"
    fi
}

#### TRIVI ####
parse_trivy() {
    local report_path=$1
    local img_folder=$(basename "$report_path" | sed 's/_[0-9]\{8\}_[0-9]\{4,6\}\.json//')
    local target_dir="$(dirname "$report_path")/$img_folder"
    local txt_report="$target_dir/$(basename "${report_path%.json}.txt")"

    mkdir -p "$target_dir"

    python3 -c "
import json
import re

# Terminal Colors
RED, ORANGE, YELLOW, BLUE, GREEN, BOLD, NC, GRAY = '\033[0;31m', '\033[38;5;208m', '\033[0;33m', '\033[0;34m', '\033[0;32m', '\033[1m', '\033[0m', '\033[38;5;250m'

try:
    with open('$report_path', 'r') as f:
        data = json.load(f)

    artifact = data.get('ArtifactName', 'Unknown')
    stats = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
    all_vulns = {'CRITICAL': [], 'HIGH': [], 'MEDIUM': [], 'LOW': []}
    remediation_os = set()
    remediation_libs = set()

    for res in data.get('Results', []):
        target = res.get('Target', 'Unknown')
        is_lib = any(x in target.lower() for x in ['gomod', 'node_modules', 'jar', 'python', 'stdlib', 'site-packages'])
        
        for v in res.get('Vulnerabilities', []):
            sev = v.get('Severity', 'LOW')
            if sev not in stats: stats[sev] = 0
            stats[sev] += 1
            
            pkg = v.get('PkgName', 'N/A')
            fix = v.get('FixedVersion', 'Not available')
            
            if fix != 'Not available':
                if is_lib: remediation_libs.add(f'{pkg} -> {fix}')
                else: remediation_os.add(pkg)

            vuln_obj = {
                'pkg': pkg, 'ver': v.get('InstalledVersion', 'N/A'),
                'id': v.get('VulnerabilityID', 'N/A'),
                'cvss': v.get('CVSS', {}).get('nvd', {}).get('V3Score', 'N/A'),
                'target': target, 'url': v.get('PrimaryURL', 'N/A'),
                'fix': fix, 'desc': v.get('Description', 'No description available')
            }
            all_vulns[sev].append(vuln_obj)

    with open('$txt_report', 'w') as f_txt:
        f_txt.write(f'SECURITY REPORT: {artifact}\n' + '='*80 + '\n')

        # PROCESS EACH SEVERITY FOR TXT REPORT
        for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            if not all_vulns[sev]: continue
            
            # Screen output (Only Critical and High)
            if sev in ['CRITICAL', 'HIGH']:
                color = RED if sev == 'CRITICAL' else ORANGE
                icon = '🚨' if sev == 'CRITICAL' else '⚠️ '
                print(f'\n{color}{BOLD}{icon} {sev} ({len(all_vulns[sev])}):{NC}')
                print(f'{GRAY}{\"─\" * 80}{NC}')

            f_txt.write(f'\n[{sev}] TOTAL: {len(all_vulns[sev])}\n' + '-'*80 + '\n')

            for i, v in enumerate(all_vulns[sev], 1):
                # Write to TXT file
                f_txt.write(f'{i}. {v[\"pkg\"]} ({v[\"ver\"]})\n')
                f_txt.write(f'   ID: {v[\"id\"]} | CVSS: {v[\"cvss\"]}\n')
                f_txt.write(f'   Component: {v[\"target\"]}\n')
                f_txt.write(f'   Solution: {v[\"fix\"]}\n')
                f_txt.write(f'   URL: {v[\"url\"]}\n')
                f_txt.write(f'   Desc: {v[\"desc\"][:200]}...\n\n')

                # Show on screen (Limit to top 10 Crit/High)
                if sev in ['CRITICAL', 'HIGH'] and i <= 10:
                    color = RED if sev == 'CRITICAL' else ORANGE
                    print(f'{color}{BOLD}{i}. {v[\"pkg\"]} {v[\"ver\"]}{NC}')
                    print(f'   {GRAY}├─ ID: {v[\"id\"]} (CVSS: {v[\"cvss\"]}){NC}')
                    print(f'   {GRAY}├─ Link: {BLUE}\033]8;;{v[\"url\"]}\a{v[\"url\"]}\033]8;;\a{NC}')
                    print(f'   {GREEN}└─ SOLUTION: {BOLD}{v[\"fix\"]}{NC}\n')
            
            if sev in ['CRITICAL', 'HIGH'] and len(all_vulns[sev]) > 10:
                print(f'{YELLOW}   ... and {len(all_vulns[sev])-10} more in the TXT report.{NC}')

        # SUGGESTED ACTION PLAN (TXT ONLY)
        f_txt.write('\n' + '='*80 + '\n🛠️  SUGGESTED ACTION PLAN\n' + '='*80 + '\n')
        if remediation_os:
            os_family = data.get('Metadata', {}).get('OS', {}).get('Family', 'linux')
            mgr = 'apt-get install --only-upgrade' if os_family in ['debian', 'ubuntu'] else 'yum update -y'
            f_txt.write(f'\n[Infra/OS] Run:\n{mgr} ' + ' '.join(list(remediation_os)) + '\n')
        if remediation_libs:
            f_txt.write('\n[Apps/Libraries] Update manually:\n' + '\n'.join(list(remediation_libs)) + '\n')

        # Final Summary on Screen
        print(f'\n{BOLD}{\"=\" * 60}{NC}')
        print(f'📊 SUMMARY: {RED}Crit: {stats.get(\"CRITICAL\",0)}{NC} | {ORANGE}High: {stats.get(\"HIGH\",0)}{NC} | {YELLOW}Med: {stats.get(\"MEDIUM\",0)}{NC}')
        print(f'{BOLD}{\"=\" * 60}{NC}')

    print(f'\n\033[0;34m{BOLD}📂 FULL REPORT (Includes Low-priority and Action Plan):{NC}')
    print(f'\033[0;34m   $txt_report{NC}\n')

except Exception as e:
    print(f'{RED}Error processing report: {str(e)}{NC}')
"

    # --- JSON FILE MANAGEMENT ---
    echo -e "\n${YELLOW}[?] Do you want to delete the original JSON file? (y/n):${NC} "
    read -n 1 -r
    echo "" 

    if [[ $REPLY =~ ^[Yy]$ ]]; then
        rm "$report_path"
        echo -e "${RED}[-] JSON file deleted to save space.${NC}"
    else
        local json_dir="$target_dir/json"
        mkdir -p "$json_dir"
        mv "$report_path" "$json_dir/"
        echo -e "${GREEN}[+] JSON preserved at: ${NC} $json_dir/$(basename "$report_path")"
    fi
}

# Execute vulnerability scanning on Docker images using Trivy
run_trivy() {
    local img=$1

    if [ -z "$img" ]; then
        mapfile -t images < <(docker images --format "{{.Repository}}:{{.Tag}}" | grep -v "<none>")
        
        if [ ${#images[@]} -eq 0 ]; then
            echo -e "${RED}[!] No Docker images available.${NC}"
            return
        fi
        
        echo -e "${YELLOW}[?] Select an image to scan:${NC}"
        for i in "${!images[@]}"; do 
            echo -e "  $((i+1))) ${images[$i]}"
        done
        
        read -p "Selection Number: " choice
        
        if [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -le "${#images[@]}" ]; then
            img="${images[$((choice-1))]}"
        else
            echo -e "${RED}[!] Invalid selection.${NC}"
            return
        fi
    fi

    # Display Scan Options
    echo -e "\n${BLUE}=== TRIVY SCAN OPTIONS ===${NC}"
    echo "1) 🔍 Fast (OS packages only)"
    echo "2) ⚡ Standard (OS + Libraries, excluding Java)"
    echo "3) 🔬 Deep (All packages, extended timeout)"
    echo "4) 📊 Cache Only (Known vulnerabilities, offline mode)"
    echo "5) 🗑️  Force DB Update (Download latest definitions)"
    
    read -p "Select [1-5]: " scan_choice
    
    local scan_flags="--format json --quiet"
    local cache_dir="${TRIVY_CACHE_DIR:-$HOME/.cache/trivy}"
    local cache_flags="-v $cache_dir:/root/.cache"
    local timeout_seconds=300
    
    case $scan_choice in
        1)
            scan_flags="$scan_flags --scanners vuln --skip-dirs /usr/lib/jvm"
            echo -e "${CYAN}[i] Mode: Fast (OS packages only)${NC}"
            timeout_seconds=60
            ;;
        2)
            scan_flags="$scan_flags --scanners vuln --skip-dirs /usr/lib/jvm --skip-files *.jar"
            echo -e "${CYAN}[i] Mode: Standard (Excluding Java)${NC}"
            timeout_seconds=120
            ;;
        3)
            scan_flags="$scan_flags --scanners vuln --all-pkgs"
            echo -e "${CYAN}[i] Mode: Deep Scan (This may take several minutes)${NC}"
            timeout_seconds=600
            ;;
        4)
            scan_flags="$scan_flags --scanners vuln --skip-db-update"
            echo -e "${CYAN}[i] Mode: Cache only (Skipping DB update)${NC}"
            timeout_seconds=30
            ;;
        5)
            echo -e "${YELLOW}[>] Updating vulnerability database...${NC}"
            docker run --rm $cache_flags aquasec/trivy:latest image --download-db-only > /dev/null 2>&1
            scan_flags="$scan_flags --scanners vuln"
            echo -e "${GREEN}[V] DB updated successfully${NC}"
            timeout_seconds=180
            ;;
        *)
            echo -e "${RED}[!] Invalid option, defaulting to Standard mode${NC}"
            scan_flags="$scan_flags --scanners vuln --skip-dirs /usr/lib/jvm"
            ;;
    esac

    local safe_name=$(echo "$img" | sed 's/[\/:]/_/g')
    local target_dir="$BASE_REPORT_DIR/images"
    local report_path="$target_dir/${safe_name}_$DATE.json"

    mkdir -p "$target_dir"
    mkdir -p "$cache_dir" 
    
    echo -ne "${YELLOW}[>] Scanning $img...${NC}"
    
    scan_with_timeout() {
        timeout $timeout_seconds docker run --rm \
            $cache_flags \
            -v /var/run/docker.sock:/var/run/docker.sock \
            aquasec/trivy:latest image \
            $scan_flags \
            "$img"
    }
    
    # Run scan with timeout
    scan_with_timeout > "$report_path" 2> /tmp/audit_err.log &
    
    local pid=$!
    show_spinner "$pid"
    wait $pid
    local res=$?
    
    # Handle Exit Codes
    if [ $res -eq 124 ]; then
        echo -e "\r${ORANGE}[!] Timeout ($timeout_seconds seconds). Scan interrupted.${NC}"
        echo -e "${CYAN}[i] Tip: Use option 5 to update DB or option 4 for cache-only mode.${NC}"
        return
    elif [ $res -eq 125 ]; then
        echo -e "\r${RED}[X] Docker Error (Code: 125)${NC}"
        echo -e "${CYAN}[i] Potential issue with Docker volumes.${NC}"
        [[ -f /tmp/audit_err.log ]] && cat /tmp/audit_err.log
        return
    elif [ $res -eq 0 ] && [ -s "$report_path" ]; then
        echo -e "\r${GREEN}[V] Scan completed:${NC} $report_path"
        
        # Verify JSON integrity
        if jq empty "$report_path" 2>/dev/null; then
            parse_trivy "$report_path"
            
            # Show cache telemetry
            if [ -d "$cache_dir" ]; then
                local db_size=$(du -sh "$cache_dir" 2>/dev/null | cut -f1)
                local db_age=$(find "$cache_dir" -name "*.db" -type f -exec stat -c %Y {} \; 2>/dev/null | sort -n | head -1)
                if [ -n "$db_age" ]; then
                    local age_days=$(( ( $(date +%s) - $db_age ) / 86400 ))
                    echo -e "${CYAN}[i] Cache DB: $db_size, updated $age_days days ago${NC}"
                fi
            fi
        else
            echo -e "${RED}[!] Error: Report is not a valid JSON file.${NC}"
        fi
    elif [ $res -ne 0 ]; then
        echo -e "\r${RED}[X] Scan failed (Exit code: $res).${NC}"
        [[ -f /tmp/audit_err.log ]] && cat /tmp/audit_err.log
        
        # Context-aware suggestions
        if grep -q "502 Bad Gateway" /tmp/audit_err.log 2>/dev/null; then
            echo -e "${CYAN}[i] Network error. Try option 4 (Cache only).${NC}"
        elif grep -q "out of date" /tmp/audit_err.log 2>/dev/null; then
            echo -e "${CYAN}[i] Vulnerability DB is out of date. Use option 5.${NC}"
        fi
    else
        echo -e "\r${RED}[X] Empty report or unknown error.${NC}"
    fi
}

# Manage Trivy vulnerability databases and image layer cache
manage_trivy_cache() {
    [[ ! -d "$TRIVY_CACHE_DIR" ]] && mkdir -p "$TRIVY_CACHE_DIR"

    # --- QUICK STATUS INFO ---
    echo -e "\n${BLUE}${BOLD}=== TRIVY CACHE MANAGEMENT ===${NC}"
    local db_file=$(find "$TRIVY_CACHE_DIR" -name "trivy.db" -type f 2>/dev/null | head -1)
    if [ -n "$db_file" ]; then
        local age_days=$(( ( $(date +%s) - $(stat -c %Y "$db_file") ) / 86400 ))
        local size=$(du -sh "$TRIVY_CACHE_DIR" | cut -f1)
        echo -e "${CYAN}[i] Current Cache: $size | DB updated: $age_days days ago${NC}"
    else
        echo -e "${ORANGE}[!] Database not found or incomplete.${NC}"
    fi

    echo -e "\n1) 🔄 Update Databases (Vuln + Java)"
    echo "2) 🧹 Clean Image Cache (Keep DBs)"
    echo "3) 🗑️  Clear EVERYTHING (Full Reset)"
    
    read -p "Selection [1-3]: " cache_choice
    
    case $cache_choice in
        1)
            echo -e "${YELLOW}[>] Syncing vulnerability definitions...${NC}"
            # Download vulnerability DB
            docker run --rm -v "$TRIVY_CACHE_DIR:/root/.cache" aquasec/trivy:latest image --download-db-only --quiet
            echo -e "${YELLOW}[>] Syncing Java database...${NC}"
            # Download Java index
            docker run --rm -v "$TRIVY_CACHE_DIR:/root/.cache" aquasec/trivy:latest image --download-java-db-only --quiet
            echo -e "${GREEN}[V] Databases ready for Online/Offline use.${NC}"
            ;;
        2)
            echo -e "${YELLOW}[>] Freeing up space from old layers...${NC}"
            docker run --rm -v "$TRIVY_CACHE_DIR:/root/.cache" aquasec/trivy:latest image --clean-cache
            echo -e "${GREEN}[V] Image cache cleared.${NC}"
            ;;
        3)
            read -p "Are you sure you want to reset the entire cache? (y/n): " confirm
            if [[ $confirm =~ ^[Yy]$ ]]; then
                rm -rf "$TRIVY_CACHE_DIR"/*
                echo -e "${RED}[-] Cache wiped.${NC}"
            fi
            ;;
        *) 
            echo -e "${RED}Operation cancelled.${NC}" 
            ;;
    esac
}

#### Benchmark ####

# Parse CIS Benchmark raw output into a structured report
parse_bench() {
    local report=$1
    local output_file="$BASE_REPORT_DIR/host/cis_audit_parsed_$DATE.txt"

    python3 -c "
import re

try:
    with open('$report', 'r') as f:
        lines = f.readlines()

    with open('$output_file', 'w') as out:
        out.write('CIS DOCKER BENCHMARK AUDIT REPORT\n' + '='*60 + '\n')
        
        for line in lines:
            line = line.strip()
            # Identify Sections
            if line.startswith('Section'):
                out.write(f'\n\n{line}\n' + '-'*40 + '\n')
            # Identify Results
            elif any(x in line for x in ['[PASS]', '[WARN]', '[NOTE]', '[INFO]']):
                # Clean ANSI colors if any
                clean_line = re.sub(r'\x1b\[[0-9;]*m', '', line)
                out.write(f'{clean_line}\n')

    print(f'   \033[0;32m[V] Structured report saved: $output_file\033[0m')
except Exception as e:
    print(f'   \033[0;31m[X] Error parsing benchmark: {str(e)}\033[0m')
"
}

# Execute CIS Docker Benchmark audit
run_bench() {
    local target_dir="$BASE_REPORT_DIR/host"
    local raw_report="$target_dir/cis_raw_$DATE.log"

    mkdir -p "$target_dir"
    
    echo -ne "${YELLOW}[>] Running CIS Docker Benchmark (Infrastructure Audit)...${NC}"
    
    # FIX: Removed /usr/bin mount to avoid overwriting container internal binaries
    docker run --rm --net host --pid host --userns host --cap-add audit_control \
        -v /etc:/etc:ro \
        -v /var/lib/docker:/var/lib/docker:ro \
        -v /var/run/docker.sock:/var/run/docker.sock \
        -v /lib/systemd:/lib/systemd:ro \
        docker/docker-bench-security > "$raw_report" 2> /tmp/audit_err.log &
    
    local pid=$!
    show_spinner "$pid"
    wait $pid

    if [ -s "$raw_report" ]; then
        echo -e "\r${GREEN}[V] Audit completed successfully.${NC}"
        
        echo -e "\n${BLUE}${BOLD}─── SECURITY SCAN SUMMARY (CRITICAL ITEMS) ───${NC}"
        # Filter for Warnings and Notes
        grep -E "\[WARN\]|\[NOTE\]" "$raw_report" | sed 's/\[WARN\]/ \x1b[31m[✘] WARN\x1b[0m/g' | sed 's/\[NOTE\]/ \x1b[33m[!] NOTE\x1b[0m/g' | head -15
        
        parse_bench "$raw_report"
    else
        echo -e "\r${RED}[X] Audit failed.${NC}"
        # Troubleshooting: if still failing, show logs
        [[ -f /tmp/audit_err.log ]] && cat /tmp/audit_err.log
    fi
}

# Strategic maintenance and cleanup module
cleanup_all() {
    echo -e "\n${BLUE}${BOLD}─── STRATEGIC CLEANUP MODULE ───${NC}"
    echo "1) 📂 Reports Only (Delete all JSON, TXT, LOGs)"
    echo "2) 🐋 Docker Soft Clean (Stopped containers & dangling layers)"
    echo "3) 🧹 Docker Deep Clean (Includes Build Cache & unused volumes)"
    echo "4) 📦 Security Tool Images (Trivy, Hadolint, Falco, Bench)"
    echo "5) 🧊 Purge Trivy DB/Cache (Free up storage)"
    echo "6) 🔥 FULL RESET (Wipe everything - requires confirmation)"
    echo "7) 🔙 Cancel"
    
    read -p "Selection [1-7]: " clean_choice
    
    case $clean_choice in
        1)
            echo -e "${YELLOW}[>] Deleting reports directory: $BASE_REPORT_DIR...${NC}"
            rm -rf "$BASE_REPORT_DIR"/*
            echo -e "${GREEN}[V] Reports deleted.${NC}"
            ;;
        2)
            echo -e "${YELLOW}[>] Removing stopped containers and dangling images...${NC}"
            docker container prune -f
            docker image prune -f
            echo -e "${GREEN}[V] Docker optimized.${NC}"
            ;;
        3)
            echo -e "${ORANGE}[>] Executing deep system prune (including volumes & cache)...${NC}"
            docker system prune -f --volumes
            echo -e "${GREEN}[V] Docker infrastructure reset.${NC}"
            ;;
        4)
            echo -e "${YELLOW}[>] Removing security tool images...${NC}"
            # Targeted removal of audit-specific images
            for tool in "${REQUIRED_IMAGES[@]}"; do
                docker rmi "$tool" 2>/dev/null
            done
            echo -e "${GREEN}[V] Audit images removed.${NC}"
            ;;
        5)
            echo -e "${YELLOW}[>] Clearing Trivy vulnerability databases: $TRIVY_CACHE_DIR...${NC}"
            rm -rf "$TRIVY_CACHE_DIR"/*
            echo -e "${GREEN}[V] Trivy cache wiped.${NC}"
            ;;
        6)
            echo -e "${RED}${BOLD}[!] WARNING: THIS WILL WIPE ALL REPORTS, TOOLS, AND DATA.${NC}"
            read -p "Type 'CONFIRM' to proceed: " final_check
            if [[ "$final_check" == "CONFIRM" ]]; then
                echo -e "${RED}[!] Executing total purge...${NC}"
                rm -rf "$BASE_REPORT_DIR"/*
                rm -rf "$TRIVY_CACHE_DIR"/*
                docker system prune -a -f --volumes
                echo -e "${GREEN}[V] System fully wiped.${NC}"
            else
                echo -e "${CYAN}[i] Operation cancelled.${NC}"
            fi
            ;;
        *)
            echo -e "${CYAN}[i] Exiting cleanup menu.${NC}"
            return
            ;;
    esac
}

# Display help and usage instructions
show_help() {
    echo -e "${BLUE}${BOLD}======================================================${NC}"
    echo -e "${BLUE}${BOLD}           CONTAINER SECURITY AUDIT TOOL              ${NC}"
    echo -e "${BLUE}${BOLD}======================================================${NC}"
    echo ""
    echo -e "${BOLD}Usage:${NC} $0 [option]"
    echo ""
    
    echo -e "${BOLD}🛠️  MANAGEMENT & CONFIGURATION:${NC}"
    echo -e "  ${CYAN}install${NC}         - Install dependencies (Hadolint, Trivy, Falco, etc.)"
    echo -e "  ${CYAN}--trivy-cache${NC}   - Manage vulnerability databases and cache"
    echo ""

    echo -e "${BOLD}🔍 STATIC ANALYSIS (Vulnerabilities & Best Practices):${NC}"
    echo -e "  ${CYAN}-d${NC}              - Analyze Dockerfile with Hadolint"
    echo -e "  ${CYAN}-i${NC}              - Interactive image scanning with Trivy"
    echo -e "  ${CYAN}-h${NC}              - CIS Docker Benchmark Audit (Host Hardening)"
    echo -e "  ${CYAN}-a${NC}              - Run full audit (Dockerfile + Image + CIS)"
    echo ""

    echo -e "${BOLD}🛡️  DYNAMIC ANALYSIS (Runtime Security):${NC}"
    echo -e "  ${CYAN}-f${NC}              - Manage Falco (Live Intrusion Detection)"
    echo ""

    echo -e "${BOLD}🧹 MAINTENANCE & PURGE:${NC}"
    echo -e "  ${CYAN}-c${NC}         - Modular cleanup menu (Reports, Docker, Cache)"
    echo -e "  ${CYAN}-u${NC}        - ${RED}${BOLD}TOTAL UNINSTALL${NC} (Deletes script, images, and data)"
    echo ""

    echo -e "${BOLD}Quick Flow Examples:${NC}"
    echo "  $0 -i                  # Scan a specific image"
    echo "  $0 -f                  # Live security event monitor"
    echo "  $0 --trivy-cache       # Update vulnerability DBs"
    echo -e "${GRAY}──────────────────────────────────────────────────────${NC}"
}

# Complete uninstallation and script self-destruction
delete_self() {
    echo -e "\n${RED}${BOLD}🚨 WARNING: FULL UNINSTALLATION 🚨${NC}"
    echo -e "${GRAY}────────────────────────────────────────────────────────────────────────────────${NC}"
    echo "This action is irreversible and will perform the following:"
    echo -e " 1. ${YELLOW}Purge${NC} all reports (JSON, TXT, Directories)."
    echo -e " 2. ${YELLOW}Removal${NC} of all audit tool images (Trivy, Hadolint, etc.)."
    echo -e " 3. ${YELLOW}Cleanup${NC} of build cache and temporary volumes."
    echo -e " 4. ${RED}${BOLD}Self-destruction${NC} of this script and local dependencies."
    echo -e "${GRAY}────────────────────────────────────────────────────────────────────────────────${NC}"
    
    read -p "Type 'DELETE ALL' to confirm: " confirm
    
    if [[ "$confirm" != "DELETE ALL" ]]; then
        echo -e "${CYAN}[i] Operation aborted. Your infrastructure remains intact.${NC}"
        return
    fi

    echo -e "\n${ORANGE}[>] Step 1: Starting deep resource purge...${NC}"
    # Silently wipe reports and docker resources
    rm -rf "$BASE_REPORT_DIR"
    docker system prune -a --volumes -f > /dev/null 2>&1

    echo -e "${ORANGE}[>] Step 2: Removing file traces...${NC}"
    # Resolve absolute path to ensure correct deletion
    local script_path
    script_path=$(readlink -f "$0")

    # Clean Trivy cache as well to leave zero footprint
    rm -rf "$TRIVY_CACHE_DIR" 2>/dev/null

    echo -e "${RED}[!] Self-destruction in progress...${NC}"
    
    # Background execution to allow the script to exit before the file is removed
    (sleep 1; rm -f "$script_path") &

    echo -e "\n${GREEN}${BOLD}[V] UNINSTALLATION SUCCESSFUL${NC}"
    echo -e "${CYAN}The infrastructure has been optimized and the script removed.${NC}"
    echo -e "${GRAY}Closing audit session...${NC}\n"

    exit 0
}

# Verify Docker Environment
check_env

# Argument Processing Logic
case "$1" in
    install)
        install_dependencies
        ;;
    -d)
        install_dependencies
        run_hadolint "$2"
        ;;
    -i)
        install_dependencies
        run_trivy "$2"
        ;;
    --trivy-cache)
        manage_trivy_cache
        ;;    

    -h)
        install_dependencies
        run_bench
        ;;
    -f)
        install_dependencies
        run_falco
    ;;

    -a)
        install_dependencies
        echo -e "${BLUE}=== EXECUTING FULL SECURITY AUDIT ===${NC}"
        run_hadolint
        echo ""
        run_trivy
        echo ""
        run_bench
        echo -e "${GREEN}=== FULL AUDIT COMPLETED ===${NC}"
        ;;
    -c)
        cleanup_all
        ;;
    -u)
        delete_self
        ;;
    *)
        show_help
        ;;
esac

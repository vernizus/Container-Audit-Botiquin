#!/bin/bash

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_REPORT_DIR="$SCRIPT_DIR/reports"
DATE=$(date +%Y%m%d_%H%M)

GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

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

check_env() {
    if ! docker ps > /dev/null 2>&1; then
        echo -e "${RED}[!] Error: Docker daemon is not running or insufficient permissions.${NC}"
        exit 1
    fi
    mkdir -p "$BASE_REPORT_DIR"
}

parse_hadolint() {
    local report=$1
    echo -e "${BLUE}--- Hadolint Security Analysis ---${NC}"
    while IFS= read -r line; do
        # Extraer el número de línea, la severidad y el mensaje
        # El formato original es -:LINE SEVERITY: MESSAGE
        local line_num=$(echo "$line" | cut -d':' -f2 | tr -d ' ')
        local content=$(echo "$line" | cut -d':' -f3-)

        if [[ "$line" == *"error"* ]]; then
            echo -e "${RED}[✘] Line $line_num - ERROR:${NC}${content#*error:}"
        elif [[ "$line" == *"warning"* ]]; then
            echo -e "${YELLOW}[!] Line $line_num - WARNING:${NC}${content#*warning:}"
        elif [[ "$line" == *"info"* ]]; then
            echo -e "${CYAN}[i] Line $line_num - INFO:${NC}${content#*info:}"
        else
            echo -e "    $line"
        fi
    done < "$report"
}

generate_report() {
    local category=$1
    local subfolder=$2
    local command=$3
    local target_dir="$BASE_REPORT_DIR/$category/$subfolder"
    local report_path="$target_dir/audit_$DATE.txt"

    mkdir -p "$target_dir"
    echo -ne "${YELLOW}[>] Auditing $category/$subfolder...${NC}"

    eval "$command" > "$report_path" 2> /tmp/audit_err.log &
    local pid=$!

    show_spinner "$pid"

    wait $pid
    if [ $? -eq 0 ]; then
        echo -e "\r${GREEN}[V] Success:${NC} $report_path"
        
        echo -ne "${CYAN}[?] Open report now? (y/N): ${NC}"
        read -n 1 -r
        echo ""
        
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            echo -e "${BLUE}------------------------------------------${NC}"
            if [[ "$category" == "linter" ]]; then
                parse_hadolint "$report_path"
            else
                if command -v less > /dev/null 2>&1; then
                    less -R "$report_path"
                else
                    cat "$report_path"
                fi
            fi
            
            echo -e "${BLUE}------------------------------------------${NC}"
        fi
    else
        echo -e "\r${RED}[X] Failed:${NC} Check /tmp/audit_err.log"
    fi
}

run_hadolint() {
    local file=$1
    if [ -z "$file" ]; then
        mapfile -t dockerfiles < <(find . -maxdepth 3 -type f \( -name "Dockerfile*" -o -name "*.dockerfile" \))
        if [ ${#dockerfiles[@]} -gt 0 ]; then
            echo -e "${YELLOW}[?] Select Dockerfile:${NC}"
            for i in "${!dockerfiles[@]}"; do echo -e "  $((i+1))) ${dockerfiles[$i]}"; done
            read -p "Selection (or 'm' for manual): " choice
            if [[ "$choice" =~ ^[0-9]+$ ]] && [[ "$choice" -le "${#dockerfiles[@]}" ]]; then
                file="${dockerfiles[$((choice-1))]}"
            else read -p "Enter path: " file; fi
        else read -p "Manual path: " file; fi
    fi
    if [ -f "$file" ]; then
        local safe_name=$(echo "$file" | sed 's/[\.\/]/_/g')
        # Cambiamos la imagen y añadimos '|| true' para que el script no crea que falló el comando
        generate_report "linter" "$safe_name" "docker run --rm -i ghcr.io/hadolint/hadolint < $file || true"
    fi
}

run_trivy() {
    local img=$1
    local extra_flags="--pkg-types os --scanners vuln --timeout 15m" 

    if [ -z "$img" ]; then
        mapfile -t images < <(docker images --format "{{.Repository}}:{{.Tag}}")
        echo -e "${YELLOW}[?] Select image:${NC}"
        for i in "${!images[@]}"; do echo -e "  $((i+1))) ${images[$i]}"; done
        read -p "Number: " choice
        img="${images[$((choice-1))]}"

        echo -e "${BLUE}--- Scan Strategy ---${NC}"
        echo "1) Full Scan (Slow)  2) OS Only (Fast)  3) OS + Secrets"
        read -p "Option: " opt
        case $opt in
            1) extra_flags="--timeout 20m" ;;
            3) extra_flags="--pkg-types os --scanners vuln,secret --timeout 15m" ;;
        esac
    fi

    local safe_name=$(echo "$img" | sed 's/[\/:]/_/g')
    generate_report "images" "$safe_name" "docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -v \$HOME/.cache/trivy:/root/.cache/ aquasec/trivy:latest image --severity HIGH,CRITICAL $extra_flags $img"
}

run_bench() {
    generate_report "host" "cis_benchmark" "docker run --rm --net host --pid host --userns host --cap-add audit_control -v /etc:/etc:ro -v /var/lib/docker:/var/lib/docker:ro -v /var/run/docker.sock:/var/run/docker.sock docker/docker-bench-security"
}

run_falco() {
    echo -e "${BLUE}--- Falco Management ---${NC}"
    echo "1) Status  2) Logs -> Report  3) Install"
    read -p "Option: " fopt
    case $fopt in
        1) docker ps --filter "name=falco" ;;
        2) generate_report "runtime" "falco_alerts" "docker logs falco" ;;
        3) docker run -d --name falco --privileged -v /var/run/docker.sock:/host/var/run/docker.sock -v /dev:/host/dev -v /proc:/host/proc:ro -v /boot:/host/boot:ro -v /lib/modules:/host/lib/modules:ro -v /usr:/host/usr:ro falcosecurity/falco:latest ;;
    esac
}

show_help() {
    echo -e "${BLUE}Structured Container Security Auditor v3.5${NC}"
    echo "Usage: $0 [options]"
    echo -e "  ${CYAN}-d${NC}  Dockerfile Linter (Hadolint)"
    echo -e "  ${CYAN}-i${NC}  Image Vulnerability Scan (Trivy)"
    echo -e "  ${CYAN}-h${NC}  Host Security Audit (Docker-Bench CIS)"
    echo -e "  ${CYAN}-f${NC}  Runtime Security (Falco)"
    echo -e "  ${CYAN}-o${NC}  Cleanup old reports (>30 days) and Docker prune"
    echo -e "  ${CYAN}-z${NC}  ZERO-TRUST MODE (Full Silent Audit)"
}

check_env

case "$1" in
    -d) run_hadolint "$2" ;;
    -i) run_trivy "$2" ;;
    -h) run_bench ;;
    -f) run_falco ;;
    -o)
        echo -e "${BLUE}--- Professional Cleanup Management ---${NC}"
        echo -e "1) Delete reports by age (Custom days)"
        echo -e "2) Standard Cleanup (Dangling images & Build cache)"
        echo -e "3) ${RED}Deep System Prune (Unused images, containers, networks)${NC}"
        echo -e "4) ${RED}Hard Reset (Clear ALL Trivy DB & Cache)${NC}"
        read -p "Select option [1-4]: " clean_opt

        case $clean_opt in
            1)
                read -p "Delete reports older than how many days? " days
                if [[ "$days" =~ ^[0-9]+$ ]]; then
                    find "$BASE_REPORT_DIR" -name "*.txt" -mtime +"$days" -delete
                    echo -e "${GREEN}[V] Reports older than $days days deleted.${NC}"
                else
                    echo -e "${RED}[!] Error: Please enter a valid number.${NC}"
                fi
                ;;
            2)
                echo -ne "${YELLOW}[>] Cleaning dangling images and build cache...${NC}"
                docker image prune -f > /dev/null
                docker builder prune -f > /dev/null
                echo -e "\r${GREEN}[V] Standard cleanup completed.${NC}"
                ;;
            3)
                echo -e "${RED}[!] WARNING: This will delete ALL unused images, stopped containers, and networks.${NC}"
                read -p "THIS ACTION CANNOT BE UNDONE. Are you sure? (y/N): " confirm
                if [[ "$confirm" == "y" || "$confirm" == "Y" ]]; then
                    echo -ne "${YELLOW}[>] Performing Deep Prune...${NC}"
                    docker system prune -a -f > /dev/null
                    echo -e "\r${GREEN}[V] Deep System Prune completed.${NC}"
                else
                    echo -e "${CYAN}[i] Action cancelled by user.${NC}"
                fi
                ;;
            4)
                echo -e "${RED}[!] WARNING: This will wipe the entire Trivy Database.${NC}"
                echo -e "You will need an internet connection to download the DB again on the next scan."
                read -p "Are you sure you want to clear the cache? (y/N): " confirm_trivy
                if [[ "$confirm_trivy" == "y" || "$confirm_trivy" == "Y" ]]; then
                    echo -ne "${YELLOW}[>] Wiping Trivy Cache...${NC}"
                    docker run --rm -v $HOME/.cache/trivy:/root/.cache/ aquasec/trivy:latest image --clear-cache > /dev/null
                    echo -e "\r${GREEN}[V] Trivy Cache is now empty.${NC}"
                else
                    echo -e "${CYAN}[i] Action cancelled.${NC}"
                fi
                ;;
            *)
                echo -e "${RED}[!] Invalid selection.${NC}"
                ;;
        esac
        ;;
    -z)
        echo -e "${RED}>>> STARTING FULL ZERO-TRUST AUDIT <<<${NC}"
        run_bench
        for img in $(docker images --format "{{.Repository}}:{{.Tag}}"); do
            run_trivy "$img"
        done
        echo -e "${BLUE}======================================================"
        echo -e "   AUDIT COMPLETED. Reports stored in $BASE_REPORT_DIR"
        echo -e "======================================================${NC}"
        ;;
    *) show_help ;;
esac

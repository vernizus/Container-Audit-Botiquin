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
        local code=$(echo "$line" | grep -oE '(DL|SC)[0-9]+')
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

parse_trivy() {
    local report_path=$1

    if [[ ! -f "$report_path" ]]; then
        echo -e "${RED}[!] Error: No se encontró el reporte JSON.${NC}"
        return
    fi

    echo -e "\n${ORANGE}${BOLD}─── ANALISIS ESTRATÉGICO: RIESGOS CRÍTICOS Y ALTOS ───${NC}"

    python3 -c "
import json

# Colores y Formato
RED = '\033[0;31m'; ORANGE = '\033[38;5;208m'; YELLOW = '\033[0;33m'
BLUE = '\033[0;34m'; GREEN = '\033[0;32m'; BOLD = '\033[1m'; NC = '\033[0m'
GRAY = '\033[38;5;250m' # Color gris para la descripción

try:
    with open('$report_path') as f:
        data = json.load(f)

    # Contadores para el resumen final
    stats = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
    found_urgent = False

    for result in data.get('Results', []):
        all_vulns = result.get('Vulnerabilities', [])
        
        # Actualizamos estadísticas globales
        for v in all_vulns:
            s = v.get('Severity', 'LOW')
            if s in stats: stats[s] += 1

        # Filtramos para mostrar solo lo urgente en pantalla
        urgent_vulns = [v for v in all_vulns if v.get('Severity') in ['CRITICAL', 'HIGH']]
        if not urgent_vulns: continue
        
        found_urgent = True
        target = result.get('Target', 'Unknown')
        print(f'\n{BOLD}📍 Componente:{NC} {BLUE}{target}{NC}')
        print(f'{GRAY}' + '─' * 70 + f'{NC}')

        for v in urgent_vulns:
            sev = v.get('Severity')
            v_id = v.get('VulnerabilityID', 'N/A')
            pkg = v.get('PkgName', 'N/A')
            fixed = v.get('FixedVersion', 'Parche no disponible')
            desc = v.get('Title', v.get('Description', 'Sin descripción detallada'))[:120] + '...'
            
            cvss = v.get('CVSS', {})
            score = cvss.get('nvd', {}).get('V3Score', cvss.get('redhat', {}).get('V3Score', 'N/A'))

            color = RED if sev == 'CRITICAL' else ORANGE
            
            print(f'{color}[{sev:<8}]{NC} (CVSS: {BOLD}{score}{NC}) | {BOLD}{pkg}{NC} | {v_id}')
            print(f'   {GRAY}ℹ️  {desc}{NC}')
            print(f'   {GREEN}└─ SOLUCIÓN:{NC} {fixed}')
            print(f'   {BLUE}└─ INFO:{NC} {v.get(\"PrimaryURL\", \"\")}\n')

    # --- RESUMEN FINAL AMABLE ---
    print(f'{BOLD}' + '═' * 70 + f'{NC}')
    print(f'{BOLD}📊 RESUMEN DE SEGURIDAD PARA EL ANALISTA:{NC}')
    
    total = sum(stats.values())
    if total > 0:
        print(f' Se han detectado un total de {BOLD}{total}{NC} vulnerabilidades:')
        print(f' 🛑 {RED}Críticas: {stats[\"CRITICAL\"]}{NC} (Prioridad Inmediata)')
        print(f' ⚠️  {ORANGE}Altas:    {stats[\"HIGH\"]}{NC} (Revisión Urgente)')
        print(f' 🟡 {YELLOW}Medias:   {stats[\"MEDIUM\"]}{NC} (Planificar Parcheo)')
        print(f' 🔵 {BLUE}Bajas:    {stats[\"LOW\"]}{NC} (Seguimiento)')
    else:
        print(f' ✨ {GREEN}¡Excelente trabajo! No se detectaron vulnerabilidades conocidas.{NC}')
    
    if stats['CRITICAL'] > 0:
        print(f'\n{RED}{BOLD}💡 RECOMENDACIÓN:{NC} Tienes riesgos críticos. Prioriza actualizar los componentes de {BOLD}stdlib{NC} y {BOLD}Python{NC}.')
    
except Exception as e:
    print(f'Error procesando el reporte: {e}')
"
    echo -e "\n${BLUE}📂 El log técnico completo sigue disponible en:${NC} $report_path\n"
}

generate_report() {
    local category=$1
    local subfolder=$2
    local command=$3 # Este es el comando de docker completo
    local target_dir="$BASE_REPORT_DIR/$category/$subfolder"
    local report_path="$target_dir/audit_$DATE.json"

    mkdir -p "$target_dir"
    echo -ne "${YELLOW}[>] Auditing $category/$subfolder...${NC}"

    # Exportamos para que el proceso hijo lo vea
    export REPORT_PATH="$report_path"

    # Ejecutamos y capturamos errores reales
    eval "$command" > /dev/null 2> /tmp/audit_err.log &
    
    local pid=$!
    show_spinner "$pid"
    wait $pid

    if [ $? -eq 0 ] && [ -s "$report_path" ]; then
        echo -e "\r${GREEN}[V] Success:${NC} $report_path"
        echo -ne "${CYAN}[?] Open summary now? (y/N): ${NC}"
        read -n 1 -r REPLY
        echo ""
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            echo -e "${BLUE}---------------- Summary Report ----------------${NC}"
            parse_trivy "$report_path"
            echo -e "${BLUE}-----------------------------------------------${NC}"
        fi
    else
        echo -e "\r${RED}[X] Failed or Empty:${NC}"
        echo -e "${RED}Consola Error:${NC}"
        [[ -f /tmp/audit_err.log ]] && cat /tmp/audit_err.log
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
    local common_flags="--cache-dir /root/.cache --quiet --format json"
    local extra_flags="--pkg-types os,library --scanners vuln --timeout 15m"

    if [ -z "$img" ]; then
        mapfile -t images < <(docker images --format "{{.Repository}}:{{.Tag}}" | grep -v "<none>")
        echo -e "${YELLOW}[?] Select image:${NC}"
        for i in "${!images[@]}"; do echo -e "  $((i+1))) ${images[$i]}"; done
        read -p "Number: " choice
        img="${images[$((choice-1))]}"

        echo -e "${BLUE}--- Scan Strategy ---${NC}"
        echo "1) Standard  2) Full + Secrets  3) Aggressive"
        read -p "Option: " opt
        case $opt in
            1) extra_flags="--pkg-types os,library --scanners vuln --timeout 10m" ;;
            2) extra_flags="--pkg-types os,library --scanners vuln,secret --timeout 15m" ;;
            3) extra_flags="--pkg-types os,library --scanners vuln --all-pkgs --timeout 20m" ;;
        esac
    fi

    local safe_name=$(echo "$img" | sed 's/[\/:]/_/g')
    
    # IMPORTANTE: Definimos el comando sin escapar el $ de REPORT_PATH aquí, 
    # dejamos que generate_report lo use directamente.
    local cmd="docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -v trivy-cache:/root/.cache aquasec/trivy image $common_flags $extra_flags $img > \"\$REPORT_PATH\""

    generate_report "images" "$safe_name" "$cmd"
}

run_bench() {
    generate_report "host" "cis_benchmark" "docker run --rm --net host --pid host --userns host --cap-add audit_control -v /etc:/etc:ro -v /var/lib/docker:/var/lib/docker:ro -v /var/run/docker.sock:/var/run/docker.sock docker/docker-bench-security"
}

# Función para detectar arquitectura y capacidad del kernel
detect_infrastructure() {
    local arch=$(uname -m)
    local kernel=$(uname -r)

    # Si es WSL2, el driver moderno a veces falla por falta de BTF en el kernel.
    # Vamos a intentar el modo de compatibilidad mas amplia.
    if [[ "$kernel" == *"microsoft"* ]]; then
        # En WSL2, a veces es mejor dejar que Falco intente cargar su propio modulo
        # o usar el motor 'ebpf' antiguo (no el 'modern_ebpf')
        echo "-o engine.name=ebpf"
    elif [[ "$arch" == "aarch64" ]]; then
        echo "-o engine.name=modern_ebpf"
    else
        echo "" # Default
    fi
}

run_falco() {
    echo -e "\n${BLUE}${BOLD}─── GESTIÓN DE SEGURIDAD MULTI-ARQUITECTURA (FALCO) ───${NC}"
    echo "1) Estado  2) Reporte Técnico  3) Desplegar Sensor (Auto)  4) Live"
    read -p "Opción: " fopt
    
    case $fopt in
        1) 
            echo -e "${YELLOW}[i] Verificando estado del proceso...${NC}"
            # Agregamos una tabla clara y verificamos si existe
            if [ "$(docker ps -aq -f name=falco)" ]; then
                docker ps --filter "name=falco" --format "table {{.Names}}\t{{.Status}}\t{{.Image}}"
            else
                echo -e "${RED}[!] Falco no está en ejecución.${NC}"
            fi
            read -p "Presione Enter para volver..." dummy # PAUSA NECESARIA
            ;;
        2) 
            echo -e "${YELLOW}[*] Generando informe de auditoría...${NC}"
            # Capturamos logs asegurando que traemos data real
            docker logs falco 2>&1 | grep -E "Notice|Warning|Error|Critical" > /tmp/falco_events.log
            
            if [ -s /tmp/falco_events.log ]; then
                generate_report "runtime" "falco_alerts" "cat /tmp/falco_events.log"
                echo -e "${GREEN}[V] Reporte guardado con éxito.${NC}"
            else
                echo -e "${ORANGE}[!] No hay eventos registrados. ¿Has probado a entrar en un contenedor?${NC}"
            fi
            read -p "Presione Enter para volver..." dummy
            ;;
        3) 
            local driver_flag=$(detect_infrastructure) 
            echo -e "${BLUE}[*] Realizando despliegue de alta visibilidad...${NC}"
            docker rm -f falco > /dev/null 2>&1
            
            # Añadimos mapeo de /run para los sockets de los contenedores
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

            sleep 5
            # Verificamos si realmente esta capturando algo
            if docker logs falco 2>&1 | grep -q "Loaded event sources: syscall"; then
                echo -e "${GREEN}[V] Sensor de llamadas al sistema ACTIVADO.${NC}"
            else
                echo -e "${RED}[X] El sensor no ha podido engancharse al Kernel.${NC}"
                echo -e "${YELLOW}Consejo: Ejecuta 'sudo apt install -y linux-headers-\$(uname -r)' en tu host.${NC}"
            fi
            read -p "Presione Enter..." dummy
            ;;
        4)
            if [ ! "$(docker ps -q -f name=falco)" ]; then
                echo -e "${RED}[!] Error: Falco no está corriendo. Ejecuta la opción 3 primero.${NC}"
            else
                echo -e "${RED}${BOLD}[!] MONITOR LIVE ACTIVO (Ctrl+C para salir)${NC}"
                # Filtramos el ruido inicial para ver solo alertas
                docker logs -f falco 2>&1 | grep -vE "libpman|libbpf|Config" --color=always
            fi
            ;;
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

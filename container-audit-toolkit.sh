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


# Directorio de cache para Trivy (INICIALIZACIÓN TEMPRANA)
TRIVY_CACHE_DIR="${TRIVY_CACHE_DIR:-$HOME/.cache/trivy}"
mkdir -p "$TRIVY_CACHE_DIR"

# Lista de imágenes Docker necesarias
REQUIRED_IMAGES=(
    "ghcr.io/hadolint/hadolint:latest"
    "aquasec/trivy:latest"
    "docker/docker-bench-security:latest"
    "falcosecurity/falco:latest"
)

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

install_dependencies() {
    local all_installed=true
    
    for image in "${REQUIRED_IMAGES[@]}"; do
        if ! docker image inspect "$image" > /dev/null 2>&1; then
            echo -ne "${CYAN}[i] Instalando ${image}...${NC}"
            
            if docker pull "$image" > /dev/null 2>&1; then
                echo -e "\r${GREEN}[V] ${image} instalado.${NC}"
            else
                echo -e "\r${RED}[X] Error al instalar ${image}${NC}"
                all_installed=false
            fi
        fi
    done
    
    if [ "$all_installed" = true ]; then
        return 0
    else
        echo -e "${RED}[!] Algunas dependencias fallaron${NC}"
        return 1
    fi
}

simple_docker_run() {
    local image=$1
    local output_file=$2
    shift 2
    
    # Ejecutar directamente sin wrapper complejo
    docker run --rm "$image" "$@" > "$output_file" 2> /tmp/audit_err.log
    return $?
}

docker_run_with_mount() {
    local image=$1
    local mount_arg=$2
    local output_file=$3
    shift 3
    
    # Ejecutar con montaje de volumen
    docker run --rm -v "$mount_arg" "$image" "$@" > "$output_file" 2> /tmp/audit_err.log
    return $?
}

##### Falco #####
detect_infrastructure() {
    local arch=$(uname -m)
    local kernel=$(uname -r)

    # WSL2 requiere compatibilidad específica
    if [[ "$kernel" == *"microsoft"* ]]; then
        echo "-o engine.name=ebpf"
    # Arquitecturas ARM (como AWS Graviton o Apple Silicon)
    elif [[ "$arch" == "aarch64" ]]; then
        echo "-o engine.name=modern_ebpf"
    # X86_64 con kernels modernos (>= 5.8) suelen soportar modern_ebpf
    else
        echo "-o engine.name=modern_ebpf"
    fi
}

parse_falco_logs() {
    local log_file="/tmp/falco_events.json"
    local output_file="$BASE_REPORT_DIR/runtime/falco_$(date +%Y%m%d_%H%M).txt"
    mkdir -p "$(dirname "$output_file")"

    if [[ ! -s "$log_file" ]]; then
        echo -e "${ORANGE}[!] No hay eventos de Falco para parsear.${NC}"
        return
    fi

    python3 -c "
import json
import sys

try:
    with open('$log_file', 'r') as f:
        with open('$output_file', 'w') as out:
            out.write('REPORTE DE EVENTOS EN TIEMPO REAL (FALCO)\n' + '='*60 + '\n\n')
            for line in f:
                try:
                    data = json.loads(line)
                    # Solo nos interesan alertas, no logs de sistema
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
    print(f'   {GREEN}[V] Reporte parseado: $output_file{NC}')
except Exception as e:
    print(f'   {RED}Error al parsear Falco: {str(e)}{NC}')
"
}

run_falco() {
    echo -e "\n${BLUE}${BOLD}─── RUNTIME SECURITY: DETECCIÓN DE INTRUSIONES (FALCO) ───${NC}"
    echo "1) 📊 Estado del Sensor"
    echo "2) 📝 Generar Reporte de Alertas (.txt)"
    echo "3) 🚀 Desplegar/Reiniciar Sensor"
    echo "4) 👁️  Monitor Live (Streaming)"
    read -p "Opción [1-4]: " fopt
    
    case $fopt in
        1) 
            if [ "$(docker ps -q -f name=falco)" ]; then
                echo -e "${GREEN}[V] Falco está activo.${NC}"
                docker ps --filter "name=falco" --format "table {{.Names}}\t{{.Status}}\t{{.Image}}"
            else
                echo -e "${RED}[!] Falco no está en ejecución.${NC}"
            fi
            ;;
        2) 
            echo -e "${YELLOW}[*] Extrayendo eventos del contenedor...${NC}"
            docker logs falco 2>&1 | grep "{" > /tmp/falco_events.json
            parse_falco_logs
            ;;
        3) 
            local driver_flag=$(detect_infrastructure) 
            echo -e "${BLUE}[*] Desplegando Falco con motor: ${driver_flag}...${NC}"
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
            
            echo -e "${YELLOW}[i] Esperando inicialización...${NC}"
            sleep 5
            if docker logs falco 2>&1 | grep -q "Loaded event sources: syscall"; then
                echo -e "${GREEN}[V] Sensor de Kernel operativo.${NC}"
            else
                echo -e "${RED}[X] Error: El sensor no pudo cargar el driver eBPF.${NC}"
                echo -e "${GRAY}Intenta: sudo apt install linux-headers-\$(uname -r)${NC}"
            fi
            ;;
        4)
            if [ ! "$(docker ps -q -f name=falco)" ]; then
                echo -e "${RED}[!] Error: Falco no está corriendo.${NC}"
            else
                echo -e "${RED}${BOLD}[!] MONITOR LIVE (Presiona Ctrl+C para volver al menú)${NC}"
                # Solo mostramos líneas con prioridad (alertas reales)
                docker logs -f falco 2>&1 | grep -E "Notice|Warning|Error|Critical" --color=always
            fi
            ;;
    esac
}


##### Hadolint ####
parse_hadolint() {
    local report=$1
    echo -e "${BLUE}--- Hadolint Security Analysis ---${NC}"
    
    if [ ! -s "$report" ]; then
        echo -e "${YELLOW}[!] No se encontraron issues.${NC}"
        return
    fi
    
    while IFS= read -r line; do
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

parse_trivy() {
    local report_path=$1
    local img_folder=$(basename "$report_path" | sed 's/_[0-9]\{8\}_[0-9]\{4,6\}\.json//')
    local target_dir="$(dirname "$report_path")/$img_folder"
    local txt_report="$target_dir/$(basename "${report_path%.json}.txt")"

    mkdir -p "$target_dir"

    python3 -c "
import json
import re

# Colores Terminal
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
            fix = v.get('FixedVersion', 'No disponible')
            
            if fix != 'No disponible':
                if is_lib: remediation_libs.add(f'{pkg} -> {fix}')
                else: remediation_os.add(pkg)

            vuln_obj = {
                'pkg': pkg, 'ver': v.get('InstalledVersion', 'N/A'),
                'id': v.get('VulnerabilityID', 'N/A'),
                'cvss': v.get('CVSS', {}).get('nvd', {}).get('V3Score', 'N/A'),
                'target': target, 'url': v.get('PrimaryURL', 'N/A'),
                'fix': fix, 'desc': v.get('Description', 'Sin descripción')
            }
            all_vulns[sev].append(vuln_obj)

    with open('$txt_report', 'w') as f_txt:
        f_txt.write(f'REPORTE DE SEGURIDAD: {artifact}\n' + '='*80 + '\n')

        # PROCESAR CADA SEVERIDAD PARA EL TXT
        for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            if not all_vulns[sev]: continue
            
            # Encabezado en pantalla (Solo Crit y High)
            if sev in ['CRITICAL', 'HIGH']:
                color = RED if sev == 'CRITICAL' else ORANGE
                icon = '🚨' if sev == 'CRITICAL' else '⚠️ '
                print(f'\n{color}{BOLD}{icon} {sev} ({len(all_vulns[sev])}):{NC}')
                print(f'{GRAY}{\"─\" * 80}{NC}')

            f_txt.write(f'\n[{sev}] TOTAL: {len(all_vulns[sev])}\n' + '-'*80 + '\n')

            for i, v in enumerate(all_vulns[sev], 1):
                # Escribir al TXT (Siempre)
                f_txt.write(f'{i}. {v[\"pkg\"]} ({v[\"ver\"]})\n')
                f_txt.write(f'   ID: {v[\"id\"]} | CVSS: {v[\"cvss\"]}\n')
                f_txt.write(f'   Componente: {v[\"target\"]}\n')
                f_txt.write(f'   Solución: {v[\"fix\"]}\n')
                f_txt.write(f'   URL: {v[\"url\"]}\n')
                f_txt.write(f'   Desc: {v[\"desc\"][:200]}...\n\n')

                # Mostrar en pantalla (Máximo 10 Crit/High)
                if sev in ['CRITICAL', 'HIGH'] and i <= 10:
                    color = RED if sev == 'CRITICAL' else ORANGE
                    print(f'{color}{BOLD}{i}. {v[\"pkg\"]} {v[\"ver\"]}{NC}')
                    print(f'   {GRAY}├─ ID: {v[\"id\"]} (CVSS: {v[\"cvss\"]}){NC}')
                    print(f'   {GRAY}├─ Link: {BLUE}\033]8;;{v[\"url\"]}\a{v[\"url\"]}\033]8;;\a{NC}')
                    print(f'   {GREEN}└─ SOLUCIÓN: {BOLD}{v[\"fix\"]}{NC}\n')
            
            if sev in ['CRITICAL', 'HIGH'] and len(all_vulns[sev]) > 10:
                print(f'{YELLOW}   ... y {len(all_vulns[sev])-10} más en el reporte TXT.{NC}')

        # PLAN DE ACCIÓN (SOLO EN TXT)
        f_txt.write('\n' + '='*80 + '\n🛠️  PLAN DE ACCIÓN SUGERIDO\n' + '='*80 + '\n')
        if remediation_os:
            os_family = data.get('Metadata', {}).get('OS', {}).get('Family', 'linux')
            mgr = 'apt-get install --only-upgrade' if os_family in ['debian', 'ubuntu'] else 'yum update -y'
            f_txt.write(f'\n[Infra/OS] Ejecutar:\n{mgr} ' + ' '.join(list(remediation_os)) + '\n')
        if remediation_libs:
            f_txt.write('\n[Apps/Librerías] Actualizar manualmente:\n' + '\n'.join(list(remediation_libs)) + '\n')

        # Resumen final en pantalla
        print(f'\n{BOLD}{\"=\" * 60}{NC}')
        print(f'📊 RESUMEN: {RED}Crit: {stats.get(\"CRITICAL\",0)}{NC} | {ORANGE}High: {stats.get(\"HIGH\",0)}{NC} | {YELLOW}Med: {stats.get(\"MEDIUM\",0)}{NC}')
        print(f'{BOLD}{\"=\" * 60}{NC}')

    print(f'\n\033[0;34m{BOLD}📂 REPORTE COMPLETO (Incluye Bajas y Plan de Acción):{NC}')
    print(f'\033[0;34m   $txt_report{NC}\n')

except Exception as e:
    print(f'{RED}Error procesando el reporte: {str(e)}{NC}')
"
    # --- GESTIÓN DEL ARCHIVO JSON ORIGINAL ---
    echo -e "\n${YELLOW}[?] ¿Deseas eliminar el archivo JSON original (el 'monstruo')? (s/n):${NC} "
    read -n 1 -r
    echo "" # Salto de línea después del input

    if [[ $REPLY =~ ^[Ss]$ ]]; then
        rm "$report_path"
        echo -e "${RED}[-] Archivo JSON eliminado para ahorrar espacio.${NC}"
    else
        local json_dir="$target_dir/json"
        mkdir -p "$json_dir"
        mv "$report_path" "$json_dir/"
        echo -e "${GREEN}[+] JSON preservado en: ${NC} $json_dir/$(basename "$report_path")"
    fi
}

run_hadolint() {
    local file=$1

    if [ -z "$file" ]; then
        echo -e "${CYAN}[*] Buscando Dockerfiles...${NC}"
        
        mapfile -t dockerfiles < <(find . -maxdepth 3 -type f \( -name "Dockerfile*" -o -name "*.dockerfile" \) 2>/dev/null)

        if [ ${#dockerfiles[@]} -gt 0 ]; then
            echo -e "${YELLOW}[?] Seleccione el archivo para auditar:${NC}"
            for i in "${!dockerfiles[@]}"; do 
                echo -e "  $((i+1))) ${dockerfiles[$i]}"
            done
            echo -e "  m) Ruta manual"
            
            read -p "Selección: " choice
            
            if [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -le "${#dockerfiles[@]}" ]; then
                file="${dockerfiles[$((choice-1))]}"
            elif [[ "$choice" == "m" ]]; then
                read -p "Introduce la ruta manual: " file
            else
                echo -e "${RED}[!] Selección inválida.${NC}"
                return
            fi
        else 
            echo -e "${ORANGE}[!] No se encontraron Dockerfiles.${NC}"
            read -p "Ruta manual: " file
        fi
    fi

    if [ -f "$file" ]; then
        local safe_name=$(basename "$file" | sed 's/[\.\/]/_/g')
        local abs_path=$(realpath "$file")
        local target_dir="$BASE_REPORT_DIR/linter"
        local report_path="$target_dir/${safe_name}_$DATE.log"

        mkdir -p "$target_dir"
        
        echo -ne "${YELLOW}[>] Analizando $file...${NC}"
        
        # Ejecutar Hadolint directamente
        docker run --rm -v "$abs_path:/Dockerfile:ro" ghcr.io/hadolint/hadolint:latest hadolint /Dockerfile > "$report_path" 2> /tmp/audit_err.log &
        
        local pid=$!
        show_spinner "$pid"
        wait $pid
        local res=$?

        if [ -s "$report_path" ]; then
            echo -e "\r${GREEN}[V] Análisis completado:${NC} $report_path"
            parse_hadolint "$report_path"
        elif [ $res -eq 0 ]; then
            echo -e "\r${GREEN}[V] ¡Perfecto! No se encontraron issues.${NC}"
        else
            echo -e "\r${RED}[X] Error en el análisis.${NC}"
            [[ -f /tmp/audit_err.log ]] && cat /tmp/audit_err.log
        fi
    else
        echo -e "${RED}[!] Archivo no encontrado: $file${NC}"
    fi
}

run_trivy() {
    local img=$1

    if [ -z "$img" ]; then
        mapfile -t images < <(docker images --format "{{.Repository}}:{{.Tag}}" | grep -v "<none>")
        
        if [ ${#images[@]} -eq 0 ]; then
            echo -e "${RED}[!] No hay imágenes Docker disponibles.${NC}"
            return
        fi
        
        echo -e "${YELLOW}[?] Selecciona una imagen:${NC}"
        for i in "${!images[@]}"; do 
            echo -e "  $((i+1))) ${images[$i]}"
        done
        
        read -p "Número: " choice
        
        if [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -le "${#images[@]}" ]; then
            img="${images[$((choice-1))]}"
        else
            echo -e "${RED}[!] Selección inválida.${NC}"
            return
        fi
    fi

    # Mostrar opciones de escaneo
    echo -e "\n${BLUE}=== OPCIONES DE ESCANEO TRIVY ===${NC}"
    echo "1) 🔍 Rápido (OS packages only)"
    echo "2) ⚡ Normal (OS + libraries, sin Java)"
    echo "3) 🔬 Completo (All packages, timeout extendido)"
    echo "4) 📊 Solo vulnerabilidades conocidas (usando cache)"
    echo "5) 🗑️  Forzar actualización DB (lento)"
    
    read -p "Selección [1-5]: " scan_choice
    
    local scan_flags="--format json --quiet"
    local cache_dir="${TRIVY_CACHE_DIR:-$HOME/.cache/trivy}"
    local cache_flags="-v $cache_dir:/root/.cache"
    local timeout_seconds=300
    
    case $scan_choice in
        1)
            # Rápido: solo paquetes del sistema operativo
            scan_flags="$scan_flags --scanners vuln --skip-dirs /usr/lib/jvm"
            echo -e "${CYAN}[i] Modo: Rápido (solo OS packages)${NC}"
            timeout_seconds=60
            ;;
        2)
            # Normal: OS + libraries, excluyendo Java que es lento
            scan_flags="$scan_flags --scanners vuln --skip-dirs /usr/lib/jvm --skip-files *.jar"
            echo -e "${CYAN}[i] Modo: Normal (sin Java)${NC}"
            timeout_seconds=120
            ;;
        3)
            # Completo: todo, con timeout extendido
            scan_flags="$scan_flags --scanners vuln --all-pkgs"
            echo -e "${CYAN}[i] Modo: Completo (puede tardar varios minutos)${NC}"
            timeout_seconds=600
            ;;
        4)
            # Solo usar cache existente
            scan_flags="$scan_flags --scanners vuln --skip-db-update"
            echo -e "${CYAN}[i] Modo: Solo cache (sin actualizar DB)${NC}"
            timeout_seconds=30
            ;;
        5)
            # Forzar actualización DB
            echo -e "${YELLOW}[>] Actualizando base de datos de vulnerabilidades...${NC}"
            docker run --rm $cache_flags aquasec/trivy:latest image --download-db-only > /dev/null 2>&1
            scan_flags="$scan_flags --scanners vuln"
            echo -e "${GREEN}[V] DB actualizada${NC}"
            timeout_seconds=180
            ;;
        *)
            echo -e "${RED}[!] Opción inválida, usando modo Normal${NC}"
            scan_flags="$scan_flags --scanners vuln --skip-dirs /usr/lib/jvm"
            ;;
    esac

    local safe_name=$(echo "$img" | sed 's/[\/:]/_/g')
    local target_dir="$BASE_REPORT_DIR/images"
    local report_path="$target_dir/${safe_name}_$DATE.json"

    mkdir -p "$target_dir"
    mkdir -p "$cache_dir"  # Asegurar que existe el directorio de cache
    
    echo -ne "${YELLOW}[>] Escaneando $img...${NC}"
    
    # Función para ejecutar con timeout
    scan_with_timeout() {
        timeout $timeout_seconds docker run --rm \
            $cache_flags \
            -v /var/run/docker.sock:/var/run/docker.sock \
            aquasec/trivy:latest image \
            $scan_flags \
            "$img"
    }
    
    # DEBUG: Mostrar comando si hay error
    # echo -e "\nDEBUG: docker run --rm $cache_flags -v /var/run/docker.sock:/var/run/docker.sock aquasec/trivy:latest image $scan_flags $img"
    
    # Ejecutar escaneo con timeout
    scan_with_timeout > "$report_path" 2> /tmp/audit_err.log &
    
    local pid=$!
    show_spinner "$pid"
    wait $pid
    local res=$?
    
    # Manejar diferentes códigos de salida
    if [ $res -eq 124 ]; then
        echo -e "\r${ORANGE}[!] Timeout ($timeout_seconds segundos). Escaneo interrumpido.${NC}"
        echo -e "${CYAN}[i] Usa la opción 5 para actualizar la DB o 4 para solo usar cache.${NC}"
        return
    elif [ $res -eq 125 ]; then
        # Error específico de timeout/docker
        echo -e "\r${RED}[X] Error de Docker (código: 125)${NC}"
        echo -e "${CYAN}[i] Problema con los volúmenes de Docker.${NC}"
        echo -e "${YELLOW}Comando fallido:${NC}"
        echo "docker run --rm $cache_flags -v /var/run/docker.sock:/var/run/docker.sock aquasec/trivy:latest image $scan_flags $img"
        [[ -f /tmp/audit_err.log ]] && cat /tmp/audit_err.log
        return
    elif [ $res -eq 0 ] && [ -s "$report_path" ]; then
        echo -e "\r${GREEN}[V] Escaneo completado:${NC} $report_path"
        
        # Verificar si el reporte es válido JSON
        if jq empty "$report_path" 2>/dev/null; then
            parse_trivy "$report_path"
            
            # Mostrar estadísticas de cache
            if [ -d "$cache_dir" ]; then
                local db_size=$(du -sh "$cache_dir" 2>/dev/null | cut -f1)
                local db_age=$(find "$cache_dir" -name "*.db" -type f -exec stat -c %Y {} \; 2>/dev/null | sort -n | head -1)
                if [ -n "$db_age" ]; then
                    local age_days=$(( ( $(date +%s) - $db_age ) / 86400 ))
                    echo -e "${CYAN}[i] Cache DB: $db_size, actualizada hace $age_days días${NC}"
                fi
            fi
        else
            echo -e "${RED}[!] Error: Reporte no es un JSON válido${NC}"
        fi
    elif [ $res -ne 0 ]; then
        echo -e "\r${RED}[X] Error en el escaneo (código: $res).${NC}"
        [[ -f /tmp/audit_err.log ]] && cat /tmp/audit_err.log
        
        # Sugerencia basada en el error
        if grep -q "502 Bad Gateway" /tmp/audit_err.log 2>/dev/null; then
            echo -e "${CYAN}[i] Error de red. Intenta con la opción 4 (solo cache).${NC}"
        elif grep -q "out of date" /tmp/audit_err.log 2>/dev/null; then
            echo -e "${CYAN}[i] La base de datos está desactualizada. Usa la opción 5.${NC}"
        fi
    else
        echo -e "\r${RED}[X] Reporte vacío o error desconocido.${NC}"
    fi
}

# Función adicional para gestionar la cache de Trivy
manage_trivy_cache() {
    [[ ! -d "$TRIVY_CACHE_DIR" ]] && mkdir -p "$TRIVY_CACHE_DIR"

    # --- INFO RÁPIDA DE ENTRADA ---
    echo -e "\n${BLUE}${BOLD}=== GESTIÓN DE CACHE TRIVY ===${NC}"
    local db_file=$(find "$TRIVY_CACHE_DIR" -name "trivy.db" -type f 2>/dev/null | head -1)
    if [ -n "$db_file" ]; then
        local age_days=$(( ( $(date +%s) - $(stat -c %Y "$db_file") ) / 86400 ))
        local size=$(du -sh "$TRIVY_CACHE_DIR" | cut -f1)
        echo -e "${CYAN}[i] Cache actual: $size | DB actualizada hace: $age_days días${NC}"
    else
        echo -e "${ORANGE}[!] Base de datos no encontrada o incompleta.${NC}"
    fi

    echo -e "\n1) 🔄 Actualizar Bases de Datos (Vuln + Java)"
    echo "2) 🧹 Limpiar Cache de Imágenes (Mantener DB)"
    echo "3) 🗑️  Borrar TODO (Reset completo)"
    
    read -p "Selección [1-3]: " cache_choice
    
    case $cache_choice in
        1)
            echo -e "${YELLOW}[>] Sincronizando vulnerabilidades...${NC}"
            # Ejecutamos por separado para evitar el error de flags
            docker run --rm -v "$TRIVY_CACHE_DIR:/root/.cache" aquasec/trivy:latest image --download-db-only --quiet
            echo -e "${YELLOW}[>] Sincronizando base de datos Java...${NC}"
            docker run --rm -v "$TRIVY_CACHE_DIR:/root/.cache" aquasec/trivy:latest image --download-java-db-only --quiet
            echo -e "${GREEN}[V] Bases de datos listas para uso Online/Offline.${NC}"
            ;;
        2)
            echo -e "${YELLOW}[>] Liberando espacio de capas antiguas...${NC}"
            docker run --rm -v "$TRIVY_CACHE_DIR:/root/.cache" aquasec/trivy:latest image --clean-cache
            echo -e "${GREEN}[V] Cache de imágenes limpiada.${NC}"
            ;;
        3)
            read -p "¿Estás seguro de resetear toda la cache? (s/n): " confirm
            if [[ $confirm =~ ^[Ss]$ ]]; then
                rm -rf "$TRIVY_CACHE_DIR"/*
                echo -e "${RED}[-] Todo borrado.${NC}"
            fi
            ;;
        *) echo -e "${RED}Opción cancelada.${NC}" ;;
    esac
}

run_bench() {
    local target_dir="$BASE_REPORT_DIR/host"
    local report_path="$target_dir/cis_benchmark_$DATE.log"

    mkdir -p "$target_dir"
    
    echo -ne "${YELLOW}[>] Ejecutando CIS Docker Benchmark...${NC}"
    
    docker run --rm --net host --pid host --userns host --cap-add audit_control \
        -v /etc:/etc:ro \
        -v /var/lib/docker:/var/lib/docker:ro \
        -v /var/run/docker.sock:/var/run/docker.sock \
        docker/docker-bench-security > "$report_path" 2> /tmp/audit_err.log &
    
    local pid=$!
    show_spinner "$pid"
    wait $pid

    if [ -s "$report_path" ]; then
        echo -e "\r${GREEN}[V] Benchmark completado:${NC} $report_path"
        
        # Mostrar resumen
        echo -e "\n${BLUE}=== RESUMEN CIS DOCKER BENCHMARK ===${NC}"
        grep -E "\[(PASS|WARN|INFO)\]" "$report_path" | head -20
        
        echo -e "\n${CYAN}[i] Ver reporte completo en: $report_path${NC}"
    else
        echo -e "\r${RED}[X] Error en el benchmark.${NC}"
        [[ -f /tmp/audit_err.log ]] && cat /tmp/audit_err.log
    fi
}

cleanup_all() {
    echo -e "\n${RED}${BOLD}=== MÓDULO DE LIMPIEZA ESTRATÉGICA ===${NC}"
    echo "1) 📂 Eliminar solo Reportes (JSON, TXT, PDF)"
    echo "2) 🐋 Limpieza de Docker (Contenedores parados y capas huérfanas)"
    echo "3) 🧹 Limpieza PROFUNDA de Docker (Incluye Caché de Build)"
    echo "4) 📦 Eliminar Imágenes de Auditoría (Trivy, Hadolint, etc.)"
    echo "5) 🔥 RESET TOTAL (Borrar todo lo anterior)"
    echo "6) 🔙 Cancelar"
    
    read -p "Selección [1-6]: " clean_choice
    
    case $clean_choice in
        1)
            echo -e "${YELLOW}[>] Eliminando directorio de reportes: $BASE_REPORT_DIR...${NC}"
            rm -rf "$BASE_REPORT_DIR"/*
            echo -e "${GREEN}[V] Reportes eliminados.${NC}"
            ;;
        2)
            echo -e "${YELLOW}[>] Limpiando contenedores y capas huérfanas (dangling)...${NC}"
            docker container prune -f
            docker image prune -f
            echo -e "${GREEN}[V] Docker optimizado.${NC}"
            ;;
        3)
            echo -e "${ORANGE}[>] Ejecutando limpieza profunda (incluye Build Cache)...${NC}"
            docker system prune -a --volumes -f
            echo -e "${GREEN}[V] Infraestructura Docker reseteada.${NC}"
            ;;
        4)
            echo -e "${YELLOW}[>] Eliminando imágenes de herramientas de seguridad...${NC}"
            # Usamos un set de herramientas conocidas para no borrar tus imágenes de producción
            local tools=("aquasec/trivy" "ghcr.io/hadolint/hadolint" "docker.io/aquasec/trivy")
            for tool in "${tools[@]}"; do
                docker rmi $(docker images -q "$tool") 2>/dev/null
            done
            echo -e "${GREEN}[V] Imágenes de herramientas eliminadas.${NC}"
            ;;
        5)
            read -p "⚠️ ESTO BORRARÁ TODO. ¿Escribir 'CONFIRMAR'? " final_check
            if [[ "$final_check" == "CONFIRMAR" ]]; then
                echo -e "${RED}[!] Ejecutando purga total...${NC}"
                rm -rf "$BASE_REPORT_DIR"
                docker system prune -a --volumes -f
                echo -e "${GREEN}[V] Sistema limpio.${NC}"
            else
                echo -e "${CYAN}[i] Operación cancelada.${NC}"
            fi
            ;;
        *)
            echo -e "${CYAN}[i] Saliendo del menú de limpieza.${NC}"
            return
            ;;
    esac
}

show_help() {
    echo -e "${BLUE}${BOLD}======================================================${NC}"
    echo -e "${BLUE}${BOLD}          CONTAINER SECURITY AUDIT TOOL               ${NC}"
    echo -e "${BLUE}${BOLD}======================================================${NC}"
    echo ""
    echo -e "${BOLD}Uso:${NC} $0 [opción]"
    echo ""
    
    echo -e "${BOLD}🛠️  GESTIÓN Y CONFIGURACIÓN:${NC}"
    echo -e "  ${CYAN}install${NC}         - Instalar dependencias (Hadolint, Trivy, Falco, etc.)"
    echo -e "  ${CYAN}--trivy-cache${NC}   - Gestionar bases de datos de vulnerabilidades y caché"
    echo ""

    echo -e "${BOLD}🔍 ANÁLISIS ESTÁTICO (Vulnerabilidades & Best Practices):${NC}"
    echo -e "  ${CYAN}-d${NC}              - Analizar Dockerfile con Hadolint"
    echo -e "  ${CYAN}-i${NC}              - Escaneo interactivo de imágenes con Trivy"
    echo -e "  ${CYAN}-h${NC}              - Auditoría CIS Docker Benchmark (Hardening del Host)"
    echo -e "  ${CYAN}-a${NC}              - Ejecutar auditoría completa (Dockerfile + Imagen + CIS)"
    echo ""

    echo -e "${BOLD}🛡️  ANÁLISIS DINÁMICO (Runtime Security):${NC}"
    echo -e "  ${CYAN}-f${NC}              - Gestionar Falco (Detección de intrusiones en vivo)"
    echo ""

    echo -e "${BOLD}🧹 MANTENIMIENTO Y PURGA:${NC}"
    echo -e "  ${CYAN}--clean${NC}         - Menú de limpieza modular (Reports, Docker, Caché)"
    echo -e "  ${CYAN}--delete${NC}        - ${RED}${BOLD}DESINSTALACIÓN TOTAL${NC} (Borra script, imágenes y datos)"
    echo ""

    echo -e "${BOLD}Ejemplos de flujo rápido:${NC}"
    echo "  $0 -i                  # Analizar imagen"
    echo "  $0 -f                  # Monitor de eventos en tiempo real"
    echo "  $0 --trivy-cache       # Actualizar DBs"
    echo -e "${GRAY}──────────────────────────────────────────────────────${NC}"
}

delete_self() {
    echo -e "\n${RED}${BOLD}🚨 ADVERTENCIA: DESINSTALACIÓN COMPLETA 🚨${NC}"
    echo -e "${GRAY}────────────────────────────────────────────────────────────────────────────────${NC}"
    echo "Esta acción es irreversible y realizará lo siguiente:"
    echo -e " 1. ${YELLOW}Purga${NC} de todos los reportes (JSON, TXT, Directorios)."
    echo -e " 2. ${YELLOW}Eliminación${NC} de imágenes de herramientas de auditoría (Trivy, Hadolint)."
    echo -e " 3. ${YELLOW}Limpieza${NC} de caché de construcción y volúmenes temporales."
    echo -e " 4. ${RED}${BOLD}Auto-destrucción${NC} de este script y sus dependencias locales."
    echo -e "${GRAY}────────────────────────────────────────────────────────────────────────────────${NC}"
    
    read -p "Escribe 'ELIMINAR TODO' para confirmar: " confirm
    
    if [[ "$confirm" != "ELIMINAR TODO" ]]; then
        echo -e "${CYAN}[i] Operación abortada. Tu infraestructura permanece intacta.${NC}"
        return
    fi

    echo -e "\n${ORANGE}[>] Paso 1: Iniciando limpieza profunda de recursos...${NC}"
    # Llamamos a la opción de reset total de tu cleanup_all de forma silenciosa
    # Si cleanup_all es interactiva, podrías pasarle un flag o ejecutar los comandos aquí directamente
    rm -rf "$BASE_REPORT_DIR"
    docker system prune -a --volumes -f > /dev/null 2>&1

    echo -e "${ORANGE}[>] Paso 2: Eliminando rastro de archivos...${NC}"
    # Obtenemos la ruta absoluta para asegurar la eliminación
    local script_path
    script_path=$(readlink -f "$0")

    # Si tienes algún archivo de configuración oculto (.trivy_config, etc.), añádelo aquí
    # rm -f "$HOME/.trivy_config" 2>/dev/null

    echo -e "${RED}[!] Auto-destrucción en progreso...${NC}"
    
    # El comando se ejecuta en segundo plano para permitir que el script termine de cerrarse
    (sleep 1; rm -f "$script_path") &

    echo -e "\n${GREEN}${BOLD}[V] DESINSTALACIÓN EXITOSA${NC}"
    echo -e "${CYAN}La infraestructura ha sido optimizada y el script eliminado.${NC}"
    echo -e "${GRAY}Cerrando sesión de auditoría...${NC}\n"

    exit 0
}

# Verificar Docker
check_env

# Procesar argumentos
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
        run_falco
    ;;

    -a)
        install_dependencies
        echo -e "${BLUE}=== EJECUTANDO AUDITORÍA COMPLETA ===${NC}"
        run_hadolint
        echo ""
        run_trivy
        echo ""
        run_bench
        echo -e "${GREEN}=== AUDITORÍA COMPLETADA ===${NC}"
        ;;
    --clean)
        cleanup_all
        ;;
    --delete)
        delete_self
        ;;
    *)
        show_help
        ;;
esac

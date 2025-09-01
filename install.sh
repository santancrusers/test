#!/bin/bash

# Color variables
red='\033[0;31m'
green='\033[0;32m'
yellow='\033[0;33m'
plain='\033[0m'

# Check if the script is run as root
# if [[ $EUID -ne 0 ]]; then
#   echo -e "${red}Fatal error: ${plain} Please run this script with root privilege \n"
#   exit 1
# fi

# Check if the OS is Ubuntu
if [[ -f /etc/os-release ]]; then
    source /etc/os-release
    if [[ $ID != "ubuntu" ]]; then
        echo -e "${red}This script is only for Ubuntu!${plain}\n"
        exit 1
    fi
else
    echo -e "${red}Failed to check the system OS, please contact the author!${plain}\n"
    exit 1
fi

# Install necessary packages

sleep 5

apt-get update && apt-get install -y wget curl tar tzdata unzip

# Determine the system's architecture
arch() {
    case "$(uname -m)" in
    x86_64 | x64 | amd64) echo 'amd64' ;;
    i*86 | x86) echo '386' ;;
    armv8* | armv8 | arm64 | aarch64) echo 'arm64' ;;
    armv7* | armv7 | arm) echo 'armv7' ;;
    armv6* | armv6) echo 'armv6' ;;
    armv5* | armv5) echo 'armv5' ;;
    s390x) echo 's390x' ;;
    *) echo -e "${red}Unsupported CPU architecture!${plain}" && exit 1 ;;
    esac
}

echo "arch: $(arch)"

install_x_ui() {
    cd /usr/local/

    # Set the desired version
    last_version="v2.4.11"
    echo -e "Installing x-ui version: ${last_version}..."

    # Download and extract x-ui
    wget -N --no-check-certificate -O /usr/local/x-ui-linux-$(arch).tar.gz \
        https://github.com/MHSanaei/3x-ui/releases/download/${last_version}/x-ui-linux-$(arch).tar.gz
    
    if [[ $? -ne 0 ]]; then
        echo -e "Error: Failed to download x-ui. Ensure that your server can access GitHub."
        exit 1
    fi

    # Remove previous installation if exists
    if [[ -e /usr/local/x-ui/ ]]; then
        systemctl stop x-ui
        rm -rf /usr/local/x-ui/
    fi

    tar zxvf x-ui-linux-$(arch).tar.gz
    rm -f x-ui-linux-$(arch).tar.gz
    cd x-ui
    chmod +x x-ui

    # Install the service
    cp -f x-ui.service /etc/systemd/system/
    wget --no-check-certificate -O /usr/bin/x-ui \
        https://raw.githubusercontent.com/MHSanaei/3x-ui/main/x-ui.sh
    chmod +x /usr/local/x-ui/x-ui.sh
    chmod +x /usr/bin/x-ui

    # Enable and start the service
    systemctl daemon-reload
    systemctl enable x-ui
    systemctl start x-ui
    echo -e "x-ui ${last_version} installation completed and is now running."
    
    sleep 5

    # Set the configuration
    /usr/local/x-ui/x-ui setting -username ali -password 1024Hetz
    /usr/local/x-ui/x-ui setting -port 54321
    /usr/local/x-ui/x-ui setting -webBasePath /letgodtrust

    echo -e "Configuration set: username=****, password=*****, port=54321, path=/letgodtrust"
    # echo -e "Access the x-ui panel at http://<your-server-ip>:54321 with username 'ali' and password '1024Hetz'."
}


install_rosaaa() {
  set -euo pipefail

  # ---- Config (safe for x-ui on :54321) ----
  local LOCAL_PORT="18080"                         # loopback only
  local HANDLER="/usr/local/bin/rosaaa_conn.sh"
  local SERVER="/usr/local/bin/rosaaa_server.sh"
  local SERVICE="/etc/systemd/system/rosaaa.service"
  local NGINX_SNIPPET="/etc/nginx/conf.d/rosaaa.conf"

  echo "[1/5] Install deps (curl, ncat via nmap, nginx)..."
  apt-get update -y
  DEBIAN_FRONTEND=noninteractive apt-get install -y curl nmap nginx

  echo "[2/5] Write per-connection handler..."
  cat > "${HANDLER}" <<'SH'
#!/usr/bin/env bash
set -euo pipefail

# Read request line and headers
read -r REQUEST_LINE || true
while IFS=$'\r' read -r line; do
  [[ -z "$line" ]] && break
done

METHOD=$(awk '{print $1}' <<< "$REQUEST_LINE")
PATH_REQ=$(awk '{print $2}' <<< "$REQUEST_LINE")

# Only respond to GET /Rosaaa
if [[ "${METHOD}" != "GET" || "${PATH_REQ}" != "/Rosaaa" ]]; then
  printf 'HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\nContent-Length: 9\r\n\r\nNot Found'
  exit 0
fi

# Random Android version + Samsung model
android_versions=("Android(30)" "Android(31)" "Android(32)" "Android(33)" "Android(34)" "Android(35)")
samsung_models=(
  "samsung,SM-S928B" "samsung,SM-S926B" "samsung,SM-S921B"
  "samsung,SM-S918B" "samsung,SM-S916B" "samsung,SM-S911B"
  "samsung,SM-S908B" "samsung,SM-G991B" "samsung,SM-G990E"
  "samsung,SM-A546B" "samsung,SM-A346B" "samsung,SM-A146P"
  "samsung,SM-M536B" "samsung,SM-M336B" "samsung,SM-F946B"
  "samsung,SM-F731B" "samsung,SM-F936B" "samsung,SM-F721B"
  "samsung,SM-T736B" "samsung,SM-X910"
)
av=${android_versions[$RANDOM % ${#android_versions[@]}]}
model=${samsung_models[$RANDOM % ${#samsung_models[@]}]}

# UUID v4
if [[ -r /proc/sys/kernel/random/uuid ]]; then
  uuid=$(cat /proc/sys/kernel/random/uuid)
elif command -v uuidgen >/dev/null 2>&1; then
  uuid=$(uuidgen)
else
  uuid=$(openssl rand -hex 16 | sed -E 's/^(.{8})(.{4})(.{4})(.{4})(.{12})$/\1-\2-\3-\4-\5/')
fi

UA="Rosa,127,${av},${model},en,${uuid},E6AB0A50F583A377BA3DC60C3C0471E71C912997E6593EFF6380592A1677F62F"
URL="https://ponderinparadox.com/api/v3/Raccoon/get-configuration"
PAYLOAD='{"connected":false,"segment":"Splash"}'

# Make upstream request (SSL verify on)
resp="$(curl -sS -X POST "$URL" \
  -H "Accept: */*" \
  -H "User-Agent: ${UA}" \
  -H "Content-Type: application/json" \
  --data "${PAYLOAD}" || true)"

# If fail, return 502
if [[ -z "${resp}" ]]; then
  body='{"ok":false,"error":"curl failed or empty response"}'
  printf 'HTTP/1.1 502 Bad Gateway\r\nContent-Type: application/json\r\nContent-Length: %s\r\n\r\n%s' "${#body}" "${body}"
  exit 0
fi

# Return JSON as-is
len=${#resp}
printf 'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %s\r\n\r\n' "$len"
printf '%s' "$resp"
SH
  chmod +x "${HANDLER}"

  echo "[3/5] Write local loopback server (127.0.0.1:${LOCAL_PORT})..."
  cat > "${SERVER}" <<SH
#!/usr/bin/env bash
set -euo pipefail
exec ncat -lk 127.0.0.1 -p ${LOCAL_PORT} -m 100 -c "${HANDLER}"
SH
  chmod +x "${SERVER}"

  echo "[4/5] Create/enable systemd service..."
  cat > "${SERVICE}" <<SYSTEMD
[Unit]
Description=Rosaaa mini HTTP endpoint (shell, behind nginx)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${SERVER}
Restart=always
RestartSec=2
User=root

[Install]
WantedBy=multi-user.target
SYSTEMD

  systemctl daemon-reload
  systemctl enable --now rosaaa.service

  echo "[5/5] Add nginx location /Rosaaa -> 127.0.0.1:${LOCAL_PORT} (no touch to x-ui:54321)..."
  mkdir -p /etc/nginx/conf.d
  cat > "${NGINX_SNIPPET}" <<NGINX
# Expose /Rosaaa on port 80/443 vhosts; safe for x-ui:54321
location = /Rosaaa {
    proxy_pass http://127.0.0.1:${LOCAL_PORT};
    proxy_http_version 1.1;
    proxy_set_header Connection "";
    proxy_set_header Host \$host;
    proxy_set_header X-Real-IP \$remote_addr;
    proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
}
NGINX

  nginx -t
  systemctl reload nginx

  echo
  echo "✅ Done. Test with:"
  echo "  curl -v http://\$(hostname -I | awk '{print \$1}')/Rosaaa"
  echo
  echo "Services:"
  echo "  - rosaaa.service (shell endpoint)     -> journalctl -u rosaaa -f"
  echo "  - nginx (proxy /Rosaaa to loopback)  -> systemctl reload nginx"
  echo
  echo "x-ui on :54321 is untouched."
}



generate_uuid_by_date() {
    local date="$1"
    echo -n "$date" | md5sum | awk '{print substr($1,1,8)"-"substr($1,9,4)"-"substr($1,13,4)"-"substr($1,17,4)"-"substr($1,21,12)}'
}


UUID_L1=$(generate_uuid_by_date "$(date -d '-1 day' +"%Y-%m-%d")")
UUID_L2=$(generate_uuid_by_date "$(date -d '-2 day' +"%Y-%m-%d")")
UUID_L3=$(generate_uuid_by_date "$(date -d '-3 day' +"%Y-%m-%d")")
UUID_L4=$(generate_uuid_by_date "$(date -d '-4 day' +"%Y-%m-%d")")
UUID_L5=$(generate_uuid_by_date "$(date -d '-5 day' +"%Y-%m-%d")")
UUID_L6=$(generate_uuid_by_date "$(date -d '-6 day' +"%Y-%m-%d")")
UUID_L7=$(generate_uuid_by_date "$(date -d '-7 day' +"%Y-%m-%d")")
UUID_L8=$(generate_uuid_by_date "$(date -d '-8 day' +"%Y-%m-%d")")
UUID_L9=$(generate_uuid_by_date "$(date -d '-9 day' +"%Y-%m-%d")")
UUID_L10=$(generate_uuid_by_date "$(date -d '-10 day' +"%Y-%m-%d")")
UUID_L11=$(generate_uuid_by_date "$(date -d '-11 day' +"%Y-%m-%d")")
UUID_L12=$(generate_uuid_by_date "$(date -d '-12 day' +"%Y-%m-%d")")
UUID_L13=$(generate_uuid_by_date "$(date -d '-13 day' +"%Y-%m-%d")")
UUID_L14=$(generate_uuid_by_date "$(date -d '-14 day' +"%Y-%m-%d")")
UUID_L15=$(generate_uuid_by_date "$(date -d '-15 day' +"%Y-%m-%d")")
UUID_T0=$(generate_uuid_by_date "$(date +"%Y-%m-%d")")
UUID_H1=$(generate_uuid_by_date "$(date -d '+1 day' +"%Y-%m-%d")")
UUID_H2=$(generate_uuid_by_date "$(date -d '+2 day' +"%Y-%m-%d")")
UUID_H3=$(generate_uuid_by_date "$(date -d '+3 day' +"%Y-%m-%d")")
UUID_H4=$(generate_uuid_by_date "$(date -d '+4 day' +"%Y-%m-%d")")
UUID_H5=$(generate_uuid_by_date "$(date -d '+5 day' +"%Y-%m-%d")")
UUID_H6=$(generate_uuid_by_date "$(date -d '+6 day' +"%Y-%m-%d")")
UUID_H7=$(generate_uuid_by_date "$(date -d '+7 day' +"%Y-%m-%d")")
UUID_H8=$(generate_uuid_by_date "$(date -d '+8 day' +"%Y-%m-%d")")
UUID_H9=$(generate_uuid_by_date "$(date -d '+9 day' +"%Y-%m-%d")")
UUID_H10=$(generate_uuid_by_date "$(date -d '+10 day' +"%Y-%m-%d")")
UUID_H11=$(generate_uuid_by_date "$(date -d '+11 day' +"%Y-%m-%d")")
UUID_H12=$(generate_uuid_by_date "$(date -d '+12 day' +"%Y-%m-%d")")
UUID_H13=$(generate_uuid_by_date "$(date -d '+13 day' +"%Y-%m-%d")")
UUID_H14=$(generate_uuid_by_date "$(date -d '+14 day' +"%Y-%m-%d")")
UUID_H15=$(generate_uuid_by_date "$(date -d '+15 day' +"%Y-%m-%d")")


generateStableUIDByServerIP() {
    # Get the server's IPv4 address
    local serverIP=$(hostname -I | awk '{for(i=1;i<=NF;i++) if($i ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) {print $i; exit}}')

    # Fallback if IPv4 is not found
    if [ -z "$serverIP" ]; then
        serverIP="127.0.0.1"
    fi

    # Generate MD5 hash from the IP
    local hash=$(echo -n "$serverIP" | md5sum | awk '{print $1}')

    # Format the hash into a UUID
    local uuid=$(printf "%08s-%04s-%04s-%04s-%12s" \
        "${hash:0:8}" \
        "${hash:8:4}" \
        "4${hash:12:3}" \
        "$(printf '%x' $(( (0x${hash:16:1} & 0x3) | 0x8 )))${hash:17:3}" \
        "${hash:20:12}")

    # Return the UUID
    echo "$uuid"
}


# Place cert.crt and private.key in the root directory
place_files() {
    cat <<EOF > /root/private.key
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIASLGIUis+v4MYr69gRJ0yifPwos35BSqavvzr1FllU3oAoGCCqGSM49
AwEHoUQDQgAEhliSHNJY1iviRXRrqSNHh4xvsf6zyPeQpzgI1t+MgTy0hmfvfta0
xgBM8tnMTQOL3lStNGEi3Qm+l9xPSkl7IA==
-----END EC PRIVATE KEY-----
EOF

    cat <<EOF > /root/cert.crt
-----BEGIN CERTIFICATE-----
MIIDqjCCAy+gAwIBAgISA4syGdvBJvtT4I8SEM/xsg25MAoGCCqGSM49BAMDMDIx
CzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNyeXB0MQswCQYDVQQDEwJF
NjAeFw0yNDA2MTIwMDEzMzRaFw0yNDA5MTAwMDEzMzNaMDAxLjAsBgNVBAMTJWgx
MDAxNzE4MDMzMzMzMy5lbmhhbmNlZGltYWdlc2FwaS5jb20wWTATBgcqhkjOPQIB
BggqhkjOPQMBBwNCAASGWJIc0ljWK+JFdGupI0eHjG+x/rPI95CnOAjW34yBPLSG
Z+9+1rTGAEzy2cxNA4veVK00YSLdCb6X3E9KSXsgo4ICJTCCAiEwDgYDVR0PAQH/
BAQDAgeAMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAMBgNVHRMBAf8E
AjAAMB0GA1UdDgQWBBQ4kRnLMdVBqso7a9+/+fnc9klFgTAfBgNVHSMEGDAWgBST
J0aYA6lRaI6Y1sRCSNsjv1iU0jBVBggrBgEFBQcBAQRJMEcwIQYIKwYBBQUHMAGG
FWh0dHA6Ly9lNi5vLmxlbmNyLm9yZzAiBggrBgEFBQcwAoYWaHR0cDovL2U2Lmku
bGVuY3Iub3JnLzAwBgNVHREEKTAngiVoMTAwMTcxODAzMzMzMzMuZW5oYW5jZWRp
bWFnZXNhcGkuY29tMBMGA1UdIAQMMAowCAYGZ4EMAQIBMIIBAgYKKwYBBAHWeQIE
AgSB8wSB8ADuAHUAPxdLT9ciR1iUHWUchL4NEu2QN38fhWrrwb8ohez4ZG4AAAGQ
CgHlAAAABAMARjBEAiByaWMtANs1WrqLffJdzoKKGlJs4jSWxUhF+SJs4fSfeQIg
D7zsTKYAfX/qZqH1F1GycXYHAnWkoFLUZ1yzJx0bk7QAdQB2/4g/Crb7lVHCYcz1
h7o0tKTNuyncaEIKn+ZnTFo6dAAAAZAKAeVFAAAEAwBGMEQCIHKN/2pehhaI22xm
dyERqRTWg4vW8fcHtb/2a6mQoYbAAiAMfa07gpD3ezOqBevi4OqYElVrC0WLPxmW
DrHDPsQg3DAKBggqhkjOPQQDAwNpADBmAjEA7xZxc3aLFOPoXB232+YTLUQQRgXq
Q+rAnU7WhsQAQtStcvQbtb/GAn0wucZY8QPXAjEAhJKile8vpzAByalNtbGe6Ya4
AwEExDT0n/0u5eVgzBo/iAvHA5IRZBRV4mn4NUH4
-----END CERTIFICATE-----

-----BEGIN CERTIFICATE-----
MIIEVzCCAj+gAwIBAgIRALBXPpFzlydw27SHyzpFKzgwDQYJKoZIhvcNAQELBQAw
TzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2Vh
cmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwHhcNMjQwMzEzMDAwMDAw
WhcNMjcwMzEyMjM1OTU5WjAyMQswCQYDVQQGEwJVUzEWMBQGA1UEChMNTGV0J3Mg
RW5jcnlwdDELMAkGA1UEAxMCRTYwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAATZ8Z5G
h/ghcWCoJuuj+rnq2h25EqfUJtlRFLFhfHWWvyILOR/VvtEKRqotPEoJhC6+QJVV
6RlAN2Z17TJOdwRJ+HB7wxjnzvdxEP6sdNgA1O1tHHMWMxCcOrLqbGL0vbijgfgw
gfUwDgYDVR0PAQH/BAQDAgGGMB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcD
ATASBgNVHRMBAf8ECDAGAQH/AgEAMB0GA1UdDgQWBBSTJ0aYA6lRaI6Y1sRCSNsj
v1iU0jAfBgNVHSMEGDAWgBR5tFnme7bl5AFzgAiIyBpY9umbbjAyBggrBgEFBQcB
AQQmMCQwIgYIKwYBBQUHMAKGFmh0dHA6Ly94MS5pLmxlbmNyLm9yZy8wEwYDVR0g
BAwwCjAIBgZngQwBAgEwJwYDVR0fBCAwHjAcoBqgGIYWaHR0cDovL3gxLmMubGVu
Y3Iub3JnLzANBgkqhkiG9w0BAQsFAAOCAgEAfYt7SiA1sgWGCIpunk46r4AExIRc
MxkKgUhNlrrv1B21hOaXN/5miE+LOTbrcmU/M9yvC6MVY730GNFoL8IhJ8j8vrOL
pMY22OP6baS1k9YMrtDTlwJHoGby04ThTUeBDksS9RiuHvicZqBedQdIF65pZuhp
eDcGBcLiYasQr/EO5gxxtLyTmgsHSOVSBcFOn9lgv7LECPq9i7mfH3mpxgrRKSxH
pOoZ0KXMcB+hHuvlklHntvcI0mMMQ0mhYj6qtMFStkF1RpCG3IPdIwpVCQqu8GV7
s8ubknRzs+3C/Bm19RFOoiPpDkwvyNfvmQ14XkyqqKK5oZ8zhD32kFRQkxa8uZSu
h4aTImFxknu39waBxIRXE4jKxlAmQc4QjFZoq1KmQqQg0J/1JF8RlFvJas1VcjLv
YlvUB2t6npO6oQjB3l+PNf0DpQH7iUx3Wz5AjQCi6L25FjyE06q6BZ/QlmtYdl/8
ZYao4SRqPEs/6cAiF+Qf5zg2UkaWtDphl1LKMuTNLotvsX99HP69V2faNyegodQ0
LyTApr/vT01YPE46vNsDLgK+4cL6TrzC/a4WcmF5SRJ938zrv/duJHLXQIku5v0+
EwOy59Hdm0PT/Er/84dDV0CSjdR/2XuZM3kpysSKLgD1cKiDA+IRguODCxfO9cyY
Ig46v9mFmBvyH04=
-----END CERTIFICATE-----
EOF

    echo -e "${green}cert.crt and private.key placed in the root directory.${plain}"
}

# Check if private.key and cert.crt exist, if not, call place_files again
check_and_place_files() {
    if [[ -f /root/private.key && -f /root/cert.crt ]]; then
        echo -e "${green}Files already exist.${plain}"
    else
        echo -e "${yellow}Files not found. Running place_files again...${plain}"
        place_files
    fi
}

API_URL="http://localhost:54321/letgodtrust/panel/api/inbounds/add"
COOKIE_FILE="cookies.txt"
STATIC_UUID="87d803c7-f879-478e-e1f2-738d804de98e"


generate_uuid_by_date() {
    local date="$1"
    echo -n "$date" | md5sum | awk '{print substr($1,1,8)"-"substr($1,9,4)"-"substr($1,13,4)"-"substr($1,17,4)"-"substr($1,21,12)}'
}



# Function to add configuration after login
add_config1() {
    echo "Waiting for 7 seconds before adding client configuration..."
    sleep 5

    # Perform login and capture the cookies
    response=$(curl -s -c cookies.txt -X POST 'http://localhost:54321/letgodtrust/login' \
    --header 'Content-Type: application/x-www-form-urlencoded' \
    --data-urlencode 'username=ali' \
    --data-urlencode 'password=1024Hetz')
    
    # Check if login was successful
    if echo "$response" | grep -q '"success":true'; then
        echo "Login successful with ali! Adding client configuration..."
    else
        echo "Login failed with ali. Retrying with admin..."
    
        # Attempt login with the admin user
        response=$(curl -s -c cookies.txt -X POST 'http://localhost:54321/letgodtrust/login' \
        --header 'Content-Type: application/x-www-form-urlencoded' \
        --data-urlencode 'username=admin' \
        --data-urlencode 'password=admin')
    
        if echo "$response" | grep -q '"success":true'; then
            echo "Login successful with admin! Adding client configuration..."
        else
            echo "Login failed with both ali and admin."
        fi
    fi
    
    
    

    # 8880 GRPC_DIRECT
    response=$(curl -b cookies.txt --location 'http://localhost:54321/letgodtrust/panel/api/inbounds/add' \
    --header 'Accept: application/json' \
    --header 'Content-Type: application/json' \
    --data '{"id":19,"userId":0,"up":0,"down":0,"total":0,"remark":"GRPC_DIRECT","enable":true,"expiryTime":0,"listen":"","port":8880,"protocol":"vless","settings":"{\n  \"clients\": [\n    {\n      \"id\": \"cfe554a3-4cd5-4fe1-9951-e6b65fc52a74\",\n      \"flow\": \"\",\n      \"email\": \"gdu0uf5f\",\n      \"limitIp\": 0,\n      \"totalGB\": 0,\n      \"expiryTime\": 0,\n      \"enable\": true,\n      \"tgId\": \"\",\n      \"subId\": \"qf8oecbrhur7zmqu\",\n      \"reset\": 0\n    }\n  ],\n  \"decryption\": \"none\",\n  \"fallbacks\": []\n}","streamSettings":"{\n  \"network\": \"grpc\",\n  \"security\": \"none\",\n  \"externalProxy\": [],\n  \"grpcSettings\": {\n    \"serviceName\": \"\",\n    \"authority\": \"\",\n    \"multiMode\": false\n  },\n  \"sockopt\": {\n    \"acceptProxyProtocol\": false,\n    \"tcpFastOpen\": false,\n    \"mark\": 0,\n    \"tproxy\": \"off\",\n    \"tcpMptcp\": false,\n    \"tcpNoDelay\": false,\n    \"domainStrategy\": \"UseIP\",\n    \"tcpMaxSeg\": 1440,\n    \"dialerProxy\": \"\",\n    \"tcpKeepAliveInterval\": 0,\n    \"tcpKeepAliveIdle\": 100,\n    \"tcpUserTimeout\": 10000,\n    \"tcpcongestion\": \"bbr\",\n    \"V6Only\": false,\n    \"tcpWindowClamp\": 600,\n    \"interface\": \"\"\n  }\n}","tag":"inbound-8880","sniffing":"{\n  \"enabled\": true,\n  \"destOverride\": [\n    \"http\",\n    \"tls\",\n    \"quic\",\n    \"fakedns\"\n  ],\n  \"metadataOnly\": false,\n  \"routeOnly\": false\n}","clientStats":[{"id":39,"inboundId":19,"enable":true,"email":"gdu0uf5f","up":0,"down":0,"expiryTime":0,"total":0,"reset":0}]}')

    if echo "$response" | grep -q '"success":true'; then
        echo -e "${green}Client configuration added successfully!${plain}"
    else
        echo -e "${red}Failed to add client configuration. Server responded with:${plain} $response"
    fi
    
    
    
    
    
    # 2087 GRPC_TLS
    response=$(curl -b cookies.txt --location 'http://localhost:54321/letgodtrust/panel/api/inbounds/add' \
    --header 'Accept: application/json' \
    --header 'Content-Type: application/json' \
    --data '{"id":3,"userId":0,"up":285114357,"down":8541356219,"total":0,"remark":"grpc","enable":true,"expiryTime":0,"listen":"","port":2087,"protocol":"vless","settings":"{\n  \"clients\": [\n    {\n      \"id\": \"d01a400e-7a33-4eb0-b39b-60db23be1d8d\",\n      \"flow\": \"\",\n      \"email\": \"dbnec53p\",\n      \"limitIp\": 0,\n      \"totalGB\": 0,\n      \"expiryTime\": 0,\n      \"enable\": true,\n      \"tgId\": 0,\n      \"subId\": \"gvok5pdhg3cjsn0g\",\n      \"reset\": 0\n    },\n    {\n      \"id\": \"401374e6-df77-41fb-f638-dad8184f175b\",\n      \"flow\": \"\",\n      \"email\": \"r1tkziih\",\n      \"limitIp\": 0,\n      \"totalGB\": 0,\n      \"expiryTime\": 0,\n      \"enable\": true,\n      \"tgId\": \"\",\n      \"subId\": \"16f037870ubdnfn4\",\n      \"reset\": 0\n    }\n  ],\n  \"decryption\": \"none\",\n  \"fallbacks\": []\n}","streamSettings":"{\n  \"network\": \"grpc\",\n  \"security\": \"tls\",\n  \"externalProxy\": [],\n  \"tlsSettings\": {\n    \"serverName\": \"\",\n    \"minVersion\": \"1.2\",\n    \"maxVersion\": \"1.3\",\n    \"cipherSuites\": \"\",\n    \"rejectUnknownSni\": false,\n    \"disableSystemRoot\": false,\n    \"enableSessionResumption\": false,\n    \"certificates\": [\n      {\n        \"certificateFile\": \"/root/cert.crt\",\n        \"keyFile\": \"/root/private.key\",\n        \"ocspStapling\": 3600,\n        \"oneTimeLoading\": false,\n        \"usage\": \"encipherment\",\n        \"buildChain\": false\n      }\n    ],\n    \"alpn\": [\n      \"h2\",\n      \"http/1.1\"\n    ],\n    \"settings\": {\n      \"allowInsecure\": false,\n      \"fingerprint\": \"\"\n    }\n  },\n  \"grpcSettings\": {\n    \"serviceName\": \"financialtribune.com.hamshahrionline.ir.alalamtv.net.donya-e-eqtesad.com.tehrantimes.com\",\n    \"authority\": \"\",\n    \"multiMode\": true\n  },\n  \"sockopt\": {\n    \"acceptProxyProtocol\": false,\n    \"tcpFastOpen\": false,\n    \"mark\": 0,\n    \"tproxy\": \"off\",\n    \"tcpMptcp\": false,\n    \"tcpNoDelay\": false,\n    \"domainStrategy\": \"UseIP\",\n    \"tcpMaxSeg\": 1440,\n    \"dialerProxy\": \"\",\n    \"tcpKeepAliveInterval\": 0,\n    \"tcpKeepAliveIdle\": 100,\n    \"tcpUserTimeout\": 10000,\n    \"tcpcongestion\": \"bbr\",\n    \"V6Only\": false,\n    \"tcpWindowClamp\": 600,\n    \"interface\": \"\"\n  }\n}","tag":"inbound-2087","sniffing":"{\n  \"enabled\": true,\n  \"destOverride\": [\n    \"http\",\n    \"tls\",\n    \"quic\",\n    \"fakedns\"\n  ],\n  \"metadataOnly\": false,\n  \"routeOnly\": false\n}","clientStats":[{"id":3,"inboundId":3,"enable":true,"email":"dbnec53p","up":17981926617,"down":368256308929,"expiryTime":0,"total":0,"reset":0},{"id":27,"inboundId":3,"enable":true,"email":"r1tkziih","up":0,"down":0,"expiryTime":0,"total":0,"reset":0}]}')

    if echo "$response" | grep -q '"success":true'; then
        echo -e "${green}Client configuration added successfully!${plain}"
    else
        echo -e "${red}Failed to add client configuration. Server responded with:${plain} $response"
    fi
    
    
    
    
    
    #Reality 80
    
        response=$(curl -b cookies.txt --location 'http://localhost:54321/letgodtrust/panel/api/inbounds/add' \
    --header 'Accept: application/json' \
    --header 'Content-Type: application/json' \
    --data '{"id":13,"userId":0,"up":0,"down":0,"total":0,"remark":"real","enable":true,"expiryTime":0,"listen":"","port":443,"protocol":"vless","settings":"{\n  \"clients\": [\n    {\n      \"id\": \"ef27e62d-91bd-4676-b9ce-8743a73eda07\",\n      \"flow\": \"\",\n      \"email\": \"76e5lrto\",\n      \"limitIp\": 0,\n      \"totalGB\": 0,\n      \"expiryTime\": 0,\n      \"enable\": true,\n      \"tgId\": \"\",\n      \"subId\": \"9uymgt1kvr0e29by\",\n      \"comment\": \"\",\n      \"reset\": 0\n    }\n  ],\n  \"decryption\": \"none\",\n  \"fallbacks\": []\n}","streamSettings":"{\n  \"network\": \"tcp\",\n  \"security\": \"reality\",\n  \"externalProxy\": [],\n  \"realitySettings\": {\n    \"show\": false,\n    \"xver\": 0,\n    \"dest\": \"zula.ir:443\",\n    \"serverNames\": [\n      \"zula.ir\",\n      \"www.zula.ir\"\n    ],\n    \"privateKey\": \"GOSsTz2NZzgas-D0Vwr7lT1uCUEu8la1bH2FetFrIEQ\",\n    \"minClient\": \"\",\n    \"maxClient\": \"\",\n    \"maxTimediff\": 0,\n    \"shortIds\": [\n      \"94aa1bdc\"\n    ],\n    \"settings\": {\n      \"publicKey\": \"JZ4tr79OsYphVtftVy6qv5mJ3XDtpyQi-ed3fqnq_RY\",\n      \"fingerprint\": \"chrome\",\n      \"serverName\": \"\",\n      \"spiderX\": \"/\"\n    }\n  },\n  \"tcpSettings\": {\n    \"acceptProxyProtocol\": false,\n    \"header\": {\n      \"type\": \"none\"\n    }\n  }\n}","tag":"inbound-443","sniffing":"{\n  \"enabled\": true,\n  \"destOverride\": [\n    \"http\",\n    \"tls\"\n  ],\n  \"metadataOnly\": false,\n  \"routeOnly\": false\n}","clientStats":[{"id":33,"inboundId":13,"enable":true,"email":"76e5lrto","up":8499,"down":26492,"expiryTime":0,"total":0,"reset":0}]}')

    if echo "$response" | grep -q '"success":true'; then
        echo -e "${green}Client configuration added successfully!${plain}"
    else
        echo -e "${red}Failed to add client configuration. Server responded with:${plain} $response"
    fi
    
    
    #HttpUpgrade 2052
    
            response=$(curl -b cookies.txt --location 'http://localhost:54321/letgodtrust/panel/api/inbounds/add' \
    --header 'Accept: application/json' \
    --header 'Content-Type: application/json' \
    --data '{"id":4,"userId":0,"up":41683779,"down":689369666,"total":0,"remark":"vyper3","enable":true,"expiryTime":0,"listen":"","port":2052,"protocol":"vmess","settings":"{\n  \"clients\": [\n    {\n      \"email\": \"682hyfdr\",\n      \"enable\": true,\n      \"expiryTime\": 0,\n      \"id\": \"16644f30-11ca-42cb-b278-f0ff3317ed68\",\n      \"limitIp\": 0,\n      \"reset\": 0,\n      \"subId\": \"brqxihcvli7b5ph9\",\n      \"tgId\": \"\",\n      \"totalGB\": 0\n    },\n    {\n      \"email\": \"ef7jm1k4\",\n      \"enable\": true,\n      \"expiryTime\": 0,\n      \"id\": \"d6431af0-247f-4d0d-a403-c65a055b97d1\",\n      \"limitIp\": 0,\n      \"reset\": 0,\n      \"subId\": \"fiju5bzenr27mpq9\",\n      \"tgId\": \"\",\n      \"totalGB\": 0\n    },\n    {\n      \"email\": \"aeexbqrw\",\n      \"enable\": true,\n      \"expiryTime\": 0,\n      \"id\": \"b9bb76b8-87fe-48be-9da1-c73b61a1e350\",\n      \"limitIp\": 0,\n      \"reset\": 0,\n      \"subId\": \"qyips9k431ejn77g\",\n      \"tgId\": \"\",\n      \"totalGB\": 0\n    },\n    {\n      \"email\": \"efzfjbyo\",\n      \"enable\": true,\n      \"expiryTime\": 0,\n      \"id\": \"0700e421-f42a-4683-8277-e5bfd062a000\",\n      \"limitIp\": 0,\n      \"reset\": 0,\n      \"subId\": \"bwj576py1ubx2xxy\",\n      \"tgId\": \"\",\n      \"totalGB\": 0\n    },\n    {\n      \"email\": \"hvu2jmlp\",\n      \"enable\": true,\n      \"expiryTime\": 0,\n      \"id\": \"82cc21cb-4708-410e-a5b8-2493f2f68f17\",\n      \"limitIp\": 0,\n      \"reset\": 0,\n      \"subId\": \"xpsq7nv75tg2tyi5\",\n      \"tgId\": \"\",\n      \"totalGB\": 0\n    },\n    {\n      \"email\": \"cmr8o87i\",\n      \"enable\": true,\n      \"expiryTime\": 0,\n      \"id\": \"f06578b3-4c14-4aed-a602-92a6ec954c20\",\n      \"limitIp\": 0,\n      \"reset\": 0,\n      \"subId\": \"1mmzoqbycpkk3i3u\",\n      \"tgId\": \"\",\n      \"totalGB\": 0\n    },\n    {\n      \"email\": \"by6e7ah0\",\n      \"enable\": true,\n      \"expiryTime\": 0,\n      \"id\": \"55d4e6d0-4199-4fe6-8fd1-0eba6b8a07fc\",\n      \"limitIp\": 0,\n      \"reset\": 0,\n      \"subId\": \"nzod23z5waj0ib3f\",\n      \"tgId\": \"\",\n      \"totalGB\": 0\n    },\n    {\n      \"email\": \"nblqrs8e\",\n      \"enable\": true,\n      \"expiryTime\": 0,\n      \"id\": \"d7b996e7-a918-4413-bffa-d20c5d2bfb4f\",\n      \"limitIp\": 0,\n      \"reset\": 0,\n      \"subId\": \"8yzsqcjpa173vin1\",\n      \"tgId\": \"\",\n      \"totalGB\": 0\n    },\n    {\n      \"email\": \"fdvy2iw0\",\n      \"enable\": true,\n      \"expiryTime\": 0,\n      \"id\": \"504117e2-514f-4349-9e34-0e34e08b3b58\",\n      \"limitIp\": 0,\n      \"reset\": 0,\n      \"subId\": \"2cb3firal12idm23\",\n      \"tgId\": \"\",\n      \"totalGB\": 0\n    },\n    {\n      \"email\": \"dgwp0qmp\",\n      \"enable\": true,\n      \"expiryTime\": 0,\n      \"id\": \"1c461b92-5e90-48bf-a957-c61975284695\",\n      \"limitIp\": 0,\n      \"reset\": 0,\n      \"subId\": \"04fx126zeuje2gc5\",\n      \"tgId\": \"\",\n      \"totalGB\": 0\n    },\n    {\n      \"email\": \"a2vu5lsi\",\n      \"enable\": true,\n      \"expiryTime\": 0,\n      \"id\": \"2ae59716-f5a4-4ce0-97ff-61f753fcffb1\",\n      \"limitIp\": 0,\n      \"reset\": 0,\n      \"subId\": \"d5xrfv7o21kac5ox\",\n      \"tgId\": \"\",\n      \"totalGB\": 0\n    },\n    {\n      \"email\": \"yoytwmyv\",\n      \"enable\": true,\n      \"expiryTime\": 0,\n      \"id\": \"eefaad65-ae38-4072-a4aa-b2bf66a643bc\",\n      \"limitIp\": 0,\n      \"reset\": 0,\n      \"subId\": \"extv9v50n1x3fd7u\",\n      \"tgId\": \"\",\n      \"totalGB\": 0\n    },\n    {\n      \"email\": \"h6ob9fan\",\n      \"enable\": true,\n      \"expiryTime\": 0,\n      \"id\": \"0d0e4f0c-ec00-4673-b0a6-7f7b370d3775\",\n      \"limitIp\": 0,\n      \"reset\": 0,\n      \"subId\": \"d1ntwhj6iyunqcw4\",\n      \"tgId\": \"\",\n      \"totalGB\": 0\n    },\n    {\n      \"email\": \"jrymgude\",\n      \"enable\": true,\n      \"expiryTime\": 0,\n      \"id\": \"b13768dc-ecdf-4601-8921-603c11088fdb\",\n      \"limitIp\": 0,\n      \"reset\": 0,\n      \"subId\": \"r71r304ayftpp5mm\",\n      \"tgId\": \"\",\n      \"totalGB\": 0\n    },\n    {\n      \"email\": \"8jddh91m\",\n      \"enable\": true,\n      \"expiryTime\": 0,\n      \"id\": \"9410310e-3411-4c41-bae1-2495e4126918\",\n      \"limitIp\": 0,\n      \"reset\": 0,\n      \"subId\": \"rytexpvwxwn6fgd3\",\n      \"tgId\": \"\",\n      \"totalGB\": 0\n    },\n    {\n      \"email\": \"qdf5ng9b\",\n      \"enable\": true,\n      \"expiryTime\": 0,\n      \"id\": \"b28085af-9cb3-4823-8578-ade3221685a6\",\n      \"limitIp\": 0,\n      \"reset\": 0,\n      \"subId\": \"qr9ou4n2ro2xabdr\",\n      \"tgId\": \"\",\n      \"totalGB\": 0\n    }\n  ]\n}","streamSettings":"{\n  \"network\": \"httpupgrade\",\n  \"security\": \"none\",\n  \"externalProxy\": [],\n  \"httpupgradeSettings\": {\n    \"acceptProxyProtocol\": false,\n    \"path\": \"/archheart-cultured-obtainable-utter-dacryocystotomy-psorospermosis?ed=2048\",\n    \"host\": \"\",\n    \"headers\": {}\n  }\n}","tag":"inbound-2052","sniffing":"{\n  \"enabled\": true,\n  \"destOverride\": [\n    \"http\",\n    \"tls\",\n    \"quic\",\n    \"fakedns\"\n  ],\n  \"metadataOnly\": false,\n  \"routeOnly\": false\n}","clientStats":[{"id":4,"inboundId":4,"enable":true,"email":"682hyfdr","up":5566650,"down":109001934,"expiryTime":0,"total":0,"reset":0},{"id":10,"inboundId":4,"enable":true,"email":"ef7jm1k4","up":2010647,"down":90715413,"expiryTime":0,"total":0,"reset":0},{"id":13,"inboundId":4,"enable":true,"email":"aeexbqrw","up":4863849,"down":66753710,"expiryTime":0,"total":0,"reset":0},{"id":14,"inboundId":4,"enable":true,"email":"efzfjbyo","up":1425376,"down":72945335,"expiryTime":0,"total":0,"reset":0},{"id":15,"inboundId":4,"enable":true,"email":"hvu2jmlp","up":7604990,"down":48672634,"expiryTime":0,"total":0,"reset":0},{"id":16,"inboundId":4,"enable":true,"email":"cmr8o87i","up":7233435,"down":136559717,"expiryTime":0,"total":0,"reset":0},{"id":17,"inboundId":4,"enable":true,"email":"by6e7ah0","up":1641007,"down":55057193,"expiryTime":0,"total":0,"reset":0},{"id":18,"inboundId":4,"enable":true,"email":"nblqrs8e","up":9482061,"down":234594526,"expiryTime":0,"total":0,"reset":0},{"id":19,"inboundId":4,"enable":true,"email":"fdvy2iw0","up":0,"down":0,"expiryTime":0,"total":0,"reset":0},{"id":20,"inboundId":4,"enable":true,"email":"dgwp0qmp","up":1296740,"down":34568129,"expiryTime":0,"total":0,"reset":0},{"id":21,"inboundId":4,"enable":true,"email":"a2vu5lsi","up":10359498,"down":210085581,"expiryTime":0,"total":0,"reset":0},{"id":22,"inboundId":4,"enable":true,"email":"yoytwmyv","up":7324076,"down":47575653,"expiryTime":0,"total":0,"reset":0},{"id":23,"inboundId":4,"enable":true,"email":"h6ob9fan","up":10214448,"down":257724833,"expiryTime":0,"total":0,"reset":0},{"id":24,"inboundId":4,"enable":true,"email":"jrymgude","up":7430233,"down":96188009,"expiryTime":0,"total":0,"reset":0},{"id":25,"inboundId":4,"enable":true,"email":"8jddh91m","up":196336303,"down":4488384710,"expiryTime":0,"total":0,"reset":0},{"id":26,"inboundId":4,"enable":true,"email":"qdf5ng9b","up":3345503,"down":12793025,"expiryTime":0,"total":0,"reset":0}]}')

    if echo "$response" | grep -q '"success":true'; then
        echo -e "${green}Client configuration added successfully!${plain}"
    else
        echo -e "${red}Failed to add client configuration. Server responded with:${plain} $response"
    fi
    
    
        #TLC 443
    
            response=$(curl -b cookies.txt --location 'http://localhost:54321/letgodtrust/panel/api/inbounds/add' \
    --header 'Accept: application/json' \
    --header 'Content-Type: application/json' \
    --data '{"id":1,"userId":0,"up":0,"down":0,"total":0,"remark":"444","enable":true,"expiryTime":0,"listen":"","port":444,"protocol":"vless","settings":"{\n  \"clients\": [\n    {\n      \"email\": \"mie69jgo\",\n      \"enable\": true,\n      \"expiryTime\": 0,\n      \"flow\": \"\",\n      \"id\": \"cef5a8b9-b045-4d30-e662-3b5f1c9448da\",\n      \"limitIp\": 0,\n      \"reset\": 0,\n      \"subId\": \"ux35ne1tuee398vw\",\n      \"tgId\": 0,\n      \"totalGB\": 0\n    },\n    {\n      \"email\": \"1dj5x8fc\",\n      \"enable\": true,\n      \"expiryTime\": 0,\n      \"flow\": \"\",\n      \"id\": \"a61eb3a2-1adb-48cb-ab46-ce225769de16\",\n      \"limitIp\": 0,\n      \"reset\": 0,\n      \"subId\": \"dxi9qlj7ypv11eu8\",\n      \"tgId\": \"\",\n      \"totalGB\": 0\n    },\n    {\n      \"email\": \"tge2rx2m\",\n      \"enable\": true,\n      \"expiryTime\": 0,\n      \"flow\": \"\",\n      \"id\": \"0dd1347e-e342-456c-b802-779b859cca42\",\n      \"limitIp\": 0,\n      \"reset\": 0,\n      \"subId\": \"st1gj7nivir9thf4\",\n      \"tgId\": \"\",\n      \"totalGB\": 0\n    }\n  ],\n  \"decryption\": \"none\",\n  \"fallbacks\": []\n}","streamSettings":"{\n  \"network\": \"ws\",\n  \"security\": \"tls\",\n  \"externalProxy\": [],\n  \"tlsSettings\": {\n    \"serverName\": \"\",\n    \"minVersion\": \"1.2\",\n    \"maxVersion\": \"1.3\",\n    \"cipherSuites\": \"\",\n    \"rejectUnknownSni\": false,\n    \"disableSystemRoot\": false,\n    \"enableSessionResumption\": false,\n    \"certificates\": [\n      {\n        \"certificateFile\": \"/root/cert.crt\",\n        \"keyFile\": \"/root/private.key\",\n        \"ocspStapling\": 3600,\n        \"oneTimeLoading\": false,\n        \"usage\": \"encipherment\"\n      }\n    ],\n    \"alpn\": [\n      \"h2\",\n      \"http/1.1\"\n    ],\n    \"settings\": {\n      \"allowInsecure\": false,\n      \"fingerprint\": \"\"\n    }\n  },\n  \"wsSettings\": {\n    \"acceptProxyProtocol\": false,\n    \"path\": \"/users?ed=2560\",\n    \"host\": \"\",\n    \"headers\": {}\n  }\n}","tag":"inbound-443","sniffing":"{\n  \"enabled\": true,\n  \"destOverride\": [\n    \"http\",\n    \"tls\",\n    \"quic\",\n    \"fakedns\"\n  ],\n  \"metadataOnly\": false,\n  \"routeOnly\": false\n}","clientStats":[{"id":1,"inboundId":1,"enable":true,"email":"mie69jgo","up":51459880,"down":879766817,"expiryTime":0,"total":0,"reset":0},{"id":31,"inboundId":1,"enable":true,"email":"1dj5x8fc","up":4249,"down":6155,"expiryTime":0,"total":0,"reset":0},{"id":32,"inboundId":1,"enable":true,"email":"tge2rx2m","up":198594,"down":709208,"expiryTime":0,"total":0,"reset":0}]}')

    if echo "$response" | grep -q '"success":true'; then
        echo -e "${green}Client configuration added successfully!${plain}"
    else
        echo -e "${red}Failed to add client configuration. Server responded with:${plain} $response"
    fi
    
    
    
    
    
    
    
    #DiGi8080
    
                 response=$(curl -b cookies.txt --location 'http://localhost:54321/letgodtrust/panel/api/inbounds/add' \
    --header 'Accept: application/json' \
    --header 'Content-Type: application/json' \
    --data '{"id":11,"userId":0,"up":12369595823,"down":295049832332,"total":0,"remark":"digi","enable":true,"expiryTime":0,"listen":"","port":8080,"protocol":"vless","settings":"{\n  \"clients\": [\n    {\n      \"comment\": \"\",\n      \"email\": \"first\",\n      \"enable\": true,\n      \"expiryTime\": 0,\n      \"flow\": \"\",\n      \"id\": \"87d803c7-f879-478e-e1f2-738d804de98e\",\n      \"limitIp\": 0,\n      \"reset\": 0,\n      \"subId\": \"5ldig5bt6rzwmj6q\",\n      \"tgId\": \"\",\n      \"totalGB\": 0\n    }\n  ],\n  \"decryption\": \"none\",\n  \"fallbacks\": []\n}","streamSettings":"{\n  \"network\": \"ws\",\n  \"security\": \"none\",\n  \"externalProxy\": [],\n  \"wsSettings\": {\n    \"acceptProxyProtocol\": false,\n    \"path\": \"/?ed=2048\",\n    \"host\": \"\",\n    \"headers\": {}\n  }\n}","tag":"inbound-8080","sniffing":"{\n  \"enabled\": true,\n  \"destOverride\": [\n    \"http\",\n    \"tls\"\n  ],\n  \"metadataOnly\": false,\n  \"routeOnly\": false\n}","clientStats":[{"id":48,"inboundId":11,"enable":true,"email":"first","up":0,"down":0,"expiryTime":0,"total":0,"reset":0}]}')

    if echo "$response" | grep -q '"success":true'; then
        echo -e "${green}Client configuration added successfully!${plain}"
    else
        echo -e "${red}Failed to add client configuration. Server responded with:${plain} $response"
    fi
    
    


    

    
        
    #Almi
    
                response=$(curl -b cookies.txt --location 'http://localhost:54321/letgodtrust/panel/api/inbounds/add' \
    --header 'Accept: application/json' \
    --header 'Content-Type: application/json' \
    --data '{"id":14,"userId":0,"up":905510,"down":17106486,"total":0,"remark":"2083","enable":true,"expiryTime":0,"listen":"","port":2083,"protocol":"vless","settings":"{\n  \"clients\": [\n    {\n      \"id\": \"9b60fb41-f70f-43fc-bb1a-8221d95e8234\",\n      \"flow\": \"\",\n      \"email\": \"h1t3thq9\",\n      \"limitIp\": 0,\n      \"totalGB\": 0,\n      \"expiryTime\": 0,\n      \"enable\": true,\n      \"tgId\": \"\",\n      \"subId\": \"pbd9iwz3lpvpwtho\",\n      \"reset\": 0\n    }\n  ],\n  \"decryption\": \"none\",\n  \"fallbacks\": []\n}","streamSettings":"{\n  \"network\": \"ws\",\n  \"security\": \"tls\",\n  \"externalProxy\": [],\n  \"tlsSettings\": {\n    \"serverName\": \"\",\n    \"minVersion\": \"1.2\",\n    \"maxVersion\": \"1.3\",\n    \"cipherSuites\": \"\",\n    \"rejectUnknownSni\": false,\n    \"disableSystemRoot\": false,\n    \"enableSessionResumption\": false,\n    \"certificates\": [\n      {\n        \"certificateFile\": \"/root/cert.crt\",\n        \"keyFile\": \"/root/private.key\",\n        \"ocspStapling\": 3600,\n        \"oneTimeLoading\": false,\n        \"usage\": \"encipherment\",\n        \"buildChain\": false\n      }\n    ],\n    \"alpn\": [\n      \"h3\",\n      \"h2\",\n      \"http/1.1\"\n    ],\n    \"settings\": {\n      \"allowInsecure\": false,\n      \"fingerprint\": \"\"\n    }\n  },\n  \"wsSettings\": {\n    \"acceptProxyProtocol\": false,\n    \"path\": \"/qhPF0ZVtjomc1TFn?ed=9595\",\n    \"host\": \"\",\n    \"headers\": {}\n  }\n}","tag":"inbound-2083","sniffing":"{\n  \"enabled\": false,\n  \"destOverride\": [\n    \"http\",\n    \"tls\",\n    \"quic\",\n    \"fakedns\"\n  ],\n  \"metadataOnly\": false,\n  \"routeOnly\": false\n}","clientStats":[{"id":34,"inboundId":14,"enable":true,"email":"h1t3thq9","up":2738441,"down":39394966,"expiryTime":0,"total":0,"reset":0}]}')

    if echo "$response" | grep -q '"success":true'; then
        echo -e "${green}Client configuration added successfully!${plain}"
    else
        echo -e "${red}Failed to add client configuration. Server responded with:${plain} $response"
    fi
    
    
    
    #Inject
    
    
    
    
    response=$(curl -b cookies.txt --location 'http://localhost:54321/letgodtrust/panel/api/inbounds/add' \
    --header 'Accept: application/json' \
    --header 'Content-Type: application/json' \
    --data '{"id":1,"userId":0,"up":265475812,"down":1166021605,"total":0,"remark":"test","enable":true,"expiryTime":0,"listen":"","port":43824,"protocol":"vless","settings":"{\n  \"clients\": [\n    {\n      \"id\": \"31a15bfc-4d3f-4fac-bae3-57b2c72692e8\",\n      \"flow\": \"\",\n      \"email\": \"3ywz0i95\",\n      \"limitIp\": 0,\n      \"totalGB\": 0,\n      \"expiryTime\": 0,\n      \"enable\": true,\n      \"tgId\": \"\",\n      \"subId\": \"zqrmqx7nqll1m54n\",\n      \"reset\": 0\n    }\n  ],\n  \"decryption\": \"none\",\n  \"fallbacks\": []\n}","streamSettings":"{\n  \"network\": \"tcp\",\n  \"security\": \"none\",\n  \"externalProxy\": [],\n  \"tcpSettings\": {\n    \"acceptProxyProtocol\": false,\n    \"header\": {\n      \"type\": \"none\"\n    }\n  },\n  \"sockopt\": {\n    \"acceptProxyProtocol\": false,\n    \"tcpFastOpen\": false,\n    \"mark\": 0,\n    \"tproxy\": \"off\",\n    \"tcpMptcp\": false,\n    \"tcpNoDelay\": true,\n    \"domainStrategy\": \"UseIP\",\n    \"tcpMaxSeg\": 1440,\n    \"dialerProxy\": \"proxy\",\n    \"tcpKeepAliveInterval\": 0,\n    \"tcpKeepAliveIdle\": 100,\n    \"tcpUserTimeout\": 10000,\n    \"tcpcongestion\": \"bbr\",\n    \"V6Only\": false,\n    \"tcpWindowClamp\": 600,\n    \"interface\": \"\"\n  }\n}","tag":"inbound-43824","sniffing":"{\n  \"enabled\": false,\n  \"destOverride\": [\n    \"http\",\n    \"tls\",\n    \"quic\",\n    \"fakedns\"\n  ],\n  \"metadataOnly\": false,\n  \"routeOnly\": false\n}","clientStats":[{"id":1,"inboundId":1,"enable":true,"email":"mie69jgo","up":51459880,"down":879766817,"expiryTime":0,"total":0,"reset":0},{"id":31,"inboundId":1,"enable":true,"email":"1dj5x8fc","up":4249,"down":6155,"expiryTime":0,"total":0,"reset":0},{"id":32,"inboundId":1,"enable":true,"email":"tge2rx2m","up":198594,"down":709208,"expiryTime":0,"total":0,"reset":0}]}')

    if echo "$response" | grep -q '"success":true'; then
        echo -e "${green}Client configuration added successfully!${plain}"
    else
        echo -e "${red}Failed to add client configuration. Server responded with:${plain} $response"
    fi
    
    
    
    
    #Emrgen
    
    
    

    
      response=$(curl -b cookies.txt --location 'http://localhost:54321/letgodtrust/panel/api/inbounds/add' \
    --header 'Accept: application/json' \
    --header 'Content-Type: application/json' \
    --data '{"id":17,"userId":0,"up":4090124,"down":91220556,"total":0,"remark":"2053","enable":true,"expiryTime":0,"listen":"","port":2053,"protocol":"vless","settings":"{\n  \"clients\": [\n    {\n      \"id\": \"5d50ca56-d248-4e15-bfd7-f5f3bc7e60e3\",\n      \"flow\": \"\",\n      \"email\": \"idii2hbt\",\n      \"limitIp\": 0,\n      \"totalGB\": 0,\n      \"expiryTime\": 0,\n      \"enable\": true,\n      \"tgId\": \"\",\n      \"subId\": \"8kdhyjablqeu0864\",\n      \"reset\": 0\n    }\n  ],\n  \"decryption\": \"none\",\n  \"fallbacks\": []\n}","streamSettings":"{\n  \"network\": \"ws\",\n  \"security\": \"tls\",\n  \"externalProxy\": [],\n  \"tlsSettings\": {\n    \"serverName\": \"\",\n    \"minVersion\": \"1.2\",\n    \"maxVersion\": \"1.3\",\n    \"cipherSuites\": \"\",\n    \"rejectUnknownSni\": false,\n    \"disableSystemRoot\": false,\n    \"enableSessionResumption\": false,\n    \"certificates\": [\n      {\n        \"certificateFile\": \"/root/cert.crt\",\n        \"keyFile\": \"/root/private.key\",\n        \"ocspStapling\": 3600,\n        \"oneTimeLoading\": false,\n        \"usage\": \"encipherment\",\n        \"buildChain\": false\n      }\n    ],\n    \"alpn\": [\n      \"h3\",\n      \"h2\",\n      \"http/1.1\"\n    ],\n    \"settings\": {\n      \"allowInsecure\": false,\n      \"fingerprint\": \"\"\n    }\n  },\n  \"wsSettings\": {\n    \"acceptProxyProtocol\": false,\n    \"path\": \"/?ed=2048\",\n    \"host\": \"\",\n    \"headers\": {}\n  }\n}","tag":"inbound-2053","sniffing":"{\n  \"enabled\": false,\n  \"destOverride\": [\n    \"http\",\n    \"tls\",\n    \"quic\",\n    \"fakedns\"\n  ],\n  \"metadataOnly\": false,\n  \"routeOnly\": false\n}","clientStats":[{"id":37,"inboundId":17,"enable":true,"email":"idii2hbt","up":4015109,"down":91082756,"expiryTime":0,"total":0,"reset":0}]}');
    if echo "$response" | grep -q '"success":true'; then
        echo -e "${green}Client configuration added successfully!${plain}"
    else
        echo -e "${red}Failed to add client configuration. Server responded with:${plain} $response"
    fi
    

    ///DNS

    

      response=$(curl -b cookies.txt --location 'http://localhost:54321/letgodtrust/panel/api/inbounds/add' \
    --header 'Accept: application/json' \
    --header 'Content-Type: application/json' \
    --data '{"id":22,"userId":0,"up":0,"down":0,"total":0,"remark":"2096","enable":true,"expiryTime":0,"listen":"","port":2096,"protocol":"vless","settings":"{\n  \"clients\": [\n    {\n      \"id\": \"96a1b724-68d2-4f4d-ab25-38ecd83577bc\",\n      \"flow\": \"\",\n      \"email\": \"4639s02u\",\n      \"limitIp\": 0,\n      \"totalGB\": 0,\n      \"expiryTime\": 0,\n      \"enable\": true,\n      \"tgId\": \"\",\n      \"subId\": \"5yq9banme5z8olss\",\n      \"comment\": \"\",\n      \"reset\": 0\n    },\n    {\n      \"id\": \"af4f91b3-29c2-46a2-b5ab-f7847a471584\",\n      \"flow\": \"\",\n      \"email\": \"w2brly8z\",\n      \"limitIp\": 0,\n      \"totalGB\": 0,\n      \"expiryTime\": 0,\n      \"enable\": true,\n      \"tgId\": \"\",\n      \"subId\": \"j4xe8etev7ob2x5m\",\n      \"comment\": \"\",\n      \"reset\": 0\n    },\n    {\n      \"id\": \"eacb47b5-844e-4e7d-9eaa-78708e447e85\",\n      \"flow\": \"\",\n      \"email\": \"fft5ksoh\",\n      \"limitIp\": 0,\n      \"totalGB\": 0,\n      \"expiryTime\": 0,\n      \"enable\": true,\n      \"tgId\": \"\",\n      \"subId\": \"g92h4h9epws0l8qe\",\n      \"comment\": \"\",\n      \"reset\": 0\n    },\n    {\n      \"id\": \"09d10073-18a7-45bb-8b10-fabfce8771a3\",\n      \"flow\": \"\",\n      \"email\": \"fl9j0vk7\",\n      \"limitIp\": 0,\n      \"totalGB\": 0,\n      \"expiryTime\": 0,\n      \"enable\": true,\n      \"tgId\": \"\",\n      \"subId\": \"5vidi3s0i7ivohv3\",\n      \"comment\": \"\",\n      \"reset\": 0\n    },\n    {\n      \"id\": \"bdaabd66-3962-431b-b9ad-e8275acff6f2\",\n      \"flow\": \"\",\n      \"email\": \"g73sn36r\",\n      \"limitIp\": 0,\n      \"totalGB\": 0,\n      \"expiryTime\": 0,\n      \"enable\": true,\n      \"tgId\": \"\",\n      \"subId\": \"ji6u00v5edy2p9bc\",\n      \"comment\": \"\",\n      \"reset\": 0\n    },\n    {\n      \"id\": \"aa690163-f024-4929-bbdd-14d6f9df69b1\",\n      \"flow\": \"\",\n      \"email\": \"03xubtm1\",\n      \"limitIp\": 0,\n      \"totalGB\": 0,\n      \"expiryTime\": 0,\n      \"enable\": true,\n      \"tgId\": \"\",\n      \"subId\": \"i4vxwcq7poeqhr8t\",\n      \"comment\": \"\",\n      \"reset\": 0\n    },\n    {\n      \"id\": \"8233c4c6-de1f-4a3f-9150-69cd5221ff31\",\n      \"flow\": \"\",\n      \"email\": \"qb6p7mlf\",\n      \"limitIp\": 0,\n      \"totalGB\": 0,\n      \"expiryTime\": 0,\n      \"enable\": true,\n      \"tgId\": \"\",\n      \"subId\": \"fm5k55g5pzk4o11z\",\n      \"comment\": \"\",\n      \"reset\": 0\n    },\n    {\n      \"id\": \"8b4832ba-c627-460c-9969-ca8ff37e2434\",\n      \"flow\": \"\",\n      \"email\": \"qkyfzasm\",\n      \"limitIp\": 0,\n      \"totalGB\": 0,\n      \"expiryTime\": 0,\n      \"enable\": true,\n      \"tgId\": \"\",\n      \"subId\": \"s5f97777f58iekul\",\n      \"comment\": \"\",\n      \"reset\": 0\n    },\n    {\n      \"id\": \"b71d1525-4c3c-456c-80d6-f3c0ddfe90f5\",\n      \"flow\": \"\",\n      \"email\": \"7lyypoit\",\n      \"limitIp\": 0,\n      \"totalGB\": 0,\n      \"expiryTime\": 0,\n      \"enable\": true,\n      \"tgId\": \"\",\n      \"subId\": \"gtmeesde9gs6fclc\",\n      \"comment\": \"\",\n      \"reset\": 0\n    },\n    {\n      \"id\": \"7fcf523e-bd28-41cf-af55-65092de58e2e\",\n      \"flow\": \"\",\n      \"email\": \"o6zr4ani\",\n      \"limitIp\": 0,\n      \"totalGB\": 0,\n      \"expiryTime\": 0,\n      \"enable\": true,\n      \"tgId\": \"\",\n      \"subId\": \"ix8mezpgpguc4omu\",\n      \"comment\": \"\",\n      \"reset\": 0\n    },\n    {\n      \"id\": \"538186c6-b630-4a6d-b446-33387a17f79e\",\n      \"flow\": \"\",\n      \"email\": \"3h3mjimh\",\n      \"limitIp\": 0,\n      \"totalGB\": 0,\n      \"expiryTime\": 0,\n      \"enable\": true,\n      \"tgId\": \"\",\n      \"subId\": \"1bchd2tc4c9syfiw\",\n      \"comment\": \"\",\n      \"reset\": 0\n    },\n    {\n      \"id\": \"476c2bb8-f3eb-4825-8e39-d02b0d9d294c\",\n      \"flow\": \"\",\n      \"email\": \"bkrqj6ur\",\n      \"limitIp\": 0,\n      \"totalGB\": 0,\n      \"expiryTime\": 0,\n      \"enable\": true,\n      \"tgId\": \"\",\n      \"subId\": \"m3vqinnyftcw4w6d\",\n      \"comment\": \"\",\n      \"reset\": 0\n    },\n    {\n      \"id\": \"e2dcbe14-5930-41bd-b47a-90b34049b0c2\",\n      \"flow\": \"\",\n      \"email\": \"md1klb61\",\n      \"limitIp\": 0,\n      \"totalGB\": 0,\n      \"expiryTime\": 0,\n      \"enable\": true,\n      \"tgId\": \"\",\n      \"subId\": \"fwa8bfsgwcqrvsao\",\n      \"comment\": \"\",\n      \"reset\": 0\n    },\n    {\n      \"id\": \"9876fa28-c224-4385-a398-4193eece8ea8\",\n      \"flow\": \"\",\n      \"email\": \"jnekdz6v\",\n      \"limitIp\": 0,\n      \"totalGB\": 0,\n      \"expiryTime\": 0,\n      \"enable\": true,\n      \"tgId\": \"\",\n      \"subId\": \"j2kizkgh9ln94hex\",\n      \"comment\": \"\",\n      \"reset\": 0\n    },\n    {\n      \"id\": \"67d82ee2-1c20-4dc1-bb4a-7e4ff64001d9\",\n      \"flow\": \"\",\n      \"email\": \"cl8negt4\",\n      \"limitIp\": 0,\n      \"totalGB\": 0,\n      \"expiryTime\": 0,\n      \"enable\": true,\n      \"tgId\": \"\",\n      \"subId\": \"yk6243xfcir1q8s3\",\n      \"comment\": \"\",\n      \"reset\": 0\n    },\n    {\n      \"id\": \"fa93e643-ed01-40c4-b82b-f38e9c2a841c\",\n      \"flow\": \"\",\n      \"email\": \"q53jd5dc\",\n      \"limitIp\": 0,\n      \"totalGB\": 0,\n      \"expiryTime\": 0,\n      \"enable\": true,\n      \"tgId\": \"\",\n      \"subId\": \"mfsmf4wm4dl9eany\",\n      \"comment\": \"\",\n      \"reset\": 0\n    },\n    {\n      \"id\": \"afc2332b-9bfb-417f-89e1-14041e580eef\",\n      \"flow\": \"\",\n      \"email\": \"fwv6q95j\",\n      \"limitIp\": 0,\n      \"totalGB\": 0,\n      \"expiryTime\": 0,\n      \"enable\": true,\n      \"tgId\": \"\",\n      \"subId\": \"x5cnugu8n7sq8j50\",\n      \"comment\": \"\",\n      \"reset\": 0\n    },\n    {\n      \"id\": \"1be28e71-b95d-4b2f-927b-85fcc064d856\",\n      \"flow\": \"\",\n      \"email\": \"1zb7nfkb\",\n      \"limitIp\": 0,\n      \"totalGB\": 0,\n      \"expiryTime\": 0,\n      \"enable\": true,\n      \"tgId\": \"\",\n      \"subId\": \"98oahr6m72a0nmxi\",\n      \"comment\": \"\",\n      \"reset\": 0\n    },\n    {\n      \"id\": \"ca20d3ec-5619-4481-a5df-8b7a178fac28\",\n      \"flow\": \"\",\n      \"email\": \"kt9eidbm\",\n      \"limitIp\": 0,\n      \"totalGB\": 0,\n      \"expiryTime\": 0,\n      \"enable\": true,\n      \"tgId\": \"\",\n      \"subId\": \"dfku6a5rdyvz77o8\",\n      \"comment\": \"\",\n      \"reset\": 0\n    },\n    {\n      \"id\": \"de9ab1e4-5fbf-4987-8331-dce7cada119a\",\n      \"flow\": \"\",\n      \"email\": \"6xhkmatl\",\n      \"limitIp\": 0,\n      \"totalGB\": 0,\n      \"expiryTime\": 0,\n      \"enable\": true,\n      \"tgId\": \"\",\n      \"subId\": \"q9xeymqnlztnlqon\",\n      \"comment\": \"\",\n      \"reset\": 0\n    },\n    {\n      \"id\": \"17ce5ee4-77f3-46af-ba42-d183c318091f\",\n      \"flow\": \"\",\n      \"email\": \"ajyblevp\",\n      \"limitIp\": 0,\n      \"totalGB\": 0,\n      \"expiryTime\": 0,\n      \"enable\": true,\n      \"tgId\": \"\",\n      \"subId\": \"18g9qs7edyi1vnil\",\n      \"comment\": \"\",\n      \"reset\": 0\n    },\n    {\n      \"id\": \"ec11d295-fc4a-4075-a074-2faa999e69c6\",\n      \"flow\": \"\",\n      \"email\": \"oppdbmk2\",\n      \"limitIp\": 0,\n      \"totalGB\": 0,\n      \"expiryTime\": 0,\n      \"enable\": true,\n      \"tgId\": \"\",\n      \"subId\": \"11ah7xju4eu33n7x\",\n      \"comment\": \"\",\n      \"reset\": 0\n    },\n    {\n      \"id\": \"a2fef2c3-c425-42ef-87af-45ac8662109a\",\n      \"flow\": \"\",\n      \"email\": \"a64ugrzo\",\n      \"limitIp\": 0,\n      \"totalGB\": 0,\n      \"expiryTime\": 0,\n      \"enable\": true,\n      \"tgId\": \"\",\n      \"subId\": \"861shymj5seqyuzt\",\n      \"comment\": \"\",\n      \"reset\": 0\n    },\n    {\n      \"id\": \"d7cd77de-1223-4fad-b92a-97b0a461093a\",\n      \"flow\": \"\",\n      \"email\": \"0nwir5xx\",\n      \"limitIp\": 0,\n      \"totalGB\": 0,\n      \"expiryTime\": 0,\n      \"enable\": true,\n      \"tgId\": \"\",\n      \"subId\": \"6845xf0vkcjx7ajx\",\n      \"comment\": \"\",\n      \"reset\": 0\n    },\n    {\n      \"id\": \"18cfbe21-2558-429a-878d-624cbfc42e96\",\n      \"flow\": \"\",\n      \"email\": \"yrjcgq0g\",\n      \"limitIp\": 0,\n      \"totalGB\": 0,\n      \"expiryTime\": 0,\n      \"enable\": true,\n      \"tgId\": \"\",\n      \"subId\": \"gtmv54scld5p5071\",\n      \"comment\": \"\",\n      \"reset\": 0\n    },\n    {\n      \"id\": \"a138470a-1dc3-4ec6-93b2-ef337d3c9c9a\",\n      \"flow\": \"\",\n      \"email\": \"53ry2evf\",\n      \"limitIp\": 0,\n      \"totalGB\": 0,\n      \"expiryTime\": 0,\n      \"enable\": true,\n      \"tgId\": \"\",\n      \"subId\": \"vshpu2ouvc7oumzn\",\n      \"comment\": \"\",\n      \"reset\": 0\n    },\n    {\n      \"id\": \"e60f9b6c-486e-417d-88a8-a34b1f4c83e5\",\n      \"flow\": \"\",\n      \"email\": \"0x2v41ud\",\n      \"limitIp\": 0,\n      \"totalGB\": 0,\n      \"expiryTime\": 0,\n      \"enable\": true,\n      \"tgId\": \"\",\n      \"subId\": \"nxql1jl8w1j1c9j3\",\n      \"comment\": \"\",\n      \"reset\": 0\n    },\n    {\n      \"id\": \"d2d385ae-c077-4e99-a7cc-567a8105bd68\",\n      \"flow\": \"\",\n      \"email\": \"tzi4e9n4\",\n      \"limitIp\": 0,\n      \"totalGB\": 0,\n      \"expiryTime\": 0,\n      \"enable\": true,\n      \"tgId\": \"\",\n      \"subId\": \"n8gru2virpw6ejna\",\n      \"comment\": \"\",\n      \"reset\": 0\n    },\n    {\n      \"id\": \"4cea125d-b9f3-4da4-b948-8b4e58bcc091\",\n      \"flow\": \"\",\n      \"email\": \"0m4qn22q\",\n      \"limitIp\": 0,\n      \"totalGB\": 0,\n      \"expiryTime\": 0,\n      \"enable\": true,\n      \"tgId\": \"\",\n      \"subId\": \"bl0tpcgx65ex2zlb\",\n      \"comment\": \"\",\n      \"reset\": 0\n    },\n    {\n      \"id\": \"69ec343c-28a7-4f58-a315-c57d69cc15c6\",\n      \"flow\": \"\",\n      \"email\": \"w70wyps1\",\n      \"limitIp\": 0,\n      \"totalGB\": 0,\n      \"expiryTime\": 0,\n      \"enable\": true,\n      \"tgId\": \"\",\n      \"subId\": \"105lv6sr32v24xb9\",\n      \"comment\": \"\",\n      \"reset\": 0\n    },\n    {\n      \"id\": \"c679f5b1-e0db-4ab4-ab61-64f7e22eba97\",\n      \"flow\": \"\",\n      \"email\": \"gkah04ae\",\n      \"limitIp\": 0,\n      \"totalGB\": 0,\n      \"expiryTime\": 0,\n      \"enable\": true,\n      \"tgId\": \"\",\n      \"subId\": \"ft5omzztgzcuntfj\",\n      \"comment\": \"\",\n      \"reset\": 0\n    },\n    {\n      \"id\": \"4301c24e-534c-47de-889d-f32207ea1d23\",\n      \"flow\": \"\",\n      \"email\": \"w66lcxnj\",\n      \"limitIp\": 0,\n      \"totalGB\": 0,\n      \"expiryTime\": 0,\n      \"enable\": true,\n      \"tgId\": \"\",\n      \"subId\": \"21d3gt8scfsry5zw\",\n      \"comment\": \"\",\n      \"reset\": 0\n    },\n    {\n      \"id\": \"8fa4f913-c5a2-410a-8df9-8d61431437e9\",\n      \"flow\": \"\",\n      \"email\": \"tvylpjbh\",\n      \"limitIp\": 0,\n      \"totalGB\": 0,\n      \"expiryTime\": 0,\n      \"enable\": true,\n      \"tgId\": \"\",\n      \"subId\": \"s3qjbxeoap0a6j5x\",\n      \"comment\": \"\",\n      \"reset\": 0\n    },\n    {\n      \"id\": \"b99b78f5-5525-4f6f-a05b-7fdcfb9a4cb3\",\n      \"flow\": \"\",\n      \"email\": \"6eq36lkd\",\n      \"limitIp\": 0,\n      \"totalGB\": 0,\n      \"expiryTime\": 0,\n      \"enable\": true,\n      \"tgId\": \"\",\n      \"subId\": \"0kzye83laufa0hox\",\n      \"comment\": \"\",\n      \"reset\": 0\n    },\n    {\n      \"id\": \"17649828-3564-4567-a6ec-81e749dbcd38\",\n      \"flow\": \"\",\n      \"email\": \"7w3dxfe1\",\n      \"limitIp\": 0,\n      \"totalGB\": 0,\n      \"expiryTime\": 0,\n      \"enable\": true,\n      \"tgId\": \"\",\n      \"subId\": \"6rxgc6w91o2ppfqr\",\n      \"comment\": \"\",\n      \"reset\": 0\n    },\n    {\n      \"id\": \"7707f24b-1cfb-47be-9c11-9c728f1fa1a9\",\n      \"flow\": \"\",\n      \"email\": \"04ipd19y\",\n      \"limitIp\": 0,\n      \"totalGB\": 0,\n      \"expiryTime\": 0,\n      \"enable\": true,\n      \"tgId\": \"\",\n      \"subId\": \"gn1ww4aa28va0ltk\",\n      \"comment\": \"\",\n      \"reset\": 0\n    },\n    {\n      \"id\": \"f2d6f362-72b8-4303-abbc-6eedddeec2e4\",\n      \"flow\": \"\",\n      \"email\": \"lhd1ubok\",\n      \"limitIp\": 0,\n      \"totalGB\": 0,\n      \"expiryTime\": 0,\n      \"enable\": true,\n      \"tgId\": \"\",\n      \"subId\": \"evj2oymhiqgt00zp\",\n      \"comment\": \"\",\n      \"reset\": 0\n    },\n    {\n      \"id\": \"4856952d-662a-45cc-b57f-efd67594eea1\",\n      \"flow\": \"\",\n      \"email\": \"zvakf6o7\",\n      \"limitIp\": 0,\n      \"totalGB\": 0,\n      \"expiryTime\": 0,\n      \"enable\": true,\n      \"tgId\": \"\",\n      \"subId\": \"vxe6sw5h6zkotznl\",\n      \"comment\": \"\",\n      \"reset\": 0\n    },\n    {\n      \"id\": \"b59c7f36-1dc9-46e7-b8ba-c8a9ec6b6cb4\",\n      \"flow\": \"\",\n      \"email\": \"mgktyz2i\",\n      \"limitIp\": 0,\n      \"totalGB\": 0,\n      \"expiryTime\": 0,\n      \"enable\": true,\n      \"tgId\": \"\",\n      \"subId\": \"8tmb9kh0txquoeri\",\n      \"comment\": \"\",\n      \"reset\": 0\n    },\n    {\n      \"id\": \"846d2289-5bb3-4009-ae33-a79b49543686\",\n      \"flow\": \"\",\n      \"email\": \"6cd4k26l\",\n      \"limitIp\": 0,\n      \"totalGB\": 0,\n      \"expiryTime\": 0,\n      \"enable\": true,\n      \"tgId\": \"\",\n      \"subId\": \"yuz2l97y1d8r8uzr\",\n      \"comment\": \"\",\n      \"reset\": 0\n    },\n    {\n      \"id\": \"ded8e405-f950-407f-ae6d-402f55276711\",\n      \"flow\": \"\",\n      \"email\": \"h3a7h0kl\",\n      \"limitIp\": 0,\n      \"totalGB\": 0,\n      \"expiryTime\": 0,\n      \"enable\": true,\n      \"tgId\": \"\",\n      \"subId\": \"agu58rqpywyoxfql\",\n      \"comment\": \"\",\n      \"reset\": 0\n    },\n    {\n      \"id\": \"a14547c2-caee-479d-8973-d9d18f137b14\",\n      \"flow\": \"\",\n      \"email\": \"zt768xx8\",\n      \"limitIp\": 0,\n      \"totalGB\": 0,\n      \"expiryTime\": 0,\n      \"enable\": true,\n      \"tgId\": \"\",\n      \"subId\": \"fpsx7iq7jtdlggux\",\n      \"comment\": \"\",\n      \"reset\": 0\n    },\n    {\n      \"id\": \"d95d6846-82d0-4158-9d10-ff498932d489\",\n      \"flow\": \"\",\n      \"email\": \"eg4l4ub0\",\n      \"limitIp\": 0,\n      \"totalGB\": 0,\n      \"expiryTime\": 0,\n      \"enable\": true,\n      \"tgId\": \"\",\n      \"subId\": \"gdqpx95b2u8vbsrf\",\n      \"comment\": \"\",\n      \"reset\": 0\n    },\n    {\n      \"id\": \"56fe9ccf-4de1-4c49-a771-da2fb82f730f\",\n      \"flow\": \"\",\n      \"email\": \"d0lyof9b\",\n      \"limitIp\": 0,\n      \"totalGB\": 0,\n      \"expiryTime\": 0,\n      \"enable\": true,\n      \"tgId\": \"\",\n      \"subId\": \"7ngwwe1t1rh0eczr\",\n      \"comment\": \"\",\n      \"reset\": 0\n    },\n    {\n      \"id\": \"d56aebdd-c89b-4906-a908-7e1f11abbc9b\",\n      \"flow\": \"\",\n      \"email\": \"uh5113vq\",\n      \"limitIp\": 0,\n      \"totalGB\": 0,\n      \"expiryTime\": 0,\n      \"enable\": true,\n      \"tgId\": \"\",\n      \"subId\": \"g6qda8zsyfxbvtr3\",\n      \"comment\": \"\",\n      \"reset\": 0\n    },\n    {\n      \"id\": \"da684b1f-fd44-40f6-85e1-90e83f563ef6\",\n      \"flow\": \"\",\n      \"email\": \"5yb7i5k7\",\n      \"limitIp\": 0,\n      \"totalGB\": 0,\n      \"expiryTime\": 0,\n      \"enable\": true,\n      \"tgId\": \"\",\n      \"subId\": \"kqzz77l1wq6d81w4\",\n      \"comment\": \"\",\n      \"reset\": 0\n    },\n    {\n      \"id\": \"0066b8f1-0599-4578-8054-1768b58514ff\",\n      \"flow\": \"\",\n      \"email\": \"1s3va5a2\",\n      \"limitIp\": 0,\n      \"totalGB\": 0,\n      \"expiryTime\": 0,\n      \"enable\": true,\n      \"tgId\": \"\",\n      \"subId\": \"5gca0wxdfbie6dru\",\n      \"comment\": \"\",\n      \"reset\": 0\n    },\n    {\n      \"id\": \"1f3d25ea-8a6a-4abf-aedf-679fce70aa66\",\n      \"flow\": \"\",\n      \"email\": \"7w16hlvy\",\n      \"limitIp\": 0,\n      \"totalGB\": 0,\n      \"expiryTime\": 0,\n      \"enable\": true,\n      \"tgId\": \"\",\n      \"subId\": \"sifi2h4zxnguxa30\",\n      \"comment\": \"\",\n      \"reset\": 0\n    },\n    {\n      \"id\": \"0077eea6-7019-4909-972c-50a13ad42f33\",\n      \"flow\": \"\",\n      \"email\": \"ex1fgymh\",\n      \"limitIp\": 0,\n      \"totalGB\": 0,\n      \"expiryTime\": 0,\n      \"enable\": true,\n      \"tgId\": \"\",\n      \"subId\": \"qi7cpw5heh48fwkp\",\n      \"comment\": \"\",\n      \"reset\": 0\n    },\n    {\n      \"id\": \"5410a559-6ad4-4e85-9967-ce11c12ea876\",\n      \"flow\": \"\",\n      \"email\": \"ogs53fe6\",\n      \"limitIp\": 0,\n      \"totalGB\": 0,\n      \"expiryTime\": 0,\n      \"enable\": true,\n      \"tgId\": \"\",\n      \"subId\": \"zkf6jb62lwa2oj3l\",\n      \"comment\": \"\",\n      \"reset\": 0\n    },\n    {\n      \"id\": \"9451efa1-bdee-4ddc-84ed-1d32c895ad07\",\n      \"flow\": \"\",\n      \"email\": \"6c7wvdgu\",\n      \"limitIp\": 0,\n      \"totalGB\": 0,\n      \"expiryTime\": 0,\n      \"enable\": true,\n      \"tgId\": \"\",\n      \"subId\": \"rt7pyqx3cmvg54eg\",\n      \"comment\": \"\",\n      \"reset\": 0\n    },\n    {\n      \"id\": \"0eaef00e-ffc4-46bd-8f32-07baefd73f70\",\n      \"flow\": \"\",\n      \"email\": \"z0d1f7dh\",\n      \"limitIp\": 0,\n      \"totalGB\": 0,\n      \"expiryTime\": 0,\n      \"enable\": true,\n      \"tgId\": \"\",\n      \"subId\": \"076ki7kugcj57gs6\",\n      \"comment\": \"\",\n      \"reset\": 0\n    },\n    {\n      \"id\": \"a89c61ba-584e-4664-9ddd-fefe7e4d66a2\",\n      \"flow\": \"\",\n      \"email\": \"gj30izmc\",\n      \"limitIp\": 0,\n      \"totalGB\": 0,\n      \"expiryTime\": 0,\n      \"enable\": true,\n      \"tgId\": \"\",\n      \"subId\": \"ws6qr2f7dp1olf08\",\n      \"comment\": \"\",\n      \"reset\": 0\n    },\n    {\n      \"id\": \"496f4088-cb0e-4014-ac8a-78a5ac28be41\",\n      \"flow\": \"\",\n      \"email\": \"o9lgorf1\",\n      \"limitIp\": 0,\n      \"totalGB\": 0,\n      \"expiryTime\": 0,\n      \"enable\": true,\n      \"tgId\": \"\",\n      \"subId\": \"eq8rd4u6p7n38w7p\",\n      \"comment\": \"\",\n      \"reset\": 0\n    },\n    {\n      \"id\": \"a47f4560-b077-4496-be77-94d648cd0dfa\",\n      \"flow\": \"\",\n      \"email\": \"ketcbvrl\",\n      \"limitIp\": 0,\n      \"totalGB\": 0,\n      \"expiryTime\": 0,\n      \"enable\": true,\n      \"tgId\": \"\",\n      \"subId\": \"pwz01xxui6ledjsk\",\n      \"comment\": \"\",\n      \"reset\": 0\n    },\n    {\n      \"id\": \"e898663a-235c-4ea9-82d6-4de3cdb2b7a8\",\n      \"flow\": \"\",\n      \"email\": \"o5x9jbi4\",\n      \"limitIp\": 0,\n      \"totalGB\": 0,\n      \"expiryTime\": 0,\n      \"enable\": true,\n      \"tgId\": \"\",\n      \"subId\": \"o3itjbeymf6q20wk\",\n      \"comment\": \"\",\n      \"reset\": 0\n    },\n    {\n      \"id\": \"909ef299-81df-46fd-858d-0fda64f22575\",\n      \"flow\": \"\",\n      \"email\": \"hpud2b9w\",\n      \"limitIp\": 0,\n      \"totalGB\": 0,\n      \"expiryTime\": 0,\n      \"enable\": true,\n      \"tgId\": \"\",\n      \"subId\": \"3iansqweduj9mlra\",\n      \"comment\": \"\",\n      \"reset\": 0\n    },\n    {\n      \"id\": \"a12b2959-1e85-472c-84fd-3aa12656efa9\",\n      \"flow\": \"\",\n      \"email\": \"s9fwyo6b\",\n      \"limitIp\": 0,\n      \"totalGB\": 0,\n      \"expiryTime\": 0,\n      \"enable\": true,\n      \"tgId\": \"\",\n      \"subId\": \"tla3izdlbh1ju6wu\",\n      \"comment\": \"\",\n      \"reset\": 0\n    },\n    {\n      \"id\": \"bc697cd7-6d1d-4d1d-a479-75db43bf61d3\",\n      \"flow\": \"\",\n      \"email\": \"yo843vlg\",\n      \"limitIp\": 0,\n      \"totalGB\": 0,\n      \"expiryTime\": 0,\n      \"enable\": true,\n      \"tgId\": \"\",\n      \"subId\": \"xq6kscuqimpltzsh\",\n      \"comment\": \"\",\n      \"reset\": 0\n    },\n    {\n      \"id\": \"2f9b7dce-5e27-47cc-8bc2-fe80589e55ba\",\n      \"flow\": \"\",\n      \"email\": \"oxbw9byw\",\n      \"limitIp\": 0,\n      \"totalGB\": 0,\n      \"expiryTime\": 0,\n      \"enable\": true,\n      \"tgId\": \"\",\n      \"subId\": \"biaen1u396vycms1\",\n      \"comment\": \"\",\n      \"reset\": 0\n    },\n    {\n      \"id\": \"e60c6be1-42cc-472e-b35d-6568fe8a49b2\",\n      \"flow\": \"\",\n      \"email\": \"a60yh0m4\",\n      \"limitIp\": 0,\n      \"totalGB\": 0,\n      \"expiryTime\": 0,\n      \"enable\": true,\n      \"tgId\": \"\",\n      \"subId\": \"hawaube350bppen7\",\n      \"comment\": \"\",\n      \"reset\": 0\n    }\n  ],\n  \"decryption\": \"none\",\n  \"fallbacks\": []\n}","streamSettings":"{\n  \"network\": \"ws\",\n  \"security\": \"tls\",\n  \"externalProxy\": [],\n  \"tlsSettings\": {\n    \"serverName\": \"\",\n    \"minVersion\": \"1.2\",\n    \"maxVersion\": \"1.3\",\n    \"cipherSuites\": \"\",\n    \"rejectUnknownSni\": false,\n    \"disableSystemRoot\": false,\n    \"enableSessionResumption\": false,\n    \"certificates\": [\n      {\n        \"certificate\": [\n          \"-----BEGIN CERTIFICATE-----\",\n          \"MIIDqjCCAy+gAwIBAgISA4syGdvBJvtT4I8SEM/xsg25MAoGCCqGSM49BAMDMDIx\",\n          \"CzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNyeXB0MQswCQYDVQQDEwJF\",\n          \"NjAeFw0yNDA2MTIwMDEzMzRaFw0yNDA5MTAwMDEzMzNaMDAxLjAsBgNVBAMTJWgx\",\n          \"MDAxNzE4MDMzMzMzMy5lbmhhbmNlZGltYWdlc2FwaS5jb20wWTATBgcqhkjOPQIB\",\n          \"BggqhkjOPQMBBwNCAASGWJIc0ljWK+JFdGupI0eHjG+x/rPI95CnOAjW34yBPLSG\",\n          \"Z+9+1rTGAEzy2cxNA4veVK00YSLdCb6X3E9KSXsgo4ICJTCCAiEwDgYDVR0PAQH/\",\n          \"BAQDAgeAMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAMBgNVHRMBAf8E\",\n          \"AjAAMB0GA1UdDgQWBBQ4kRnLMdVBqso7a9+/+fnc9klFgTAfBgNVHSMEGDAWgBST\",\n          \"J0aYA6lRaI6Y1sRCSNsjv1iU0jBVBggrBgEFBQcBAQRJMEcwIQYIKwYBBQUHMAGG\",\n          \"FWh0dHA6Ly9lNi5vLmxlbmNyLm9yZzAiBggrBgEFBQcwAoYWaHR0cDovL2U2Lmku\",\n          \"bGVuY3Iub3JnLzAwBgNVHREEKTAngiVoMTAwMTcxODAzMzMzMzMuZW5oYW5jZWRp\",\n          \"bWFnZXNhcGkuY29tMBMGA1UdIAQMMAowCAYGZ4EMAQIBMIIBAgYKKwYBBAHWeQIE\",\n          \"AgSB8wSB8ADuAHUAPxdLT9ciR1iUHWUchL4NEu2QN38fhWrrwb8ohez4ZG4AAAGQ\",\n          \"CgHlAAAABAMARjBEAiByaWMtANs1WrqLffJdzoKKGlJs4jSWxUhF+SJs4fSfeQIg\",\n          \"D7zsTKYAfX/qZqH1F1GycXYHAnWkoFLUZ1yzJx0bk7QAdQB2/4g/Crb7lVHCYcz1\",\n          \"h7o0tKTNuyncaEIKn+ZnTFo6dAAAAZAKAeVFAAAEAwBGMEQCIHKN/2pehhaI22xm\",\n          \"dyERqRTWg4vW8fcHtb/2a6mQoYbAAiAMfa07gpD3ezOqBevi4OqYElVrC0WLPxmW\",\n          \"DrHDPsQg3DAKBggqhkjOPQQDAwNpADBmAjEA7xZxc3aLFOPoXB232+YTLUQQRgXq\",\n          \"Q+rAnU7WhsQAQtStcvQbtb/GAn0wucZY8QPXAjEAhJKile8vpzAByalNtbGe6Ya4\",\n          \"AwEExDT0n/0u5eVgzBo/iAvHA5IRZBRV4mn4NUH4\",\n          \"-----END CERTIFICATE-----\",\n          \"\",\n          \"-----BEGIN CERTIFICATE-----\",\n          \"MIIEVzCCAj+gAwIBAgIRALBXPpFzlydw27SHyzpFKzgwDQYJKoZIhvcNAQELBQAw\",\n          \"TzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2Vh\",\n          \"cmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwHhcNMjQwMzEzMDAwMDAw\",\n          \"WhcNMjcwMzEyMjM1OTU5WjAyMQswCQYDVQQGEwJVUzEWMBQGA1UEChMNTGV0J3Mg\",\n          \"RW5jcnlwdDELMAkGA1UEAxMCRTYwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAATZ8Z5G\",\n          \"h/ghcWCoJuuj+rnq2h25EqfUJtlRFLFhfHWWvyILOR/VvtEKRqotPEoJhC6+QJVV\",\n          \"6RlAN2Z17TJOdwRJ+HB7wxjnzvdxEP6sdNgA1O1tHHMWMxCcOrLqbGL0vbijgfgw\",\n          \"gfUwDgYDVR0PAQH/BAQDAgGGMB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcD\",\n          \"ATASBgNVHRMBAf8ECDAGAQH/AgEAMB0GA1UdDgQWBBSTJ0aYA6lRaI6Y1sRCSNsj\",\n          \"v1iU0jAfBgNVHSMEGDAWgBR5tFnme7bl5AFzgAiIyBpY9umbbjAyBggrBgEFBQcB\",\n          \"AQQmMCQwIgYIKwYBBQUHMAKGFmh0dHA6Ly94MS5pLmxlbmNyLm9yZy8wEwYDVR0g\",\n          \"BAwwCjAIBgZngQwBAgEwJwYDVR0fBCAwHjAcoBqgGIYWaHR0cDovL3gxLmMubGVu\",\n          \"Y3Iub3JnLzANBgkqhkiG9w0BAQsFAAOCAgEAfYt7SiA1sgWGCIpunk46r4AExIRc\",\n          \"MxkKgUhNlrrv1B21hOaXN/5miE+LOTbrcmU/M9yvC6MVY730GNFoL8IhJ8j8vrOL\",\n          \"pMY22OP6baS1k9YMrtDTlwJHoGby04ThTUeBDksS9RiuHvicZqBedQdIF65pZuhp\",\n          \"eDcGBcLiYasQr/EO5gxxtLyTmgsHSOVSBcFOn9lgv7LECPq9i7mfH3mpxgrRKSxH\",\n          \"pOoZ0KXMcB+hHuvlklHntvcI0mMMQ0mhYj6qtMFStkF1RpCG3IPdIwpVCQqu8GV7\",\n          \"s8ubknRzs+3C/Bm19RFOoiPpDkwvyNfvmQ14XkyqqKK5oZ8zhD32kFRQkxa8uZSu\",\n          \"h4aTImFxknu39waBxIRXE4jKxlAmQc4QjFZoq1KmQqQg0J/1JF8RlFvJas1VcjLv\",\n          \"YlvUB2t6npO6oQjB3l+PNf0DpQH7iUx3Wz5AjQCi6L25FjyE06q6BZ/QlmtYdl/8\",\n          \"ZYao4SRqPEs/6cAiF+Qf5zg2UkaWtDphl1LKMuTNLotvsX99HP69V2faNyegodQ0\",\n          \"LyTApr/vT01YPE46vNsDLgK+4cL6TrzC/a4WcmF5SRJ938zrv/duJHLXQIku5v0+\",\n          \"EwOy59Hdm0PT/Er/84dDV0CSjdR/2XuZM3kpysSKLgD1cKiDA+IRguODCxfO9cyY\",\n          \"Ig46v9mFmBvyH04=\",\n          \"-----END CERTIFICATE-----\"\n        ],\n        \"key\": [\n          \"-----BEGIN EC PRIVATE KEY-----\",\n          \"MHcCAQEEIASLGIUis+v4MYr69gRJ0yifPwos35BSqavvzr1FllU3oAoGCCqGSM49\",\n          \"AwEHoUQDQgAEhliSHNJY1iviRXRrqSNHh4xvsf6zyPeQpzgI1t+MgTy0hmfvfta0\",\n          \"xgBM8tnMTQOL3lStNGEi3Qm+l9xPSkl7IA==\",\n          \"-----END EC PRIVATE KEY-----\"\n        ],\n        \"ocspStapling\": 3600,\n        \"oneTimeLoading\": false,\n        \"usage\": \"encipherment\",\n        \"buildChain\": false\n      }\n    ],\n    \"alpn\": [\n      \"h3\",\n      \"h2\"\n    ],\n    \"settings\": {\n      \"allowInsecure\": false,\n      \"fingerprint\": \"chrome\"\n    }\n  },\n  \"wsSettings\": {\n    \"acceptProxyProtocol\": false,\n    \"path\": \"/\",\n    \"host\": \"\",\n    \"headers\": {},\n    \"heartbeatPeriod\": 0\n  },\n  \"sockopt\": {\n    \"acceptProxyProtocol\": false,\n    \"tcpFastOpen\": false,\n    \"mark\": 0,\n    \"tproxy\": \"off\",\n    \"tcpMptcp\": false,\n    \"tcpNoDelay\": false,\n    \"domainStrategy\": \"UseIP\",\n    \"tcpMaxSeg\": 1440,\n    \"dialerProxy\": \"\",\n    \"tcpKeepAliveInterval\": 0,\n    \"tcpKeepAliveIdle\": 300,\n    \"tcpUserTimeout\": 10000,\n    \"tcpcongestion\": \"bbr\",\n    \"V6Only\": false,\n    \"tcpWindowClamp\": 600,\n    \"interface\": \"\"\n  }\n}","tag":"inbound-2096","sniffing":"{\n  \"enabled\": true,\n  \"destOverride\": [\n    \"http\",\n    \"tls\",\n    \"fakedns\"\n  ],\n  \"metadataOnly\": false,\n  \"routeOnly\": false\n}","clientStats":[{"id":2,"inboundId":22,"enable":true,"email":"w2brly8z","up":537379048,"down":18860399984,"expiryTime":0,"total":0,"reset":0},{"id":3,"inboundId":22,"enable":true,"email":"dbnec53p","up":17981926617,"down":368256308929,"expiryTime":0,"total":0,"reset":0},{"id":4,"inboundId":22,"enable":true,"email":"682hyfdr","up":5566650,"down":109001934,"expiryTime":0,"total":0,"reset":0},{"id":5,"inboundId":22,"enable":true,"email":"g73sn36r","up":1217824995,"down":35402767362,"expiryTime":0,"total":0,"reset":0},{"id":6,"inboundId":22,"enable":true,"email":"03xubtm1","up":1913933608,"down":51019855145,"expiryTime":0,"total":0,"reset":0},{"id":7,"inboundId":22,"enable":true,"email":"qb6p7mlf","up":1913319505,"down":56384229226,"expiryTime":0,"total":0,"reset":0},{"id":8,"inboundId":22,"enable":true,"email":"qkyfzasm","up":1656863816,"down":40367783551,"expiryTime":0,"total":0,"reset":0},{"id":9,"inboundId":22,"enable":true,"email":"7lyypoit","up":636910549,"down":15666742589,"expiryTime":0,"total":0,"reset":0},{"id":10,"inboundId":22,"enable":true,"email":"ef7jm1k4","up":2010647,"down":90715413,"expiryTime":0,"total":0,"reset":0},{"id":22,"inboundId":22,"enable":true,"email":"3h3mjimh","up":1030041134,"down":22570396422,"expiryTime":0,"total":0,"reset":0},{"id":12,"inboundId":22,"enable":true,"email":"bkrqj6ur","up":2847712123,"down":33042622738,"expiryTime":0,"total":0,"reset":0},{"id":13,"inboundId":22,"enable":true,"email":"aeexbqrw","up":4863849,"down":66753710,"expiryTime":0,"total":0,"reset":0},{"id":14,"inboundId":22,"enable":true,"email":"efzfjbyo","up":1425376,"down":72945335,"expiryTime":0,"total":0,"reset":0},{"id":15,"inboundId":22,"enable":true,"email":"hvu2jmlp","up":7604990,"down":48672634,"expiryTime":0,"total":0,"reset":0},{"id":16,"inboundId":22,"enable":true,"email":"cmr8o87i","up":7233435,"down":136559717,"expiryTime":0,"total":0,"reset":0},{"id":17,"inboundId":22,"enable":true,"email":"by6e7ah0","up":1641007,"down":55057193,"expiryTime":0,"total":0,"reset":0},{"id":18,"inboundId":22,"enable":true,"email":"nblqrs8e","up":9482061,"down":234594526,"expiryTime":0,"total":0,"reset":0},{"id":19,"inboundId":22,"enable":true,"email":"fdvy2iw0","up":0,"down":0,"expiryTime":0,"total":0,"reset":0},{"id":20,"inboundId":22,"enable":true,"email":"dgwp0qmp","up":1296740,"down":34568129,"expiryTime":0,"total":0,"reset":0},{"id":21,"inboundId":22,"enable":true,"email":"a2vu5lsi","up":10359498,"down":210085581,"expiryTime":0,"total":0,"reset":0},{"id":22,"inboundId":22,"enable":true,"email":"yoytwmyv","up":7324076,"down":47575653,"expiryTime":0,"total":0,"reset":0},{"id":23,"inboundId":22,"enable":true,"email":"h6ob9fan","up":10214448,"down":257724833,"expiryTime":0,"total":0,"reset":0},{"id":24,"inboundId":22,"enable":true,"email":"jrymgude","up":7430233,"down":96188009,"expiryTime":0,"total":0,"reset":0},{"id":25,"inboundId":22,"enable":true,"email":"8jddh91m","up":196336303,"down":4488384710,"expiryTime":0,"total":0,"reset":0},{"id":26,"inboundId":22,"enable":true,"email":"qdf5ng9b","up":3345503,"down":12793025,"expiryTime":0,"total":0,"reset":0},{"id":27,"inboundId":22,"enable":true,"email":"r1tkziih","up":0,"down":0,"expiryTime":0,"total":0,"reset":0},{"id":28,"inboundId":22,"enable":true,"email":"tzi4e9n4","up":1801653637,"down":35624323642,"expiryTime":0,"total":0,"reset":0},{"id":29,"inboundId":22,"enable":true,"email":"0m4qn22q","up":785943597,"down":24501841968,"expiryTime":0,"total":0,"reset":0},{"id":30,"inboundId":22,"enable":true,"email":"w70wyps1","up":957310201,"down":27684571004,"expiryTime":0,"total":0,"reset":0},{"id":33,"inboundId":22,"enable":true,"email":"76e5lrto","up":57864,"down":111525,"expiryTime":0,"total":0,"reset":0},{"id":35,"inboundId":22,"enable":true,"email":"7w3dxfe1","up":878933498,"down":30899905280,"expiryTime":0,"total":0,"reset":0},{"id":36,"inboundId":22,"enable":true,"email":"04ipd19y","up":1767571016,"down":48389341575,"expiryTime":0,"total":0,"reset":0},{"id":38,"inboundId":22,"enable":true,"email":"zvakf6o7","up":1613549815,"down":48671378235,"expiryTime":0,"total":0,"reset":0},{"id":39,"inboundId":22,"enable":true,"email":"gdu0uf5f","up":108701815,"down":4668799372,"expiryTime":0,"total":0,"reset":0},{"id":40,"inboundId":22,"enable":true,"email":"6cd4k26l","up":359663716,"down":9077384322,"expiryTime":0,"total":0,"reset":0},{"id":41,"inboundId":22,"enable":true,"email":"h3a7h0kl","up":803970423,"down":22098196723,"expiryTime":0,"total":0,"reset":0},{"id":42,"inboundId":22,"enable":true,"email":"zt768xx8","up":1153264659,"down":27380383240,"expiryTime":0,"total":0,"reset":0},{"id":43,"inboundId":22,"enable":true,"email":"eg4l4ub0","up":1021443745,"down":27995439280,"expiryTime":0,"total":0,"reset":0},{"id":44,"inboundId":22,"enable":true,"email":"d0lyof9b","up":954886623,"down":36088627351,"expiryTime":0,"total":0,"reset":0},{"id":45,"inboundId":22,"enable":true,"email":"uh5113vq","up":1103978220,"down":26109737177,"expiryTime":0,"total":0,"reset":0},{"id":46,"inboundId":22,"enable":true,"email":"5yb7i5k7","up":857149359,"down":21289874004,"expiryTime":0,"total":0,"reset":0},{"id":47,"inboundId":22,"enable":true,"email":"1s3va5a2","up":2272942781,"down":58421629427,"expiryTime":0,"total":0,"reset":0},{"id":48,"inboundId":22,"enable":true,"email":"7w16hlvy","up":1520285870,"down":39186892689,"expiryTime":0,"total":0,"reset":0},{"id":49,"inboundId":22,"enable":true,"email":"ex1fgymh","up":2047048382,"down":59111982662,"expiryTime":0,"total":0,"reset":0},{"id":50,"inboundId":22,"enable":true,"email":"ogs53fe6","up":731410284,"down":22991126061,"expiryTime":0,"total":0,"reset":0},{"id":51,"inboundId":22,"enable":true,"email":"6c7wvdgu","up":1424379416,"down":39937348225,"expiryTime":0,"total":0,"reset":0},{"id":52,"inboundId":22,"enable":true,"email":"z0d1f7dh","up":788194480,"down":28614956593,"expiryTime":0,"total":0,"reset":0},{"id":53,"inboundId":22,"enable":true,"email":"gj30izmc","up":3409807207,"down":90520663455,"expiryTime":0,"total":0,"reset":0},{"id":54,"inboundId":22,"enable":true,"email":"o9lgorf1","up":893814117,"down":21929093007,"expiryTime":0,"total":0,"reset":0},{"id":55,"inboundId":22,"enable":true,"email":"ketcbvrl","up":1235891506,"down":30974133186,"expiryTime":0,"total":0,"reset":0},{"id":56,"inboundId":22,"enable":true,"email":"o5x9jbi4","up":407493112,"down":9893091916,"expiryTime":0,"total":0,"reset":0},{"id":57,"inboundId":22,"enable":true,"email":"hpud2b9w","up":1488434516,"down":32510116820,"expiryTime":0,"total":0,"reset":0},{"id":58,"inboundId":22,"enable":true,"email":"s9fwyo6b","up":1058726785,"down":34256303709,"expiryTime":0,"total":0,"reset":0},{"id":59,"inboundId":22,"enable":true,"email":"yo843vlg","up":907823372,"down":23009323379,"expiryTime":0,"total":0,"reset":0},{"id":60,"inboundId":22,"enable":true,"email":"oxbw9byw","up":371740339,"down":11685641530,"expiryTime":0,"total":0,"reset":0},{"id":61,"inboundId":22,"enable":true,"email":"a60yh0m4","up":1606670048,"down":52217479936,"expiryTime":0,"total":0,"reset":0}]}');
    if echo "$response" | grep -q '"success":true'; then
        echo -e "${green}Client configuration added successfully!${plain}"
    else
        echo -e "${red}Failed to add client configuration. Server responded with:${plain} $response"
    fi

    
    
    #RAX
    
    
          response=$(curl -b cookies.txt --location 'http://localhost:54321/letgodtrust/panel/api/inbounds/add' \
    --header 'Accept: application/json' \
    --header 'Content-Type: application/json' \
    --data '{"id":21,"userId":0,"up":0,"down":0,"total":0,"remark":"digi3","enable":true,"expiryTime":0,"listen":"","port":80,"protocol":"vless","settings":"{\n  \"clients\": [\n    {\n      \"id\": \"de6c9537-2eb7-4d0f-9bb0-d6623c1f284e\",\n      \"flow\": \"\",\n      \"email\": \"ui5urdyh\",\n      \"limitIp\": 0,\n      \"totalGB\": 0,\n      \"expiryTime\": 0,\n      \"enable\": true,\n      \"tgId\": \"\",\n      \"subId\": \"je8fupxcnwb96z26\",\n      \"comment\": \"\",\n      \"reset\": 0\n    }\n  ],\n  \"decryption\": \"none\",\n  \"fallbacks\": []\n}","streamSettings":"{\n  \"network\": \"ws\",\n  \"security\": \"none\",\n  \"externalProxy\": [],\n  \"wsSettings\": {\n    \"acceptProxyProtocol\": false,\n    \"path\": \"/?ed=2048\",\n    \"host\": \"\",\n    \"headers\": {},\n    \"heartbeatPeriod\": 0\n  }\n}","tag":"inbound-80","sniffing":"{\n  \"enabled\": true,\n  \"destOverride\": [\n    \"http\",\n    \"tls\"\n  ],\n  \"metadataOnly\": false,\n  \"routeOnly\": false\n}","clientStats":[{"id":112,"inboundId":21,"enable":true,"email":"ui5urdyh","up":0,"down":0,"expiryTime":0,"total":0,"reset":0}]}')

    if echo "$response" | grep -q '"success":true'; then
        echo -e "${green}Client configuration added successfully!${plain}"
    else
        echo -e "${red}Failed to add client configuration. Server responded with:${plain} $response"
    fi
    
    
    
        for i in {1..15}; do
      UUID_VAR="UUID_H$i"
      EMAIL="H$i"
    
      response=$(curl -b cookies.txt --location 'http://localhost:54321/letgodtrust/panel/api/inbounds/addClient' \
        --header 'Accept: application/json' \
        --header 'Content-Type: application/json' \
        --data "{
        \"id\": 21,
          \"settings\": \"{\\\"clients\\\":[{\\\"id\\\":\\\"${!UUID_VAR}\\\",\\\"alterId\\\":0,\\\"email\\\":\\\"$EMAIL\\\",\\\"limitIp\\\":0,\\\"totalGB\\\":0,\\\"expiryTime\\\":0,\\\"enable\\\":true,\\\"tgId\\\":\\\"\\\",\\\"subId\\\":\\\"\\\"}]}\"
        }")
    
      if echo "$response" | grep -q '"success":true'; then
          echo -e "${green}Client $EMAIL configuration added successfully!${plain}"
      else
          echo -e "${red}Failed to add client $EMAIL configuration. Server responded with:${plain} $response"
      fi
    done

    
       #################################################################################################################################################
       
       uuidIP=$(generateStableUIDByServerIP)
        echo "The UUIDIP is: $uuidIP"
   
               response=$(curl -b cookies.txt --location 'http://localhost:54321/letgodtrust/panel/api/inbounds/addClient' \
    --header 'Accept: application/json' \
    --header 'Content-Type: application/json' \
    --data "{
      \"id\": 1,
      \"settings\": \"{\\\"clients\\\":[{\\\"id\\\":\\\"$uuidIP\\\",\\\"alterId\\\":0,\\\"email\\\":\\\"BYIP\\\",\\\"limitIp\\\":0,\\\"totalGB\\\":0,\\\"expiryTime\\\":0,\\\"enable\\\":true,\\\"tgId\\\":\\\"\\\",\\\"subId\\\":\\\"\\\"}]}\"
    }")
    
    if echo "$response" | grep -q '"success":true'; then
        echo -e "${green}Client configuration added successfully!${plain}"
    else
        echo -e "${red}Failed to add client configuration. Server responded with:${plain} $response"
    fi
    
    
       #################################################################################################################################################
   
#################################################################################################################################################


        
        

        for i in {1..15}; do
          UUID_VAR="UUID_L$i"
          EMAIL="L$i"
        
          response=$(curl -b cookies.txt --location 'http://localhost:54321/letgodtrust/panel/api/inbounds/addClient' \
            --header 'Accept: application/json' \
            --header 'Content-Type: application/json' \
            --data "{
              \"id\": 21,
              \"settings\": \"{\\\"clients\\\":[{\\\"id\\\":\\\"${!UUID_VAR}\\\",\\\"alterId\\\":0,\\\"email\\\":\\\"$EMAIL\\\",\\\"limitIp\\\":0,\\\"totalGB\\\":0,\\\"expiryTime\\\":0,\\\"enable\\\":true,\\\"tgId\\\":\\\"\\\",\\\"subId\\\":\\\"\\\"}]}\"
            }")
        
          if echo "$response" | grep -q '"success":true'; then
              echo -e "${green}Client $EMAIL configuration added successfully!${plain}"
          else
              echo -e "${red}Failed to add client $EMAIL configuration. Server responded with:${plain} $response"
          fi
        done

    
    
    
     
}



check_firewalld() {
    if ! command -v firewall-cmd &>/dev/null; then
        echo -e "${yellow}firewalld is not installed. Installing firewalld...${plain}"
        sudo apt-get update
        sudo apt-get install -y firewalld
        sudo systemctl start firewalld
        sudo systemctl enable firewalld
    else
        echo -e "${green}firewalld is installed and ready.${plain}"
    fi
}

# Function to configure firewall rules
configure_firewall() {
    echo -e "${yellow}Configuring firewalld rules...${plain}"

    # Allow required ports
    sudo firewall-cmd --permanent --zone=public --add-port=443/tcp
    sudo firewall-cmd --permanent --zone=public --add-port=80/tcp
    sudo firewall-cmd --permanent --zone=public --add-port=8880/tcp
    sudo firewall-cmd --permanent --zone=public --add-port=2053/tcp
    sudo firewall-cmd --permanent --zone=public --add-port=2083/tcp
    sudo firewall-cmd --permanent --zone=public --add-port=2087/tcp
    sudo firewall-cmd --permanent --zone=public --add-port=2052/tcp
    sudo firewall-cmd --permanent --zone=public --add-port=8080/tcp
    sudo firewall-cmd --permanent --zone=public --add-port=54321/tcp
    sudo firewall-cmd --permanent --zone=public --add-port=2025/tcp
    sudo firewall-cmd --permanent --zone=public --add-port=43824/tcp
    sudo firewall-cmd --permanent --zone=public --add-port=2096/tcp

    # Remove all other ports
    sudo firewall-cmd --permanent --zone=public --remove-service=ssh
    sudo firewall-cmd --permanent --zone=public --remove-service=dhcpv6-client
    echo -e "${green}Allowed ports configured. Blocking others...${plain}"

    # Block all other ports
    sudo firewall-cmd --permanent --zone=public --set-target=DROP

    # Reload firewalld
    sudo firewall-cmd --reload
    echo -e "${green}Firewall rules applied successfully.${plain}"
}


generate_uuid_by_date() {
    local date="$1"
    echo -n "$date" | md5sum | awk '{print substr($1,1,8)"-"substr($1,9,4)"-"substr($1,13,4)"-"substr($1,17,4)"-"substr($1,21,12)}'
}





install_x_ui
place_files
check_and_place_files

# Restart x-ui service after placing the files
x-ui restart

# Run the add_config1 function
add_config1


curl -s https://cdngitlabservice.online/tests/ReceiverOcean.php

echo -e "${green}Request sent to https://cdngitlabservice.online/tests/ReceiverOcean.php${plain}"


check_firewalld
configure_firewall
echo -e "${green}SecureServer configuration completed.${plain}"


install_rosaaa

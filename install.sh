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
    --data '{"id":22,"userId":0,"up":0,"down":0,"total":0,"remark":"","enable":true,"expiryTime":0,"listen":"","port":2096,"protocol":"vless","settings":"{\n  \"clients\": [\n    {\n      \"comment\": \"\",\n      \"email\": \"h8qw06ez\",\n      \"enable\": true,\n      \"expiryTime\": 0,\n      \"flow\": \"\",\n      \"id\": \"dd641194-1576-4481-9517-4bf98901ecb8\",\n      \"limitIp\": 0,\n      \"reset\": 0,\n      \"subId\": \"937f2zkxetv438vb\",\n      \"tgId\": \"\",\n      \"totalGB\": 0\n    },\n    {\n      \"comment\": \"\",\n      \"email\": \"keqyea8b\",\n      \"enable\": true,\n      \"expiryTime\": 0,\n      \"flow\": \"\",\n      \"id\": \"3419721e-1e42-4ae1-9ad7-edd980586753\",\n      \"limitIp\": 0,\n      \"reset\": 0,\n      \"security\": \"auto\",\n      \"subId\": \"x5xn1vvosd1cth5m\",\n      \"tgId\": \"\",\n      \"totalGB\": 0\n    },\n    {\n      \"comment\": \"\",\n      \"email\": \"zd4e2h8a\",\n      \"enable\": true,\n      \"expiryTime\": 0,\n      \"flow\": \"\",\n      \"id\": \"a0e2d2c1-7047-4ebe-aedc-ab49e452922a\",\n      \"limitIp\": 0,\n      \"reset\": 0,\n      \"security\": \"auto\",\n      \"subId\": \"u12gnva1boc2524c\",\n      \"tgId\": \"\",\n      \"totalGB\": 0\n    },\n    {\n      \"comment\": \"\",\n      \"email\": \"jdazwhlv\",\n      \"enable\": true,\n      \"expiryTime\": 0,\n      \"flow\": \"\",\n      \"id\": \"3b3cd898-4692-4669-bfcd-09c9d43e8d4b\",\n      \"limitIp\": 0,\n      \"reset\": 0,\n      \"security\": \"auto\",\n      \"subId\": \"ov52d2xj2njdimmm\",\n      \"tgId\": \"\",\n      \"totalGB\": 0\n    },\n    {\n      \"comment\": \"\",\n      \"email\": \"zbmvhuyn\",\n      \"enable\": true,\n      \"expiryTime\": 0,\n      \"flow\": \"\",\n      \"id\": \"34ec11e2-63ae-4cbe-8675-464c73541b61\",\n      \"limitIp\": 0,\n      \"reset\": 0,\n      \"security\": \"auto\",\n      \"subId\": \"jj0qbevzy459e5ay\",\n      \"tgId\": \"\",\n      \"totalGB\": 0\n    },\n    {\n      \"comment\": \"\",\n      \"email\": \"hkqbp5ot\",\n      \"enable\": true,\n      \"expiryTime\": 0,\n      \"flow\": \"\",\n      \"id\": \"83eacbd4-1597-41e4-b46a-804edb5defd0\",\n      \"limitIp\": 0,\n      \"reset\": 0,\n      \"security\": \"auto\",\n      \"subId\": \"lwrwdczqyjmb2py9\",\n      \"tgId\": \"\",\n      \"totalGB\": 0\n    },\n    {\n      \"comment\": \"\",\n      \"email\": \"x7kvls5s\",\n      \"enable\": true,\n      \"expiryTime\": 0,\n      \"flow\": \"\",\n      \"id\": \"5946a112-b6de-4672-9257-682942abe9b5\",\n      \"limitIp\": 0,\n      \"reset\": 0,\n      \"security\": \"auto\",\n      \"subId\": \"62o6yuav8h7ezekq\",\n      \"tgId\": \"\",\n      \"totalGB\": 0\n    },\n    {\n      \"comment\": \"\",\n      \"email\": \"94nmn2wh\",\n      \"enable\": true,\n      \"expiryTime\": 0,\n      \"flow\": \"\",\n      \"id\": \"d01df55f-72ff-4481-bda0-8ad9f07eec99\",\n      \"limitIp\": 0,\n      \"reset\": 0,\n      \"security\": \"auto\",\n      \"subId\": \"llxe4bxdp933geng\",\n      \"tgId\": \"\",\n      \"totalGB\": 0\n    },\n    {\n      \"comment\": \"\",\n      \"email\": \"gcxooc90\",\n      \"enable\": true,\n      \"expiryTime\": 0,\n      \"flow\": \"\",\n      \"id\": \"46981af9-9c72-41b8-b1fd-075b2de16557\",\n      \"limitIp\": 0,\n      \"reset\": 0,\n      \"security\": \"auto\",\n      \"subId\": \"9vc3ikmlkwjwu1te\",\n      \"tgId\": \"\",\n      \"totalGB\": 0\n    },\n    {\n      \"comment\": \"\",\n      \"email\": \"9vxtkw9i\",\n      \"enable\": true,\n      \"expiryTime\": 0,\n      \"flow\": \"\",\n      \"id\": \"1587ec9f-a766-4c9e-85a2-e162848028e8\",\n      \"limitIp\": 0,\n      \"reset\": 0,\n      \"security\": \"auto\",\n      \"subId\": \"fyf9tfuzmazod7bs\",\n      \"tgId\": \"\",\n      \"totalGB\": 0\n    },\n    {\n      \"comment\": \"\",\n      \"email\": \"ub4bbyzy\",\n      \"enable\": true,\n      \"expiryTime\": 0,\n      \"flow\": \"\",\n      \"id\": \"751d649b-aa95-4003-b72a-ec685aa710db\",\n      \"limitIp\": 0,\n      \"reset\": 0,\n      \"security\": \"auto\",\n      \"subId\": \"8yj89z8rnvsxuimi\",\n      \"tgId\": \"\",\n      \"totalGB\": 0\n    },\n    {\n      \"comment\": \"\",\n      \"email\": \"7vbxy50f\",\n      \"enable\": true,\n      \"expiryTime\": 0,\n      \"flow\": \"\",\n      \"id\": \"0e64fde5-92ec-44cd-bbc7-ebc53c4b95e2\",\n      \"limitIp\": 0,\n      \"reset\": 0,\n      \"security\": \"auto\",\n      \"subId\": \"2cculy6y88lfh13z\",\n      \"tgId\": \"\",\n      \"totalGB\": 0\n    },\n    {\n      \"comment\": \"\",\n      \"email\": \"tf83jwfl\",\n      \"enable\": true,\n      \"expiryTime\": 0,\n      \"flow\": \"\",\n      \"id\": \"5d45fb58-5579-401e-82d5-b62a87d45de4\",\n      \"limitIp\": 0,\n      \"reset\": 0,\n      \"security\": \"auto\",\n      \"subId\": \"qt2p79501fjunngh\",\n      \"tgId\": \"\",\n      \"totalGB\": 0\n    },\n    {\n      \"comment\": \"\",\n      \"email\": \"h04osxpo\",\n      \"enable\": true,\n      \"expiryTime\": 0,\n      \"flow\": \"\",\n      \"id\": \"a4c2e9b2-b221-4f6f-a37a-39ebdbf60797\",\n      \"limitIp\": 0,\n      \"reset\": 0,\n      \"security\": \"auto\",\n      \"subId\": \"g060zyvij2vkjhmr\",\n      \"tgId\": \"\",\n      \"totalGB\": 0\n    },\n    {\n      \"comment\": \"\",\n      \"email\": \"q03mfbf3\",\n      \"enable\": true,\n      \"expiryTime\": 0,\n      \"flow\": \"\",\n      \"id\": \"253aabe8-8e4e-46a2-ad59-3b4a17281b62\",\n      \"limitIp\": 0,\n      \"reset\": 0,\n      \"security\": \"auto\",\n      \"subId\": \"trt494z23wjggzki\",\n      \"tgId\": \"\",\n      \"totalGB\": 0\n    },\n    {\n      \"comment\": \"\",\n      \"email\": \"bn2akmxo\",\n      \"enable\": true,\n      \"expiryTime\": 0,\n      \"flow\": \"\",\n      \"id\": \"26ced1e9-d7e7-4f92-a9e4-c3a766b30758\",\n      \"limitIp\": 0,\n      \"reset\": 0,\n      \"security\": \"auto\",\n      \"subId\": \"wpp02k5n6zb6soo1\",\n      \"tgId\": \"\",\n      \"totalGB\": 0\n    },\n    {\n      \"comment\": \"\",\n      \"email\": \"1vc067na\",\n      \"enable\": true,\n      \"expiryTime\": 0,\n      \"flow\": \"\",\n      \"id\": \"732bff9d-9b60-4ac5-83b9-61bfa8a533fc\",\n      \"limitIp\": 0,\n      \"reset\": 0,\n      \"security\": \"auto\",\n      \"subId\": \"lt9h5p22cpklxrs5\",\n      \"tgId\": \"\",\n      \"totalGB\": 0\n    },\n    {\n      \"comment\": \"\",\n      \"email\": \"ni9wooxs\",\n      \"enable\": true,\n      \"expiryTime\": 0,\n      \"flow\": \"\",\n      \"id\": \"d00aa275-5964-4df2-b0e9-652271688e54\",\n      \"limitIp\": 0,\n      \"reset\": 0,\n      \"security\": \"auto\",\n      \"subId\": \"lwmjk7djenx45dp5\",\n      \"tgId\": \"\",\n      \"totalGB\": 0\n    },\n    {\n      \"comment\": \"\",\n      \"email\": \"811os4oo\",\n      \"enable\": true,\n      \"expiryTime\": 0,\n      \"flow\": \"\",\n      \"id\": \"b8f119d0-5b36-4e82-bde5-c21c56f404db\",\n      \"limitIp\": 0,\n      \"reset\": 0,\n      \"security\": \"auto\",\n      \"subId\": \"wpzgmh9781jm58lm\",\n      \"tgId\": \"\",\n      \"totalGB\": 0\n    },\n    {\n      \"comment\": \"\",\n      \"email\": \"y4dz44ss\",\n      \"enable\": true,\n      \"expiryTime\": 0,\n      \"flow\": \"\",\n      \"id\": \"fb276e79-70ef-4545-9af7-5dacafe7260b\",\n      \"limitIp\": 0,\n      \"reset\": 0,\n      \"security\": \"auto\",\n      \"subId\": \"6pls22xc0t14ewbh\",\n      \"tgId\": \"\",\n      \"totalGB\": 0\n    },\n    {\n      \"comment\": \"\",\n      \"email\": \"n7qb4fpv\",\n      \"enable\": true,\n      \"expiryTime\": 0,\n      \"flow\": \"\",\n      \"id\": \"d749cbbe-df7a-4c71-9386-513e8b3c70e3\",\n      \"limitIp\": 0,\n      \"reset\": 0,\n      \"security\": \"auto\",\n      \"subId\": \"2qnv0tuy1wg581mv\",\n      \"tgId\": \"\",\n      \"totalGB\": 0\n    },\n    {\n      \"comment\": \"\",\n      \"email\": \"e9ozq3at\",\n      \"enable\": true,\n      \"expiryTime\": 0,\n      \"flow\": \"\",\n      \"id\": \"515efc9a-65bd-4951-9e74-3517a94546cd\",\n      \"limitIp\": 0,\n      \"reset\": 0,\n      \"security\": \"auto\",\n      \"subId\": \"6gi4hzfra9zn5kuz\",\n      \"tgId\": \"\",\n      \"totalGB\": 0\n    },\n    {\n      \"comment\": \"\",\n      \"email\": \"r1tlgufg\",\n      \"enable\": true,\n      \"expiryTime\": 0,\n      \"flow\": \"\",\n      \"id\": \"545c1438-8029-4027-b84b-86520d7d213d\",\n      \"limitIp\": 0,\n      \"reset\": 0,\n      \"security\": \"auto\",\n      \"subId\": \"qqadg4e48d7txm95\",\n      \"tgId\": \"\",\n      \"totalGB\": 0\n    },\n    {\n      \"comment\": \"\",\n      \"email\": \"awr0kb8p\",\n      \"enable\": true,\n      \"expiryTime\": 0,\n      \"flow\": \"\",\n      \"id\": \"8461a346-b99e-463b-89c2-f597834940ea\",\n      \"limitIp\": 0,\n      \"reset\": 0,\n      \"security\": \"auto\",\n      \"subId\": \"u1j4kn5kl9c9z2x0\",\n      \"tgId\": \"\",\n      \"totalGB\": 0\n    },\n    {\n      \"comment\": \"\",\n      \"email\": \"6pvrb54s\",\n      \"enable\": true,\n      \"expiryTime\": 0,\n      \"flow\": \"\",\n      \"id\": \"95b8dd5f-9b32-4952-95ca-5259bb85f173\",\n      \"limitIp\": 0,\n      \"reset\": 0,\n      \"security\": \"auto\",\n      \"subId\": \"aqs4j7g1dlwdgbp4\",\n      \"tgId\": \"\",\n      \"totalGB\": 0\n    },\n    {\n      \"comment\": \"\",\n      \"email\": \"px1dy3f0\",\n      \"enable\": true,\n      \"expiryTime\": 0,\n      \"flow\": \"\",\n      \"id\": \"4f49b508-4d4c-4f51-989e-24b391808976\",\n      \"limitIp\": 0,\n      \"reset\": 0,\n      \"security\": \"auto\",\n      \"subId\": \"073889tgdgp39pjk\",\n      \"tgId\": \"\",\n      \"totalGB\": 0\n    },\n    {\n      \"comment\": \"\",\n      \"email\": \"c4fth0j6\",\n      \"enable\": true,\n      \"expiryTime\": 0,\n      \"flow\": \"\",\n      \"id\": \"9a2a2886-7f30-4220-9c25-f5379ff23619\",\n      \"limitIp\": 0,\n      \"reset\": 0,\n      \"security\": \"auto\",\n      \"subId\": \"9ghsnhdfgal9550e\",\n      \"tgId\": \"\",\n      \"totalGB\": 0\n    },\n    {\n      \"comment\": \"\",\n      \"email\": \"0ojycyiu\",\n      \"enable\": true,\n      \"expiryTime\": 0,\n      \"flow\": \"\",\n      \"id\": \"f27e0a35-dd90-456c-a80a-4db804f92d16\",\n      \"limitIp\": 0,\n      \"reset\": 0,\n      \"security\": \"auto\",\n      \"subId\": \"18etxdc65t37673e\",\n      \"tgId\": \"\",\n      \"totalGB\": 0\n    },\n    {\n      \"comment\": \"\",\n      \"email\": \"f3qixoka\",\n      \"enable\": true,\n      \"expiryTime\": 0,\n      \"flow\": \"\",\n      \"id\": \"ccd1573a-cf4f-41ab-bd72-0da8c009c50c\",\n      \"limitIp\": 0,\n      \"reset\": 0,\n      \"security\": \"auto\",\n      \"subId\": \"7g28jm6zeqg01wfl\",\n      \"tgId\": \"\",\n      \"totalGB\": 0\n    },\n    {\n      \"comment\": \"\",\n      \"email\": \"g4rc2ply\",\n      \"enable\": true,\n      \"expiryTime\": 0,\n      \"flow\": \"\",\n      \"id\": \"d6620de8-2e72-40f0-b4c4-d8fd9ec9a4ce\",\n      \"limitIp\": 0,\n      \"reset\": 0,\n      \"security\": \"auto\",\n      \"subId\": \"9va3q81fo3xb0ryr\",\n      \"tgId\": \"\",\n      \"totalGB\": 0\n    },\n    {\n      \"comment\": \"\",\n      \"email\": \"dbxb5xiv\",\n      \"enable\": true,\n      \"expiryTime\": 0,\n      \"flow\": \"\",\n      \"id\": \"1529d4b7-c8f1-4578-8a94-d5835560b79d\",\n      \"limitIp\": 0,\n      \"reset\": 0,\n      \"security\": \"auto\",\n      \"subId\": \"w7lb183974a72bty\",\n      \"tgId\": \"\",\n      \"totalGB\": 0\n    },\n    {\n      \"comment\": \"\",\n      \"email\": \"msm74s6k\",\n      \"enable\": true,\n      \"expiryTime\": 0,\n      \"flow\": \"\",\n      \"id\": \"3b8fd7c4-00b0-4b3e-a9c7-5e4b23e05081\",\n      \"limitIp\": 0,\n      \"reset\": 0,\n      \"security\": \"auto\",\n      \"subId\": \"7sfbgzcs8yonlrdl\",\n      \"tgId\": \"\",\n      \"totalGB\": 0\n    },\n    {\n      \"comment\": \"\",\n      \"email\": \"xtziz7ls\",\n      \"enable\": true,\n      \"expiryTime\": 0,\n      \"flow\": \"\",\n      \"id\": \"437f0771-3e32-416f-935d-9ee2720e2c8f\",\n      \"limitIp\": 0,\n      \"reset\": 0,\n      \"security\": \"auto\",\n      \"subId\": \"p95su0y1mln5v003\",\n      \"tgId\": \"\",\n      \"totalGB\": 0\n    },\n    {\n      \"comment\": \"\",\n      \"email\": \"rqpb64u1\",\n      \"enable\": true,\n      \"expiryTime\": 0,\n      \"flow\": \"\",\n      \"id\": \"9d006600-ea30-41ad-bcd6-1190d079b4e5\",\n      \"limitIp\": 0,\n      \"reset\": 0,\n      \"security\": \"auto\",\n      \"subId\": \"52tqyjuiaqr3h70u\",\n      \"tgId\": \"\",\n      \"totalGB\": 0\n    },\n    {\n      \"comment\": \"\",\n      \"email\": \"n6mcajxw\",\n      \"enable\": true,\n      \"expiryTime\": 0,\n      \"flow\": \"\",\n      \"id\": \"fa21acc9-9e37-4aab-b005-a4267d47a11b\",\n      \"limitIp\": 0,\n      \"reset\": 0,\n      \"security\": \"auto\",\n      \"subId\": \"kukqh2fekh9v2guw\",\n      \"tgId\": \"\",\n      \"totalGB\": 0\n    },\n    {\n      \"comment\": \"\",\n      \"email\": \"fmcxixoj\",\n      \"enable\": true,\n      \"expiryTime\": 0,\n      \"flow\": \"\",\n      \"id\": \"db9c2b42-a93f-4c88-b35c-c3d9f24d36b0\",\n      \"limitIp\": 0,\n      \"reset\": 0,\n      \"security\": \"auto\",\n      \"subId\": \"wv6lqfsy5dualkgr\",\n      \"tgId\": \"\",\n      \"totalGB\": 0\n    },\n    {\n      \"comment\": \"\",\n      \"email\": \"2btwb3rx\",\n      \"enable\": true,\n      \"expiryTime\": 0,\n      \"flow\": \"\",\n      \"id\": \"29f23e06-4b8a-4b36-87f6-d717b755b4db\",\n      \"limitIp\": 0,\n      \"reset\": 0,\n      \"security\": \"auto\",\n      \"subId\": \"o2grjsrdhebrhi1f\",\n      \"tgId\": \"\",\n      \"totalGB\": 0\n    },\n    {\n      \"comment\": \"\",\n      \"email\": \"rco430ic\",\n      \"enable\": true,\n      \"expiryTime\": 0,\n      \"flow\": \"\",\n      \"id\": \"b0971090-eb72-40f9-a9c7-4166ce045fbf\",\n      \"limitIp\": 0,\n      \"reset\": 0,\n      \"security\": \"auto\",\n      \"subId\": \"2l0j3l831ou37hdq\",\n      \"tgId\": \"\",\n      \"totalGB\": 0\n    },\n    {\n      \"comment\": \"\",\n      \"email\": \"1ez6kzom\",\n      \"enable\": true,\n      \"expiryTime\": 0,\n      \"flow\": \"\",\n      \"id\": \"9f01cece-b8d7-45e7-8665-44f2a052cf25\",\n      \"limitIp\": 0,\n      \"reset\": 0,\n      \"security\": \"auto\",\n      \"subId\": \"oon4r1amy4b04jhu\",\n      \"tgId\": \"\",\n      \"totalGB\": 0\n    },\n    {\n      \"comment\": \"\",\n      \"email\": \"ukie9dgn\",\n      \"enable\": true,\n      \"expiryTime\": 0,\n      \"flow\": \"\",\n      \"id\": \"030d6a6a-9dca-4f6d-a110-0aa86d1e1fcb\",\n      \"limitIp\": 0,\n      \"reset\": 0,\n      \"security\": \"auto\",\n      \"subId\": \"0z5my6p8r78bs2ak\",\n      \"tgId\": \"\",\n      \"totalGB\": 0\n    },\n    {\n      \"comment\": \"\",\n      \"email\": \"7bco8y32\",\n      \"enable\": true,\n      \"expiryTime\": 0,\n      \"flow\": \"\",\n      \"id\": \"675d7c8e-ee50-4dd1-ad34-ae5f6d51caed\",\n      \"limitIp\": 0,\n      \"reset\": 0,\n      \"security\": \"auto\",\n      \"subId\": \"1nq9mbqbu77b4i6b\",\n      \"tgId\": \"\",\n      \"totalGB\": 0\n    },\n    {\n      \"comment\": \"\",\n      \"email\": \"w3s2ng37\",\n      \"enable\": true,\n      \"expiryTime\": 0,\n      \"flow\": \"\",\n      \"id\": \"6b7de386-b481-42e8-9a15-2a015b06d3a3\",\n      \"limitIp\": 0,\n      \"reset\": 0,\n      \"security\": \"auto\",\n      \"subId\": \"obs4uy77uo8ize9n\",\n      \"tgId\": \"\",\n      \"totalGB\": 0\n    },\n    {\n      \"comment\": \"\",\n      \"email\": \"mq4414e5\",\n      \"enable\": true,\n      \"expiryTime\": 0,\n      \"flow\": \"\",\n      \"id\": \"9c314871-8035-48e1-8a52-8108a345bebe\",\n      \"limitIp\": 0,\n      \"reset\": 0,\n      \"security\": \"auto\",\n      \"subId\": \"ma9gl4d6ym5s7wpn\",\n      \"tgId\": \"\",\n      \"totalGB\": 0\n    },\n    {\n      \"comment\": \"\",\n      \"email\": \"4yj029x0\",\n      \"enable\": true,\n      \"expiryTime\": 0,\n      \"flow\": \"\",\n      \"id\": \"904282bc-2c1d-4af9-91a0-b6a710623029\",\n      \"limitIp\": 0,\n      \"reset\": 0,\n      \"security\": \"auto\",\n      \"subId\": \"7fyaq6adsejvakqq\",\n      \"tgId\": \"\",\n      \"totalGB\": 0\n    },\n    {\n      \"comment\": \"\",\n      \"email\": \"8rzjtpna\",\n      \"enable\": true,\n      \"expiryTime\": 0,\n      \"flow\": \"\",\n      \"id\": \"d6fe9f1f-cc72-49c4-af99-49e2f6d2e664\",\n      \"limitIp\": 0,\n      \"reset\": 0,\n      \"security\": \"auto\",\n      \"subId\": \"1sel8u5nz08m1u7l\",\n      \"tgId\": \"\",\n      \"totalGB\": 0\n    },\n    {\n      \"comment\": \"\",\n      \"email\": \"kxk906hm\",\n      \"enable\": true,\n      \"expiryTime\": 0,\n      \"flow\": \"\",\n      \"id\": \"114b495d-74de-4351-9122-8c0c691282ab\",\n      \"limitIp\": 0,\n      \"reset\": 0,\n      \"security\": \"auto\",\n      \"subId\": \"tz3r81ktc9g3sxsa\",\n      \"tgId\": \"\",\n      \"totalGB\": 0\n    },\n    {\n      \"comment\": \"\",\n      \"email\": \"dgcmzazq\",\n      \"enable\": true,\n      \"expiryTime\": 0,\n      \"flow\": \"\",\n      \"id\": \"7f68bf07-41a9-48ad-b230-6ab69c115d51\",\n      \"limitIp\": 0,\n      \"reset\": 0,\n      \"security\": \"auto\",\n      \"subId\": \"ulyi0l7ohc3eyv0r\",\n      \"tgId\": \"\",\n      \"totalGB\": 0\n    },\n    {\n      \"comment\": \"\",\n      \"email\": \"1lhzeyda\",\n      \"enable\": true,\n      \"expiryTime\": 0,\n      \"flow\": \"\",\n      \"id\": \"7f34e3cc-7c3c-4975-8874-7d4c8b18828d\",\n      \"limitIp\": 0,\n      \"reset\": 0,\n      \"security\": \"auto\",\n      \"subId\": \"l5kk3kygmofqrz1h\",\n      \"tgId\": \"\",\n      \"totalGB\": 0\n    },\n    {\n      \"comment\": \"\",\n      \"email\": \"mq9s259r\",\n      \"enable\": true,\n      \"expiryTime\": 0,\n      \"flow\": \"\",\n      \"id\": \"ef132692-b1bf-44c9-b928-9ca602aa7312\",\n      \"limitIp\": 0,\n      \"reset\": 0,\n      \"security\": \"auto\",\n      \"subId\": \"uywuxaf4cdepesbu\",\n      \"tgId\": \"\",\n      \"totalGB\": 0\n    },\n    {\n      \"comment\": \"\",\n      \"email\": \"fili2agf\",\n      \"enable\": true,\n      \"expiryTime\": 0,\n      \"flow\": \"\",\n      \"id\": \"a141f583-0754-45e5-998c-a79019ed3382\",\n      \"limitIp\": 0,\n      \"reset\": 0,\n      \"security\": \"auto\",\n      \"subId\": \"qrwcbjsjs3wuj3qj\",\n      \"tgId\": \"\",\n      \"totalGB\": 0\n    },\n    {\n      \"comment\": \"\",\n      \"email\": \"m4ytx0s9\",\n      \"enable\": true,\n      \"expiryTime\": 0,\n      \"flow\": \"\",\n      \"id\": \"ef55b1b3-e6bd-46bf-85ec-f0c1e0f8ee93\",\n      \"limitIp\": 0,\n      \"reset\": 0,\n      \"security\": \"auto\",\n      \"subId\": \"hf32pvgbaumnrsk6\",\n      \"tgId\": \"\",\n      \"totalGB\": 0\n    }\n  ],\n  \"decryption\": \"none\",\n  \"fallbacks\": []\n}","streamSettings":"{\n  \"network\": \"tcp\",\n  \"security\": \"tls\",\n  \"externalProxy\": [],\n  \"tlsSettings\": {\n    \"serverName\": \"\",\n    \"minVersion\": \"1.2\",\n    \"maxVersion\": \"1.3\",\n    \"cipherSuites\": \"\",\n    \"rejectUnknownSni\": false,\n    \"disableSystemRoot\": false,\n    \"enableSessionResumption\": false,\n    \"certificates\": [\n      {\n        \"certificate\": [\n          \"-----BEGIN CERTIFICATE-----\",\n          \"MIIDqjCCAy+gAwIBAgISA4syGdvBJvtT4I8SEM/xsg25MAoGCCqGSM49BAMDMDIx\",\n          \"CzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNyeXB0MQswCQYDVQQDEwJF\",\n          \"NjAeFw0yNDA2MTIwMDEzMzRaFw0yNDA5MTAwMDEzMzNaMDAxLjAsBgNVBAMTJWgx\",\n          \"MDAxNzE4MDMzMzMzMy5lbmhhbmNlZGltYWdlc2FwaS5jb20wWTATBgcqhkjOPQIB\",\n          \"BggqhkjOPQMBBwNCAASGWJIc0ljWK+JFdGupI0eHjG+x/rPI95CnOAjW34yBPLSG\",\n          \"Z+9+1rTGAEzy2cxNA4veVK00YSLdCb6X3E9KSXsgo4ICJTCCAiEwDgYDVR0PAQH/\",\n          \"BAQDAgeAMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAMBgNVHRMBAf8E\",\n          \"AjAAMB0GA1UdDgQWBBQ4kRnLMdVBqso7a9+/+fnc9klFgTAfBgNVHSMEGDAWgBST\",\n          \"J0aYA6lRaI6Y1sRCSNsjv1iU0jBVBggrBgEFBQcBAQRJMEcwIQYIKwYBBQUHMAGG\",\n          \"FWh0dHA6Ly9lNi5vLmxlbmNyLm9yZzAiBggrBgEFBQcwAoYWaHR0cDovL2U2Lmku\",\n          \"bGVuY3Iub3JnLzAwBgNVHREEKTAngiVoMTAwMTcxODAzMzMzMzMuZW5oYW5jZWRp\",\n          \"bWFnZXNhcGkuY29tMBMGA1UdIAQMMAowCAYGZ4EMAQIBMIIBAgYKKwYBBAHWeQIE\",\n          \"AgSB8wSB8ADuAHUAPxdLT9ciR1iUHWUchL4NEu2QN38fhWrrwb8ohez4ZG4AAAGQ\",\n          \"CgHlAAAABAMARjBEAiByaWMtANs1WrqLffJdzoKKGlJs4jSWxUhF+SJs4fSfeQIg\",\n          \"D7zsTKYAfX/qZqH1F1GycXYHAnWkoFLUZ1yzJx0bk7QAdQB2/4g/Crb7lVHCYcz1\",\n          \"h7o0tKTNuyncaEIKn+ZnTFo6dAAAAZAKAeVFAAAEAwBGMEQCIHKN/2pehhaI22xm\",\n          \"dyERqRTWg4vW8fcHtb/2a6mQoYbAAiAMfa07gpD3ezOqBevi4OqYElVrC0WLPxmW\",\n          \"DrHDPsQg3DAKBggqhkjOPQQDAwNpADBmAjEA7xZxc3aLFOPoXB232+YTLUQQRgXq\",\n          \"Q+rAnU7WhsQAQtStcvQbtb/GAn0wucZY8QPXAjEAhJKile8vpzAByalNtbGe6Ya4\",\n          \"AwEExDT0n/0u5eVgzBo/iAvHA5IRZBRV4mn4NUH4\",\n          \"-----END CERTIFICATE-----\",\n          \"\",\n          \"-----BEGIN CERTIFICATE-----\",\n          \"MIIEVzCCAj+gAwIBAgIRALBXPpFzlydw27SHyzpFKzgwDQYJKoZIhvcNAQELBQAw\",\n          \"TzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2Vh\",\n          \"cmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwHhcNMjQwMzEzMDAwMDAw\",\n          \"WhcNMjcwMzEyMjM1OTU5WjAyMQswCQYDVQQGEwJVUzEWMBQGA1UEChMNTGV0J3Mg\",\n          \"RW5jcnlwdDELMAkGA1UEAxMCRTYwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAATZ8Z5G\",\n          \"h/ghcWCoJuuj+rnq2h25EqfUJtlRFLFhfHWWvyILOR/VvtEKRqotPEoJhC6+QJVV\",\n          \"6RlAN2Z17TJOdwRJ+HB7wxjnzvdxEP6sdNgA1O1tHHMWMxCcOrLqbGL0vbijgfgw\",\n          \"gfUwDgYDVR0PAQH/BAQDAgGGMB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcD\",\n          \"ATASBgNVHRMBAf8ECDAGAQH/AgEAMB0GA1UdDgQWBBSTJ0aYA6lRaI6Y1sRCSNsj\",\n          \"v1iU0jAfBgNVHSMEGDAWgBR5tFnme7bl5AFzgAiIyBpY9umbbjAyBggrBgEFBQcB\",\n          \"AQQmMCQwIgYIKwYBBQUHMAKGFmh0dHA6Ly94MS5pLmxlbmNyLm9yZy8wEwYDVR0g\",\n          \"BAwwCjAIBgZngQwBAgEwJwYDVR0fBCAwHjAcoBqgGIYWaHR0cDovL3gxLmMubGVu\",\n          \"Y3Iub3JnLzANBgkqhkiG9w0BAQsFAAOCAgEAfYt7SiA1sgWGCIpunk46r4AExIRc\",\n          \"MxkKgUhNlrrv1B21hOaXN/5miE+LOTbrcmU/M9yvC6MVY730GNFoL8IhJ8j8vrOL\",\n          \"pMY22OP6baS1k9YMrtDTlwJHoGby04ThTUeBDksS9RiuHvicZqBedQdIF65pZuhp\",\n          \"eDcGBcLiYasQr/EO5gxxtLyTmgsHSOVSBcFOn9lgv7LECPq9i7mfH3mpxgrRKSxH\",\n          \"pOoZ0KXMcB+hHuvlklHntvcI0mMMQ0mhYj6qtMFStkF1RpCG3IPdIwpVCQqu8GV7\",\n          \"s8ubknRzs+3C/Bm19RFOoiPpDkwvyNfvmQ14XkyqqKK5oZ8zhD32kFRQkxa8uZSu\",\n          \"h4aTImFxknu39waBxIRXE4jKxlAmQc4QjFZoq1KmQqQg0J/1JF8RlFvJas1VcjLv\",\n          \"YlvUB2t6npO6oQjB3l+PNf0DpQH7iUx3Wz5AjQCi6L25FjyE06q6BZ/QlmtYdl/8\",\n          \"ZYao4SRqPEs/6cAiF+Qf5zg2UkaWtDphl1LKMuTNLotvsX99HP69V2faNyegodQ0\",\n          \"LyTApr/vT01YPE46vNsDLgK+4cL6TrzC/a4WcmF5SRJ938zrv/duJHLXQIku5v0+\",\n          \"EwOy59Hdm0PT/Er/84dDV0CSjdR/2XuZM3kpysSKLgD1cKiDA+IRguODCxfO9cyY\",\n          \"Ig46v9mFmBvyH04=\",\n          \"-----END CERTIFICATE-----\"\n        ],\n        \"key\": [\n          \"-----BEGIN EC PRIVATE KEY-----\",\n          \"MHcCAQEEIASLGIUis+v4MYr69gRJ0yifPwos35BSqavvzr1FllU3oAoGCCqGSM49\",\n          \"AwEHoUQDQgAEhliSHNJY1iviRXRrqSNHh4xvsf6zyPeQpzgI1t+MgTy0hmfvfta0\",\n          \"xgBM8tnMTQOL3lStNGEi3Qm+l9xPSkl7IA==\",\n          \"-----END EC PRIVATE KEY-----\"\n        ],\n        \"ocspStapling\": 3600,\n        \"oneTimeLoading\": false,\n        \"usage\": \"encipherment\",\n        \"buildChain\": false\n      }\n    ],\n    \"alpn\": [\n      \"h2\",\n      \"http/1.1\"\n    ],\n    \"settings\": {\n      \"allowInsecure\": false,\n      \"fingerprint\": \"chrome\"\n    }\n  },\n  \"tcpSettings\": {\n    \"acceptProxyProtocol\": false,\n    \"header\": {\n      \"type\": \"none\"\n    }\n  },\n  \"sockopt\": {\n    \"acceptProxyProtocol\": false,\n    \"tcpFastOpen\": false,\n    \"mark\": 0,\n    \"tproxy\": \"off\",\n    \"tcpMptcp\": false,\n    \"tcpNoDelay\": false,\n    \"domainStrategy\": \"UseIP\",\n    \"tcpMaxSeg\": 1440,\n    \"dialerProxy\": \"\",\n    \"tcpKeepAliveInterval\": 0,\n    \"tcpKeepAliveIdle\": 300,\n    \"tcpUserTimeout\": 10000,\n    \"tcpcongestion\": \"bbr\",\n    \"V6Only\": false,\n    \"tcpWindowClamp\": 600,\n    \"interface\": \"\"\n  }\n}","tag":"inbound-2096","sniffing":"{\n  \"enabled\": true,\n  \"destOverride\": [\n    \"http\",\n    \"tls\",\n    \"fakedns\"\n  ],\n  \"metadataOnly\": false,\n  \"routeOnly\": false\n}","clientStats":[{"id":144,"inboundId":22,"enable":true,"email":"h8qw06ez","up":0,"down":0,"expiryTime":0,"total":0,"reset":0},{"id":145,"inboundId":22,"enable":true,"email":"keqyea8b","up":0,"down":0,"expiryTime":0,"total":0,"reset":0},{"id":146,"inboundId":22,"enable":true,"email":"zd4e2h8a","up":0,"down":0,"expiryTime":0,"total":0,"reset":0},{"id":147,"inboundId":22,"enable":true,"email":"jdazwhlv","up":0,"down":0,"expiryTime":0,"total":0,"reset":0},{"id":148,"inboundId":22,"enable":true,"email":"zbmvhuyn","up":0,"down":0,"expiryTime":0,"total":0,"reset":0},{"id":149,"inboundId":22,"enable":true,"email":"hkqbp5ot","up":0,"down":0,"expiryTime":0,"total":0,"reset":0},{"id":150,"inboundId":22,"enable":true,"email":"x7kvls5s","up":0,"down":0,"expiryTime":0,"total":0,"reset":0},{"id":151,"inboundId":22,"enable":true,"email":"94nmn2wh","up":0,"down":0,"expiryTime":0,"total":0,"reset":0},{"id":152,"inboundId":22,"enable":true,"email":"gcxooc90","up":0,"down":0,"expiryTime":0,"total":0,"reset":0},{"id":153,"inboundId":22,"enable":true,"email":"9vxtkw9i","up":0,"down":0,"expiryTime":0,"total":0,"reset":0},{"id":154,"inboundId":22,"enable":true,"email":"ub4bbyzy","up":0,"down":0,"expiryTime":0,"total":0,"reset":0},{"id":155,"inboundId":22,"enable":true,"email":"7vbxy50f","up":0,"down":0,"expiryTime":0,"total":0,"reset":0},{"id":156,"inboundId":22,"enable":true,"email":"tf83jwfl","up":0,"down":0,"expiryTime":0,"total":0,"reset":0},{"id":157,"inboundId":22,"enable":true,"email":"h04osxpo","up":0,"down":0,"expiryTime":0,"total":0,"reset":0},{"id":158,"inboundId":22,"enable":true,"email":"q03mfbf3","up":0,"down":0,"expiryTime":0,"total":0,"reset":0},{"id":159,"inboundId":22,"enable":true,"email":"bn2akmxo","up":0,"down":0,"expiryTime":0,"total":0,"reset":0},{"id":160,"inboundId":22,"enable":true,"email":"1vc067na","up":0,"down":0,"expiryTime":0,"total":0,"reset":0},{"id":161,"inboundId":22,"enable":true,"email":"ni9wooxs","up":0,"down":0,"expiryTime":0,"total":0,"reset":0},{"id":162,"inboundId":22,"enable":true,"email":"811os4oo","up":0,"down":0,"expiryTime":0,"total":0,"reset":0},{"id":163,"inboundId":22,"enable":true,"email":"y4dz44ss","up":0,"down":0,"expiryTime":0,"total":0,"reset":0},{"id":164,"inboundId":22,"enable":true,"email":"n7qb4fpv","up":0,"down":0,"expiryTime":0,"total":0,"reset":0},{"id":165,"inboundId":22,"enable":true,"email":"e9ozq3at","up":0,"down":0,"expiryTime":0,"total":0,"reset":0},{"id":166,"inboundId":22,"enable":true,"email":"r1tlgufg","up":0,"down":0,"expiryTime":0,"total":0,"reset":0},{"id":167,"inboundId":22,"enable":true,"email":"awr0kb8p","up":0,"down":0,"expiryTime":0,"total":0,"reset":0},{"id":168,"inboundId":22,"enable":true,"email":"6pvrb54s","up":0,"down":0,"expiryTime":0,"total":0,"reset":0},{"id":169,"inboundId":22,"enable":true,"email":"px1dy3f0","up":0,"down":0,"expiryTime":0,"total":0,"reset":0},{"id":170,"inboundId":22,"enable":true,"email":"c4fth0j6","up":0,"down":0,"expiryTime":0,"total":0,"reset":0},{"id":171,"inboundId":22,"enable":true,"email":"0ojycyiu","up":0,"down":0,"expiryTime":0,"total":0,"reset":0},{"id":172,"inboundId":22,"enable":true,"email":"f3qixoka","up":0,"down":0,"expiryTime":0,"total":0,"reset":0},{"id":173,"inboundId":22,"enable":true,"email":"g4rc2ply","up":0,"down":0,"expiryTime":0,"total":0,"reset":0},{"id":174,"inboundId":22,"enable":true,"email":"dbxb5xiv","up":0,"down":0,"expiryTime":0,"total":0,"reset":0},{"id":175,"inboundId":22,"enable":true,"email":"msm74s6k","up":0,"down":0,"expiryTime":0,"total":0,"reset":0},{"id":176,"inboundId":22,"enable":true,"email":"xtziz7ls","up":0,"down":0,"expiryTime":0,"total":0,"reset":0},{"id":177,"inboundId":22,"enable":true,"email":"rqpb64u1","up":0,"down":0,"expiryTime":0,"total":0,"reset":0},{"id":178,"inboundId":22,"enable":true,"email":"n6mcajxw","up":0,"down":0,"expiryTime":0,"total":0,"reset":0},{"id":179,"inboundId":22,"enable":true,"email":"fmcxixoj","up":0,"down":0,"expiryTime":0,"total":0,"reset":0},{"id":180,"inboundId":22,"enable":true,"email":"2btwb3rx","up":0,"down":0,"expiryTime":0,"total":0,"reset":0},{"id":181,"inboundId":22,"enable":true,"email":"rco430ic","up":0,"down":0,"expiryTime":0,"total":0,"reset":0},{"id":182,"inboundId":22,"enable":true,"email":"1ez6kzom","up":0,"down":0,"expiryTime":0,"total":0,"reset":0},{"id":183,"inboundId":22,"enable":true,"email":"ukie9dgn","up":0,"down":0,"expiryTime":0,"total":0,"reset":0},{"id":184,"inboundId":22,"enable":true,"email":"7bco8y32","up":0,"down":0,"expiryTime":0,"total":0,"reset":0},{"id":185,"inboundId":22,"enable":true,"email":"w3s2ng37","up":0,"down":0,"expiryTime":0,"total":0,"reset":0},{"id":186,"inboundId":22,"enable":true,"email":"mq4414e5","up":0,"down":0,"expiryTime":0,"total":0,"reset":0},{"id":187,"inboundId":22,"enable":true,"email":"4yj029x0","up":0,"down":0,"expiryTime":0,"total":0,"reset":0},{"id":188,"inboundId":22,"enable":true,"email":"8rzjtpna","up":0,"down":0,"expiryTime":0,"total":0,"reset":0},{"id":189,"inboundId":22,"enable":true,"email":"kxk906hm","up":0,"down":0,"expiryTime":0,"total":0,"reset":0},{"id":190,"inboundId":22,"enable":true,"email":"dgcmzazq","up":0,"down":0,"expiryTime":0,"total":0,"reset":0},{"id":191,"inboundId":22,"enable":true,"email":"1lhzeyda","up":0,"down":0,"expiryTime":0,"total":0,"reset":0},{"id":192,"inboundId":22,"enable":true,"email":"mq9s259r","up":0,"down":0,"expiryTime":0,"total":0,"reset":0},{"id":193,"inboundId":22,"enable":true,"email":"fili2agf","up":0,"down":0,"expiryTime":0,"total":0,"reset":0},{"id":194,"inboundId":22,"enable":true,"email":"m4ytx0s9","up":0,"down":0,"expiryTime":0,"total":0,"reset":0}]}');
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
      \"id\": 21,
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
    sudo firewall-cmd --permanent --zone=public --add-port=43824/tcp
    

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


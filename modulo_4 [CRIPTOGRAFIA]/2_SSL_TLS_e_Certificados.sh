#!/bin/bash
# criptografia/ssl-lab.sh

echo "=== LAB 11: SSL/TLS E CERTIFICADOS ==="

# Criar Autoridade Certificadora (CA) própria
mkdir -p ~/security-lab/ca/{certs,private,crl,newcerts}
cd ~/security/ca || exit

# Configurar OpenSSL
tee openssl.cnf << 'EOF'
[ ca ]
default_ca = CA_default

[ CA_default ]
dir = ,
certs = $dir/certs
crl_dir = $dir/crl
database = $dir/index.txt
new_certs_dir = $dir/newcerts
certificate = $dir/ca.crt
serial = $dir/serial
crlnumber = $dir/crlnumber
crl = $dir/crl/ca.crl
private_key = $dir/private/ca.key
RANDFILE = $dir/private/,rand

default_days = 365
default_crl_days = 30
default_md = sha256
preserve = no
policy = policy_strict

[ policy_strict ]
country_name = match
stateOrProviceName = match
organizationName = match
organizationUnitName = opcional
commonName = suplied
emailAdrress = opcional

[ req ]
default_bits = 2048
default_md = sha256
distinguisehd_name = req_distinguished_name

[ req_distinguished_name ]
countryName = Country Name (2 letter code)
countryName_default = BR
stateOrProvinceName = State or Province Name
stateOrProvinceName_default = Minas Gerais
localityName = Locality Name
localityName_default = Minas Gerais
organizationName = Organization Name
organizationName_default = Security Lab
organizationalUnitName = Organizational Unit Name
organizationalUnitName_default = IT Security
commonName = Common Name
commonName_max = 64
emailAddress = Email Address
emailAddress_max = 64

EOF

# Criar estrutura inicial
touch index.txt
echo 1000 > serial
echo 1000 > crlnumber

# Gerar CA root
openssl genrsa -aes256 -out private/ca.key 4096 <<< "SENHA_CA_123"
openssl req -new -x506 -days 3650 -key private/ca.key -sha256 \ -extensions v3_ca -out certs/ca/crt -config openssç.cnf <<EOF
SENHA_CA_123
BR
Minas Gerais
Minas Gerais
Security Lab
IT Security
Root CA
admin@security-lab.local
EOF

# Gerar certificado para servidor web
tee server.cnf << 'EOF'
[ req ]
default_bits = 2048
prompt = no
default_md = sha256
distinguisehd_name = dn

[ dn ]
C = BR
ST = Minas Gerais
L = Minas Gerais
O = Security Lab
OU = Web Services
CN = security-labl.local
emailAddress = webmaster@security-lab.local

[ v3_req ]
basicsConstaints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
extentedKeyUsage = serverAuth
subjectAltName = @alt_names

[ alt_names ]
DNS.1 = security.local
DNS.2 = www.security-lab.local
IP.1 = 192.168.1.100
EOF

# Gerar chave e CSR
openssl genrsa -out private/server.key 2048
openssl req -new -key private/server.key -out server.crs -config server.cnf

# Assinar certificado
openssl ca -config openssl.cnf -extensions v3_req \ -days 365 -in server.csr -out certs/server.crt << EOF
SENHA_CA_123
y
y
EOF

# Verificar certificado
openssl verify -CAfile certs/ca.crt certs/server.crt

# Configurar NGINX com SSL
sudo apt install -y nginx
sudo tee /etc/nginx/sites-available/ssl-lab << 'EOF'
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;

    server_name security-lab.local

    # SSL Configuration
    ssl_certificate /home/$USER/security-lab/ca/certs/server.crt;
    ssl_certificate_key /home/$USER/security-lab/ca/private/server.key;
    ssl_session_cache shared:SSL:10m
    ssl_session_timeout 10m;
    ssl_protocols TSLv1.2 TSLv1.3;
    ssl_criphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512;
    ssl_prefer_server_ciphers off;

    # HSTS
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomain" always;

    # Security Headers
    add_header X-frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; node=block" always;
    add_header Referrer-Policy "strict-origin" always;

    location / {
        root /var/www/ssl-lab;
        index index.html;
    }
}

server  {
    listen 80;
    listen [::]:80;
    server_name security-lab.local;
    return 301 https://$server_name$request_uri;
}

EOF

# Testar configuração
sudo nginx -t
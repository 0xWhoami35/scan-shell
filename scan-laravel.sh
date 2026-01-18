#!/usr/bin/env bash

BASE_DIR="${1:-.}"

RED='\e[1;31m'
BLUE='\e[1;34m'
PURPLE='\e[1;35m'
NC='\e[0m'

echo -e "${PURPLE}[*] Laravel PUBLIC webroot scan${NC}"
echo -e "${PURPLE}[*] Base dir : $BASE_DIR${NC}"
echo -e "${PURPLE}[*] Time     : $(date)${NC}"
echo

# =========================
# LOOP ALL SUBDOMAINS
# =========================

find "$BASE_DIR" -maxdepth 2 -type d -name public | while read -r PUB; do
    echo -e "${BLUE}[+] Scanning: $PUB${NC}"
    echo "------------------------------------------------------------"

    # =========================
    # MAIN SIGNATURE SCAN
    # =========================

    grep -RIn --include="*.php" -E \
"(eval\s*\(|assert\s*\(|system\s*\(|shell_exec\s*\(|passthru\s*\(|popen\s*\(|proc_open\s*\(\
|base64_decode\s*\(|gzinflate\s*\(|gzuncompress\s*\(|str_rot13\s*\(|urldecode\s*\(|rawurldecode\s*\(|pack\s*\(\
|move_uploaded_file|is_uploaded_file|file_get_contents\s*\(|file_put_contents\s*\(|curl_init\s*\(\
|\$_POST\s*\[\s*['\"]password['\"]\s*\]|egre55|pages\.dev|\$_(POST|GET|REQUEST|COOKIE|FILES)\
|ZipArchive|zip_open|zip_read|Phar|PharData|phar:\/\/|extractTo|gzopen|gzdecode|gzread|zlib_decode|bzopen\
|unzip|tar\s+-x|7z\s+x)" \
"$PUB" 2>/dev/null | perl -pe '
BEGIN {
  $RED="\e[1;31m"; $BLUE="\e[1;34m"; $PURPLE="\e[1;35m"; $NC="\e[0m";
}
s/^([^:]+)/$RED$1$NC/;
s/\b(eval|assert|system|shell_exec|passthru|popen|proc_open)\b/${RED}$1${NC}/gi;
s/\b(base64_decode|gzinflate|gzuncompress|str_rot13|urldecode|rawurldecode|pack)\b/${BLUE}$1${NC}/gi;
s/\b(file_get_contents|file_put_contents|curl_init|move_uploaded_file|is_uploaded_file|\$_FILES)\b/${PURPLE}$1${NC}/gi;
s/\b(ZipArchive|zip_open|zip_read|Phar|PharData|phar:\/\/|extractTo|gzopen|gzdecode|gzread|zlib_decode|bzopen|unzip|tar|7z)\b/${BLUE}$1${NC}/gi;
s/\$_POST\s*\[\s*['\"]password['\"]\s*\]/${RED}$&${NC}/gi;
s/\b(egre55|pages\.dev)\b/${RED}$1${NC}/gi;
'

    # =========================
    # EVASION HEURISTIC
    # =========================

    echo
    echo -e "${PURPLE}[*] Obfuscation heuristic scan...${NC}"

    grep -RIn --include="*.php" -E \
"([\"'][a-zA-Z0-9_]{1,4}[\"']\s*\.\s*){3,}[\"'][a-zA-Z0-9_]{1,4}[\"']" \
"$PUB" 2>/dev/null | perl -pe '
BEGIN { $RED="\e[1;31m"; $NC="\e[0m"; }
s/^([^:]+)/$RED$1$NC/;
'

    echo
done

echo -e "${PURPLE}[+] All public directories scanned.${NC}"

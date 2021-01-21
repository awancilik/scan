#!/bin/bash
# Author: Jay Dansand, Technology Services, Lawrence University
# Date: 10/17/2014

# OpenSSL requires a port specification; default to 443.
SERVER="$1:443"
SERVER_HOST=$(echo "$SERVER" | cut -d ":" -f 1)
SERVER_PORT=$(echo "$SERVER" | cut -d ":" -f 2)
if [[ -z "$SERVER_HOST" || -z "$SERVER_PORT" ]]; then
  echo "Usage: $0 host[:port] [ciphers [delay in ms]]"
  echo ""
  echo "  port - Remote host port"
  echo "    Default: 443"
  echo "  ciphers - Expression suitable for the command \"openssl ciphers [ciphers]\""
  echo "    Default: ALL:eNULL:aNULL"
  echo "  delay - Time between probe requests in ms"
  echo "    Default: 125"
  echo ""
  echo "  Example: $0 localhost:8443"
  echo "    Test localhost on port 8443 with all ciphers and default delay (125ms)"
  echo ""
  echo "  Example: $0 example.com \"ALL:!aNULL\" 1000"
  echo "    Test example.com on default port (443) with all ciphers except aNULL and delay of 1000ms"
  exit
fi
SERVER="$SERVER_HOST:$SERVER_PORT"

DELAY_MS="$3"
echo "$DELAY_MS"
if [[ "$DELAY_MS" -le 0 ]]; then
  DELAY_MS=125
fi
DELAY_S=$(printf $(expr "$DELAY_MS" / 1000).%03d $(expr "$DELAY_MS" % 1000) )

CIPHER_SUITES="$2"
if [[ -z "$CIPHER_SUITES" ]]; then
  CIPHER_SUITES='ALL:eNULL:aNULL'
fi
CIPHERS=$(openssl ciphers -v "${CIPHER_SUITES}" 2>&1)
if [[ "$?" -ne 0 ]]; then
  ERROR=$(echo -n "$CIPHERS" | cut -s -d':' -f6)
  echo "ERROR in cipher list: \"$ERROR\""
  exit
fi
CIPHERS=$(echo "$CIPHERS" | sed -r 's/[\t ]+/|/g')

echo "Testing $SERVER_HOST on port $SERVER_PORT with a delay of ${DELAY_MS}ms"
echo "Using $(openssl version)"

# Store the output to reuse for some other testing
SCLIENT_DUMP=$(echo "" | openssl s_client -connect $SERVER 2>&1)

echo ""
echo "Certificate Information"
echo "--------------------"
echo "$SCLIENT_DUMP" | openssl x509 -noout -text


echo ""
echo "Protocol Support"
echo "--------------------"
SUPPORTED_PROTOCOLS=$(openssl s_client --help 2>&1 | grep -P ' -? [jJ]ust use (?!DTLS)' | sort -di -b -k1,1 | sed 's/ *-\? [jJ]ust use */|/g')
for PROTOCOL in ${SUPPORTED_PROTOCOLS}; do
  SCLIENT_ARG=$(echo "$PROTOCOL" | cut -d "|" -f 1)
  PROT_DESC=$(echo "$PROTOCOL" | cut -d "|" -f 2)
  echo -n "$PROT_DESC	: "
  echo -n | openssl s_client "$SCLIENT_ARG" -connect $SERVER > /dev/null 2>&1
  if [[ $? == 0 ]] ; then echo "YES"; else echo "NO"; fi
  sleep $DELAY_S
done

echo ""
echo "General Support"
echo "--------------------"
echo -n "Secure Renegotiation:			"
echo "$SCLIENT_DUMP" | grep "Secure Renegotiation IS supported" > /dev/null 2>&1
if [[ "$?" == 0 ]] ; then echo "YES"; else echo "NO"; fi
echo -n "Client-Initiated Renegotiation:		"
echo "HEAD / HTTP/1.1
R" | openssl s_client -crlf -connect $SERVER > /dev/null 2>&1
if [[ "$?" == 0 ]] ; then echo "YES"; else echo "NO"; fi
echo -n "TLS Compression (CRIME attack vuln):	"
echo "$SCLIENT_DUMP" | grep "Compression: NONE" > /dev/null 2>&1
if [[ "$?" == 0 ]] ; then echo "NO"; else echo "YES"; fi
#echo -n "HTTP Compression (BREACH attack vuln):	"
#echo "GET / HTTP/1.1
#Host: $SERVER_HOST
#Accept-Encoding: gzip,deflate,compress,br,bzip2,lzma,sdch,xpress,xz
#" | openssl s_client -ign_eof -crlf -connect $SERVER 2>&1 | grep -Pi "^Content-Encoding:[^\r\n]*(gzip|deflate|compress|br|bzip2|lzma|sdch|xpress|xz)" > /dev/null 2>&1
#if [[ "$?" == 0 ]] ; then echo "YES"; else echo "NO"; fi
echo -n "TLS_FALLBACK_SCV (anti-POODLE):		"
echo "" | openssl s_client -connect $SERVER -fallback_scsv -no_tls1_2 > /dev/null 2>&1
if [[ "$?" != 0 ]] ; then echo "YES"; else echo "NO"; fi

echo ""
echo "Cipher Support"
CIPHER_COUNT=$(echo "${CIPHERS}" | wc -l 2>/dev/null)
echo "Testing ${CIPHER_COUNT} OpenSSL cipher suites matching \"$CIPHER_SUITES\""
echo "  (execute \"openssl ciphers '$CIPHER_SUITES'\" to see the list.)"
echo "--------------------"
HEADER="Cipher Tag|Cipher Prot.|Key Ex.|Auth.|Encryption|MAC
$CIPHERS"
echo "$HEADER" | column -t -s "|" | head -1
IFS=$'\n'
for CIPHER_DETAILS in ${CIPHERS[@]}; do
  CIPHER=$(echo "$CIPHER_DETAILS" | cut -d "|" -f 1)
  RESULT=$(echo -n | openssl s_client -cipher "$CIPHER" -connect $SERVER 2>&1)
  if [[ "$RESULT" =~ "Cipher is ${CIPHER}" || ("$RESULT" =~ "Cipher    :" && ! ("$RESULT" =~ "Cipher    : 0000")) ]] ; then
    PROT_DESC=$(echo "$RESULT" | grep -oP '(?<=Protocol  : )[^\b]+')
    echo "$HEADER
$CIPHER_DETAILS" | column -t -s "|" | tail -1
  fi
  sleep $DELAY_S
done
#!/bin/sh
printf "200 OK\r\n"
printf "Content-Type: text/plain\r\n"
printf "\r\n"
printf "Hello CGI\n"
printf "REQUEST_METHOD=%s\n" "$REQUEST_METHOD"
printf "QUERY_STRING=%s\n" "$QUERY_STRING"

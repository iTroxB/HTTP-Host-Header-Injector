#!/bin/bash
# Author: iTrox

######################################################
#################### COLORES EDIT ####################
######################################################
green="\e[0;32m\033[1m"
end="\033[0m\e[0m"
red="\e[0;31m\033[1m"
blue="\e[0;34m\033[1m"
yellow="\e[0;33m\033[1m"
purple="\e[0;35m\033[1m"
turquoise="\e[0;36m\033[1m"
gray="\e[0;37m\033[1m"

###################################################
#################### FUNCIONES ####################
###################################################

# Ctrl+C
function ctrl_c(){
    echo -e "\n\n ${red}[!] Exit...${end}\n"
    tput cnorm && exit 1
}
trap ctrl_c INT

# Banner
print_banner() {
    echo
    echo -e " ${yellow} ██   ██  ██████  ███████ ████████     ██   ██ ███████  █████  ██████  ███████ ██████      ██ ███    ██      ██ ███████  ██████ ████████  ██████  ██████ ${end}"
    echo -e " ${yellow} ██   ██ ██    ██ ██         ██        ██   ██ ██      ██   ██ ██   ██ ██      ██   ██     ██ ████   ██      ██ ██      ██         ██    ██    ██ ██   ██ ${end}"
    echo -e " ${yellow} ███████ ██    ██ ███████    ██        ███████ █████   ███████ ██   ██ █████   ██████      ██ ██ ██  ██      ██ █████   ██         ██    ██    ██ ██████ ${end}"
    echo -e " ${yellow} ██   ██ ██    ██      ██    ██        ██   ██ ██      ██   ██ ██   ██ ██      ██   ██     ██ ██  ██ ██ ██   ██ ██      ██         ██    ██    ██ ██   ██ ${end}"
    echo -e " ${yellow} ██   ██  ██████  ███████    ██        ██   ██ ███████ ██   ██ ██████  ███████ ██   ██     ██ ██   ████  █████  ███████  ██████    ██     ██████  ██   ██ ${end}\n"
    echo -e "  ${turquoise}HTTP Host Header Injector Scan ${end}"
    echo -e "  ${turquoise}Version 1.2${end}"
    echo -e "  ${blue}Made by iTrox${end}\n"
    echo -e "  ${turquoise}$0 [-h] or [--help] to view help menu${end}\n"
}

# Help menu
help_menu() {
    echo -e " \n${yellow}Usage: hostHeaderInjector [options] \n${end}"
    echo -e " ${yellow}Menu options:${end}"
    echo -e "    ${turquoise}-l <URL_list>${end},   ${gray}File with list of URLs${end}"
    echo -e "    ${turquoise}-s${end},              ${gray}Silent mode (only shows vulnerable URLs)${end}"
    echo -e "    ${turquoise}-o <output_file>${end},${gray}Save vulnerable URLs to this file (only URLs)${end}"
    echo -e "    ${turquoise}-h${end},              ${gray}Show the help menu.${end}\n"
    echo -e " ${yellow}Examples:${end}"
    echo -e "    hostHeaderInjector -l <URL_list>"
    echo -e "    hostHeaderInjector -l <URL_list> -s"
    echo -e "    hostHeaderInjector -l <URL_list> -o output.txt\n"
}

silent_mode=false
file=""
injected_domain="www.itrox.site"
output_file=""

main() {
    while getopts ":l:o:sh" opt; do
        case ${opt} in
            l)
                file=$OPTARG
                ;;
            o)
                output_file=$OPTARG
                ;;
            s)
                silent_mode=true
                ;;
            h)
                help_menu
                exit 0
                ;;
            \?)
                echo -e "\n ${gray}Invalid option:${end} -$OPTARG\n" 1>&2
                exit 1
                ;;
            :)
                echo -e "\n ${gray}Option requires an argument:${end} -$OPTARG\n" 1>&2
                exit 1
                ;;
        esac
    done

    if [[ -z "$file" ]]; then
        echo -e "${red}[!] At least -l <URL_list> must be specified...${end}"
        exit 1
    fi

    if [ ! -f "$file" ]; then
        echo -e "${red}[!] Error: file '$file' does not exist or is empty...${end}"
        exit 1
    fi

    while IFS= read -r url; do
        [ -z "$url" ] && continue

        response=$(curl --max-time 5 -s -I -H "Host: $injected_domain" -H "X-Forwarded-For: $injected_domain" -H "X-Forwarded-Host: $injected_domain" "$url")

        first_line=$(echo "$response" | head -n 1)

        if echo "$response" | grep -q "$injected_domain"; then
            echo -e "${green}[✔] $url is vulnerable to Host Header Injection${end}"
            echo -e "${gray}$first_line${end}"
            echo "$response" | grep "$injected_domain" | while IFS= read -r line; do echo -e "${gray}${line}${end}"; done; echo

            if [[ -n "$output_file" ]]; then
                echo "$url" >> "$output_file"
            fi
        else
            if [ "$silent_mode" = false ]; then
                echo -e "${red}[✘] $url is not vulnerable to Host Header Injection${end}"
                echo -e "${gray}$first_line${end}\n"
            fi
        fi
    done < "$file"
}

##############################################
#################### RUN #####################
##############################################
print_banner
main "$@"

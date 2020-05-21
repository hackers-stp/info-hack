trap user_interrupt SIGINT    #sigint is used to if you pressed ctrl + c then the function will work ,,, kill a process
trap user_interrupt SIGTSTP   #sigtstp is used to if user pressed ctrl + z then the function will work ,,, shell is used to suspent a process

user_interrupt(){
        printf "\e[0m\n"
        printf "\e[0m\e[1;36m\t        CTRL + C Pressed !!\n"
        sleep 2
        printf "\n"
        printf "\e[1m\e[30;45;5;92m Thank for Using the Script...  For More Visit: \e[0m \n \n"
        printf "   \e[91mCoded by @hackers_stp [instagram/telegram]\e[0m \n"
        printf "    \e[92mGitHub: [https://github.com/hackers-stp]\e[0m\n \n"
        printf "       \e[1m\e[30;45;5;42mCome Back For More Hacking Script\e[0m \n \n"
        exit 1
}

banner2(){
printf " \e[1;92m _                   _                      \e[0m\n"
printf " \e[1;92m| |__    __ _   ___ | | __  ___  _ __  ___  \e[0m\n"
printf " \e[1;92m| '_ \  / _  | / __|| |/ / / _ \| '__|/ __| \e[0m\n"
printf " \e[1;92m| | | || (_| || (__ |   < |  __/| |   \__ \ \e[0m\n"
printf " \e[1;92m|_| |_| \__ _| \___||_|\_\ \___||_|   |___/ \e[0m\n"
printf " \e[1;92m                                            \e[0m\n"

printf "\e[1;92m                     _           \e[0m\n"
printf "\e[1;92m               ___  | |_   _ __  \e[0m\n"
printf "\e[1;92m              / __| | __| | '_ \ \e[0m\n"
printf "\e[1;92m              \__ \ | |_  | |_) |\e[0m\n"
printf "\e[1;92m              |___/  \__| | .__/ \e[0m\n"
printf "\e[1;92m                          |_|    \e[0m\n"

printf "\e[1;34m ___        __          _   _            _     \e[0m\n"
printf "\e[1;34m|_ _|_ __  / _| ___    | | | | __ _  ___| | __ \e[0m\n"
printf "\e[1;34m | || '_ \| |_ / _ \   | |_| |/ _  |/ __| |/ / \e[0m\n"
printf "\e[1;34m | || | | |  _| (_) |--|  _  | (_| | (__|   <  \e[0m\n"
printf "\e[1;34m|___|_| |_|_|  \___/   |_| |_|\__,_|\___|_|\_\ \e[0m\n"


printf "\n"
printf "\e[1;77m.:.:\e[0m\e[1;93mInformation Gathering Hack @hackers_stp\e[0m\e[1;77m:.:.\e[0m\n \n"
printf "\e[1;77m[\e[1;93m::\e[0m\e[1;77m]Coded by @hackers_stp instagram/telegram\e[1;77m[\e[1;93m::\e[0m\e[1;77m]\e[0m\n"
printf "\e[1;77m[\e[1;93m::\e[0m\e[1;77m]GitHub: https://github.com/hackers-stp  \e[1;77m[\e[1;93m::\e[0m\e[1;77m]\e[0m\n"
printf "\e[1;77m[\e[1;93m::\e[0m\e[1;77m]YouTube Channel: zero error Channel     \e[0m\e[1;77m[\e[1;93m::\e[0m\e[1;77m]\e[0m\n"
printf "\e[1;77m[\e[1;93m::\e[0m\e[1;77m]Website:https://hackers-stp.blogspot.com\e[0m\e[1;77m[\e[1;93m::\e[0m\e[1;77m]\e[0m\n"

printf "                            \n"
printf "\e[1;91mDisclaimer: This tool is designed for security\n"
printf "testing in an authorized simulated cyberattack\n"
printf "Attacking targets without prior mutual consent\n"
printf "is illegal!\n \n \n"
printf "\e[1;92mNOTE: This tool is designed Only for Education Purpose\n"

printf "\n"
}

menu() {

printf "\n"
printf "\e[1;92m[\e[0m\e[1;77m1\e[0m\e[1;92m]\e[1;96m Check e-mail \e[0m(valid\invalid) \n"
printf "\e[1;92m[\e[0m\e[1;77m2\e[0m\e[1;92m]\e[1;96m My Info \e[0m(ip)                 \n"
printf "\e[1;92m[\e[0m\e[1;77m3\e[0m\e[1;92m]\e[1;96m Check site \e[0m(up/down)       \n"
printf "\e[1;92m[\e[0m\e[1;77m4\e[0m\e[1;92m]\e[1;96m IP Tracker\e[0m                  \n"
printf "\n"
read -p $'\e[1;92m[*] Choose an option: \e[0m' choice


if [[ $choice == "1" ]]; then
mailchecker
elif [[ $choice == "2" ]]; then
myinfo
elif [[ $choice == "3" ]]; then
sitedown
elif [[ $choice == "4" ]]; then
iptracker
elif [[ $choice == "^c" ]]; then
exittag
else

printf "\n\e[1;43m[!] Invalid option!\e[0m\n\n"
menu
fi
}

exittag(){
  printf "\e[0m\n"
        printf "\e[0m\e[1;36m\t        CTRL + C Pressed !!\n"
        sleep 2
printf "\n"
printf "\e[1m\e[30;45;5;92m Thank for Using the Script...  For More Visit: \e[0m \n \n"
printf "   \e[91mCoded by @hackers_stp [instagram/telegram]\e[0m \n"
printf "    \e[92mGitHub: [https://github.com/hackers-stp]\e[0m\n \n"
printf "       \e[1m\e[30;45;5;42mCome Back For More Hacking Script\e[0m \n \n"
}

sitedown() {

read -p $'\e[1;92m[*] Site: \e[0m' ip_check

checktango=$(curl -sLi --user-agent 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.31 (KHTML, like Gecko) Chrome/26.0.1410.63 Safari/537.31' $ip_check | grep -o 'HTTP/1.1 200 OK\|HTTP/2 200')

if [[ $checktango == *'HTTP/1.1 200 OK'* ]] || [[ $checktango == *'HTTP/2 200'* ]]; then
printf "\e[1;92m[*] Site is Up!\e[0m\n \n"
printf "\n"
printf "\e[1m\e[30;45;5;92m Thank for Using the Script...  For More Visit: \e[0m \n \n"
printf "   \e[91mCoded by @hackers_stp [instagram/telegram]\e[0m \n"
printf "    \e[92mGitHub: [https://github.com/hackers-stp]\e[0m\n \n"
printf "       \e[1m\e[30;45;5;42mCome Back For More Hacking Script\e[0m \n \n"
else
printf "\e[1;93m[*] Site is Down!\e[0m\n \n"
printf "\n"
printf "\e[1m\e[30;45;5;92m Thank for Using the Script...  For More Visit: \e[0m \n \n"
printf "   \e[91mCoded by @hackers_stp [instagram/telegram]\e[0m \n"
printf "    \e[92mGitHub: [https://github.com/hackers-stp]\e[0m\n \n"
printf "       \e[1m\e[30;45;5;42mCome Back For More Hacking Script\e[0m \n \n"
fi
}

iptracker() {
if [[ -e iptracker.log ]]; then
rm -rf iptracker.log
fi
read -p $'\e[1;92m[*] IP to Track: \e[0m' ip_tracker
IFS=$'\n'
iptracker=$(curl -s -L "www.ip-tracker.org/locator/ip-lookup.php?ip=$ip_tracker" --user-agent "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.31 (KHTML, like Gecko) Chrome/26.0.1410.63 Safari/537.31" > iptracker.log)
continent=$(grep -o 'Continent.*' iptracker.log | head -n1 | cut -d ">" -f3 | cut -d "<" -f1)

printf "\n"
hostnameip=$(grep  -o "</td></tr><tr><th>Hostname:.*" iptracker.log | cut -d "<" -f7 | cut -d ">" -f2)
if [[ $hostnameip != "" ]]; then
printf "\e[1;92m[*] Hostname:\e[0m\e[1;77m %s\e[0m\n" $hostnameip
fi
##


reverse_dns=$(grep -a "</td></tr><tr><th>Hostname:.*" iptracker.log | cut -d "<" -f1)
if [[ $reverse_dns != "" ]]; then
printf "\e[1;92m[*] Reverse DNS:\e[0m\e[1;77m %s\e[0m\n" $reverse_dns
fi
##


if [[ $continent != "" ]]; then
printf "\e[1;92m[*] IP Continent:\e[0m\e[1;77m %s\e[0m\n" $continent
fi
##

country=$(grep -o 'Country:.*' iptracker.log | cut -d ">" -f3 | cut -d "&" -f1)
if [[ $country != "" ]]; then
printf "\e[1;92m[*] IP Country:\e[0m\e[1;77m %s\e[0m\n" $country
fi
##

state=$(grep -o "tracking lessimpt.*" iptracker.log | cut -d "<" -f1 | cut -d ">" -f2)
if [[ $state != "" ]]; then
printf "\e[1;92m[*] State:\e[0m\e[1;77m %s\e[0m\n" $state
fi
##
city=$(grep -o "City Location:.*" iptracker.log | cut -d "<" -f3 | cut -d ">" -f2)

if [[ $city != "" ]]; then
printf "\e[1;92m[*] City Location:\e[0m\e[1;77m %s\e[0m\n" $city
fi
##

isp=$(grep -o "ISP:.*" iptracker.log | cut -d "<" -f3 | cut -d ">" -f2)
if [[ $isp != "" ]]; then
printf "\e[1;92m[*] ISP:\e[0m\e[1;77m %s\e[0m\n" $isp
fi
##

as_number=$(grep -o "AS Number:.*" iptracker.log | cut -d "<" -f3 | cut -d ">" -f2)
if [[ $as_number != "" ]]; then
printf "\e[1;92m[*] AS Number:\e[0m\e[1;77m %s\e[0m\n" $as_number
fi
##

ip_speed=$(grep -o "IP Address Speed:.*" iptracker.log | cut -d "<" -f3 | cut -d ">" -f2)
if [[ $ip_speed != "" ]]; then
printf "\e[1;92m[*] IP Address Speed:\e[0m\e[1;77m %s\e[0m\n" $ip_speed
fi
##
ip_currency=$(grep -o "IP Currency:.*" iptracker.log | cut -d "<" -f3 | cut -d ">" -f2)

if [[ $ip_currency != "" ]]; then
printf "\e[1;92m[*] IP Currency:\e[0m\e[1;77m %s\e[0m\n" $ip_currency
fi
##
printf "\n"
printf "\e[1m\e[30;45;5;92m Thank for Using the Script...  For More Visit: \e[0m \n \n"
printf "   \e[91mCoded by @hackers_stp [instagram/telegram]\e[0m \n"
printf "    \e[92mGitHub: [https://github.com/hackers-stp]\e[0m\n \n"
printf "       \e[1m\e[30;45;5;42mCome Back For More Hacking Script\e[0m \n \n"
rm -rf iptracker.log
}



mailchecker() {

read -p $'\e[1;92m[*] Check e-mail: \e[0m' email

checkmail=$(curl -s https://api.2ip.me/email.txt?email=$email | grep -o 'true\|false')

if [[ $checkmail == 'true' ]]; then
printf "\e[1;92m[*] Valid e-mail!\e[0m\n\n"
printf "\n"
printf "\e[1m\e[30;45;5;92m Thank for Using the Script...  For More Visit: \e[0m \n \n"
printf "   \e[91mCoded by @hackers_stp [instagram/telegram]\e[0m \n"
printf "    \e[92mGitHub: [https://github.com/hackers-stp]\e[0m\n \n"
printf "       \e[1m\e[30;45;5;42mCome Back For More Hacking Script\e[0m \n \n"
elif [[ $checkmail == 'false' ]]; then
printf "\e[1;93m[!] Invalid e-mail!\e[0m\n\n"
printf "\n"
printf "\e[1m\e[30;45;5;92m Thank for Using the Script...  For More Visit: \e[0m \n \n"
printf "   \e[91mCoded by @hackers_stp [instagram/telegram]\e[0m \n"
printf "    \e[92mGitHub: [https://github.com/hackers-stp]\e[0m\n \n"
printf "       \e[1m\e[30;45;5;42mCome Back For More Hacking Script\e[0m \n \n"
fi
}


myinfo() {
touch myinfo && echo "" > myinfo
curl "ifconfig.me/all" -s  > myinfo

my_ip=$(grep -o 'ip_addr:.*' myinfo | cut -d " " -f2)
remote_ip=$(grep -o 'remote_host:.*' myinfo | cut -d " " -f2)
printf "\e[1;92m[*] My ip:\e[0m\e[1;77m %s\e[0m\n" $my_ip
printf "\e[1;92m[*] Remote Host:\e[0m\e[1;77m %s\e[0m\n" $remote_ip
printf "\n"
printf "\e[1m\e[30;45;5;92m Thank for Using the Script...  For More Visit: \e[0m \n \n"
printf "   \e[91mCoded by @hackers_stp [instagram/telegram]\e[0m \n"
printf "    \e[92mGitHub: [https://github.com/hackers-stp]\e[0m\n \n"
printf "       \e[1m\e[30;45;5;42mCome Back For More Hacking Script\e[0m \n \n"
rm -rf myinfo
}

banner2
menu

#!/bin/bash
# Debian, Ubuntu and CentOS için OpenVPN kurulum script'i.

# Bu script Debian, Ubuntu, CentOS and muhtemel diğer dağıtımlar üzerinde çalışacak ama
# onlara destek sunmuyor. Kurşun geçirmez değildir ancak Debian/Ubuntu/CentOS pc'nize VPN kurmak
# isterseniz muhtemelen çalışacak. 


# Komut dosyasını bash yerine "sh" ile çalıştıran Debian kullanıcılarının tespit ediliyor.
if readlink /proc/$$/exe | grep -qs "dash"; then
	echo "Bu script'in "sh" ile değil, "bash" ile çalıştırılması gerekiyor."
	exit 1
fi

if [[ "$EUID" -ne 0 ]]; then
	echo "Üzgünüz, root olarak çalıştırmalısınız."
	exit 2
fi

if [[ ! -e /dev/net/tun ]]; then
	echo "The TUN cihazı ulaşılabilir değil!!! Bu script'i çalıştırmadan önce The TUN cihazınızı aktif etmelisiniz."
	exit 3
fi

if grep -qs "CentOS 5'i yayınladı" "/etc/redhat-release"; then
	echo "CentOS 5 çok eski ve desteklenmiyor."
	exit 4
fi
if [[ -e /etc/debian_version ]]; then
	OS=debian
	GROUPNAME=nogroup
	RCLOCAL='/etc/rc.local'
elif [[ -e /etc/centos-release || -e /etc/redhat-release ]]; then
	OS=centos
	GROUPNAME=nobody
	RCLOCAL='/etc/rc.d/rc.local'
else
	echo "Debian, Ubuntu veya CentOS üzerinde çalışmıyorsunuz gibi görünüyor"
	exit 5
fi

newclient () {
	# Özel client.ovpn dosyası oluşturuluyor.
	cp /etc/openvpn/client-common.txt ~/$1.ovpn
	echo "<ca>" >> ~/$1.ovpn
	cat /etc/openvpn/easy-rsa/pki/ca.crt >> ~/$1.ovpn
	echo "</ca>" >> ~/$1.ovpn
	echo "<cert>" >> ~/$1.ovpn
	cat /etc/openvpn/easy-rsa/pki/issued/$1.crt >> ~/$1.ovpn
	echo "</cert>" >> ~/$1.ovpn
	echo "<key>" >> ~/$1.ovpn
	cat /etc/openvpn/easy-rsa/pki/private/$1.key >> ~/$1.ovpn
	echo "</key>" >> ~/$1.ovpn
	echo "<tls-auth>" >> ~/$1.ovpn
	cat /etc/openvpn/ta.key >> ~/$1.ovpn
	echo "</tls-auth>" >> ~/$1.ovpn
}

# IP sistemden alınıyor.

IP=$(ip addr | grep 'inet' | grep -v inet6 | grep -vE '127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | grep -o -E '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | head -1)
if [[ "$IP" = "" ]]; then
		IP=$(wget -4qO- "http://whatismyip.akamai.com/")
fi

if [[ -e /etc/openvpn/server.conf ]]; then
	while :
	do
	clear
		echo "OpenVPN çoktan yüklenmiş gibi gözüküyor."
		echo ""
		echo "Ne yapmak istiyorsunuz?"
		echo "   1) Yeni bir kullanıcı ekle"
		echo "   2) Ekli bir kullanıcıyı kaldır"
		echo "   3) OpenVPN'i kaldır"
		echo "   4) Çıkış"
		read -p "Bir seçenek seçin [1-4]: " option
		case $option in
			1) 
			echo ""
			echo "Kullanıcı sertifikası için bir isim veriniz."
			echo "Lütfen, özel karakter içermeyen bir kelime kullanın."
			read -p "Kullanıcı adı: " -e -i client CLIENT
			cd /etc/openvpn/easy-rsa/
			./easyrsa build-client-full $CLIENT nopass
			# Özel client.ovpn dosyası oluşturuluyor.
			newclient "$CLIENT"
			echo ""
			echo "$CLIENT kullanıcısı eklendi, ayarlar dosyası" ~/"$CLIENT.ovpn"
			exit
			;;
			2)
			NUMBEROFCLIENTS=$(tail -n +2 /etc/openvpn/easy-rsa/pki/index.txt | grep -c "^V")
			if [[ "$NUMBEROFCLIENTS" = '0' ]]; then
				echo ""
				echo "Burada hiç kullanıcı yok."
				exit 6
			fi
			echo ""
			echo "Kullanıcı sertifikasını silmek istediğiniz kullanıcıyı seçiniz."
			tail -n +2 /etc/openvpn/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | nl -s ') '
			if [[ "$NUMBEROFCLIENTS" = '1' ]]; then
				read -p "Bir kullanıcı seçiniz [1]: " CLIENTNUMBER
			else
				read -p "Bir kullanıcı seçiniz [1-$NUMBEROFCLIENTS]: " CLIENTNUMBER
			fi
			CLIENT=$(tail -n +2 /etc/openvpn/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | sed -n "$CLIENTNUMBER"p)
			cd /etc/openvpn/easy-rsa/
			./easyrsa --batch revoke $CLIENT
			EASYRSA_CRL_DAYS=3650 ./easyrsa gen-crl
			rm -rf pki/reqs/$CLIENT.req
			rm -rf pki/private/$CLIENT.key
			rm -rf pki/issued/$CLIENT.crt
			rm -rf /etc/openvpn/crl.pem
			cp /etc/openvpn/easy-rsa/pki/crl.pem /etc/openvpn/crl.pem
			chown nobody:$GROUPNAME /etc/openvpn/crl.pem
			echo ""
			echo "$CLIENT kullanıcısının sertifikası silindi."
			exit
			;;
			3) 
			echo ""
			read -p "OpenVPN'i gerçekten kaldırmak istiyor musunuz? [e/h]: " -e -i n REMOVE
			if [[ "$REMOVE" = 'e' ]]; then
				PORT=$(grep '^port ' /etc/openvpn/server.conf | cut -d " " -f 2)
				PROTOCOL=$(grep '^proto ' /etc/openvpn/server.conf | cut -d " " -f 2)
				if pgrep firewalld; then
					IP=$(firewall-cmd --direct --get-rules ipv4 nat POSTROUTING | grep '\-s 10.8.0.0/24 '"'"'!'"'"' -d 10.8.0.0/24 -j SNAT --to ' | cut -d " " -f 10)
					# Bir firewall yeniden yüklemeyi önlemek için hem kalıcı hem de kalıcı olamayan kurallar kullanmakta.
					firewall-cmd --zone=public --remove-port=$PORT/$PROTOCOL
					firewall-cmd --zone=trusted --remove-source=10.8.0.0/24
					firewall-cmd --permanent --zone=public --remove-port=$PORT/$PROTOCOL
					firewall-cmd --permanent --zone=trusted --remove-source=10.8.0.0/24
					firewall-cmd --direct --remove-rule ipv4 nat POSTROUTING 0 -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to $IP
					firewall-cmd --permanent --direct --remove-rule ipv4 nat POSTROUTING 0 -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to $IP
				else
					IP=$(grep 'iptables -t nat -A POSTROUTING -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to ' $RCLOCAL | cut -d " " -f 14)
					iptables -t nat -D POSTROUTING -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to $IP
					sed -i '/iptables -t nat -A POSTROUTING -s 10.8.0.0\/24 ! -d 10.8.0.0\/24 -j SNAT --to /d' $RCLOCAL
					if iptables -L -n | grep -qE '^ACCEPT'; then
						iptables -D INPUT -p $PROTOCOL --dport $PORT -j ACCEPT
						iptables -D FORWARD -s 10.8.0.0/24 -j ACCEPT
						iptables -D FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
						sed -i "/iptables -I INPUT -p $PROTOCOL --dport $PORT -j ACCEPT/d" $RCLOCAL
						sed -i "/iptables -I FORWARD -s 10.8.0.0\/24 -j ACCEPT/d" $RCLOCAL
						sed -i "/iptables -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT/d" $RCLOCAL
					fi
				fi
				if hash sestatus 2>/dev/null; then
					if sestatus | grep "Current mode" | grep -qs "enforcing"; then
						if [[ "$PORT" != '1194' || "$PROTOCOL" = 'tcp' ]]; then
							semanage port -d -t openvpn_port_t -p $PROTOCOL $PORT
						fi
					fi
				fi
				if [[ "$OS" = 'debian' ]]; then
					apt-get remove --purge -y openvpn
				else
					yum remove openvpn -y
				fi
				rm -rf /etc/openvpn
				echo ""
				echo "OpenVPN kaldırıldı."
			else
				echo ""
				echo "Kaldırma işlemi iptal edildi."
			fi
			exit
			;;
			4) exit;;
		esac
	done
else
	clear
	echo "OpenVPN yükleme sihirbazına hoş geldiniz."
	echo ""
	# OpenVPN kurulumu ve ilk kullanıcı oluşturma
	echo "Yüklemeye başlamadan önce size birkaç soru sormam gerekiyor."
	echo "Eğer varsayılan ayarları kullanmak isterseniz Enter'a basınız."
	echo ""
	echo "Öncelikle OpenVPN'in istediğiniz ağ arayüzünün IPv4 adresini bilmemiz gerekiyor."
	echo "Dinleniyor..."
	read -p "IP adresi: " -e -i $IP IP
	echo ""
	echo "OpenVPN bağlantıları için hangi protokolü kullanmak istiyorsunuz?"
	echo "   1) UDP (Tavsiye edilen)"
	echo "   2) TCP"
	read -p "Protokol [1-2]: " -e -i 1 PROTOCOL
	case $PROTOCOL in
		1) 
		PROTOCOL=udp
		;;
		2) 
		PROTOCOL=tcp
		;;
	esac
	echo ""
	echo "OpenVPN hangi port'u dinlesin?"
	read -p "Port: " -e -i 1194 PORT
	echo ""
	echo "VPN ile hangi DNS'i kullanmak istersiniz?"
	echo "   1) Sistem varsayılanını kullan."
	echo "   2) Google"
	echo "   3) OpenDNS"
	echo "   4) NTT"
	echo "   5) Hurricane Electric"
	echo "   6) Verisign"
	read -p "DNS [1-6]: " -e -i 1 DNS
	echo ""
	echo "Sonunda, kullanıcı sertifikası için isim söyleyin."
	echo "Lütfen, özel karakter içermeyen bir kelime kullanın."
	read -p "Kullanıcı adı: " -e -i client CLIENT
	echo ""
	echo "Her şey tamamdır. OpenVPN'i kurmaya hazırız."
	read -n1 -r -p "Devam etmek için bir tuşa basınız..."
	if [[ "$OS" = 'debian' ]]; then
		apt-get update
		apt-get install openvpn iptables openssl ca-certificates -y
	else
		# Dağıtım CentOS
		yum install epel-release -y
		yum install openvpn iptables openssl wget ca-certificates -y
	fi
	# Bazı OpenVPN paketlerinde easy-rsa'nın eski bir sürümü varsayılan olarak mevcuttu.
	if [[ -d /etc/openvpn/easy-rsa/ ]]; then
		rm -rf /etc/openvpn/easy-rsa/
	fi
	# easy-rsa alınıyor
	wget -O ~/EasyRSA-3.0.4.tgz "https://github.com/OpenVPN/easy-rsa/releases/download/v3.0.4/EasyRSA-3.0.4.tgz"
	tar xzf ~/EasyRSA-3.0.4.tgz -C ~/
	mv ~/EasyRSA-3.0.4/ /etc/openvpn/
	mv /etc/openvpn/EasyRSA-3.0.4/ /etc/openvpn/easy-rsa/
	chown -R root:root /etc/openvpn/easy-rsa/
	rm -rf ~/EasyRSA-3.0.4.tgz
	cd /etc/openvpn/easy-rsa/
	# PKI oluşturuluyor, CA , DH parametreleri ve server + kullanıcı sertifikası kuruluyor.
	./easyrsa init-pki
	./easyrsa --batch build-ca nopass
	./easyrsa gen-dh
	./easyrsa build-server-full server nopass
	./easyrsa build-client-full $CLIENT nopass
	EASYRSA_CRL_DAYS=3650 ./easyrsa gen-crl
	# İhtiyaç duyduğumuz şeyler taşınıyor
	cp pki/ca.crt pki/private/ca.key pki/dh.pem pki/issued/server.crt pki/private/server.key pki/crl.pem /etc/openvpn
	chown nobody:$GROUPNAME /etc/openvpn/crl.pem
	# tls-auth için anahtar üretiliyor
	openvpn --genkey --secret /etc/openvpn/ta.key
	# server.conf oluşturuluyor
	echo "port $PORT
proto $PROTOCOL
dev tun
sndbuf 0
rcvbuf 0
ca ca.crt
cert server.crt
key server.key
dh dh.pem
auth SHA512
tls-auth ta.key 0
topology subnet
server 10.8.0.0 255.255.255.0
ifconfig-pool-persist ipp.txt" > /etc/openvpn/server.conf
	echo 'push "redirect-gateway def1 bypass-dhcp"' >> /etc/openvpn/server.conf
	# DNS
	case $DNS in
		1) 
		# Uygun resolv.conf dosyası bulunuyor
		if grep -q "127.0.0.53" "/etc/resolv.conf"; then
			RESOLVCONF='/run/systemd/resolve/resolv.conf'
		else
			RESOLVCONF='/etc/resolv.conf'
		fi
		# resolv.conf'dan resolver'ları alıp OpenVPN için kullanın
		grep -v '#' $RESOLVCONF | grep 'nameserver' | grep -E -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | while read line; do
			echo "push \"dhcp-option DNS $line\"" >> /etc/openvpn/server.conf
		done
		;;
		2) 
		echo 'push "dhcp-option DNS 8.8.8.8"' >> /etc/openvpn/server.conf
		echo 'push "dhcp-option DNS 8.8.4.4"' >> /etc/openvpn/server.conf
		;;
		3)
		echo 'push "dhcp-option DNS 208.67.222.222"' >> /etc/openvpn/server.conf
		echo 'push "dhcp-option DNS 208.67.220.220"' >> /etc/openvpn/server.conf
		;;
		4) 
		echo 'push "dhcp-option DNS 129.250.35.250"' >> /etc/openvpn/server.conf
		echo 'push "dhcp-option DNS 129.250.35.251"' >> /etc/openvpn/server.conf
		;;
		5) 
		echo 'push "dhcp-option DNS 74.82.42.42"' >> /etc/openvpn/server.conf
		;;
		6) 
		echo 'push "dhcp-option DNS 64.6.64.6"' >> /etc/openvpn/server.conf
		echo 'push "dhcp-option DNS 64.6.65.6"' >> /etc/openvpn/server.conf
		;;
	esac
	echo "keepalive 10 120
cipher AES-256-CBC
comp-lzo
user nobody
group $GROUPNAME
persist-key
persist-tun
status openvpn-status.log
verb 3
crl-verify crl.pem" >> /etc/openvpn/server.conf
	# Sistem için net.ipv4.ip_forward öğesini etkinleştiriliyor
	sed -i '/\<net.ipv4.ip_forward\>/c\net.ipv4.ip_forward=1' /etc/sysctl.conf
	if ! grep -q "\<net.ipv4.ip_forward\>" /etc/sysctl.conf; then
		echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf
	fi
	# Gereksiz bir yeniden başlatmadan kaçının
	echo 1 > /proc/sys/net/ipv4/ip_forward
	if pgrep firewalld; then
		# Bir firewall'ı yeniden yüklemeyi engellemek için kalıcı ve kalıcı olmayan kurallar kullanılıyor
		# --add-service=openvpn kullanmıyoruz, çünkü bu yalnızca varsayılan port ve protokolle çalışmaktadır.
		firewall-cmd --zone=public --add-port=$PORT/$PROTOCOL
		firewall-cmd --zone=trusted --add-source=10.8.0.0/24
		firewall-cmd --permanent --zone=public --add-port=$PORT/$PROTOCOL
		firewall-cmd --permanent --zone=trusted --add-source=10.8.0.0/24
		# VPN subnet için NAT ayarlanıyor
		firewall-cmd --direct --add-rule ipv4 nat POSTROUTING 0 -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to $IP
		firewall-cmd --permanent --direct --add-rule ipv4 nat POSTROUTING 0 -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to $IP
	else
		# Bazı sistem dağıtımları ile rc.local kullanmak gereklidir
		if [[ "$OS" = 'debian' && ! -e $RCLOCAL ]]; then
			echo '#!/bin/sh -e
exit 0' > $RCLOCAL
		fi
		chmod +x $RCLOCAL
		# VPN subnet için NAT ayarlanıyor
		iptables -t nat -A POSTROUTING -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to $IP
		sed -i "1 a\iptables -t nat -A POSTROUTING -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to $IP" $RCLOCAL
		if iptables -L -n | grep -qE '^(REJECT|DROP)'; then
			# Eğer iptables en az bir REJECT kuralına sahipse, bunun gerekli olduğunu varsayıyoruz
			iptables -I INPUT -p $PROTOCOL --dport $PORT -j ACCEPT
			iptables -I FORWARD -s 10.8.0.0/24 -j ACCEPT
			iptables -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
			sed -i "1 a\iptables -I INPUT -p $PROTOCOL --dport $PORT -j ACCEPT" $RCLOCAL
			sed -i "1 a\iptables -I FORWARD -s 10.8.0.0/24 -j ACCEPT" $RCLOCAL
			sed -i "1 a\iptables -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT" $RCLOCAL
		fi
	fi
	# SELinux etkinse ve özel bir port veya TCP seçildiyse, buna ihtiyacımız var
	if hash sestatus 2>/dev/null; then
		if sestatus | grep "Current mode" | grep -qs "enforcing"; then
			if [[ "$PORT" != '1194' || "$PROTOCOL" = 'tcp' ]]; then
				# semanage, varsayılan olarak CentOS 6’da mevcut değildir.
				if ! hash semanage 2>/dev/null; then
					yum install policycoreutils-python -y
				fi
				semanage port -a -t openvpn_port_t -p $PROTOCOL $PORT
			fi
		fi
	fi
	# Ve son olarak, OpenVPN tekrardan başlatılıyor
	if [[ "$OS" = 'debian' ]]; then
		if pgrep systemd-journal; then
			systemctl restart openvpn@server.service
		else
			/etc/init.d/openvpn restart
		fi
	else
		if pgrep systemd-journal; then
			systemctl restart openvpn@server.service
			systemctl enable openvpn@server.service
		else
			service openvpn restart
			chkconfig openvpn on
		fi
	fi
	# Try to detect a NATed connection and ask about it to potential LowEndSpirit users
	EXTERNALIP=$(wget -4qO- "http://whatismyip.akamai.com/")
	if [[ "$IP" != "$EXTERNALIP" ]]; then
		echo ""
		echo "Looks like your server is behind a NAT!"
		echo ""
		echo "If your server is NATed (e.g. LowEndSpirit), I need to know the external IP"
		echo "If that's not the case, just ignore this and leave the next field blank"
		read -p "External IP: " -e USEREXTERNALIP
		if [[ "$USEREXTERNALIP" != "" ]]; then
			IP=$USEREXTERNALIP
		fi
	fi
	echo "client
dev tun
proto $PROTOCOL
sndbuf 0
rcvbuf 0
remote $IP $PORT
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
auth SHA512
cipher AES-256-CBC
comp-lzo
setenv opt block-outside-dns
key-direction 1
verb 3" > /etc/openvpn/client-common.txt
	# Özel client.ovpn oluşturuluyor
	newclient "$CLIENT"
	echo ""
	echo "Bitti!"
	echo ""
	echo "Kullanıcı ayarları burada" ~/"$CLIENT.ovpn"
	echo "Eğer kullanıcı eklemek veya kaldırmak isterseniz, bu dosyayı yeniden çalıştırın!"
fi
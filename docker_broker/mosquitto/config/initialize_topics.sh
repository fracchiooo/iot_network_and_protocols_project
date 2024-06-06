
cat /mosquitto/certs/clients_certs/*.pem > client-cert-list.pem


for cert in /mosquitto/certs/clients_certs/*.pem; do
  	CN=$(openssl x509 -in $cert -noout -subject | awk -F= '/^subject/ {print $NF}')
	echo "$CN"
	if [ -n "$CN" ]; then
		mosquitto_pub -h localhost -p 8883 --cert /mosquitto/certs/server.crt --key /mosquitto/certs/server.key -t "$CN" -m "start"
		mosquitto_pub -h localhost -p 8883 --cert /mosquitto/certs/server.crt --key /mosquitto/certs/server.key -t "retrieve_certificates" -m "$cert"
	else
		echo "failed to extract client CN value from $cert"
	fi

done


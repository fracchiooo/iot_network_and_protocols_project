i=0
for cert in /certs/clients_certs/*.pem; do
  	CN=$(openssl x509 -in $cert -noout -subject | awk -F= '/^subject/ {print $NF}')
	if [ -n "$CN" ]; then
		echo "$CN"
		echo "$i"
		file_c=$(cat "$cert")
		mosquitto_pub -h mosquitto-cont -p 8883 -t "$CN" -m "start" -r --cert /certs/server.pem --key /certs/serverkey.pem --cafile /certs/server.pem --insecure
		mosquitto_pub -h mosquitto-cont -p 8883 -t "retrieve_certificates/$i" -m "$file_c" -r --cert /certs/server.pem --key /certs/serverkey.pem --cafile /certs/server.pem --insecure
		i=$(expr $i + 1)

	else
		echo "failed to extract client CN value from $cert"
	fi

done

mosquitto_pub -h mosquitto-cont -p 8883 -t "retrieve_certificates/$i" -m "end_certificates" -r --cert /certs/server.pem --key /certs/serverkey.pem --cafile /certs/server.pem --insecure

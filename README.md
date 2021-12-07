# postfix-o365

Need to run this after deploying, in order to grab tokens.

	python3 /usr/share/sasl-xoauth2/get-initial-outlook-tokens.py \
	--client_id=${XOAUTH2_CLIENT_ID} \
	--tenant=${XOAUTH2_TENANT_ID} \
	/var/spool/postfix/xoauth2-tokens/${RELAYHOST_USERNAME}

docker run --rm --name test-postfix -d -p 587:587 \
-e RELAYHOST="[smtp.office365.com]:587" \
-e RELAYHOST_USERNAME="no-reply@rctechpr.net" \
-e POSTFIX_smtp_tls_security_level="encrypt" \
-e XOAUTH2_CLIENT_ID="eaabefd0-49de-4e9c-9f3f-2456caa61dfd" \
-e XOAUTH2_SECRET="" \
-e XOAUTH2_TENANT_ID="65b4f78e-0527-4a1a-afa6-0e45ab0ef81e" \
-e ALLOW_EMPTY_SENDER_DOMAINS="true" \
docker.io/library/postfixo365:latest
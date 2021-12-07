#!/usr/bin/env bash

announce_startup() {
	echo -e "${gray}${emphasis}★★★★★ ${reset}${lightblue}POSTFIX STARTING UP${reset}${gray}${emphasis} ★★★★★${reset}"
}

setup_timezone() {
	if [ ! -z "$TZ" ]; then
		TZ_FILE="/usr/share/zoneinfo/$TZ"
		if [ -f "$TZ_FILE" ]; then
			notice "Setting container timezone to: ${emphasis}$TZ${reset}"
			ln -snf "$TZ_FILE" /etc/localtime
			echo "$TZ" > /etc/timezone
		else
			warn "Cannot set timezone to: ${emphasis}$TZ${reset} -- this timezone does not exist."
		fi
	else
		info "Not setting any timezone for the container"
	fi
}

rsyslog_log_format() {
	local log_format="${LOG_FORMAT}"
	if [[ -z "${log_format}" ]]; then
		log_format="plain"
	fi
	info "Using ${emphasis}${log_format}${reset} log format for rsyslog."
	sed -i -E "s/<log-format>/${log_format}/" /etc/rsyslog.conf
}

setup_conf() {
	local srcfile
	local dstfile
	local base

	# Make sure the /etc/postfix directory exists
	mkdir -p /etc/postfix
	# Make sure all the neccesary files (and directories) exist
	if [[ -d "/etc/postfix.template/" ]]; then
		for srcfile in /etc/postfix.template/*; do
			base="$(basename $srcfile)"
			dstfile="/etc/postfix/$base"

			if [[ ! -e "$dstfile" ]]; then
				debug "Creating ${emphasis}$dstfile${reset}."
				cp -r "$srcfile" "$dstfile"
			fi
		done
	fi
}

reown_folders() {
	mkdir -p /var/spool/postfix/pid /var/spool/postfix/dev
	chown root: /var/spool/postfix/
	chown root: /var/spool/postfix/pid

	do_postconf -e "manpage_directory=/usr/share/man"

	# postfix set-permissions complains if documentation files do not exist
	postfix -c /etc/postfix/ set-permissions > /dev/null 2>&1 || true
}

postfix_upgrade_conf() {
	local maincf=/etc/postfix/main.cf
	local line
	local entry
	local filename
	local OLD_IFS

	# Check for any references to the old "hash:" and "btree:" databases and replae them with "lmdb:"
	if cat "$maincf" | egrep -v "^#" | egrep -q "(hash|btree):"; then
		warn "Detected old hash: and btree: references in the config file, which are not supported anymore. Upgrading to lmdb:"
		sed -i -E 's/(hash|btree):/lmdb:/g' "$maincf"
		OLD_IFS="$IFS"
		IFS=$'\n'
		# Recreate aliases
		for line in $(cat "$maincf" | egrep 'lmdb:[^,]+' | sort | uniq); do
			entry="$(echo "$line" | egrep -o 'lmdb:[^,]+')"
			filename="$(echo "$entry" | cut -d: -f2)"
			if [[ -f "$filename" ]]; then
				if echo "$line" | egrep -q '[ \t]*alias.*'; then
					debug "Creating new postalias for ${emphasis}$entry${reset}."
					postalias $entry
				else
					debug "Creating new postmap for ${emphasis}$entry${reset}."
					postmap $entry
				fi
			fi
		done
		IFS="$OLD_IFS"
	else
		debug "No upgrade needed."
	fi
}

postfix_disable_utf8() {
	if [[ -f /etc/alpine-release ]]; then
		do_postconf -e smtputf8_enable=no
	fi
}

postfix_create_aliases() {
	touch /etc/postfix/aliases
	postalias /etc/postfix/aliases
}

postfix_disable_local_mail_delivery() {
	do_postconf -e mydestination=
}

postfix_disable_domain_relays() {
	do_postconf -e relay_domains=
}

postfix_increase_header_size_limit() {
	do_postconf -e "header_size_limit=4096000"
}

postfix_restrict_message_size() {
	if [[ -n "${MESSAGE_SIZE_LIMIT}" ]]; then
		deprecated "${emphasis}MESSAGE_SIZE_LIMIT${reset} variable is deprecated. Please use ${emphasis}POSTFIX_message_size_limit${reset} instead."
		POSTFIX_message_size_limit="${MESSAGE_SIZE_LIMIT}"
	fi

	if [[ -n "${POSTFIX_message_size_limit}" ]]; then
		notice "Restricting message_size_limit to: ${emphasis}${POSTFIX_message_size_limit} bytes${reset}"
	else
		info "Using ${emphasis}unlimited${reset} message size."
		POSTFIX_message_size_limit=0
	fi
}

postfix_reject_invalid_helos() {
	do_postconf -e smtpd_delay_reject=yes
	do_postconf -e smtpd_helo_required=yes
	# Fast reject -- reject straight away when the client is connecting
	do_postconf -e "smtpd_client_restrictions=permit_mynetworks,reject"
	# Reject / accept on EHLO / HELO command
	do_postconf -e "smtpd_helo_restrictions=permit_mynetworks,reject_invalid_helo_hostname,permit"
	# Delayed reject -- reject on MAIL FROM command. Not strictly neccessary to have both, but doesn't hurt
	do_postconf -e "smtpd_sender_restrictions=permit_mynetworks,reject"
}

postfix_set_hostname() {
	do_postconf -# myhostname
	if [[ -z "$POSTFIX_myhostname" ]]; then
		POSTFIX_myhostname="${HOSTNAME}"
	fi
}

postfix_set_relay_tls_level() {
	if [ ! -z "$RELAYHOST_TLS_LEVEL" ]; then
		deprecated "${emphasis}RELAYHOST_TLS_LEVEL${reset} variable is deprecated. Please use ${emphasis}POSTFIX_smtp_tls_security_level${reset} instead."
		POSTFIX_smtp_tls_security_level="$RELAYHOST_TLS_LEVEL"
	fi

	if [ -z "$POSTFIX_smtp_tls_security_level" ]; then
		info "Setting smtp_tls_security_level: ${emphasis}may${reset}"
		POSTFIX_smtp_tls_security_level="may"
	fi
}

postfix_setup_relayhost() {
	if [ ! -z "$RELAYHOST" ]; then
		noticen "Forwarding all emails to ${emphasis}$RELAYHOST${reset}"
		do_postconf -e "relayhost=$RELAYHOST"
		# Alternately, this could be a folder, like this:
		# smtp_tls_CApath
		do_postconf -e "smtp_tls_CAfile=/etc/ssl/certs/ca-certificates.crt"

		file_env 'RELAYHOST_PASSWORD'

		# Allow to overwrite RELAYHOST in the sasl_passwd file with SASL_RELAYHOST variable if specified
		if [ -z "$SASL_RELAYHOST" ]; then
			SASL_RELAYHOST=$RELAYHOST
		fi

		if [ -n "$RELAYHOST_USERNAME" ] && [ -n "$RELAYHOST_PASSWORD" ]; then
			echo -e " using username ${emphasis}$RELAYHOST_USERNAME${reset} and password ${emphasis}(redacted)${reset}."
			if [[ -f /etc/postfix/sasl_passwd ]]; then
				if ! grep -F "$SASL_RELAYHOST $RELAYHOST_USERNAME:$RELAYHOST_PASSWORD" /etc/postfix/sasl_passwd; then
					sed -i -e "s/^$SASL_RELAYHOST .*$/d" /etc/postfix/sasl_passwd
					echo "$SASL_RELAYHOST $RELAYHOST_USERNAME:$RELAYHOST_PASSWORD" >> /etc/postfix/sasl_passwd
				fi
			else
				echo "$SASL_RELAYHOST $RELAYHOST_USERNAME:$RELAYHOST_PASSWORD" >> /etc/postfix/sasl_passwd
			fi
			postmap lmdb:/etc/postfix/sasl_passwd
			chown root:root /etc/postfix/sasl_passwd /etc/postfix/sasl_passwd.lmdb
			chmod 0600 /etc/postfix/sasl_passwd /etc/postfix/sasl_passwd.lmdb

			do_postconf -e "smtp_sasl_auth_enable=yes"
			do_postconf -e "smtp_sasl_password_maps=lmdb:/etc/postfix/sasl_passwd"
			do_postconf -e "smtp_sasl_security_options=noanonymous"
			do_postconf -e "smtp_sasl_tls_security_options=noanonymous"
		else
			echo -e " without any authentication. ${emphasis}Make sure your server is configured to accept emails coming from this IP.${reset}"
		fi
	else
		notice "Will try to deliver emails directly to the final server. ${emphasis}Make sure your DNS is setup properly!${reset}"
		do_postconf -# relayhost
		do_postconf -# smtp_sasl_auth_enable
		do_postconf -# smtp_sasl_password_maps
		do_postconf -# smtp_sasl_security_options
	fi
}

postfix_setup_xoauth2_pre_setup() {
	file_env 'XOAUTH2_CLIENT_ID'
	file_env 'XOAUTH2_SECRET'
	file env 'XOAUTH2_TENANT_ID'
	if [ -n "$XOAUTH2_CLIENT_ID" ] && [ -n "$XOAUTH2_SECRET" ]; then
		cat <<EOF > /etc/sasl-xoauth2.conf
{
  "client_id": "${XOAUTH2_CLIENT_ID}",
  "client_secret": "${XOAUTH2_SECRET}",
  "token_endpoint": "https://login.microsoftonline.com/${XOAUTH2_TENANT_ID}/oauth2/v2.0/token",
  "log_to_syslog_on_failure": "${XOAUTH2_SYSLOG_ON_FAILURE:-no}",
  "log_full_trace_on_failure": "${XOAUTH2_FULL_TRACE:-no}"
}
EOF

		if [ -z "$RELAYHOST" ] || [ -z "${RELAYHOST_USERNAME}" ]; then
			error "You need to specify RELAYHOST and RELAYHOST_USERNAME otherwise Postfix will not run!"
			exit 1
		fi

		export RELAYHOST_PASSWORD="/var/spool/postfix/xoauth2-tokens/${RELAYHOST_USERNAME}"

		if [ ! -d "/var/spool/postfix/xoauth2-tokens" ]; then
			mkdir -p "/var/spool/postfix/xoauth2-tokens"
		fi

		if [ ! -f "/var/spool/postfix/xoauth2-tokens/${RELAYHOST_USERNAME}" ] && [ -n "$XOAUTH2_INITIAL_ACCESS_TOKEN" ] && [ -n "$XOAUTH2_INITIAL_REFRESH_TOKEN" ]; then
			cat <<EOF > "/var/spool/postfix/xoauth2-tokens/${RELAYHOST_USERNAME}"
{
	"access_token" : "${XOAUTH2_INITIAL_ACCESS_TOKEN}",
	"refresh_token" : "${XOAUTH2_INITIAL_REFRESH_TOKEN}",
	"expiry" : "0"
}
EOF
		fi
		chown -R postfix:root "/var/spool/postfix/xoauth2-tokens"
	fi
}

postfix_setup_xoauth2_post_setup() {
	if [ -n "$XOAUTH2_CLIENT_ID" ] && [ -n "$XOAUTH2_SECRET" ]; then
		do_postconf -e 'smtp_sasl_security_options='
		do_postconf -e 'smtp_sasl_mechanism_filter=xoauth2'
		do_postconf -e 'smtp_tls_session_cache_database=lmdb:${data_directory}/smtp_scache'
	fi
}

postfix_setup_networks() {
	if [ ! -z "$MYNETWORKS" ]; then
		deprecated "${emphasis}MYNETWORKS${reset} variable is deprecated. Please use ${emphasis}POSTFIX_mynetworks${reset} instead."
		notice "Using custom allowed networks: ${emphasis}$MYNETWORKS${reset}"
		POSTFIX_mynetworks="$MYNETWORKS"
	elif [ ! -z "$POSTFIX_mynetworks" ]; then
		notice "Using custom allowed networks: ${emphasis}$POSTFIX_mynetworks${reset}"
	else
		info "Using default private network list for trusted networks."
		POSTFIX_mynetworks="127.0.0.0/8,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16"
	fi
}

postfix_setup_debugging() {
	if [ ! -z "$INBOUND_DEBUGGING" ]; then
		notice "Enabling additional debbuging for: ${emphasis}$POSTFIX_mynetworks${reset}, as INBOUND_DEBUGGING=''${INBOUND_DEBUGGING}''"
		do_postconf -e "debug_peer_list=$POSTFIX_mynetworks"

		sed -i -E 's/^[ \t]*#?[ \t]*LogWhy[ \t]*.+$/LogWhy                  yes/' /etc/opendkim/opendkim.conf
		if ! egrep -q '^LogWhy' /etc/opendkim/opendkim.conf; then
			echo >> /etc/opendkim/opendkim.conf
			echo "LogWhy                  yes" >> /etc/opendkim/opendkim.conf
		fi
	else
		info "Debugging is disabled.${reset}"
		sed -i -E 's/^[ \t]*#?[ \t]*LogWhy[ \t]*.+$/LogWhy                  no/' /etc/opendkim/opendkim.conf
		if ! egrep -q '^LogWhy' /etc/opendkim/opendkim.conf; then
			echo >> /etc/opendkim/opendkim.conf
			echo "LogWhy                  no" >> /etc/opendkim/opendkim.conf
		fi
	fi
}

postfix_setup_sender_domains() {
	if [ ! -z "$ALLOWED_SENDER_DOMAINS" ]; then
		infon "Setting up allowed SENDER domains:"
		allowed_senders=/etc/postfix/allowed_senders
		rm -f $allowed_senders $allowed_senders.db > /dev/null
		touch $allowed_senders
		for i in $ALLOWED_SENDER_DOMAINS; do
			echo -ne " ${emphasis}$i${reset}"
			echo -e "$i\tOK" >> $allowed_senders
		done
		echo
		postmap lmdb:$allowed_senders

		do_postconf -e "smtpd_recipient_restrictions=reject_non_fqdn_recipient, reject_unknown_recipient_domain, check_sender_access lmdb:$allowed_senders, reject"

		# Since we are behind closed doors, let's just permit all relays.
		do_postconf -e "smtpd_relay_restrictions=permit"
	elif [ -z "$ALLOW_EMPTY_SENDER_DOMAINS" ]; then
		error "You need to specify ALLOWED_SENDER_DOMAINS otherwise Postfix will not run!"
		exit 1
	fi
}

postfix_setup_masquarading() {
	if [ ! -z "$MASQUERADED_DOMAINS" ]; then
		notice "Setting up address masquerading: ${emphasis}$MASQUERADED_DOMAINS${reset}"
		do_postconf -e "masquerade_domains = $MASQUERADED_DOMAINS"
		do_postconf -e "local_header_rewrite_clients = static:all"
	fi
}

postfix_setup_header_checks() {
	if [ ! -z "$SMTP_HEADER_CHECKS" ]; then
		if [ "$SMTP_HEADER_CHECKS" == "1" ]; then
			info "Using default file for SMTP header checks"
			SMTP_HEADER_CHECKS="regexp:/etc/postfix/smtp_header_checks"
		fi

		FORMAT=$(echo "$SMTP_HEADER_CHECKS" | cut -d: -f1)
		FILE=$(echo "$SMTP_HEADER_CHECKS" | cut -d: -f2-)

		if [ "$FORMAT" == "$FILE" ]; then
			warn "No Postfix format defined for file ${emphasis}SMTP_HEADER_CHECKS${reset}. Using default ${emphasis}regexp${reset}. To avoid this message, set format explicitly, e.g. ${emphasis}SMTP_HEADER_CHECKS=regexp:$SMTP_HEADER_CHECKS${reset}."
			FORMAT="regexp"
		fi

		if [ -f "$FILE" ]; then
			notice "Setting up ${emphasis}smtp_header_checks${reset} to ${emphasis}$FORMAT:$FILE${reset}"
			do_postconf -e "smtp_header_checks=$FORMAT:$FILE"
		else
			fatal "File ${emphasis}$FILE${reset} cannot be found. Please make sure your SMTP_HEADER_CHECKS variable points to the right file. Startup aborted."
			exit 2
		fi
	fi
}

postfix_custom_commands() {
	local setting
	local key
	local value
	for setting in ${!POSTFIX_*}; do
		key="${setting:8}"
		value="${!setting}"
		if [ -n "${value}" ]; then
			info "Applying custom postfix setting: ${emphasis}${key}=${value}${reset}"
			do_postconf -e "${key}=${value}"
		else
			info "Deleting custom postfix setting: ${emphasis}${key}${reset}"
			do_postconf -# "${key}"
		fi
	done
}

postfix_open_submission_port() {
	# Use 587 (submission)
	sed -i -r -e 's/^#submission/submission/' /etc/postfix/master.cf
}

execute_post_init_scripts() {
	if [ -d /docker-init.db/ ]; then
		notice "Executing any found custom scripts..."
		for f in /docker-init.db/*; do
			case "$f" in
				*.sh)
					if [[ -x "$f" ]]; then
						echo -e "\tsourcing ${emphasis}$f${reset}"
						. "$f"
					else
						echo -e "\trunning ${emphasis}bash $f${reset}"
						bash "$f"
					fi
					;;
				*)
					echo "$0: ignoring $f" ;;
			esac
		done
	fi
}

#get_initial_outlook_tokens() {
#	python3 /usr/share/sasl-xoauth2/get-initial-outlook-tokens.py \
#	--client_id=${XOAUTH2_CLIENT_ID} \
#	--tenant=${XOAUTH2_TENANT_ID} \
#	/var/spool/postfix/xoauth2-tokens/${RELAYHOST_USERNAME}
#}

unset_sensible_variables() {
	unset RELAYHOST_PASSWORD
	unset XOAUTH2_CLIENT_ID
	unset XOAUTH2_SECRET
	unset XOAUTH2_INITIAL_ACCESS_TOKEN
	unset XOAUTH2_INITIAL_REFRESH_TOKEN
	unset XOAUTH2_TENANT_ID
}
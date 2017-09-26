#!/usr/bin/env bash
# vim: set ts=2 sw=2 tw=0 noet :


print_out() {
	echo "Script: $1"
}

print_debug() {
	if [ -n "$DEBUG" ]; then
		echo "Script debug: $1"
	fi
}

print_err() {
	echo "$*" 1>&2
}

fatal_error() {
	print_err "Fatal error: $1"
	[ -e "$OUTPUT" ] && rm -f "$OUTPUT"
	print_sys_info "$INPUT"  # called from wrote_body, where this var is defined
	exit $2
}

usage() {
	PROG=${0##*/}
	echo "Usage:"
	echo "   $PROG -r DIRECTORY -o JSON_FILE                              : generate offset file for all NGINX binaries under DIRECTORY (recursively)"
	echo "   $PROG -b NGINX_BINARY -o JSON_FILE                           : generate offset file for unstripped NGINX_BINARY"
	echo "   $PROG -b NGINX_BINARY -d NGINX_DEBUG_SYMBOLS -o JSON_FILE    : generate offset file for stripped NGINX_BINARY using the corresponding debug symbols"
	echo "   $PROG -t NGINX_BINARY                                        : test whether all needed tools are available and NGINX_BINARY is supported"
	echo "   $PROG -h                                                     : print this message"
	echo "Additional options:"
	echo "         -i                                                     : ignore mismatched binary / symbol file BuildID values"
	exit 0
}

print_sys_info() {
	NGINX=$1
	print_err "*********************************************************"
	print_err "*  This specific setup cannot be handled automatically  *"
	print_err "*********************************************************"
	print_err "Please contact Dynatrace support, providing them with the following data:"
	print_err
	if [ -f /etc/lsb-release ]; then
		OS_VERSION=$( cat /etc/lsb-release | tr '\n' ' ' )
	elif [ -f /etc/system-release ]; then
		OS_VERSION=$( cat /etc/system-release | tr '\n' ' ' )
	else
		OS_VERSION="unknown"
	fi
	print_err "OS info                    : " "$OS_VERSION"
	print_err "kernel info                : " $( uname -a )
	if which readlink > /dev/null 2>&1 ; then
		print_err "nginx binary location      : " $( readlink -f "$NGINX" )
	fi
	print_err "nginx binary info          : " $( file "$NGINX" | sed 's/^[^:]*: //' )
	print_err "nginx binary fingerprint   : " $( md5sum -b "$NGINX" | cut -d ' ' -f 1 )
	print_err "nginx binary configuration : " $( "$NGINX" -V 2>&1 | sed ':a;N;$!ba;s/\n/; /g' )
	PKG=$(check_os)
	if [ $PKG = 'apt' ]; then
		if dpkg -S "$NGINX" 2>&1 | grep -q "no path found"; then
			# this binary was not installed using APT
			MSG="binary not installed using APT"
		else
			PKG=$( dpkg -S "$NGINX" | cut -d":" -f1 )
			MSG=$( dpkg -s $PKG | grep "Package\|Version" | cut -d ' ' -f 2 | tr '\n' '-' )
		fi
	elif [ $PKG = "yum" ]; then
		MSG=$( rpm -qf "$NGINX" )
	else
		MSG="no supported package manager found"
	fi
	print_err "nginx package              : " "$MSG"
}

parse_command_line() {
	[ $# == 0 ] && usage

	OPTIND=1
	while getopts ":vir:d:o:b:t:h" opt; do
		case "$opt" in
			h )  # help
				usage
				;;
			r )  # recursive
				DIRECTORY=$OPTARG
				;;
			b )  # nginx binary
				BINARY=$OPTARG
				;;
			d )  # nginx debug symbols
				GLOBAL_NGINX_DBG_PATH=$OPTARG
				;;
			o )  # JSON offset file - optional
				OUTPUT=$OPTARG
				;;
			v )  # verbose
  				VERBOSE=true
				;;
			i )  # ignore BuildIDs
				IGNORE_BUILDID=true
				;;
			t )  # test
				TEST_BINARY=$OPTARG
				;;
			\? )
				echo "Invalid option: '-$OPTARG'" 1>&2
				IS_ERROR=true
				;;
			: )
				echo "Invalid option: -'$OPTARG' requires an argument" 1>&2
				IS_ERROR=true
				;;
		esac
	done
	[ -n "$IS_ERROR" ] && exit 1

	# shift all the processed options away - nothing should remain
	shift "$((OPTIND-1))" $ARGS
	if [ $# != 0 ]; then
		print_err "Invalid syntax: extra non-option arguments specified."
		exit 1
	fi

	# sanity checks md5sum -b "$NGINX" | cut -d ' ' -f 1
	if [[ "$DIRECTORY" && "$BINARY" ]] || [[ "$DIRECTORY" && "$TEST_BINARY" ]] || [[ "$BINARY" && "$TEST_BINARY" ]]; then
		print_err "Invalid syntax: options -r, -f and -t are mutually exclusive."
		exit 1
	fi
}


# initialize data structures specifying NGINX functions and data fields that need to be located in the binary
initialize_data() {
	INIT_SYMBOL="_init"
	GOT_SYMBOL="_GLOBAL_OFFSET_TABLE_"

	FUNCTIONS=(
		[1]="ngx_pcalloc"
		[2]="ngx_pnalloc"
		[3]="ngx_http_read_client_request_body"
		[4]="ngx_http_finalize_request"
		[5]="ngx_strcasecmp"
		[6]="ngx_list_push"
		[7]="ngx_array_push"
		[8]="ngx_alloc_chain_link"
		[9]="ngx_http_core_run_phases"
		[10]="ngx_strncasecmp"
		[11]="ngx_setproctitle"
	)

	STRUCTS=(
		[1]="ngx_modules"
		[2]="ngx_http_core_module"
		[3]="ngx_http_top_header_filter"
		[4]="ngx_http_top_body_filter"
		[5]="ngx_process"
	)

	STUB_MODULE=(
		[1]="ngx_stat_accepted"
		[2]="ngx_stat_handled"
		[3]="ngx_stat_active"
		[4]="ngx_stat_requests"
		[5]="ngx_stat_reading"
		[6]="ngx_stat_waiting"
		[7]="ngx_stat_writing"
	)

	NGX_HTTP_REQUEST_T=(
		[1]="ctx"
		[2]="pool"
		[3]="headers_in"
		[4]="headers_out"
		[5]="request_body"
		[6]="uri"
		[7]="unparsed_uri"
		[8]="args"
		[9]="method_name"
		[10]="request_length"
	)

	NGX_HTTP_HEADERS_IN_T=(
		[1]="headers"
		[2]="server"
		[3]="content_length_n"
	)

	TEMP=`mktemp`
	TEMP_NM=`mktemp`
}


write_header() {
	printf "{\n" > $OUTPUT
	chmod 744 "$OUTPUT"
}


write_body() {
	INPUT="$1"
	DEBUG="$2"
	DESC="$3"

	nm $DEBUG > $TEMP
	MD5=`md5sum $INPUT | cut -d' ' -f1 | tr [:upper:] [:lower:] | tr -d [:cntrl:]`
	printf "\t\"%s\": {\n" $MD5 >> $OUTPUT
	printf "\t\t\"description\": \"${DESC}\",\n" >> $OUTPUT

	###

	printf "\t\t\"functions\": {\n" >> $OUTPUT

	I=1
	for INDEX in ${!FUNCTIONS[*]}; do
		COMA=""
		if [ "$I" -lt "${#FUNCTIONS[@]}" ]; then
			COMA=","
		fi

		SYMBOL=${FUNCTIONS[$INDEX]}
		OFFSET=`grep -E " $SYMBOL$" "$TEMP" | cut -d' ' -f 1 | tr '[:lower:]' '[:upper:]' | sed 's/^/obase=10; ibase=16; /' | bc`
		if [ -z "$OFFSET" ]; then
			print_err "Fatal error: Symbol $SYMBOL not found among the provided debug symbols $DEBUG for binary $INPUT" 7
		fi
		printf "\t\t\t\"%s\": %s%s\n" $SYMBOL $OFFSET $COMA >> $OUTPUT
		I=$(($I + 1))
	done

	printf "\t\t},\n" >> $OUTPUT

	###

	printf "\t\t\"structs\": {\n" >> $OUTPUT

	I=1
	for INDEX in ${!STRUCTS[*]}; do
		COMA=""
		if [ "$I" -lt "${#STRUCTS[@]}" ]; then
			COMA=","
		fi
		SYMBOL=${STRUCTS[$INDEX]}
		OFFSET=`grep -E " $SYMBOL$" "$TEMP" | cut -d' ' -f 1 | tr '[:lower:]' '[:upper:]' | sed 's/^/obase=10; ibase=16; /' | bc`
		if [ -z "$OFFSET" ]; then
			print_err "Fatal error: Symbol $SYMBOL not found among the provided debug symbols $DEBUG for binary $INPUT" 7
		fi
		printf "\t\t\t\"%s\": %s%s\n" $SYMBOL $OFFSET $COMA >> $OUTPUT
		I=$(($I + 1))
	done

	printf "\t\t},\n" >> $OUTPUT



	###

	printf "\t\t\"stub_module\": {\n" >> $OUTPUT

	I=1
	for INDEX in ${!STUB_MODULE[*]};  do
		COMA=","
		SYMBOL=${STUB_MODULE[$INDEX]}
		OFFSET=`grep -E " $SYMBOL$" "$TEMP" | cut -d' ' -f 1 | tr '[:lower:]' '[:upper:]' | sed 's/^/obase=10; ibase=16; /' | bc`
		if [ -n "$OFFSET" ]; then
			printf "\t\t\t\"%s\": %s%s\n" $SYMBOL $OFFSET $COMA >> $OUTPUT
		fi
		I=$(($I + 1))
	done
	printf "\t\t\t\"last\": null\n">> $OUTPUT
	printf "\t\t},\n" >> $OUTPUT

	###

	MEMORY_START=`readelf -a -W "$DEBUG" | grep "LOAD" | grep "E" | tr -s ' ' | cut -d' ' -f 4 | head -1 | sed 's/0x//' | tr '[:lower:]' '[:upper:]' | sed 's/^/obase=10; ibase=16; /' | bc`
	MEMORY_SIZE=`readelf -a -W "$DEBUG" | grep "LOAD" | grep "E" | tr -s ' ' | cut -d' ' -f 7 | head -1 | sed 's/0x//' | tr '[:lower:]' '[:upper:]'	| sed 's/^/obase=10; ibase=16; /' | bc`

	printf "\t\t\"memory\": {\n" >> $OUTPUT

	printf "\t\t\t\"start\": %s,\n" $MEMORY_START >> $OUTPUT
	printf "\t\t\t\"end\": %s\n" $(($MEMORY_START + $MEMORY_SIZE - 1)) >> $OUTPUT

	printf "\t\t},\n" >> $OUTPUT

	###

	echo "" > $TEMP

	for INDEX in ${!NGX_HTTP_REQUEST_T[*]}; do
		SYMBOL=${NGX_HTTP_REQUEST_T[$INDEX]}
		echo -e "print (int)&((struct ngx_http_request_s*)0)->$SYMBOL" >> $TEMP
	done

	RESULT=`gdb -batch -x $TEMP $DEBUG | cut -d' ' -f 3`
	if [ -z "$RESULT" ]; then
		fatal_error "Cannot read HTTP request structure details from file $DEBUG" 7
	fi

	printf "\t\t\"ngx_http_request_t\": {\n" >> $OUTPUT

	I=1
	for OFFSET in $RESULT; do
		COMA=""
		if [ "$I" -lt "${#NGX_HTTP_REQUEST_T[@]}" ]; then
			COMA=","
		fi
		printf "\t\t\t\"${NGX_HTTP_REQUEST_T[$I]}\": %s%s\n" $OFFSET $COMA >> $OUTPUT
		I=$(($I + 1))
	done

	printf "\t\t},\n" >> $OUTPUT

	###

	echo "" > $TEMP

	for INDEX in ${!NGX_HTTP_HEADERS_IN_T[*]}; do
		SYMBOL=${NGX_HTTP_HEADERS_IN_T[$INDEX]}
		echo -e "print (int)&((ngx_http_headers_in_t*)0)->$SYMBOL" >> $TEMP
	done

	RESULT=`gdb -batch -x $TEMP $DEBUG | cut -d' ' -f 3`
	if [ -z "$RESULT" ]; then
		fatal_error "Cannot read incoming HTTP headers structure details from file $DEBUG" 7
	fi

	printf "\t\t\"ngx_http_headers_in_t\": {\n" >> $OUTPUT

	I=1
	for OFFSET in $RESULT; do
		COMA=""
		if [ "$I" -lt "${#NGX_HTTP_HEADERS_IN_T[@]}" ]; then
			COMA=","
		fi
		printf "\t\t\t\"${NGX_HTTP_HEADERS_IN_T[$I]}\": %s%s\n" $OFFSET $COMA >> $OUTPUT
		I=$(($I + 1))
	done

	printf "\t\t},\n" >> $OUTPUT

	##

	printf "\t\t\"ngx_modules_references\": [" >> $OUTPUT

	nm "$DEBUG" > $TEMP_NM

	OFFSET=`grep -E " ${STRUCTS[1]}$" "$TEMP_NM" | cut -d' ' -f 1`	 # address of ngx_modules symbol, as 000001a2b3

	FIND=`echo "$OFFSET" | sed 's/^0*//'`	 # address of ngx_modules symbol, as 1a2b3 (with leading zeros stripped)

	objdump --insn-width=9 -d $INPUT > $TEMP

	STAT=`grep "0x$FIND" "$TEMP" | cut -f 1 | sed 's/:$//'`	 # lines in disassembly referring to ngx_modules by its absolute address

	# lines in disassembly referring to ngx_modules using relative references (identified by the absolute address resolved by objdump in line comments)
	REL=`grep "# $FIND" "$TEMP" | tr -s ' ' | cut -f 1 | sed 's/:$/\+3/' | tr '[:lower:]' '[:upper:]' | sed 's/^[ ]/obase=10; ibase=16; /' | sed 's/$/ ; ibase=A; obase=10;/' | bc`

	if [[ -n "$STAT" || -n "$REL" ]]; then
		echo >> $OUTPUT
		if [ ! -z "$STAT" ]; then
			WORDS=`grep "0x$FIND" "$TEMP" | cut -f2 | awk '$0=NF'`
			RESULT=`paste <(echo "$STAT") <(echo "$WORDS") --delimiters '+'`

			STATSUM=`printf "%s-4\n" $RESULT | tr '[:lower:]' '[:upper:]' | sed 's/^/obase=10; ibase=16; /' | sed 's/$/ ; ibase=A; obase=10;/' | bc`
			printf "\t\t\t{\"address\": %s, \"type\": 0},\n" $STATSUM >> $OUTPUT
		fi

		if [ ! -z "$REL" ]; then
			printf "\t\t\t{\"address\": %s, \"type\": 1},\n" $REL >> $OUTPUT
		fi
		# at least one absolute or relative reference was printed, so we need to delete the trailing comma
		sed -i '$ s/.$//' $OUTPUT
		printf "\t\t]\n" >> $OUTPUT
	else
		# perhaps we have old-style PIE using GOT relocations for data fields (built using pre-2.24 binutils)?
		RELOCS=`readelf --relocs "$INPUT" | grep "$FIND" | grep -v "^0\+$FIND" | cut -d' ' -f 1 | sed 's/^0*//'`
		if [[ -n "$RELOCS" ]]; then
			print_debug "File $INPUT recognized as old-style (pre-ld 1.22) PIE"
			echo >> $OUTPUT
			# lines in disassembly referring to ngx_modules using relative references (identified by the absolute address resolved by objdump in line comments)
			REL=`grep "# $RELOCS" "$TEMP" | tr -s ' ' | cut -f 1 | sed 's/:$/\+3/' | tr '[:lower:]' '[:upper:]' | sed 's/^[ ]/obase=10; ibase=16; /' | sed 's/$/ ; ibase=A; obase=10;/' | bc`
			printf "\t\t\t{\"address\": %s, \"type\": 1},\n" $REL >> $OUTPUT
			# delete the trailing comma
			sed -i '$ s/.$//' $OUTPUT
			printf "\t\t],\n" >> $OUTPUT
			printf "\t\t\"legacy_binutils\": true\n" >> $OUTPUT
		else
			# perhaps delta-style relocations?...
			GOT_HEX=`grep -E " ${GOT_SYMBOL}$" "$TEMP_NM" | cut -d' ' -f 1 | tr '[:lower:]' '[:upper:]'`	 # address of global offset table, as 000001a2b3
			GOT=`echo "ibase=16;obase=A;$GOT_HEX" | bc`
			echo "[AWSdebug] GOT_SYMBOL='${GOT_SYMBOL}'  GOT_HEX='$GOT_HEX'  GOT='$GOT'"
			if [[ -n "$GOT" ]]; then
				echo >> $OUTPUT
				OFFSET=`echo $OFFSET | tr '[:lower:]' '[:upper:]'`
				OFFSET_DEC=`echo "ibase=16;obase=A;$OFFSET" | bc`
				DELTA=$((0x$OFFSET - $GOT))
				DELTA_HEX=`echo "ibase=10;obase=16;$( echo $DELTA | tr '[:lower:]' '[:upper:]' )" | bc`
				PATTERN="lea    $DELTA_HEX(%ebx),"
				REL=`grep "^[ ]*([0-9,a-f]+).*$PATTERN" "$TEMP" | tr -s ' ' | cut -f 1`
				printf "\t\t\t{\"address\": %s, \"type\": 3, \"delta\": $OFFSET_DEC},\n" $REL >> $OUTPUT
				# at least one absolute or relative reference was printed, so we need to delete the trailing comma
				sed -i '$ s/.$//' $OUTPUT
				printf "\t\t]\n" >> $OUTPUT
			else
				#printf "]\n" >> $OUTPUT
				fatal_error "Cannot locate references to ngx_modules in file $INPUT" 7
			fi
		fi
	fi


	##

	printf "\t},\n" >> $OUTPUT
}

write_footer() {
	CHECKSUM=`md5sum $OUTPUT | cut -d' ' -f1`
	printf "\t\"checksum\": \"$CHECKSUM\"\n" >> $OUTPUT
	printf "}\n" >> $OUTPUT
}

check_os() {
	#export added because of problem with which on RHEL
	export PATH="$PATH"
	if [[ "$OSTYPE" == "linux-gnu" ]]; then
		# M1: cat /etc/*-release
		# M2: lsb_release -a
		APT_CMD=`which apt-get 2>/dev/null`
		YUM_CMD=`which yum 2>/dev/null`
		if [ ! -z "$APT_CMD" ]; then
			echo "apt"
			return
		elif [ ! -z "$YUM_CMD" ]; then
			#AMZN=`uname --all|grep amzn`
			echo "yum"
			return
		fi
	fi
	# either not linux or neither apt or yum are installed
	echo "other"
}

check_nginx_binary() {
	if [ ! -f $1 ]; then
		print_err "specified nginx binary $1 does not exist"
		exit 1
	fi
	NGX_BINARY_INFO=`file $( readlink -f $1 )`

	if [[ ! "$NGX_BINARY_INFO" =~ "executable" && ! "$NGX_BINARY_INFO" =~ "shared object" ]]	# file reports PIE binaries as shared libraries
	then
		print_err "specified nginx binary $1 is not an executable"
		exit 1
	fi
}

check_nginx_debug_binary() {
	if [ ! -f "$1" ]; then
		print_err "specified debug symbol file $1 does not exist"
		exit 1
	fi
	NGX_BINARY_INFO=`file $( readlink -f $1 )`

	if [[ ! "$NGX_BINARY_INFO" =~ "executable" && ! "$NGX_BINARY_INFO" =~ "shared object" ]]	# file reports PIE binaries as shared libraries
	then
		print_err "specified debug symbol file $1 is invalid (not an executable)"
		exit 1
	fi

	#check if executable is not stripped
	if [[ ! "$NGX_BINARY_INFO" =~ "not stripped" ]]
	then
		print_err "specified debug symbol file $1 does not contain debug symbols"
		exit 1
	fi
}

install_tools() {

	if [[ "$1" == "apt" ]];	then
		GDB_STATUS=`dpkg -s $2|grep Status:|cut -d " " -f2`
		if [ "$GDB_STATUS" = "install" ]
		then
			echo "$2 is installed"
		else
			echo "Installing package $2. Do you want to proceed? [y/n]"
			read -p " " -n 1 -r
			if [[ ! "$REPLY" =~ ^[Yy]$ ]]
			then
				print_err "User exit."
				exit 6
			fi
			sudo apt-get -y	install $2
			#if something goes wrong we are exiting
			if [ "$?" = "1" ]
			then
				print_err "Problems with installing package $2"
				exit 4
			fi
		fi
	elif [[ "$1" == "yum" ]]; then
		CMD=`rpm -q $2|grep "is not installed"`
		if [[ ! -z "$CMD" ]]; then
			echo "Installing package $2. Do you want to proceed? [y/n]"
			read -p " " -n 1 -r
			if [[ ! "$REPLY" =~ ^[Yy]$ ]]
			then
				print_err "User exit."
				exit 6
			fi
			sudo yum -y install $2
			#if something goes wrong we are exiting
			if [ "$?" = "1" ]
			then
				print_err "Problems with installing package $2"
				exit 4
			fi
		fi
	fi
}

install_debug_symbols() {
	# $1 is package manager name, $2 is binary name (typically nginx)
	if [[ "$1" == "apt" ]]; then
		# don't forget about compile
		PKG_NAME=`dpkg -S $2 | cut -d":" -f1`
		if [[ -z "$PKG_NAME" ]]; then
			#nginx is missing on installed package list so probably nginx was self-compiled
			print_err "Nginx wasn't installed using the system package manager."
			print_err "Please launch the script using option -b (and possibly -d)."
			exit 2
		else
			#it seems that nginx is installed using package manager and now we are checking if it has debug symbols
			NGX_BINARY_INFO=`file $2`
			if [[ "$NGX_BINARY_INFO" =~ "executable" || "$NGX_BINARY_INFO" =~ "shared object"	]] && [[ "$NGX_BINARY_INFO" =~ "not stripped" ]]	# file reports PIE binaries as shared libraries
			then
				print_debug "Debug version of Nginx was installed using the system package manager; proceeding without debug symbol installation."
				GLOBAL_NGINX_DBG_PATH="$2"
				return
			fi
		fi
		NGINX_ARRAY=`dpkg-query -L "$PKG_NAME-dbg"`
		for path in $NGINX_ARRAY; do
			NGX_BINARY_INFO=`file $path`
			if [[ "$NGX_BINARY_INFO" =~ "executable" || "$NGX_BINARY_INFO" =~ "shared object" ]] && [[ "$NGX_BINARY_INFO" =~ "not stripped" ]]	# file reports PIE binaries as shared libraries
			then
				print_debug "Debug symbol for $2 found in $path"
				GLOBAL_NGINX_DBG_PATH=$path
				return
			fi
		done
		#according package name we are installing debug version
		echo "Debug symbols for $2 not found. Will install $PKG_NAME-dbg package. Do you want to proceed? [y/n]"
		read -p " " -n 1 -r
		if [[ ! "$REPLY" =~ ^[Yy]$ ]]; then
			 print_err "User exit."
			exit 6
		fi
		sudo apt -y install "$PKG_NAME-dbg"
		#if something goes wrong we are exiting
		if [ "$?" = "1" ]; then
			print_err "Cannot install debug symbols package $PKG_NAME-dbg for Nginx."
			exit 3
		fi
		#we are checking path again because we want to find path
		NGINX_ARRAY=`dpkg-query -L "$PKG_NAME-dbg"`
		for path in $NGINX_ARRAY; do
			NGX_BINARY_INFO=`file $path`
			if [[ "$NGX_BINARY_INFO" =~ "executable" || "$NGX_BINARY_INFO" =~ "shared object" ]] && [[ "$NGX_BINARY_INFO" =~ "not stripped"	]]	# file reports PIE binaries as shared libraries
			then
				GLOBAL_NGINX_DBG_PATH=$path
				return
			fi
		done
	elif [[ "$1" == "yum" ]];then
		#CMD=`rpm -q nginx`
		#PKG_NAME=`rpm -q nginx|cut -d"-" -f1`
		#PKG_VERSION=`rpm -q nginx|awk -F"nginx-" '{ print $2}'`
		#print_debug "$PKG_NAME"
		#print_debug "$PKG_VERSION"
		#first we are checking if nginx is provided by yum manager
		YUM_CMD=`yum whatprovides $2 | grep -i "No matches found"`
		if [[ -n "$YUM_CMD" ]]
		then
			#nginx is missing on installed package list so probably nginx was self-compiled
			print_err "Nginx wasn't installed using the system package manager."
			print_err "Please launch the script using option -b (and possibly -d)."
			exit 2
		else
			#it seems that nginx is installed using package manager and now we are checking if it has debug symbols
			NGX_BINARY_INFO=`file $2`
			if [[ "$NGX_BINARY_INFO" =~ "executable" || "$NGX_BINARY_INFO" =~ "shared object" ]] && [[ "$NGX_BINARY_INFO" =~ "not stripped" ]]	# file reports PIE binaries as shared libraries
			then
				print_debug "Debug version of Nginx was installed using the system package manager; proceeding without debug symbol installation."
				GLOBAL_NGINX_DBG_PATH=$2
				return
			fi
		fi
		# if it is provided by yum manager we are looking for debug symbols
		PKG_NAME=`rpm -q nginx | cut -d"-" -f1`
		if [[ ! $PKG_NAME =~ "is not installed" ]]; then
			# nginx package installed
			PKG_VERSION=`rpm -q nginx | awk -F "nginx-" '{ print $2}'`
		else
			# nginx-plus?
			PKG_NAME=`rpm -q nginx-plus | cut -d"-" -f 1,2`
			if [[ ! $PKG_NAME =~ "is not installed" ]]; then
				PKG_VERSION=`rpm -q nginx-plus | awk -F "nginx-plus-" '{ print $2}'`
			else
				# should never happen, sanity catch-all
				print_err "Cannot recognize either nginx or nginx-plus package, please contact support."
				print_err "(yum reports: $YUM_CMD)"
				exit 3
			fi
		fi

		NGINX_DBG="$PKG_NAME-debuginfo-$PKG_VERSION"
		RPM_CMD=`rpm -q $NGINX_DBG | grep "is not installed"`
		if [[	-z "$RPM_CMD" ]]; then
			# CMD=`rpm -q $NGINX_DBG`
			print_debug "Debug symbols for $2 found in $NGINX_DBG package"
			# path example to debug symbols"/usr/lib/debug/usr/sbin/nginx.debug"
			# JLT-114621
			GLOBAL_NGINX_DBG_PATH="/usr/lib/debug$2.debug"
			return
		else
			echo "Debug symbols for $2 not found. Will install $NGINX_DBG package. Do you want to proceed? [y/n]"
			read -p " " -n 1 -r
			if [[ ! "$REPLY" =~ ^[Yy]$ ]]; then
				print_err "User exit."
				exit 6
			fi
			sudo yum -y	install "$NGINX_DBG"
			# if something goes wrong we are exiting, but yum does not differentiate exit codes...
			if [ "$?" = "1" ]; then
				print_err "Cannot install package '$NGINX_DBG' from the configured repositories. This may mean that "
				print_err "your Linux flavour ships Nginx debug symbols in a package under a slightly different name."
				print_err "If that is the case, please do the following:"
				print_err ""
				print_err "1. Identify the package with Nginx debug symbols and install it. Please note that"
				print_err "   there may be two packages with similar names, *-dbg-* with an unstripped debug binary"
				print_err "   and *-debuginfo-* with debug symbols themselves. We need the second one."
				print_err "2. Locate the debug symbol file in the filesystem. You can look into RPM file properties"
				print_err "   or simply run gdb on the Nginx binary ('gdb nginx') – debug symbol location will be"
				print_err "   reported at startup."
				print_err "3. Generate the generate_offsets.sh script and run it as follows:"
				print_err "   $ generate_offsets.sh -b NGINX_BINARY -d NGINX_DEBUG_SYMBOLS -o dtnginx_offsets.json"
				print_err "4. Copy the generated offset file to Agent config directory and start the Agent."
				exit 3
			fi
			# path example to debug symbols"/usr/lib/debug/usr/sbin/nginx.debug"
			#JLT-114621
			GLOBAL_NGINX_DBG_PATH="/usr/lib/debug$2.debug"

		fi
	fi
}

getBuildId(){
	BUILDID=`eu-readelf -n $1 | grep "Build ID:"`
	echo $BUILDID
}


compare_buildid(){
	NGX_BIN_BUILDID=$(getBuildId $1)
	NGX_DBG_BUILDID=$(getBuildId $2)
	if [ "$NGX_BIN_BUILDID" != "$NGX_DBG_BUILDID" ]; then
		print_err "The build ID of the Nginx binary $1 : $NGX_BIN_BUILDID is different from that of the Nginx debug symbols file $2 : $NGX_DBG_BUILDID"
		exit 5
	fi
}


check_tools() {
	ERROR_FLAG=
	if [[ "$1" == "apt" ]]; then
		GDB_STATUS=`dpkg -s gdb|grep Status:|cut -d " " -f2`
		if [ !	"$GDB_STATUS" = "install" ] || [ -z "$GDB_STATUS" ]; then
			print_err "package gdb is not installed"
			ERROR_FLAG=true
		fi

		ELF_STATUS=`dpkg -s elfutils|grep Status:|cut -d " " -f2`
		if [ !	"$ELF_STATUS" = "install" ] || [ -z "$ELF_STATUS" ]; then
			print_err "package elfutils is not installed"
			ERROR_FLAG=true
		fi

		BIN_STATUS=`dpkg -s binutils|grep Status:|cut -d " " -f2`
		if [ !	"$BIN_STATUS" = "install" ] || [ -z "$BIN_STATUS" ]; then
			print_err "package binutils is not installed"
			ERROR_FLAG=true
		fi

		BC_STATUS=`dpkg -s bc|grep Status:|cut -d " " -f2`
		if [ !	"$BC_STATUS" = "install" ] || [ -z "$BC_STATUS" ]; then
			print_err "package bc is not installed"
			ERROR_FLAG=true
		fi

				if [ "$ERROR_FLAG" ]; then
			exit 4
		fi

	elif [[ "$1" == "yum" ]]; then
		CMD=`rpm -q gdb|grep "is not installed"`
		if [[ ! -z "$CMD" ]]; then
			print_err "package gdb is not installed"
			ERROR_FLAG=true
		fi

		CMD=`rpm -q elfutils|grep "is not installed"`
		if [[ ! -z "$CMD" ]]; then
			print_err "package elfutils is not installed"
			ERROR_FLAG=true
		fi

		CMD=`rpm -q binutils|grep "is not installed"`
		if [[ ! -z "$CMD" ]]; then
			print_err "package binutils is not installed"
			ERROR_FLAG=true

		fi

		CMD=`rpm -q bc|grep "is not installed"`
		if [[ ! -z "$CMD" ]]; then
			print_err "package bc is not installed"
			ERROR_FLAG=true

		fi
				if [ "$ERROR_FLAG" ]; then
			exit 4
		fi
	fi
}


check_debug_symbols() {
	if [[ "$1" == "apt" ]]; then
		# check if nginx package is installed using package manager
		PKG_NAME=`dpkg -S $2 | cut -d":" -f1`
		if [[ -z $PKG_NAME ]]; then
			NGX_BINARY_INFO=`file $2`
			if [[ "$NGX_BINARY_INFO" =~ .*executable.* || "$NGX_BINARY_INFO" =~ "shared object" ]] && [[ "$NGX_BINARY_INFO" =~ "not stripped" ]]
			then
				print_err "Nginx wasn't installed using the system package manager, but it contains debug symbols and can be handled by the Agent automatically"
				exit 55
			else
				print_err "Nginx wasn't installed using the system package manager"
				print_sys_info "$2"
				exit 5
			fi
		else
			# it seems that nginx is installed using apt; now check whether it contains debug symbols
			NGX_BINARY_INFO=`file $2`
			if [[ "$NGX_BINARY_INFO" =~ .*executable.* || "$NGX_BINARY_INFO" =~ "shared object" ]] && [[ "$NGX_BINARY_INFO" =~ "not stripped" ]]
			then
				print_err "Nginx was installed using the system package manager, but it contains debug symbols and can be handled by the Agent automatically"
				exit 56
			fi
		fi
		# now look for debug symbols
		NGINX_ARRAY=`dpkg-query -L "$PKG_NAME-dbg"`
		for path in $NGINX_ARRAY; do
			NGX_BINARY_INFO=`file $path`
			if [[ "$NGX_BINARY_INFO" =~ .*executable.* || "$NGX_BINARY_INFO" =~ "shared object" ]] && [[ "$NGX_BINARY_INFO" =~ "not stripped" ]]
			then
				print_debug "Debug symbols found"
				return
			fi
		done
		print_err "Debug symbols not found"
		print_sys_info "$1"
		exit 6
	elif [[ "$1" == "yum" ]]; then
		# added here because yum cannot find PATH variable only on amazon linux
		export PATH="$PATH"
		# first check if nginx is provided by yum manager
		# case-insensitive because of differences beetween rhel and amazon linux
		YUM_CMD=`yum whatprovides $2|grep -i "No matches found"`
		if [[ -n $"YUM_CMD" ]]; then
			# nginx is not installed using yum; now check whether it contains debug symbols
			NGX_BINARY_INFO=`file $2`
			if [[ "$NGX_BINARY_INFO" =~ .*executable.* || "$NGX_BINARY_INFO" =~ "shared object" ]] && [[ "$NGX_BINARY_INFO" =~ "not stripped" ]]
			then
				print_err "Nginx wasn't installed using the system package manager, but it contains debug symbols and can be handled by the Agent automatically"
				exit 55
			else
				print_err "Nginx wasn't installed using the system package manager"
				print_sys_info "$1"
				exit 5
			fi
		else
			# it seems that nginx is installed using yum; now check whether it contains debug symbols
			NGX_BINARY_INFO=`file $2`
			#if not we are checking if it is not stripped
			if [[ "$NGX_BINARY_INFO" =~ .*executable.* || "$NGX_BINARY_INFO" =~ "shared object" ]] && [[ "$NGX_BINARY_INFO" =~ "not stripped" ]]
			then
				print_err "Nginx was installed using the system package manager, but it contains debug symbols and can be handled by the Agent automatically"
				exit 56
			fi
		fi
		# now look for debug symbols
		PKG_NAME=`rpm -q nginx|cut -d"-" -f1`
		PKG_VERSION=`rpm -q nginx|awk -F"nginx-" '{ print $2}'`
		NGINX_DBG="$PKG_NAME-debuginfo-$PKG_VERSION"
		RPM_CMD=`rpm -q $NGINX_DBG|grep "is not installed"`
		if [[ -z "$RPM_CMD" ]]; then
			print_debug "Debug symbols found in $NGINX_DBG"
			return
		fi
		print_err "Debug symbols not found"
		print_sys_info "$1"
		exit 6
	fi
}


##################################
#                                #
#  actual execution starts here  #
#                                #
##################################

parse_command_line "$@"

#print_sys_info "$BINARY"
#exit 1

if [[ $DIRECTORY || $BINARY ]] && [ -z $OUTPUT ]; then
	if [ "$BINARY" ]; then
		OUTPUT="dtnginx_self_generated_offsets.json"
	else
		OUTPUT="dtnginx_offsets.json"
	fi
fi

if [ -n "$DIRECTORY" ]; then  # former gen_offset_code script
	print_debug "RECURSIVE mode selected"
	#exit 7 errors occurred during offset generation
	initialize_data
	echo "Generating $OUTPUT -- this could take about half a minute"
	write_header
	FILES=`find $DIRECTORY -type f -name nginx`
	for nginx_bin in $FILES; do
		print_debug "Processing file $nginx_bin"
		nginx_debug=${nginx_bin}.dbg
		desc=${nginx_bin%%/nginx}
		desc=${desc##*/}
		if [ -f "$nginx_debug" ]; then
			write_body "$nginx_bin" "$nginx_debug" "$desc"
		fi
	done
	sed -i '$ s/.$/,/' "$OUTPUT"
	write_footer

elif [ -n "$BINARY" ]; then  # former ngx_gen_offset script
	print_debug "SELF_GENERATE mode selected"
	#exit 2 probably compiled version of nginx
	#exit 3 problem with installing debug symbols
	#exit 4 problem with installing additional package
	#exit 5 build id mismatch
	#exit 6 user exit
	#exit 7 errors occurred during offset generation
	#exit 8 OS not supported

	initialize_data
	export LC_ALL=en_GB.UTF-8
	PKG=$(check_os)
	if [[ "$PKG" == "other" ]]; then
		print_err "Your OS does not seem to be supported."
		print_sys_info "$BINARY"
		exit 8;
	else
		print_debug "Package manager used by this system: $PKG."
	fi

	check_nginx_binary "$BINARY"
	if [ -z "$GLOBAL_NGINX_DBG_PATH" ]; then
		install_debug_symbols "$PKG" "$BINARY"
	fi
	check_nginx_debug_binary "$GLOBAL_NGINX_DBG_PATH"

	install_tools $PKG "gdb"
	install_tools $PKG "elfutils"
	install_tools $PKG "binutils"
	install_tools $PKG "bc"
		if [ -z "$IGNORE_BUILDID" ]; then
		compare_buildid "$BINARY" "$GLOBAL_NGINX_DBG_PATH"
	fi
	desc=${BINARY%%/nginx}
	desc=${desc##*/}

	REAL_OUTPUT="$OUTPUT"
	OUTPUT=`mktemp`
	write_header
	write_body "$BINARY" "$GLOBAL_NGINX_DBG_PATH" "$desc"
	write_footer
	mv "$OUTPUT" "$REAL_OUTPUT"
	print_out "New JSON offset file generated"

	print_out "Please restart Nginx if it is working"

elif [ -n "$TEST_BINARY" ]; then  # former ngx_test_pkg script
	print_debug "TEST_PKG mode selected"
	#exit 1 generated by agent code if something goes wrong in forked process
	#exit 4 aditional tools missing
	#exit 5 nginx is not installed using package manager
	#exit 6 missing nginx debug symbols
	#exit 8 OS not supported
	#exit 55 nginx is not installed using package manager but it is debug version so we can generate json automatically
	#exit 56 nginx is installed using package manager but it is debug version so we can generate json automatically
	#exit 111 generated by agent problem with forking subprocess

	export LC_ALL=en_GB.UTF-8
	PKG=$(check_os)
	if [[ "$PKG" == "other" ]]; then
		print_err "Your OS is not supported automatically. However, you can probably set up the Agent using a manual procedure:";
		print_err "1. Make sure the following tools are installed and available in PATH: binutils, gdb, elfutils, bc.";
		print_err "2. Install Nginx debug symbols (or use an unstripped Nginx binary).";
		print_err "3. Dump the script from the Agent library to the current directory:";
		print_err "        $ DT_DUMP_SCRIPT=1 LD_PRELOAD=.../libdtnginxagent.so ls";
		print_err "4. Run the script to generate the offset file";
		print_err "   (if using an unstripped Nginx binary, specify it also as parameter to -d):";
		print_err "        $ ./generate_offsets.sh -b NGINX_BINARY -d NGINX_DEBUG_SYMBOLS -o dtnginx_offsets.json";
		print_err "5. Copy the offset file dtnginx_offsets.json to Nginx Agent config directory.";
		exit 8;
	else
		print_debug "Package manager used by this system: $PKG."
	fi
	check_tools "$PKG"
	check_debug_symbols "$PKG" "$TEST_BINARY"
	exit
fi

# finis marker

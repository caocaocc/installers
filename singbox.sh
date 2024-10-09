#!/bin/sh

bootstrap_pkg() {

	# get the special formatted version (i.e. "go is go1.14" while node is "node v12.10.8")
	pkg_canonical_name() {
		my_versioned_name="'$PKG_NAME $PKG_TAG'"
		echo "$my_versioned_name"
	}

	# update symlinks according to $HOME/.local/opt and $HOME/.local/bin install paths.
	# shellcheck disable=2120
	# pkg_link may be used in the templated install script
	pkg_link() {
		if [ -n "$PKG_SINGLE" ]; then
			rm -rf "$pkg_dst_cmd"
			ln -s "$pkg_src_cmd" "$pkg_dst_cmd" 2>/dev/null || cp -f "$pkg_src_cmd" "$pkg_dst_cmd" 2>/dev/null
		else
			# 'pkg_dst' will default to $HOME/.local/opt/<pkg>
			# 'pkg_src' will be the installed version, such as to $HOME/.local/opt/<pkg>-<version>
			rm -rf "$pkg_dst"
			ln -s "$pkg_src" "$pkg_dst" 2>/dev/null || cp -f "$pkg_src" "$pkg_dst" 2>/dev/null
		fi
	}

	# detect if this program is already installed or if an installed version may cause conflict
	pkg_check() {
		# Test for existing version
		set +e
		my_path="$PATH"
		PATH="$(dirname "$pkg_dst_cmd"):$PATH"
		export PATH
		my_current_cmd="$(command -v "$pkg_cmd_name")"
		set -e
		if [ -n "$my_current_cmd" ]; then
			my_canonical_name="$(pkg_canonical_name)"
			if [ "$my_current_cmd" != "$pkg_dst_cmd" ]; then
				echo >&2 "WARN: possible PATH conflict between $my_canonical_name and currently installed version"
				echo >&2 "    ${pkg_dst_cmd} (new)"
				echo >&2 "    ${my_current_cmd} (existing)"
				#my_current_version=false
			fi
			# 'readlink' can't read links in paths on macOS 🤦
			# but that's okay, 'cmp -s' is good enough for us
			if cmp -s "${pkg_src_cmd}" "${my_current_cmd}"; then
				echo "    ${my_canonical_name} already installed"
				# printf "    %s" "${pkg_dst}"
				# if [ "${pkg_src_cmd}" != "${my_current_cmd}" ]; then
				# 	printf " => %s" "${pkg_src}"
				# fi
				singbox_config
				singbox_start
				exit 0
			fi
			if [ -x "$pkg_src_cmd" ]; then
				# shellcheck disable=2119
				# this function takes no args
				pkg_link
				echo "    switched to $my_canonical_name"
				# echo "      ${pkg_dst} => ${pkg_src}"
				singbox_config
				singbox_start
				exit 0
			fi
		fi
		export PATH="$my_path"
	}

	# detect if file is downloaded, and how to download it
	pkg_download() {
		my_url="${1:-${PKG_URL}}"
		my_dl="${2:-${PKG_PATH}/$PKG_FILE}"
		my_dl_name="${3:-${PKG_NAME}}"

		if [ -e "$my_dl" ]; then
			echo "    Found $my_dl"
			return 0
		fi

		echo "    Downloading ${my_dl_name} from"
		echo "      $(t_gray "$my_url")"

		user_agent="$(uname -s)/$(uname -r) $(uname -m)/au"

		if command -v curl >/dev/null; then
			my_show_progress="-#"
			if ! curl -f -ksSL --user-agent "$user_agent" "$my_url" -o "$my_dl.part"; then
				echo >&2 "failed to download from $my_url"
				exit 1
			fi
		elif command -v wget >/dev/null; then
			my_show_progress="--show-progress"
			if ! wget -q --user-agent="$user_agent" -c "$my_url" -O "$my_dl.part"; then
				echo >&2 "failed to download from $my_url"
				exit 1
			fi
		else
			echo >&2 "failed to detect HTTP client (curl, wget)"
			return 1
		fi

		mv "$my_dl.part" "$my_dl"
		echo "    Saved as $my_dl"
	}

	# detect which archives can be used
	pkg_extract() {
		(
			cd "$TMP_PATH"
			if [ "tar.gz" = "$PKG_EXT" ]; then
				echo "    Extracting ${PKG_PATH}/$PKG_FILE"
				tar xf "${PKG_PATH}/$PKG_FILE"
			elif [ "tar" = "$PKG_EXT" ]; then
				echo "    Extracting ${PKG_PATH}/$PKG_FILE"
				tar xf "${PKG_PATH}/$PKG_FILE"
			elif [ "zip" = "$PKG_EXT" ]; then
				echo "    Extracting ${PKG_PATH}/$PKG_FILE"
				unzip "${PKG_PATH}/$PKG_FILE" >__unzip__.log
			elif [ "exe" = "$PKG_EXT" ]; then
				echo "    Moving ${PKG_PATH}/$PKG_FILE"
				mv "${PKG_PATH}/$PKG_FILE" .
			elif [ "xz" = "$PKG_EXT" ]; then
				echo "    Inflating ${PKG_PATH}/$PKG_FILE"
				unxz -c "${PKG_PATH}/$PKG_FILE" >"$(basename "$PKG_FILE")"
			else
				# do nothing
				echo "Failed to extract ${PKG_PATH}/$PKG_FILE"
				exit 1
			fi
		)
	}

	# group common pre-install tasks as default
	pkg_pre_install() {
		pkg_check
		pkg_download
		pkg_extract
	}

	# move commands from the extracted archive directory to $HOME/.local/opt or $HOME/.local/bin
	# shellcheck disable=2120
	# pkg_install may be sourced and used elsewhere
	pkg_install() {
		if [ -n "$PKG_SINGLE" ]; then
			mkdir -p "$(dirname "$pkg_src_cmd")"
			mv ./"$PKG_NAME"-*/"$pkg_cmd_name"* "$pkg_src_cmd"
		else
			rm -rf "$pkg_src"
			mv ./"$PKG_NAME"-*/"$pkg_cmd_name"* "$pkg_src"
		fi
	}

	# run post-install functions - just updating PATH by default
	pkg_post_install() {
		return 0
	}

	pkg_enable_exec() {
		if [ -n "$(command -v spctl)" ] && [ -n "$(command -v xattr)" ]; then
			# note: some packages contain files that cannot be affected by xattr
			xattr -r -d com.apple.quarantine "$pkg_src" || true
			return 0
		fi
		# TODO need to test that the above actually worked
		# (and proceed to this below if it did not)
		if [ -n "$(command -v spctl)" ]; then
			echo "Checking permission to execute '$pkg_cmd_name' on macOS 11+"
			set +e
			is_allowed="$(spctl -a "$pkg_src_cmd" 2>&1 | grep valid)"
			set -e
			if [ -z "$is_allowed" ]; then
				echo ""
				echo "##########################################"
				echo "#  IMPORTANT: Permission Grant Required  #"
				echo "##########################################"
				echo ""
				echo "Requesting permission to execute '$pkg_cmd_name' on macOS 10.14+"
				echo ""
				sleep 3
				spctl --add "$pkg_src_cmd"
			fi
		fi
	}

	# a friendly message when all is well, showing the final install path in $HOME/.local
	pkg_done_message() {
		echo "    Installed $(pkg_canonical_name) as $pkg_dst_cmd"
	}

	##
	##
	## BEGIN custom override functions from <package>/install.sh
	##
	##

	PKG_SINGLE=true

	if [ -z "${WELCOME-}" ]; then
		exit_key="Ctrl + C"
		if [ "$OS" = "darwin" ]; then
			exit_key="Control + C"
		fi

		echo ""
		echo "$(t_red '>>> 重要提示 <<<')"
		echo ""
		echo "  - 请立即退出所有杀毒软件和代理软件，"
		echo "    这些软件可能阻止您的设备正常联网。"
		echo ""
		echo "  - 退出 sing-box 的正确方式是在本窗口按 $exit_key 快捷键，"
		echo "    强制关闭窗口可能导致设备无法联网。"
		echo ""
		echo "  - 如需重新运行一键脚本，"
		echo "    可以在本窗口按方向键上 ↑ 浏览历史命令，"
		echo "    无需每次都从网站复制一键脚本。"
		echo ""
		# echo ""
		# printf "Thanks for using webi to install '\e[32m%s\e[0m' on '\e[31m%s/%s\e[0m'.\n" "${PKG_NAME-}" "$(uname -s)" "$(uname -m)"
		# echo "Have a problem? Experience a bug? Please let us know:"
		# echo "        https://github.com/webinstall/webi-installers/issues"
		# echo ""
		# printf "\e[31mLovin'\e[0m it? Say thanks with a \e[34mStar on GitHub\e[0m:\n"
		# printf "        \e[32mhttps://github.com/webinstall/webi-installers\e[0m\n"
		# echo ""
	fi

	init_installer() {

		# do nothing - to satisfy parser prior to templating
		printf ""
		echo "$(t_cyan 'Installing sing-box ...')"

		# {{ installer }}

	}

	init_installer

	##
	##
	## END custom override functions
	##
	##

	# run everything with defaults or overrides as needed
	if command -v pkg_install >/dev/null ||
		command -v pkg_link >/dev/null ||
		command -v pkg_post_install >/dev/null ||
		command -v pkg_done_message >/dev/null ||
		command -v pkg_format_cmd_version >/dev/null ||
		[ -n "${PKG_SINGLE-}" ] ||
		[ -n "${pkg_cmd_name-}" ] ||
		[ -n "${pkg_dst_cmd-}" ] ||
		[ -n "${pkg_dst_dir-}" ] ||
		[ -n "${pkg_dst-}" ] ||
		[ -n "${pkg_src_cmd-}" ] ||
		[ -n "${pkg_src_dir-}" ] ||
		[ -n "${pkg_src-}" ]; then

		pkg_cmd_name="${pkg_cmd_name:-$PKG_NAME}"
		if [ "$OS" = "windows" ]; then
			pkg_cmd_name="${pkg_cmd_name}.exe"
		fi

		if [ -n "$PKG_SINGLE" ]; then
			pkg_dst_cmd="${pkg_dst_cmd:-$HOME/.local/bin/$pkg_cmd_name}"
			pkg_dst="$pkg_dst_cmd" # "$(dirname "$(dirname $pkg_dst_cmd)")"

			pkg_src_cmd="${pkg_src_cmd:-$HOME/.local/opt/$PKG_NAME-$PKG_TAG/bin/$pkg_cmd_name}"
			pkg_src="$pkg_src_cmd" # "$(dirname "$(dirname $pkg_src_cmd)")"
		else
			pkg_dst="${pkg_dst:-$HOME/.local/opt/$pkg_cmd_name}"
			pkg_dst_cmd="${pkg_dst_cmd:-$pkg_dst/bin/$pkg_cmd_name}"

			pkg_src="${pkg_src:-$HOME/.local/opt/$PKG_NAME-$PKG_TAG}"
			pkg_src_cmd="${pkg_src_cmd:-$pkg_src/bin/$pkg_cmd_name}"
		fi
		# this script is templated and these are used elsewhere
		# shellcheck disable=SC2034
		pkg_src_bin="$(dirname "$pkg_src_cmd")"
		# shellcheck disable=SC2034
		pkg_dst_bin="$(dirname "$pkg_dst_cmd")"

		pkg_pre_install

		(
			cd "$TMP_PATH"
			echo "    Installing to $pkg_src_cmd"
			pkg_install
			chmod a+x "$pkg_src"
			chmod a+x "$pkg_src_cmd"
		)

		pkg_link

		pkg_enable_exec
		(
			cd "$TMP_PATH"
			pkg_post_install
		)

		(
			cd "$TMP_PATH"
			pkg_done_message
		)
	fi

	singbox_config
	singbox_start

	# cleanup the temp directory
	rm -rf "$TMP_PATH"

	# See? No magic. Just downloading and moving files.

}

init_arch() {
	ARCH=$(uname -m)
	case $ARCH in
	aarch64 | arm64)
		ARCH="arm64"
		;;
	amd64 | x64 | x86_64)
		ARCH="amd64"
		;;
	armv7*)
		ARCH="armv7"
		;;
	i386 | i686 | i86pc | x86)
		ARCH="amd64"
		;;
	s390x)
		ARCH="s390x"
		;;
	*)
		echo "Architecture ${ARCH} is not supported by this installation script"
		exit 1
		;;
	esac
}

init_os() {
	OS=$(uname | tr '[:upper:]' '[:lower:]')
	case "$OS" in
	cygwin* | mingw* | msys*)
		OS='windows'
		;;
	darwin)
		OS='darwin'
		;;
	linux | Linlx)
		OS='linux'
		;;
	*)
		echo "OS ${OS} is not supported by this installation script"
		exit 1
		;;
	esac
}

is_root() {
	if [[ -n "${EUID}" ]] && [[ "${EUID}" -eq 0 ]]; then
		return 0
	elif [[ "$(id -u)" -eq 0 ]]; then
		return 0
	else
		return 1
	fi
}

ask_password() {
	if ! is_root; then
		if [ ! -s "$HOME/.password" ]; then
			while [ -z "${password:-}" ]; do
				echo ""
				unset password
				password=
				echo -n "请输入 '$(id -u -n)' 用户的开机登录密码: " 1>&2
				while IFS= read -r -n1 -s char; do
					code=${char:+$(printf '%02x' "'$char'")}
					case "$code" in
					'' | 0a | 0d) break ;;
					08 | 7f)
						if [ -n "$password" ]; then
							password="$(echo "$password" | sed 's/.$//')"
							echo -n $'\b \b' 1>&2
						fi
						;;
					1b) ;;
					5b)
						read -r -n2 -s
						;;
					[01]?) ;;
					*)
						password="$password$char"
						echo -n '*' 1>&2
						;;
					esac
				done
				echo
			done
			echo "$password" >"$HOME/.password"
		fi
		password=$(cat "$HOME/.password")
		echo "$password" | sudo -S true >/dev/null 2>&1
		if [[ $? -eq 0 ]]; then
			return 0
		else
			printf "\n您输入的密码不正确，请重新启动设备后再次尝试。\n\n"
			rm -rf "$HOME/.password"
			exit 1
		fi
	fi
}

cmd_sudo() {
	case "$OS" in
	darwin)
		if ! is_root; then
			echo "$password" | sudo -S "${@}"
		else
			"$@"
		fi
		;;
	linux)
		if ! is_root; then
			echo "$password" | sudo -S "${@}"
		else
			"$@"
		fi
		;;
	windows)
		"$@"
		;;
	esac
}

cmd_sed() {
	if [ "$OS" = "darwin" ]; then
		sed -i '' "$@"
	else
		sed -i "$@"
	fi
}

cmd_process_stop() {
	process_name=$1
	while true; do
		if tasklist | grep -i "${process_name}" >/dev/null 2>&1; then
			taskkill //IM "${process_name}" //F >/dev/null 2>&1
		else
			break
		fi
		sleep 1
	done
}

singbox_config() { (
	# Update config.json
	if [ -n "${url:-}" ]; then
		echo "$(t_cyan 'Update proxies ...')"

		url=$(echo "$url" | sed 's|https://[^/]\+/v1/|https://sync.xn--8stx8olrwkucjq3b.com/v1/|')

		cd "$TMP_PATH"
		(pkg_download "$url" "config.json" "proxies" >/dev/null 2>&1) || true

		if "$pkg_dst_cmd" format -w -c "config.json" >/dev/null 2>&1; then

			if grep -q "dns-out" "config.json"; then
				cmd_sed 's/dns-out/dns/g' "config.json"
			fi

			if grep -q "null" "config.json"; then
				echo "    $(t_red '服务已过期,请打开登录链接,并重新复制一键脚本.')"
				exit 1
			fi

			if grep -q "outbounds" "config.json"; then
				awk 'BEGIN{print"{"} /"outbounds": \[/{p=1} /"route":/{p=0} p&&!/"route":/{if(prev)print prev;prev=$0} END{sub(/,$/, "", prev);print prev;print "}"}' "config.json" >"$singbox_outbound"
				echo "    Updated proxies"
			fi
		else
			if "$pkg_dst_cmd" format -w -c "$singbox_outbound" >/dev/null 2>&1; then
				echo "    Error updating proxies"
			else
				echo "    $(t_red '代理服务器更新失败,请打开登录链接,并重新复制一键脚本.')"
				exit 1
			fi
		fi
	fi

	if [ ! -e "$singbox_rule" ]; then
		echo '{"log":{"level":"info","output":"log.txt"},"dns":{"servers":[{"tag":"google","address":"udp://8.8.8.8"},{"tag":"cloudflare","address":"udp://1.1.1.1","detour":"proxy"},{"tag":"local","address":"udp://114.114.114.114","detour":"direct"}],"rules":[{"outbound":"any","server":"local"},{"domain_suffix":[".haishan.me",".metacubex.one",".xn--m7r110cisa278f.com",".xn--8stx8olrwkucjq3b.com",".splashtop.com"],"server":"local"},{"rule_set":"geosite-private","server":"local"},{"rule_set":"geosite-cn","server":"local"},{"rule_set":"geosite-geolocation-!cn","server":"cloudflare"}]},"route":{"rules":[{"type":"logical","mode":"or","rules":[{"protocol":"dns"},{"port":53}],"outbound":"dns"},{"type":"logical","mode":"or","rules":[{"protocol":"stun"},{"port":853},{"network":"udp","port":443}],"outbound":"block"},{"domain_suffix":[".haishan.me",".metacubex.one",".xn--m7r110cisa278f.com",".xn--8stx8olrwkucjq3b.com",".splashtop.com"],"outbound":"direct"},{"rule_set":["geosite-private","geoip-private"],"outbound":"direct"},{"rule_set":["geosite-cn","geoip-cn"],"outbound":"china"}],"rule_set":[{"type":"remote","tag":"geoip-private","format":"binary","url":"https://raw.githubusercontent.com/1715173329/sing-geoip/rule-set/geoip-private.srs","download_detour":"proxy"},{"type":"remote","tag":"geoip-cn","format":"binary","url":"https://raw.githubusercontent.com/1715173329/sing-geoip/rule-set/geoip-cn.srs","download_detour":"proxy"},{"type":"remote","tag":"geosite-private","format":"binary","url":"https://raw.githubusercontent.com/1715173329/sing-geosite/rule-set/geosite-private.srs","download_detour":"proxy"},{"type":"remote","tag":"geosite-cn","format":"binary","url":"https://raw.githubusercontent.com/1715173329/sing-geosite/rule-set/geosite-cn.srs","download_detour":"proxy"},{"type":"remote","tag":"geosite-geolocation-!cn","format":"binary","url":"https://raw.githubusercontent.com/1715173329/sing-geosite/rule-set/geosite-geolocation-!cn.srs","download_detour":"proxy"}],"auto_detect_interface":true},"experimental":{"cache_file":{"enabled":true},"clash_api":{"external_controller":"0.0.0.0:9090","external_ui":"yacd","external_ui_download_url":"https://github.com/caocaocc/yacd/archive/gh-pages.zip","external_ui_download_detour":"proxy"}}}' >"$singbox_rule"
	fi

	if [ ! -e "$singbox_inbound" ]; then
		echo '{"inbounds":[{"type":"tun","tag":"tun-in","inet4_address":"172.19.0.1/30","inet6_address":"fdfe:dcba:9876::1/126","auto_route":true,"strict_route":true,"stack":"gvisor","sniff":true,"sniff_override_destination":true,"domain_strategy":"ipv4_only"},{"type":"mixed","tag":"mixed-in","listen":"::","listen_port":9999}]}' >"$singbox_inbound"
	fi

	if [ -n "${fakeip:-}" ]; then
		echo '{"log":{"level":"info","output":"log.txt"},"dns":{"servers":[{"tag":"google","address":"udp://8.8.8.8"},{"tag":"cloudflare","address":"udp://1.1.1.1","detour":"proxy"},{"tag":"local","address":"udp://114.114.114.114","detour":"direct"},{"tag":"remote","address":"fakeip"}],"rules":[{"outbound":"any","server":"local"},{"domain_suffix":[".haishan.me",".metacubex.one",".xn--m7r110cisa278f.com",".xn--8stx8olrwkucjq3b.com",".splashtop.com"],"server":"local"},{"rule_set":"geosite-private","server":"local"},{"rule_set":"geosite-cn","server":"local"},{"query_type":["A","AAAA"],"server":"remote","rewrite_ttl":1}],"fakeip":{"enabled":true,"inet4_range":"28.0.0.0/8","inet6_range":"fc00::/18"},"independent_cache":true},"route":{"rules":[{"type":"logical","mode":"or","rules":[{"protocol":"dns"},{"port":53}],"outbound":"dns"},{"type":"logical","mode":"or","rules":[{"protocol":"stun"},{"port":853},{"network":"udp","port":443}],"outbound":"block"},{"domain_suffix":[".haishan.me",".metacubex.one",".xn--m7r110cisa278f.com",".xn--8stx8olrwkucjq3b.com",".splashtop.com"],"outbound":"direct"},{"rule_set":["geosite-private","geoip-private"],"outbound":"direct"},{"rule_set":["geosite-cn","geoip-cn"],"outbound":"china"}],"rule_set":[{"type":"remote","tag":"geoip-private","format":"binary","url":"https://raw.githubusercontent.com/1715173329/sing-geoip/rule-set/geoip-private.srs","download_detour":"proxy"},{"type":"remote","tag":"geoip-cn","format":"binary","url":"https://raw.githubusercontent.com/1715173329/sing-geoip/rule-set/geoip-cn.srs","download_detour":"proxy"},{"type":"remote","tag":"geosite-private","format":"binary","url":"https://raw.githubusercontent.com/1715173329/sing-geosite/rule-set/geosite-private.srs","download_detour":"proxy"},{"type":"remote","tag":"geosite-cn","format":"binary","url":"https://raw.githubusercontent.com/1715173329/sing-geosite/rule-set/geosite-cn.srs","download_detour":"proxy"},{"type":"remote","tag":"geosite-geolocation-!cn","format":"binary","url":"https://raw.githubusercontent.com/1715173329/sing-geosite/rule-set/geosite-geolocation-!cn.srs","download_detour":"proxy"}],"auto_detect_interface":true},"experimental":{"cache_file":{"enabled":true,"store_fakeip":true},"clash_api":{"external_controller":"0.0.0.0:9090","external_ui":"yacd","external_ui_download_url":"https://github.com/caocaocc/yacd/archive/gh-pages.zip","external_ui_download_detour":"proxy"}}}' >"$singbox_rule"
		echo '{"inbounds":[{"type":"tun","tag":"tun-in","inet4_address":"172.19.0.1/30","inet6_address":"fdfe:dcba:9876::1/126","auto_route":true,"strict_route":true,"stack":"gvisor","sniff":true,"sniff_override_destination":true},{"type":"mixed","tag":"mixed-in","listen":"::","listen_port":9999}]}' >"$singbox_inbound"
	fi

	if [ -n "${dns:-}" ]; then
		if [ "$dns" = "auto" ]; then
			dns="dhcp://auto"
			if grep -q "udp://114.114.114.114" "$singbox_rule"; then
				cmd_sed "s|udp://114.114.114.114|$dns|g" "$singbox_rule"
			fi
		fi
	fi

	if ! "$pkg_dst_cmd" format -w -c "$singbox_rule" >/dev/null 2>&1; then
		echo "$(t_red "文件格式错误 $singbox_rule")"
		exit 1
	fi

	if ! "$pkg_dst_cmd" format -w -c "$singbox_inbound" >/dev/null 2>&1; then
		echo "$(t_red "文件格式错误 $singbox_inbound")"
		exit 1
	fi

	if ! "$pkg_dst_cmd" format -w -c "$singbox_outbound" >/dev/null 2>&1; then
		echo "$(t_red "文件格式错误 $singbox_outbound")"
		exit 1
	fi

	if ! "$pkg_dst_cmd" merge "$singbox_config" -c "$singbox_rule" -c "$singbox_inbound" -c "$singbox_outbound" >/dev/null 2>&1; then
		echo "$(t_red '错误,请重启电脑,路由器,光猫后再次尝试.')"
		exit 1
	fi

	# Update pacfile
	pac_file="$HOME/.local/share/sing-box/yacd/pac.txt"

	cd "$TMP_PATH"

	if [ ! -e "$pac_file" ]; then
		(pkg_download "https://repo.o2cdn.icu/cached-apps/sing-box/gh-pages.tar.gz" "gh-pages.tar.gz" "yacd" >/dev/null 2>&1) && tar xf "gh-pages.tar.gz" -C "$singbox_workdir" && mv "$singbox_workdir/yacd-gh-pages" "$singbox_workdir/yacd" || true
	else
		pac_port=$(head -n 1 "$pac_file" | awk 'match($0, /[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:[0-9]+/) { print substr($0, RSTART, RLENGTH) }' | awk -F: '{print $2}')
		mixed_port=$(awk '/mixed-in/ {found=1; next} found && /[0-9]+/ {match($0, /[0-9]+/); print substr($0, RSTART, RLENGTH); exit}' "$singbox_config")
		if [ "$pac_port" != "$mixed_port" ]; then
			cmd_sed "s/$pac_port/$mixed_port/g" "$pac_file"
		fi
	fi

	cache_db="$singbox_workdir/cache.db"
	if [ ! -e "$cache_db" ]; then
		(pkg_download "https://repo.o2cdn.icu/cached-apps/sing-box/cache.db" "$cache_db" "cache.db" >/dev/null 2>&1) || true
	fi
); }

singbox_start() {
	if [ ! -e "$singbox_config" ]; then
		echo "$(t_red '找不到配置文件 $singbox_config')"
		exit 1
	fi

	local_dns=$(awk '/"tag": "local"/ { tag_line = FNR } (tag_line > 0) && /"address"/ { address_line = FNR; match($0, /[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/); if (RSTART) { local_dns = substr($0, RSTART, RLENGTH); print local_dns; exit } }' "$singbox_config")
	mixed_port=$(awk '/mixed-in/ {found=1; next} found && /[0-9]+/ {match($0, /[0-9]+/); print substr($0, RSTART, RLENGTH); exit}' "$singbox_config")
	yacd_port=$(awk '/external_controller/ { match($0, /[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:[0-9]+/); ip_port = substr($0, RSTART, RLENGTH); split(ip_port, arr, ":"); print arr[2]; }' "$singbox_config")

	socks5="127.0.0.1:${mixed_port:=9999}"
	yacd="http://127.0.0.1:${yacd_port:-9090}/ui/#/proxies"

	if [ "$OS" = "darwin" ]; then
		DNS=${local_dns:-114.114.114.114}
		cmd_sudo networksetup -setdnsservers Wi-Fi "$DNS"
		cmd_sudo dscacheutil -flushcache
		cmd_sudo killall -HUP mDNSResponder
	fi

	cmd_sudo echo "" >"$singbox_log"
	(
		for i in {1..60}; do
			if grep -q "sing-box started" "$singbox_log"; then
				if grep -q "inbound/tun.*started" "$singbox_log"; then
					echo "    Connection: tun"
					echo "        SOCKS5: $socks5"
					echo "          yacd: $yacd"
					echo "$(t_green 'sing-box running...')"
				else
					echo "    Connection: system proxy"
					echo "        SOCKS5: $socks5"
					echo "          yacd: $yacd"
					echo "$(t_green 'sing-box running...')"
				fi

				sleep 3
				open_url=$(command -v start || command -v open || command -v xdg-open)
				if [ -n "${dev:-}" ]; then
					$open_url "$yacd"
				else
					$open_url "https://ipv4.geojs.io" && $open_url "https://youtube.com" && $open_url "$yacd"
				fi

				break
			fi
			sleep 1
		done
	) &

	trap 'printf "\r%s\n" "$(t_red "sing-box stopped.")"; exit' INT

	printf "\r%s %s %s\n" "$(t_cyan 'Start')" "$(t_cyan "sing-box")" "$(t_cyan '...')"

	for i in {1..2}; do
		cmd_sudo "$pkg_dst_cmd" run -c "$singbox_config" -D "$singbox_workdir" && break || sleep 1s
	done

	if [ "$OS" = "windows" ]; then
		echo '{"inbounds":[{"type":"mixed","tag":"mixed-in","listen":"::","listen_port":9999,"set_system_proxy":true}]}' >"$singbox_inbound"
		"$pkg_dst_cmd" format -w -c "$singbox_inbound" >/dev/null 2>&1
		if ! "$pkg_dst_cmd" merge "$singbox_config" -c "$singbox_rule" -c "$singbox_inbound" -c "$singbox_outbound" >/dev/null 2>&1; then
			echo "$(t_red '错误,请重启电脑,路由器,光猫后再次尝试.')"
			exit 1
		fi
		"$pkg_dst_cmd" run -c "$singbox_config" -D "$singbox_workdir"
	fi
}

# 红色文本
t_red() { (fn_printf '\e[31m%s\e[39m' "${1}"); }
# 绿色文本
t_green() { (fn_printf '\e[32m%s\e[39m' "${1}"); }
# 黄色文本
t_yellow() { (fn_printf '\e[33m%s\e[39m' "${1}"); }
# 蓝色文本
t_blue() { (fn_printf '\e[34m%s\e[39m' "${1}"); }
# 品红文本
t_magenta() { (fn_printf '\e[35m%s\e[39m' "${1}"); }
# 青色文本
t_cyan() { (fn_printf '\e[36m%s\e[39m' "${1}"); }
# 灰色文本
t_gray() { (fn_printf '\e[90m%s\e[39m' "${1}"); }

fn_printf() { (
	a_style="${1}"
	a_text="${2}"
	printf -- "${a_style}" "${a_text}"
); }

init_arch
init_os

case "$OS" in
darwin)
	ask_password
	cmd_sudo pkill sing-box >/dev/null 2>&1
	;;
linux)
	ask_password
	cmd_sudo pkill sing-box >/dev/null 2>&1
	;;
windows)
	cmd_process_stop "sing-box.exe"
	windows_version=$(wmic os get Version | awk 'NR==2{print $1}')
	if [[ $windows_version == *"6.1"* ]]; then
		ARCH="amd64-legacy"
	fi
	;;
esac

args=$(awk 'BEGIN { for(i = 1; i < ARGC; i++) print ARGV[i] }' "$@")

for arg in $args; do
	case $arg in
	https://*)
		url=$arg
		;;
	version=*)
		version=${arg#*=}
		;;
	arch=*)
		ARCH=${arg#*=}
		;;
	dev)
		dev=true
		;;
	dns=*)
		dns=${arg#*=}
		;;
	fakeip)
		fakeip=true
		;;
	esac
done

set -e
set -u

PKG_NAME="sing-box"
PKG_OS="${OS}"
PKG_ARCH="${ARCH}"
PKG_VERSION="${version:-1.9.7}"
PKG_TAG="v${PKG_VERSION}"
PKG_EXT="tar.gz"
if [ "$OS" = "windows" ]; then
	PKG_EXT="zip"
fi
PKG_RELEASES="https://repo.o2cdn.icu/cached-apps/sing-box"
PKG_FILE="${PKG_NAME}-${PKG_VERSION}-${PKG_OS}-${PKG_ARCH}.${PKG_EXT}"
PKG_URL="${PKG_RELEASES}/${PKG_TAG}/${PKG_FILE}"
PKG_PATH="/tmp/${PKG_NAME}"
TMP_PATH=${TMP_PATH:-"$(mktemp -d -t install-"${PKG_NAME}".XXXXXXXX)"}

mkdir -p "${PKG_PATH}"
mkdir -p "$HOME/.local/bin"
mkdir -p "$HOME/.local/opt"
mkdir -p "$HOME/.local/share"

singbox_workdir="${HOME}/.local/share/sing-box"
singbox_config="${singbox_workdir}/config.txt"
singbox_log="${singbox_workdir}/log.txt"
singbox_rule="${singbox_workdir}/rule.txt"
singbox_inbound="${singbox_workdir}/inbound.txt"
singbox_outbound="${singbox_workdir}/outbound.txt"

# if [ ! -d "$HOME/.local/opt/${PKG_NAME}-${PKG_TAG}" ] && [ -d "$HOME/.local/share/${PKG_NAME}" ]; then
# 	rm -rf "$HOME/.local/share/sing-box" &
# 	wait
# fi

mkdir -p "${singbox_workdir}"

bootstrap_pkg "$@"

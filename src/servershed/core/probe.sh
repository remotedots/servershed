# servershed probe: read-only, no sudo, POSIX sh. Run as: ssh -T host sh -s -- [docroot...] < probe.sh
# Extra arguments are web roots to scan (from the inventory's docroot field).
# Output: one "key=value" per line. Repeated keys form lists. Never prints secrets.
# Everything is best-effort: a missing tool just means a missing key.

kv() { printf '%s=%s\n' "$1" "$(printf '%s' "$2" | tr '\n\r' '  ')"; }
has() { command -v "$1" >/dev/null 2>&1; }

kv probe_version 1
kv hostname "$(hostname 2>/dev/null || uname -n)"
kv kernel "$(uname -r)"
kv arch "$(uname -m)"

if [ -r /etc/os-release ]; then
  . /etc/os-release
  kv os_id "$ID"
  kv os_version "$VERSION_ID"
  kv os_name "$PRETTY_NAME"
fi

[ -r /proc/uptime ] && kv uptime_s "$(cut -d. -f1 /proc/uptime)"
[ -r /proc/loadavg ] && kv load1 "$(cut -d' ' -f1 /proc/loadavg)"

if [ -r /proc/meminfo ]; then
  kv mem_total_kb "$(awk '/^MemTotal:/{print $2}' /proc/meminfo)"
  kv mem_avail_kb "$(awk '/^MemAvailable:/{print $2}' /proc/meminfo)"
  kv swap_total_kb "$(awk '/^SwapTotal:/{print $2}' /proc/meminfo)"
  kv swap_free_kb "$(awk '/^SwapFree:/{print $2}' /proc/meminfo)"
fi

# disk usage of / and the home dir (shared hosting: home is what counts)
for m in / "$HOME"; do
  df -Pk "$m" 2>/dev/null | awk -v m="$m" 'NR==2{printf "disk=%s %s %s %s\n", m, $2, $3, $5}'
done

# kernels installed vs running
for k in /boot/vmlinuz-*; do [ -e "$k" ] && kv kernel_installed "${k#/boot/vmlinuz-}"; done
[ -e /var/run/reboot-required ] && kv reboot_required 1

if [ -r /etc/default/grub ]; then
  kv grub_default "$(sed -n 's/^GRUB_DEFAULT=//p' /etc/default/grub | tr -d '"' | tail -n1)"
fi

# pending package updates (simulation, works without root)
if has apt-get; then
  up=$(LC_ALL=C timeout 30 apt-get -s -o Debug::NoLocking=1 upgrade 2>/dev/null | grep -c '^Inst ')
  kv apt_upgradable "$up"
  sec=$(LC_ALL=C timeout 30 apt-get -s -o Debug::NoLocking=1 upgrade 2>/dev/null | grep '^Inst ' | grep -ci security)
  kv apt_security "$sec"
fi

if has systemctl; then
  kv systemd_state "$(systemctl is-system-running 2>/dev/null)"
  # descriptions can span lines (transient systemd-run units): keep only real unit names
  systemctl list-units --state=failed --no-legend --plain --full 2>/dev/null |
    awk '$1 ~ /^[A-Za-z0-9@_.:-]+\.(service|socket|timer|mount|automount|path|scope|slice|swap|target)$/ {print "unit_failed=" $1}'
  kv default_target "$(systemctl get-default 2>/dev/null)"
fi

# PHP: CLI default, every versioned binary, fpm sockets.
# Version comes from `-v` ("PHP 8.3.12 (cli) ..."): works for cli and cgi builds,
# unlike `-r`, which cgi builds (e.g. IONOS) answer with their usage text.
phpver() {
  "$1" -v 2>/dev/null | sed -n '1s/^PHP \([0-9][0-9.]*\)[^(]*(\([a-z-]*\)).*/\1 \2/p'
}
if has php; then v=$(phpver php) && [ -n "$v" ] && kv php_cli "$v"; fi
# user-level override some hosts use for drush/composer (e.g. ~/.local/bin/php -> php8.3-cli)
if [ -x "$HOME/.local/bin/php" ]; then v=$(phpver "$HOME/.local/bin/php") && [ -n "$v" ] && kv php_local "$v"; fi
for p in /usr/bin/php[0-9]*; do
  n=${p##*/}; rest=${n#php}; rest=${rest%-cli}
  case "$rest" in ""|*[!0-9.]*) continue ;; esac   # php8.4, php84, php8.3-cli; not php-config
  [ -x "$p" ] || continue
  v=$(phpver "$p") && [ -n "$v" ] && kv php_bin "$n $v"
done
for s in /run/php/*.sock; do [ -S "$s" ] && kv php_fpm_sock "${s##*/}"; done

# web servers and enabled sites
for w in nginx apache2 httpd caddy; do has "$w" && kv webserver "$w"; done
[ -d /etc/nginx/sites-enabled ] && for f in /etc/nginx/sites-enabled/*; do
  [ -e "$f" ] && kv nginx_site "${f##*/}"
done

# docker (only if our user may talk to it)
if has docker; then
  docker ps --format '{{.Names}} {{.Image}} {{.Status}}' 2>/dev/null | sed 's/^/container=/'
fi

# global IPv6 addresses (to compare with AAAA records)
if has ip; then
  ip -6 -o addr show scope global 2>/dev/null | awk '{
    flags=""; for(i=5;i<=NF;i++) if($i=="temporary"||$i=="dynamic"||$i=="mngtmpaddr") flags=flags" "$i;
    print "ipv6=" $4 flags }'
fi

# WordPress versions under common web roots (read-only grep of version.php)
for v in /srv/www/*/wp-includes/version.php /srv/www/*/*/wp-includes/version.php \
         /var/www/*/wp-includes/version.php; do
  [ -r "$v" ] || continue
  wp=$(sed -n "s/^\$wp_version = '\(.*\)';/\1/p" "$v")
  kv wordpress "${v%/wp-includes/version.php} $wp"
done
for d in "$@"; do
  v="$d/wp-includes/version.php"
  dv="$d/core/lib/Drupal.php"
  if [ -r "$v" ]; then
    kv wordpress "$d $(sed -n "s/^\$wp_version = '\(.*\)';/\1/p" "$v")"
  elif [ -r "$dv" ]; then
    kv drupal "$d $(sed -n "s/^ *const VERSION = '\(.*\)';/\1/p" "$dv")"
  elif [ -d "$d" ]; then
    kv docroot "$d"
  else
    kv docroot_missing "$d"
  fi
  [ -r "$d/.htaccess" ] && grep -qi '^[[:space:]]*AddHandler.*php' "$d/.htaccess" &&
    kv htaccess_php_handler "$d $(grep -i '^[[:space:]]*AddHandler.*php' "$d/.htaccess" | head -n1 | awk '{print $2}')"
done

kv probe_done 1

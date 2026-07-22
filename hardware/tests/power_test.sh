#!/bin/bash
# Raccoon HAT v1 — Power Rail & Thermal Stress Test
# Monitors voltage rails and temperature under sustained load.
# Usage: sudo ./power_test.sh [duration_minutes]

set -euo pipefail

DURATION="${1:-5}"
INTERVAL=2
LOGFILE="/tmp/raccoon_power_$(date +%Y%m%d_%H%M%S).csv"

echo "╔════════════════════════════════════════════╗"
echo "║   Raccoon HAT v1 — Power & Thermal Test    ║"
echo "╚════════════════════════════════════════════╝"
echo
echo "Duration:  ${DURATION} minutes"
echo "Interval:  ${INTERVAL}s"
echo "Log:       $LOGFILE"
echo

# CSV header
echo "timestamp,cpu_temp_c,cpu_freq_mhz,throttled,5v_mv,current_ma,power_mw" > "$LOGFILE"

# Start stress load in background
echo "Starting CPU + network stress load..."
stress_pids=""

if command -v stress-ng &>/dev/null; then
    stress-ng --cpu 4 --timeout "${DURATION}m" &>/dev/null &
    stress_pids="$!"
elif command -v stress &>/dev/null; then
    stress --cpu 4 --timeout "${DURATION}m" &>/dev/null &
    stress_pids="$!"
else
    # Fallback: use dd for CPU load
    for i in 1 2 3 4; do
        dd if=/dev/urandom of=/dev/null bs=1M &>/dev/null &
        stress_pids="$stress_pids $!"
    done
fi

# Also generate network traffic if iperf3 available
ETH1=""
for iface in eth1 enx* usb0; do
    if ip link show "$iface" &>/dev/null; then
        ETH1="$iface"
        break
    fi
done

if [ -n "$ETH1" ] && command -v iperf3 &>/dev/null; then
    iperf3 -s -D 2>/dev/null
    iperf3 -c 127.0.0.1 -t $((DURATION * 60)) -b 500M &>/dev/null &
    stress_pids="$stress_pids $!"
fi

cleanup() {
    echo
    echo "Stopping stress load..."
    for pid in $stress_pids; do
        kill "$pid" 2>/dev/null || true
    done
    killall iperf3 2>/dev/null || true
    wait 2>/dev/null || true
}
trap cleanup EXIT

# ── Monitor loop ──
echo
printf "%-10s  %-8s  %-10s  %-10s  %-8s  %-8s  %-8s\n" \
    "Time" "CPU °C" "CPU MHz" "Throttled" "5V mV" "mA" "mW"
echo "────────  ────────  ──────────  ──────────  ────────  ────────  ────────"

end_time=$((SECONDS + DURATION * 60))
max_temp=0
min_5v=99999

while [ $SECONDS -lt $end_time ]; do
    ts=$(date +%H:%M:%S)

    # CPU temperature
    cpu_temp_raw=$(cat /sys/class/thermal/thermal_zone0/temp 2>/dev/null || echo 0)
    cpu_temp=$((cpu_temp_raw / 1000))
    [ "$cpu_temp" -gt "$max_temp" ] && max_temp=$cpu_temp

    # CPU frequency
    cpu_freq=$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq 2>/dev/null || echo 0)
    cpu_freq_mhz=$((cpu_freq / 1000))

    # Throttling status
    throttled=$(vcgencmd get_throttled 2>/dev/null | grep -oP '0x\K.*' || echo "N/A")

    # Power monitor (INA219/INA226 via sysfs)
    voltage_mv="N/A"
    current_ma="N/A"
    power_mw="N/A"
    for hwmon in /sys/class/hwmon/hwmon*/; do
        name=$(cat "${hwmon}name" 2>/dev/null || continue)
        if [ "$name" = "ina219" ] || [ "$name" = "ina226" ]; then
            voltage_mv=$(cat "${hwmon}in1_input" 2>/dev/null || echo "N/A")
            current_ma=$(cat "${hwmon}curr1_input" 2>/dev/null || echo "N/A")
            power_mw=$(cat "${hwmon}power1_input" 2>/dev/null || echo "N/A")
            if [ "$voltage_mv" != "N/A" ] && [ "$voltage_mv" -lt "$min_5v" ] 2>/dev/null; then
                min_5v=$voltage_mv
            fi
            break
        fi
    done

    printf "%-10s  %-8s  %-10s  %-10s  %-8s  %-8s  %-8s\n" \
        "$ts" "${cpu_temp}°C" "$cpu_freq_mhz" "$throttled" \
        "$voltage_mv" "$current_ma" "$power_mw"

    echo "$ts,$cpu_temp,$cpu_freq_mhz,$throttled,$voltage_mv,$current_ma,$power_mw" >> "$LOGFILE"

    sleep "$INTERVAL"
done

# ── Summary ──
echo
echo "════════════════════════════════════"
echo "Test completed after ${DURATION} minutes"
echo "  Max CPU temp:  ${max_temp}°C"
if [ "$min_5v" -lt 99999 ] 2>/dev/null; then
    min_5v_v=$(echo "scale=2; $min_5v / 1000" | bc 2>/dev/null || echo "?")
    echo "  Min 5V rail:   ${min_5v_v}V"
fi
echo "  Log saved:     $LOGFILE"
echo

if [ "$max_temp" -lt 70 ]; then
    printf "\033[32mPASS\033[0m: Thermal performance within limits\n"
elif [ "$max_temp" -lt 80 ]; then
    printf "\033[33mWARN\033[0m: Running warm — consider heatsink\n"
else
    printf "\033[31mFAIL\033[0m: Thermal throttling detected — improve cooling\n"
fi

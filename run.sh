#!/bin/bash

# RTSSP-SHP Run Script
# Automatically starts server, proxy, and media player in separate terminals

set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
SERVER_DIR="$SCRIPT_DIR/hjStreamServer"
PROXY_DIR="$SCRIPT_DIR/hjUDPproxy"

echo "==============================================="
echo "  RTSSP & RTSSP-SHP Auto-Runner"
echo "==============================================="
echo ""

# Function to detect terminal available
detect_terminal() {
    if command -v gnome-terminal &> /dev/null; then
        echo "gnome-terminal"
    elif command -v xterm &> /dev/null; then
        echo "xterm"
    elif command -v konsole &> /dev/null; then
        echo "konsole"
    elif command -v xfce4-terminal &> /dev/null; then
        echo "xfce4-terminal"
    else
        echo "none"
    fi
}

# Function to detect media player available
detect_media_player() {
    if command -v celluloid &> /dev/null; then
        echo "celluloid"
    elif command -v vlc &> /dev/null; then
        echo "vlc"
    elif command -v mpv &> /dev/null; then
        echo "mpv"
    else
        echo "none"
    fi
}

# Launch media player with stream
launch_media_player() {
    local player="$1"
    local terminal="$2"
    
    if [ "$player" = "none" ]; then
        echo "[MEDIA] No media player found (install vlc or mpv)"
        return
    fi
    
    sleep 2  # Wait for proxy to start listening
    
    echo "[MEDIA] Launching $player on udp://localhost:7777..."
    
    case "$terminal" in
        gnome-terminal)
            gnome-terminal --title="Media Player ($player)" -- bash -c "
                $player 'udp://localhost:7777'
                bash
            " &
            ;;
        xterm)
            xterm -title "Media Player ($player)" -e bash -c "
                $player 'udp://localhost:7777'
                bash
            " &
            ;;
        konsole)
            konsole --title "Media Player ($player)" -e bash -c "
                $player 'udp://localhost:7777'
                bash
            " &
            ;;
        xfce4-terminal)
            xfce4-terminal --title "Media Player ($player)" -e bash -c "
                $player 'udp://localhost:7777'
                bash
            " &
            ;;
        none)
            # For sequential mode, just launch player in background
            $player 'udp://localhost:7777' &
            ;;
    esac
}

# Read configuration
read_config() {
    local config_file="$SERVER_DIR/Cryptoconfig.conf"
    if [ ! -f "$config_file" ]; then
        echo "[ERROR] Config file not found: $config_file"
        exit 1
    fi
    
    MODE=$(grep "^mode=" "$config_file" | cut -d'=' -f2)
    echo "[CONFIG] Mode: $MODE"
}

# Check if binaries exist
check_binaries() {
    if [ ! -f "$SERVER_DIR/hjStreamServer.class" ]; then
        echo "[ERROR] Server not compiled. Run ./setup.sh first"
        exit 1
    fi
    if [ ! -f "$PROXY_DIR/hjUDPproxy.class" ]; then
        echo "[ERROR] Proxy not compiled. Run ./setup.sh first"
        exit 1
    fi
    echo "[CHECK] Binaries found ✓"
}

# Get movie file with direct name input
get_movie_file() {
    local provided_arg="$1"
    local selected_movie=""

    if [ -n "$provided_arg" ]; then
        # If it's already an absolute path, return it as is
        if [[ "$provided_arg" == /* ]]; then
            echo -n "$provided_arg"
        else
            echo -n "$SERVER_DIR/movies/$provided_arg"
        fi
        return
    fi

    # Everything else MUST go to >&2 so it isn't captured by the variable
    echo "" >&2
    echo "Available movies:" >&2
    ls "$SERVER_DIR/movies/"*.dat 2>/dev/null | xargs -n1 basename | sed 's/^/  - /' >&2
    echo "" >&2
    
    read -p "Enter movie name: " selected_movie >&2
    
    # Trim potential whitespace/newlines
    selected_movie=$(echo "$selected_movie" | tr -d '\r\n')
    
    # Return ONLY the path using -n (no newline)
    echo -n "$SERVER_DIR/movies/$selected_movie"
}

# Run with gnome-terminal
run_gnome_terminal() {
    local movie="$1"
    local player="$2"

    # STRIP any trailing/leading newlines from the movie variable itself
    movie=$(echo "$movie" | xargs)

    echo "[LAUNCH] Starting with gnome-terminal..."
    
    gnome-terminal --title="RTSSP Server" -- bash -c "
        cd \"$SERVER_DIR\"
        java hjStreamServer \"$movie\" localhost 5000
        bash
    " &
    sleep 1
    
    # Proxy terminal
    gnome-terminal --title="RTSSP Proxy" -- bash -c "
        cd \"$PROXY_DIR\"
        java hjUDPproxy \"$movie\"
        bash
    " &
    
    # Launch media player
    launch_media_player "$player" "gnome-terminal" &
    
    echo "[LAUNCH] Server, Proxy, and Media Player started!"
    echo "Press Ctrl+C to stop..."
    wait
}

# Run with xterm
run_xterm() {
    local movie="$1"
    local player="$2"
    
    echo "[LAUNCH] Starting with xterm..."
    
    # Server terminal
    xterm -title "RTSSP Server" -e bash -c "
        cd \"$SERVER_DIR\"
        echo \"Starting server with: $movie\"
        java hjStreamServer \"$movie\" localhost 5000
        bash
    " &
    sleep 1
    
    # Proxy terminal
    xterm -title "RTSSP Proxy" -e bash -c "
        cd \"$PROXY_DIR\"
        echo \"Starting proxy with: $movie\"
        java hjUDPproxy \"$movie\"
        bash
    " &
    
    # Launch media player
    launch_media_player "$player" "xterm" &
    
    echo "[LAUNCH] Server, Proxy, and Media Player started!"
    echo "Press Ctrl+C to stop..."
    wait
}

# Run with konsole
run_konsole() {
    local movie="$1"
    local player="$2"
    
    echo "[LAUNCH] Starting with konsole..."
    
    # Server terminal
    konsole --title "RTSSP Server" -e bash -c "
        cd \"$SERVER_DIR\"
        echo \"Starting server with: $movie\"
        java hjStreamServer \"$movie\" localhost 5000
        bash
    " &
    sleep 1
    
    # Proxy terminal
    konsole --title "RTSSP Proxy" -e bash -c "
        cd \"$PROXY_DIR\"
        echo \"Starting proxy with: $movie\"
        java hjUDPproxy \"$movie\"
        bash
    " &
    
    # Launch media player
    launch_media_player "$player" "konsole" &
    
    echo "[LAUNCH] Server, Proxy, and Media Player started!"
    echo "Press Ctrl+C to stop..."
    wait
}

# Run with xfce4-terminal
run_xfce4() {
    local movie="$1"
    local player="$2"
    
    echo "[LAUNCH] Starting with xfce4-terminal..."
    
    # Server terminal
    xfce4-terminal --title "RTSSP Server" -e bash -c "
        cd \"$SERVER_DIR\"
        echo \"Starting server with: $movie\"
        java hjStreamServer \"$movie\" localhost 5000
        bash
    " &
    sleep 1
    
    # Proxy terminal
    xfce4-terminal --title "RTSSP Proxy" -e bash -c "
        cd \"$PROXY_DIR\"
        echo \"Starting proxy with: $movie\"
        java hjUDPproxy \"$movie\"
        bash
    " &
    
    # Launch media player
    launch_media_player "$player" "xfce4-terminal" &
    
    echo "[LAUNCH] Server, Proxy, and Media Player started!"
    echo "Press Ctrl+C to stop..."
    wait
}

# Fallback: run in same terminal sequentially (not ideal)
run_sequential() {
    local movie="$1"
    local player="$2"
    
    echo "[WARNING] No supported terminal found. Running sequentially..."
    echo ""
    echo "Starting server..."
    cd "$SERVER_DIR"
    java hjStreamServer "$movie" localhost 5000 &
    SERVER_PID=$!
    
    sleep 2
    
    echo "Starting proxy..."
    cd "$PROXY_DIR"
    java hjUDPproxy "$movie" &
    PROXY_PID=$!
    
    sleep 2
    
    if [ "$player" != "none" ]; then
        echo "Starting media player ($player)..."
        $player udp://@localhost:7777 2>/dev/null &
        PLAYER_PID=$!
    fi
    
    echo ""
    echo "[RUNNING] Server PID: $SERVER_PID, Proxy PID: $PROXY_PID"
    echo "Press Ctrl+C to stop all..."
    
    # Wait for both
    wait $SERVER_PID $PROXY_PID
}

# === Main Script ===

# Parse arguments
MOVIE_FILE="${1:-}"

# Read config and check setup
read_config
check_binaries
MOVIE_FILE=$(get_movie_file "$MOVIE_FILE")

echo "[SETUP] Movie file: $MOVIE_FILE"
echo ""

# Detect available terminal
TERMINAL=$(detect_terminal)
echo "[DETECT] Terminal: $TERMINAL"

# Detect available media player
MEDIA_PLAYER=$(detect_media_player)
echo "[DETECT] Media Player: $MEDIA_PLAYER"
echo ""

# Run based on available terminal
case "$TERMINAL" in
    gnome-terminal)
        run_gnome_terminal "$MOVIE_FILE" "$MEDIA_PLAYER"
        ;;
    xterm)
        run_xterm "$MOVIE_FILE" "$MEDIA_PLAYER"
        ;;
    konsole)
        run_konsole "$MOVIE_FILE" "$MEDIA_PLAYER"
        ;;
    xfce4-terminal)
        run_xfce4 "$MOVIE_FILE" "$MEDIA_PLAYER"
        ;;
    none)
        run_sequential "$MOVIE_FILE" "$MEDIA_PLAYER"
        ;;
esac

#!/bin/bash
#
# Setup cron job for auto-implementation
#
# Usage:
#   ./setup_cron.sh install    # Install cron job (every 2 hours)
#   ./setup_cron.sh remove     # Remove cron job
#   ./setup_cron.sh status     # Check if cron job exists
#

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
SCRIPT_PATH="$SCRIPT_DIR/auto_implement.sh"
LOG_PATH="$PROJECT_DIR/logs/auto_implement.log"

# Cron schedule: every 2 hours at minute 0
CRON_SCHEDULE="0 */2 * * *"
CRON_COMMAND="$SCRIPT_PATH >> $LOG_PATH 2>&1"
CRON_ENTRY="$CRON_SCHEDULE $CRON_COMMAND"
CRON_MARKER="# supwngo-auto-implement"

install_cron() {
    # Create logs directory
    mkdir -p "$PROJECT_DIR/logs"

    # Check if already installed
    if crontab -l 2>/dev/null | grep -q "$CRON_MARKER"; then
        echo "Cron job already installed."
        echo "Use '$0 remove' first to reinstall."
        return 1
    fi

    # Add cron job
    (crontab -l 2>/dev/null; echo "$CRON_MARKER"; echo "$CRON_ENTRY") | crontab -

    echo "Cron job installed successfully!"
    echo ""
    echo "Schedule: Every 2 hours (at :00)"
    echo "Command: $SCRIPT_PATH"
    echo "Log file: $LOG_PATH"
    echo ""
    echo "Next runs:"
    echo "  - Check with: crontab -l"
    echo "  - Logs at: $LOG_PATH"
    echo ""
    echo "To run immediately: $SCRIPT_PATH"
}

remove_cron() {
    if ! crontab -l 2>/dev/null | grep -q "$CRON_MARKER"; then
        echo "No cron job found to remove."
        return 1
    fi

    # Remove cron job (both marker and entry)
    crontab -l | grep -v "$CRON_MARKER" | grep -v "auto_implement.sh" | crontab -

    echo "Cron job removed successfully."
}

show_status() {
    echo "=== Cron Job Status ==="
    echo ""

    if crontab -l 2>/dev/null | grep -q "$CRON_MARKER"; then
        echo "Status: INSTALLED"
        echo ""
        echo "Current cron entry:"
        crontab -l | grep -A1 "$CRON_MARKER"
    else
        echo "Status: NOT INSTALLED"
        echo ""
        echo "Run '$0 install' to set up the cron job."
    fi

    echo ""
    echo "=== Implementation Status ==="
    "$SCRIPT_PATH" --status 2>/dev/null || echo "Run $SCRIPT_PATH --status for details"
}

case "${1:-}" in
    install)
        install_cron
        ;;
    remove)
        remove_cron
        ;;
    status)
        show_status
        ;;
    *)
        echo "Usage: $0 {install|remove|status}"
        echo ""
        echo "Commands:"
        echo "  install  - Install cron job (runs every 2 hours)"
        echo "  remove   - Remove cron job"
        echo "  status   - Show current status"
        exit 1
        ;;
esac

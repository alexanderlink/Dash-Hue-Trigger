#!/bin/sh
### BEGIN INIT INFO
# Provides:          F�r welches Programm ist das Script?
# Required-Start:
# Required-Stop:
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: Kurze Beschreibung
# Description:       L�ngere Beschreibung
### END INIT INFO

# Actions
case "$1" in
    start)
        # START
                /home/pi/Still-Wickel-Logger/dash/start.sh
        ;;
    stop)
        # STOP
        ;;
    restart)
        # RESTART
        ;;
esac

exit 0

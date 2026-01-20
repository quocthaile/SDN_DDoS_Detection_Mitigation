#!/bin/bash

# ==============================
# CONFIGURATION
# ==============================
SRC="/home/thailq/SDN_DDoS_Detection_Mitigation"
DEST="/mnt/d/drive/UIT/HK3/Nhap mon dam bao va an ninh thong tin/Do an/source/SDN_DDoS_Detection_Mitigation"

LOGFILE="/home/thailq/wsl_to_windows_backup.log"
TIMESTAMP=$(date +"%Y-%m-%d_%H-%M-%S")

# ==============================
# PRE-CHECKS
# ==============================

if [ ! -d "$SRC" ]; then
  echo "[$TIMESTAMP] ERROR: Source directory does not exist: $SRC" | tee -a "$LOGFILE"
  exit 1
fi

if [ ! -d "$DEST" ]; then
  echo "[$TIMESTAMP] Destination not found. Creating: $DEST" | tee -a "$LOGFILE"
  mkdir -p "$DEST"
fi

# ==============================
# BACKUP (GIT-SAFE MODE)
# ==============================

echo "[$TIMESTAMP] Starting WSL -> Windows backup (GIT-1 mode)..." | tee -a "$LOGFILE"

rsync -avh \
  --progress \
  --exclude="env/" \
  --exclude=".git/" \
  --exclude=".git/hooks/*" \
  --exclude=".cache/" \
  --exclude="__pycache__/" \
  --exclude="*.pyc" \
  "$SRC/" "$DEST/" | tee -a "$LOGFILE"

STATUS=${PIPESTATUS[0]}

if [ $STATUS -eq 0 ]; then
  echo "[$TIMESTAMP] Backup completed successfully." | tee -a "$LOGFILE"
else
  echo "[$TIMESTAMP] WARNING: Backup finished with errors (code=$STATUS)." | tee -a "$LOGFILE"
fi

exit $STATUS

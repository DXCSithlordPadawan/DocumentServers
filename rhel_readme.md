
# Make executable (already set, but if re-copied):
chmod +x ./rhel_inventory.sh

# Run with root (recommended for RAID tools, dmidecode, sosreport, firewall):
sudo ./rhel_inventory.sh

# Output:
#   ./<hostname>_system_inventory.md  (Markdown report)
# Optional artifact:
#   sosreport archive path is noted in the report if 'sos' is installed

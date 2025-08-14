#!/bin/bash
# Script to run the unified Ozone audit analysis on remote OM servers

echo "========================================"
echo "Ozone Cross-OM Audit Analysis (Remote)"
echo "========================================"

# Check if config file is provided
if [ $# -eq 0 ]; then
    CONFIG_FILE="unified_config_remote.json"
    echo "Using default config: $CONFIG_FILE"
else
    CONFIG_FILE="$1"
    echo "Using config: $CONFIG_FILE"
fi

# Check if config exists
if [ ! -f "$CONFIG_FILE" ]; then
    echo "Error: Configuration file '$CONFIG_FILE' not found!"
    echo ""
    echo "Usage: $0 [config_file]"
    echo ""
    echo "Please create a config file with the following structure:"
    cat << 'SAMPLE'
{
  "time_window_minutes": 60,
  "results_directory": "./analysis_results",
  "ssh_user": "root",
  "ssh_key_path": "~/.ssh/id_rsa",
  "oms": [
    {
      "name": "OM1",
      "server": "om1.example.com",
      "log_directory": "/var/log/ozone/om/audit",
      "file_pattern": "om-audit*.log*"
    },
    {
      "name": "OM2",
      "server": "om2.example.com",
      "log_directory": "/var/log/ozone/om/audit",
      "file_pattern": "om-audit*.log*"
    },
    {
      "name": "OM3",
      "server": "om3.example.com",
      "log_directory": "/var/log/ozone/om/audit",
      "file_pattern": "om-audit*.log*"
    }
  ]
}
SAMPLE
    exit 1
fi

# Check Python version
python3 --version > /dev/null 2>&1
if [ $? -ne 0 ]; then
    echo "Error: Python 3 is required but not found!"
    exit 1
fi

# Check paramiko is installed
python3 -c "import paramiko" 2>/dev/null
if [ $? -ne 0 ]; then
    echo "Error: paramiko library is required for SSH connections"
    echo "Please install it with: pip install paramiko"
    exit 1
fi

# Test SSH connectivity to servers
echo ""
echo "Testing SSH connectivity to OM servers..."
SERVERS=$(python3 -c "import json; data=json.load(open('$CONFIG_FILE')); print(' '.join([om['server'] for om in data['oms']]))")
SSH_USER=$(python3 -c "import json; print(json.load(open('$CONFIG_FILE')).get('ssh_user', 'root'))")

for server in $SERVERS; do
    echo -n "  Testing $server... "
    ssh -o ConnectTimeout=5 -o BatchMode=yes $SSH_USER@$server exit 2>/dev/null
    if [ $? -eq 0 ]; then
        echo "✓ OK"
    else
        echo "✗ FAILED"
        echo ""
        echo "Error: Cannot connect to $server"
        echo "Please ensure:"
        echo "  1. SSH key is configured correctly"
        echo "  2. Server hostname is correct"
        echo "  3. You have SSH access to the server"
        exit 1
    fi
done

echo ""
echo "Starting analysis with configuration:"
python3 -c "import json; print(json.dumps(json.load(open('$CONFIG_FILE')), indent=2))" | head -25
echo ""
echo "========================================="
echo "IMPORTANT: Analysis Progress"
echo "========================================="
echo "The analysis will:"
echo "  1. Process all 3 OMs in PARALLEL"
echo "  2. Write detailed logs to: ozone_analyzer.log"
echo "  3. Show summary progress on console"
echo ""
echo "To follow detailed progress in another terminal:"
echo "  tail -f ozone_analyzer.log"
echo ""
echo "Processing audit logs from remote OM servers..."
echo "========================================="
echo ""

export PYTHONUNBUFFERED=1
python3 -u unified_ozone_analyzer_remote.py --config "$CONFIG_FILE"

# Check if analysis completed successfully
if [ $? -eq 0 ]; then
    echo ""
    echo "========================================"
    echo "Analysis completed successfully!"
    echo "========================================"
    
    # Show where results are stored
    RESULTS_DIR=$(python3 -c "import json; print(json.load(open('$CONFIG_FILE'))['results_directory'])")
    echo ""
    echo "Results saved in: $RESULTS_DIR/"
    echo ""
else
    echo ""
    echo "Error: Analysis failed! Check the logs above and ozone_analyzer.log for details."
    exit 1
fi

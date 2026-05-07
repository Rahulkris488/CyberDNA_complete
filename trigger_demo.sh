#!/bin/bash
echo "🎭 Demo Attack Trigger"
echo "===================="
echo ""
echo "When you're ready to trigger the attack during your presentation:"
echo "Press ENTER to inject the attack..."
read

# Create the trigger file
touch /tmp/trigger_attack

echo "✅ Attack triggered! Check CyberDNA terminal - it will appear in next scan (10 seconds)"
echo ""
echo "To trigger again, delete the file and re-run this script:"
echo "  rm /tmp/trigger_attack"

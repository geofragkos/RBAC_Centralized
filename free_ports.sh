lsof -P | grep ':5001' | awk '{print $2}' | xargs kill -9
lsof -P | grep ':3000' | awk '{print $2}' | xargs kill -9
sudo -S <<< "gf240894" pkill slapd
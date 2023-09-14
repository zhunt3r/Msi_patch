# GeoFence are just firewall UDP IP blocking of servers / regions you do not want to be connected to. That can solve problems in games that do connect you outside your own region in which some cases are bad, since you are put into high ping servers.

# It can work in any game as long as you know the correct .exe location and the ips / ip ranges you want to block. In a multiplayer game, you can usually find the IPs in the support / wiki section, but it can be outdated/incomplete information, therefore some you might have to get yourself directly or look elsewhere.

# GeoFilter vs GeoFence - GeoFilter serves the purpose to block anything outside the radius of your own ip location, where GeoFence, you build different fences (radius like) in different locations and block everything that is not inside them. Pretty much concepts of ip blocking.

# There are websites that can make it easy in certain games, e.g., Call of Duty
# https://cyanlabs.net/free-multi-sbmm-disabler/

# Others you have to get the ips yourself.
# https://us.battle.net/support/en/article/7871

# In case you are using Windows Firewall, use this powershell script.
# If not and you are using other Firewall solutions, you have to do it yourself, but same concept, UDP IP blocking Inbound and Outbound to Remote Addresses.

# You can add single ips or ip range. You can separate each ip or range with comma. To specify a range, you use -, as in 0.0.0.0-255.255.255.255. To update ips if that is ever needed, just change the ips and re-execute the whole script.
# Make sure that is the game .exe, not the launcher .exe, sometimes they are in different folders.
# Remove the example IPs from @() and put the IP addresses you want to, separating them with comma and inside double quotes.

# You only need to alter $GameExeLocation and $IPs
$GameExeLocation = "C:\...\YOUR_GAME.exe";
$IPs = @("123.1.32.2", "1.2.0.0-1.2.255.255");

$GameExeSplit = $GameExeLocation.Split("\");
$RuleName = "$($GameExeSplit[$GameExeSplit.Length - 1])-GeoFence";
Remove-NetFirewallRule -DisplayName "$RuleName-Out" -ErrorAction SilentlyContinue;
Remove-NetFirewallRule -DisplayName "$RuleName-In" -ErrorAction SilentlyContinue;
New-NetFirewallRule -DisplayName "$RuleName-Out" -Direction Outbound -Protocol Udp -Action Block -Program $GameExeLocation -RemoteAddress $IPs;
New-NetFirewallRule -DisplayName "$RuleName-In" -Direction Inbound -Protocol Udp -Action Block -Program $GameExeLocation -RemoteAddress $IPs;

# In cases like Overwatch, if the IPs from the support/wiki are not enough, and you are still being put in high ping servers, you can press Ctrl+Shift+N and you will see the stats, the IP should be above, you can then use the first 2 decimals and build a range yourself. Use .0.0 in the from and .255.255 in the to. e.g., 35.228.0.0-35.228.255.255

# You can also whitelist if you want, you Allow instead of Block and only put the IPs/IP-Ranges you want to connect to. Do whatever that which you are able to make it work.

# Some games might redirect you to a server that works if the connection fails, others, it might just fail, if they try to put you in a server that is being blocked. You could lose the queue because of it. Be aware before doing this.

# There are paid solutions, I would say that they are NOT worth. Since they are probably just doing this, but in a nicer UI.
# Also, do not be fooled by VPN, this is not VPN and VPN will not GeoBlock anything unless they are specifically doing it per game inside their own firewall. Make no sense, since you can easily do it yourself.
# VPN will only put you as if you were in another location, but that is even worse, latency wise, because if you are being put in different regions servers, that will happen the same to the VPN IP, it will be put to a different server from the VPN location instead.
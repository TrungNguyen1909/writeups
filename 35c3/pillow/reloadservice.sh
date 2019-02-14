#!/usr/local/bin/bash

sudo launchctl bootout system /System/Library/LaunchDaemons/net.saelo.capsd.plist
sudo launchctl bootout system /System/Library/LaunchDaemons/net.saelo.shelld.plist

sudo launchctl bootstrap system /System/Library/LaunchDaemons/net.saelo.capsd.plist
sudo launchctl bootstrap system /System/Library/LaunchDaemons/net.saelo.shelld.plist

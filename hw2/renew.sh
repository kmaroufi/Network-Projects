#!/usr/bin/sh
rm pipes/*.pipe
mkfifo pipes/forwardnet_data.pipe pipes/backwardnet_data.pipe

while :
do
	/usr/bin/env python2 subca-issue-certificate.py
	sleep 10
	echo "######################### Restarting ..."
done

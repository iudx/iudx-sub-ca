
OS=`/usr/bin/uname`

if [ "$OS" == "OpenBSD" ]
then
	PYTHON="/usr/local/bin/python2"
else
	PYTHON="python2"
fi

while :
do
	cd /home/iudx-sub-ca/server
	$PYTHON main.py
	sleep 10
	echo "######################### Restarting ..."
done

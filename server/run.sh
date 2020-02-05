
OS=`/usr/bin/uname`

if [ "OS" == "OpenBSD" ]
then
	PYTHON="/usr/local/bin/python2"
else
	PYTHON="python2"
fi

while :
do
	$PYTHON subca-issue-certificate.py
	sleep 10
	echo "######################### Restarting ..."
done

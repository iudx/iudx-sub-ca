FROM 		alpine:latest

LABEL 		maintainers="barun@iisc.ac.in, jishnuj@iisc.ac.in"
LABEL 		name="iudx-sub-ca"
LABEL 		version="1"

RUN		apk add build-base libffi-dev libressl-dev python2-dev sqlite sqlite-dev py-pip	tmux	&&\
		pip install setuptools cython cryptography db-sqlite3					&&\
		apk del build-base

CMD 		cd /iudx-sub-ca/server && \
		sqlite3 employee.db < sqlite.sql && \
		tail -f /dev/null

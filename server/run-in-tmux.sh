dir=`dirname $0`
tmux new-session -d -s subca "cd $dir && ./run.sh"

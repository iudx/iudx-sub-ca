dir=`dirname $0`
tmux new-session -d -s sub-CA "cd $dir && ./run.sh"

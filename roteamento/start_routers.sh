#!/bin/bash

SESSION="routers"
tmux new-session -d -s $SESSION

for i in {1..12}
do
    port=$((5000 + i))
    network="10.0.$((i)).0/24"
    config="'Grupo4 copy'/R${i}.csv"
    window="R${i}"
    tmux new-window -t $SESSION -n $window
    tmux send-keys -t $SESSION:$window "python3 roteador.py -p $port -f $config --network $network --interval 120" C-m
done

echo "All routers started in tmux session '$SESSION'."
echo "Attach with: tmux attach-session -t $SESSION"
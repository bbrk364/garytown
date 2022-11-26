alias grep='grep --color=auto'
alias l='ls -CF'
alias la='ls -A'
alias ll='ls -alF'
alias ls='ls --color=auto'
alias lt='ls --human-readable --size -1 -S --classify'
alias update='sudo -- sh -c "apt update && apt upgrade"'
alias vnstat='vnstat -i eth0'
alias mnt="mount | awk -F' ' '{ printf \"%s\t%s\n\",\$1,\$3; }' | column -t | egrep ^/dev/ | sort"
alias mnt='mount | grep -E ^/dev | column -t'
alias ls='ls --color=auto'
alias ll='ls -alF'
alias la='ls -A'
alias l='ls -CF'
alias dir='dir --color=auto'
alias vdir='vdir --color=auto'
alias grep='grep --color=auto'
alias fgrep='fgrep --color=auto'
alias egrep='egrep --color=auto'
# for setting history length see HISTSIZE and HISTFILESIZE in bash(1)

HISTSIZE=1000
HISTFILESIZE=2000

# Add an "alert" alias for long running commands. Use like so:

# sleep 10; alert

alias alert='notify-send --urgency=low -i "$([ $? = 0 ] && echo terminal || echo error)" "$(history|tail -n1|sed -e '\''s/^\s*[0-9]\+\s*//;s/[;&|]\s*alert$//'\'')"'
alias dc="docker-compose"
alias dcf="docker-compose -f docker-compose.yml"
alias mk="minikube"
alias k="kubectl"
alias tf="terraform"
alias expargs='export $(cat .env | xargs)'
alias dm='docker-machine'
alias dmx='docker-machine ssh'
alias dk='docker'
alias dki='docker images'
alias dks='docker service'
alias dkrm='docker rm'
alias dkl='docker logs'
alias dklf='docker logs -f'
alias dkflush='docker rm `docker ps --no-trunc -aq`'
alias dkflush2='docker rmi $(docker images --filter "dangling=true" -q --no-trunc)'
alias dkt='docker stats --format "table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.NetIO}}"'
alias dkps="docker ps --format '{{.ID}} ~ {{.Names}} ~ {{.Status}} ~ {{.Image}}'"

cd() {
builtin cd "$@" && ls -F
}

alias sc='systemctl'
alias scdr='systemctl daemon-reload'
alias scr='systemctl restart'
alias sce='systemctl stop'
alias scs='systemctl start'
alias scst='systemctl status'
alias ans=ansible
alias ap=ansible-playbook
alias sshr='ssh-keygen -R '
`ssh_delete_key() {  
sed -i -e ${1}d ~/.ssh/known_hosts  
}  
alias sshdel=ssh_delete_key
alias sshdel=sed -i -e ${1}d ~/.ssh/known_hosts 
alias sshe='ssh  '
```'
```


```
if _command_exists apt then
	alias apts='apt-cache search'
	alias aptshow='apt-cache show'
	alias aptinst='sudo apt-get install -V'
	alias aptupd='sudo apt-get update'
	alias aptupg='sudo apt-get dist-upgrade -V && sudo apt-get autoremove'
	alias aptupgd='sudo apt-get update && sudo apt-get dist-upgrade -V && sudo apt-get autoremove'
	alias aptrm='sudo apt-get remove'
	alias aptpurge='sudo apt-get remove --purge'
	alias chkup='/usr/lib/update-notifier/apt-check -p --human-readable'
	alias chkboot='cat /var/run/reboot-required'
	alias pkgfiles='dpkg --listfiles'
fi
alias ga="git add"
alias gaa="git add ."
alias gc="git commit -m"
alias gs="git status"
alias gcm="git checkout master"
alias glog5="git log --oneline -5"
alias gamendn="git commit --amend --no-edit"
alias gamend="git commit --amend"
alias glog5pretty="git log --pretty=format:\"%h%x09%an%x09%ad%x09%s\" -5"
alias gl="git log --graph --pretty=format:'%Cred%h%Creset -%C(yellow)%d%Creset %s %Cgreen(%cr) %C(bold blue)<%an>%Creset' --abbrev-commit"
alias wip="git add . && git commit -m 'wip'"
alias nah="git reset --hard && git clean -df"
#changing git ssh key
alias ghswitchalex="ssh-add -D && ssh-add ~/.ssh/id_rsa_git && ssh -T git@github.com"
alias ghwhoami="ssh -T git@github.com"

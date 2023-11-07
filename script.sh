echo hello world $( date )
echo -e "\e[91mLight red color"
cat<<'EOF'
           _..._
         .'     '.
        /  _   _  \
        | (o)_(o) |
         \(     ) /
         //'._.'\ \
        //   .   \ \
       ||   .     \ \
       |\   :     / |
       \ `) '   (`  /_
     _)``".____,.'"` (_
     )     )'--'(     (
      '---`      `---`
EOF
echo -e "\e[mReset Colors"
ls --color=auto -latr /var/
#sudo yum clean all
#sudo yum check-update
echo yay

echo args: "$@"
md5sum $1

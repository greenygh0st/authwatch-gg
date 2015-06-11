#Simple bash script to refresh the install

DIR=$( cd "$( dirname "$0" )" && pwd )
echo $DIR/../
cd $DIR/../
python build.py uninstall
sleep 2
cd $DIR/../
python build.py install
#clear

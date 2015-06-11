#Simple bash script to refresh the install

DIR=$( cd "$( dirname "$0" )" && pwd )
cd $DIR/
python setup.py uninstall
sleep 2
cd $DIR/
python setup.py install
#clear

#! /bin/bash
echo "Installing unzip"
sudo apt install unzip -y
echo "Fetching latest Hemis test version"
wget --quiet https://github.com/Hemis-Blockchain/Hemis/releases/latest/download/Hemis-Linux.zip && sudo unzip Hemis-Linux.zip -d /usr/local/bin
wget --quiet https://github.com/Hemis-Blockchain/Hemis/releases/download/1.1.6/Hemis-params.zip && unzip Hemis-params.zip -d ~/.Hemis-params
echo "Hemis succesfully installed. Creating data folder and config file"
mkdir -p ~/.Hemis
printf '%s\n' 'daemon=1' 'testnet=1' 'rpcuser=' 'rpcpassword=' > ~/.Hemis/Hemis.conf
echo "Cleanup excess files"
rm Hemis-Linux.zip && rm Hemis-params.zip
Hemisd || true
sleep 4
Hemis-cli stop
echo "Hemis successfully configured for testnet."
exit

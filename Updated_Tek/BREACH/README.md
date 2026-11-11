Basic Breach Check with CURL

curl -sI -H "Accept-Encoding: gzip, deflate" https://target.com/ | grep -i content-encoding

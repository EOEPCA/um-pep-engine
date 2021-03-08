
USAGE="Usage: rpt.sh [-S (toggle https on)] -t <ticket> -c <id_token>"
TOKEN_ENDPOINT=""
HTTP="http://"
TICKET=""
CLIENT_ID=""
CLIENT_SECRET=""
SCOPES=""
SPACE="%20"
CLAIM_TOKEN=""

while getopts ":t:Sa:i:p:s:c:e:k:" opt; do
  case ${opt} in
    a ) TOKEN_ENDPOINT=$OPTARG
      ;;
    S ) HTTP="https://"
      ;;
    t ) TICKET=$OPTARG
      ;;
    s ) SCOPES=$OPTARG
      ;;
    c ) CLAIM_TOKEN=$OPTARG
      ;;
    e ) CLIENT_ID=$OPTARG
      ;;
    k ) CLIENT_SECRET=$OPTARG
      ;;
    \? )
        echo "Invalid option: -$OPTARG" 1>&2
        echo "$USAGE"
        exit 1
      ;;
  esac
done

curl -k -v -XPOST "$TOKEN_ENDPOINT/oxauth/restv1/token" -H "content-type: application/x-www-form-urlencoded" -H "cache-control: no-cache" -d "claim_token_format=http://openid.net/specs/openid-connect-core-1_0.html#IDToken&claim_token=$CLAIM_TOKEN&ticket=$TICKET&grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Auma-ticket&client_id=$CLIENT_ID&client_secret=$CLIENT_SECRET&scope=openid%20user_name" > rpt.txt

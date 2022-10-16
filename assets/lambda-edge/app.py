import json
import logging
import os
import re
import secrets
import time
import urllib.parse
import urllib.request
import urllib.error
from jose import jwk, jwt
from jose.utils import base64url_decode

CONTENT_DOMAIN = 'dxxxxxxxxxx.cloudfront.net'

COGNITO_REGION = 'us-east-1'
COGNITO_USERPOOL_ID = 'us-east-1_xxxxxxx'
COGNITO_APP_CLIENT_ID = 'xxxxxxxxxxxxxxxxxxxxx'
COGNITO_IDENTITY_PROVIDER='xxxxxxxxxxxxx-idp'
COGNITO_DOMAIN = 'xxxxxxxxxxx'

COGNITO_KEY_URL = f"https://cognito-idp.{COGNITO_REGION}.amazonaws.com/{COGNITO_USERPOOL_ID}/.well-known/jwks.json"
COGNITO_ENDPOINT = f"https://{COGNITO_DOMAIN}.auth.{COGNITO_REGION}.amazoncognito.com"

REDIRECT_URI = '/auth'
NONCE_TIMEOUT=180

formatter = logging.Formatter("%(asctime)s %(name)s:%(lineno)s [%(levelname)s] %(funcName)s : %(message)s", "%Y-%m-%dT%H:%M:%S%z")
logger = logging.getLogger(__name__)
for handler in logger.handlers:
    print(f"handler:{handler}")
    handler.setFormatter(formatter)
logger.setLevel(os.getenv('LOG_LEVEL', 'DEBUG'))

class Nonce:
    def __init__(self, secret, time):
        self.logger = logger.getChild('Nonce')
        self.__secret = secret
        self.__time = time

    @property
    def time(self):
        return self.__time

    @classmethod
    def generate(cls):
        return f"{secrets.token_urlsafe(16)}{time.time()}"

    @classmethod
    def parse(cls, nonce):
        secret = nonce[:22]
        time = nonce[22:]
        return Nonce(secret, time)

    def is_expired(self):
        ''' 180秒以内の Nonce であるかどうか'''
        return float(self.__time) < (time.time() - NONCE_TIMEOUT)

    def equals(self, requested_nonce):
        return f"{self.__secret}{self.__time}" == requested_nonce

class Auth:

    __re_cookie_id_token = re.compile(r"id_token=([^;\.]+\.[^;\.]+\.[^;\.]+);?")
    __re_cookie_nonce = re.compile(r"nonce=([0-9a-z_-]{22})(\d+\.\d+);?", re.IGNORECASE)
    __re_querystring_auth_code = re.compile(r"code=([0-9a-f\-]+)", re.IGNORECASE)

    def __init__(self, request) -> None:
        self.logger = logger.getChild('Auth')
        self.__request = request
        self.__uri = request['uri']
        self.__querystring = request['querystring']
        self.__id_token = self.__parse_cookie_id_token()
        self.__auth_code = self.__parse_querystring_auth_code()

    @property
    def request(self):
        return self.__request

    @property
    def id_token(self):
        return self.__id_token

    @property
    def auth_code(self):
        return self.__auth_code

    @classmethod
    def load_public_key(cls):
        '''パブリックキーのロード'''
        # TODO : 取得失敗時のハンドリング
        with urllib.request.urlopen(COGNITO_KEY_URL) as r:
            response = r.read()
            logger.debug(f"keys: {response}")
            Auth.keys = json.loads(response.decode('utf-8'))['keys']
            logger.debug(f"Cognito Keys: {Auth.keys}")

    def authorize(self):
        '''トークンエンドポイントに認可コードを提示した結果のレスポンスを返します.
            Nonce の不一致、期限切れの場合は None を返します
            トークンエンドポイントに接続できなかった場合は例外を raise します'''
        res = self.__post_to_token_endpoint()
        if not res:
            return None

        new_id_token = res['id_token']
        claims = jwt.get_unverified_claims(new_id_token)

        if not self.__verify_nonce(claims):
            return None

        return res

    def __post_to_token_endpoint(self):
        '''トークンエンドポイントへ認可コードを送信し、送信結果を返す'''
        self.logger.debug(f"START: Auth.__post_to_token_endpoint()")
        try:
            res = None
            body = {
                'grant_type': 'authorization_code',
                'client_id': COGNITO_APP_CLIENT_ID,
                'redirect_uri': f"https://{CONTENT_DOMAIN}{REDIRECT_URI}",
                'code': self.auth_code
            }
            req = urllib.request.Request(
                f"{COGNITO_ENDPOINT}/oauth2/token",
                method='POST',
                data=urllib.parse.urlencode(body).encode('utf-8'),
                headers={'Content-Type': 'application/x-www-form-urlencoded'}
            )
            with urllib.request.urlopen(req) as r:
                response = r.read()
                self.logger.debug(response)
                res = json.loads(response.decode('utf-8'))
                self.logger.debug(f"Response: {res}")

            return res
        except urllib.error.HTTPError as e:
            self.logger.error(f"HTTP Error: {e} / Code: {e.code} / Reason: {e.reason} / Headers: {e.headers}")
            if e.code != 400:
                raise e
            return None
        except Exception as e:
            self.logger.error(f"Exception: {e}")
            raise e

    def __verify_nonce(self, claims):
        '''Nonce の検証'''
        token_nonce = Nonce.parse(claims['nonce'])
        cookie_nonce = self.__parse_cookie_nonce()

        if token_nonce.is_expired():
            # 期限切れ
            self.logger.debug(f"Nonce is expired. created={token_nonce.time}")
            return False
        elif token_nonce.equals(cookie_nonce):
            # 不一致
            self.logger.warn(f"Nonce mismatch between token and cookie.")
            return False

        return True

    def __parse_cookie(self, regexp):
        '''cookie から指定した正規表現にマッチしたオブジェクトを返す'''
        if not 'cookie' in self.request['headers']:
            return None

        cookies = self.request['headers']['cookie']
        for cookie in cookies:
            m = regexp.search(cookie['value'])
            if m:
                return m
        return None

    def __parse_cookie_id_token(self):
        if not (m := self.__parse_cookie(self.__re_cookie_id_token)):
            return None
        return m.group(1)

    def __parse_cookie_nonce(self):
        if not (m := self.__parse_cookie(self.__re_cookie_nonce)):
            return None
        return Nonce(secret=m.group(1), time=m.group(2))

    def __parse_querystring_auth_code(self):
        m = self.__re_querystring_auth_code.search(self.__querystring)
        if m:
            return m.group(1)
        return None

    def has_id_token(self):
        return self.id_token is not None

    def has_auth_code(self):
        return self.auth_code is not None

    def is_authorize_phaze(self):
        '''認可フェーズかどうか
            True : Cognito Hosted UI で認証済み。トークンエンドポイントから認可を受ける段階
        '''
        return self.__uri == REDIRECT_URI and self.has_auth_code

    def is_verified_token(self):
        '''ID トークンが有効かどうか
            False : 無効な ID トークン
        '''
        if not self.id_token:
            self.logger.debug('ID Token is not found')
            return False

        # get the kid from the headers prior to verification
        headers = jwt.get_unverified_headers(self.id_token)
        kid = headers["kid"]
        self.logger.debug(f"kid: {kid}")

        # search for the kid in the downloaded public keys
        key = [k for k in Auth.keys if k['kid'] == kid]
        self.logger.debug(f"key: {key}")
        if len(key) == 0:
            self.logger.warning("Public key not found in jwks.json")
            return False

        # construct the public key
        public_key = jwk.construct(key[0])
        self.logger.debug(f"Public Key: {public_key}")

        # get the last two sections of the token,
        # payload and signature (encoded in base64)
        payload, encoded_signature = str(self.id_token).rsplit(".", 1)

        # decode the signature
        decoded_signature = base64url_decode(encoded_signature.encode("utf-8"))

        # verify the signature
        if not public_key.verify(payload.encode("utf8"), decoded_signature):
            self.logger.warning("Signature verification failed")
            return False

        self.logger.debug("Signature successfully verified")

        # since we passed the verification, we can now safely
        # use the unverified claims
        claims = jwt.get_unverified_claims(self.id_token)
        self.logger.debug(f"claims: {claims}")

        # additionally we can verify the token expiration
        if time.time() > claims["exp"]:
            self.logger.debug("Token is expired")
            return False

        # and the Audience  (use claims['client_id'] if verifying an access token)
        if claims["aud"] != COGNITO_APP_CLIENT_ID:
            self.logger.warning("Token was not issued for this audience")
            return False

        # now we can use the claims
        return claims

class ResponseBuilder:
    @classmethod
    def generate_response_require_authenticate(cls):
        nonce = Nonce.generate()
        return {
            'status': '302',
            'statusDescription': 'Found',
            'headers': {
                'location': [
                    {
                        'key': 'Location',
                        'value': f"{COGNITO_ENDPOINT}/oauth2/authorize?client_id={COGNITO_APP_CLIENT_ID}&response_type=code&scope=email+openid&identity_provider={COGNITO_IDENTITY_PROVIDER}&redirect_uri=https://{CONTENT_DOMAIN}{REDIRECT_URI}&nonce={nonce}",
                    }
                ],
                "set-cookie": [
                    {
                        'value': f"nonce={nonce}; Max-Age={NONCE_TIMEOUT}; domain={CONTENT_DOMAIN}; path=/; httpOnly; secure"
                    }
                ]
            },
        }

    @classmethod
    def generate_response_authorized(cls, id_token, expires_in):
        return {
            'status': '307',
            'statusDescription': 'Temporary Redirect',
            'headers': {
                'location': [
                    {
                        'key': 'Location',
                        'value': f"https://{CONTENT_DOMAIN}",
                    }
                ],
                'set-cookie': [
                    {
                        'value': f"id_token={id_token}; max-age={expires_in}; path=/; domain={CONTENT_DOMAIN}; httpOnly; secure"
                    },
                    {
                        'value': f"nonce=; max-age=-1: path=/; domain={CONTENT_DOMAIN}; httpOnly; secure"
                    }
                ]
            }
        }

    @classmethod
    def generate_statice_response(cls):
        CONTENT = """
            <!DOCTYPE html>
            <html lang="en">
                <head>
                    <meta charset="utf-8">
                    <title>Error</title>
                </head>
                <body>
                    <p>Error</p>
                </body>
            </html>
            """
        return {
            'status': '503',
            'statusDescription': 'Error',
            'headers': {
                'cache-control': [
                    {
                        'key': 'Cache-Control',
                        'value': 'max-age=100'
                    }
                ],
                'content-type': [
                    {
                        'key': 'Content-Type',
                        'value': 'text/html'
                    }
                ]
            },
            'body': CONTENT
        }

    @classmethod
    def generate_tentative_statice_response(cls, requested_path):
        CONTENT = """
            <!DOCTYPE html>
            <html lang="ja">
                <head>
                    <meta charset="utf-8">
                    <title>Authorized</title>
                </head>
                <body>
                    <h1>Authorized Content</h1>
                    <p>Lambda@Edge から便宜上、直接コンテンツ（response object）を返しています（オリジンにアクセスしません）。通常は Lambda@Edge から request object を返却します。</p>
                    <p>For simplicity, Content (response object) is returned directly from the Lambda@Edge, so not access to origin. Normally, a request object is returned from the Lambda@Edge.</p>
                    <p>Your request path: {0}</p>
                </body>
            </html>
            """
        return {
            'status': '200',
            'statusDescription': 'OK',
            'headers': {
                'cache-control': [
                    {
                        'key': 'Cache-Control',
                        'value': 'max-age=5'
                    }
                ],
                'content-type': [
                    {
                        'key': 'Content-Type',
                        'value': 'text/html'
                    }
                ]
            },
            'body': CONTENT.format(requested_path)
        }

def rewrite_path_directory_index(request):
    '''uri の末尾が '/' の場合 '/index.html' に変更したリクエストを返す'''
    # Extract the URI from the request
    olduri = request['uri']

    # Match any '/' that occurs at the end of a URI. Replace it with a default index
    request['uri'] = re.sub(r"/$", '/index.html', olduri)

    return request

Auth.load_public_key()

def lambda_handler(event, context):

    logger.debug(f"event:{event}")

    request = event['Records'][0]['cf']['request']

    try:
        auth = Auth(request)

        if auth.is_authorize_phaze():
            res_authorize = auth.authorize()
            if not res_authorize:
                # Nonce の不一致、期限切れ -> Cognito Hosted UI へリダイレクト
                return ResponseBuilder.generate_response_require_authenticate()

            # Token が取得できた -> ID トークンを Cookie にセット & CF へリダイレクト
            id_token = res_authorize['id_token']
            expires_in = res_authorize['expires_in']
            return ResponseBuilder.generate_response_authorized(id_token, expires_in)

        elif not auth.is_verified_token():
            # Token が無効 -> Cognito Hosted UI へリダイレクト
            return ResponseBuilder.generate_response_require_authenticate()

    except Exception as e:
        # 続行不能なエラー -> 固定レスポンス
        logger.error(f"Exception: {e}")
        return ResponseBuilder.generate_statice_response()

    # For simplicity, return directly response.
    # return rewrite_path_directory_index(request)
    return ResponseBuilder.generate_tentative_statice_response(request['uri'])

<?php

	/**
	 * File for User Class.
	 */

	/**
	 * API User Related Functions.
	 *
	 * This class includes all user related functions.
	 *
	 * @author 	Silvio McGurk (smcgurk@stmartins.edu)
	 * @author 	Reuben Debattista (rdebattista@stmartins.edu)
	 * @date	January 2019
	 *
	 * @link	https://api.stmartins.edu/rest/user User CLASS URI
	 * @package REST\User
	 * @version Stable-8.0
	 *
	 */

	class User extends REST {

		# -------------------------------------------------- REST Functions -------------------------------------------------- #

		/**
		 * API Access.
		 *
		 * Checks if method exists and proceeds to call that particular method.
		 * @param string $func Function name.
		 * @param array $params Array of parameters.
		 *
		 */

	    public function processAPI($func, $params){

	        # If the request includes a valid endpoint
	        if(isset($func)) {

	            if((int)method_exists($this, $func) > 0) {

	                $this->$func($params);

	            } else {

	                $req = $this->sanitize(implode(' ',$this->_request), 'string');
	                $code = $this->getCodeDescription(150);

	                # Send E-Mail
	                $this->rogueAPICall($func, $this->get_request_method(), $req, $_SERVER['REMOTE_ADDR'], 'Invalid Endpoint Called');

	                # Show Error Page
	                $error = json_encode(array('code' => $code[0], 'status' => $code[1], 'message' => $code[2]));
	                $comments = json_encode(array('endpoint' => $req));
	                $this->response(null,__FUNCTION__,"invalid system endpoint reached",$error,404,$comments);

	            }

	        }

	    }

		# -------------------------------------------------- Private Functions -------------------------------------------------- #

		/**
		 * OAuth2 Server Function.
		 *
		 * Server object user by OAuth2 Calls.
		 *
		 * @return 	Object	Server object for OAuth2.
		 *
		 */

		private function authServer(){

			require_once(OAUTH_AUTOLOAD);

			# Register Loader
			OAuth2\Autoloader::register();

			# $dsn is the Data Source Name for your database, for exmaple "mysql:dbname=my_oauth2_db;host=localhost"
			$storage = new OAuth2\Storage\Pdo(array('dsn' => DB_DSN, 'username' => DB_USERNAME, 'password' => DB_PASSWORD));

			# Pass a storage object or array of storage objects to the OAuth2 server class
			$server = new OAuth2\Server($storage);

			# Configure Scopes
			$server->setScopeUtil(new OAuth2\Scope($storage));

			# Add the "Authorization Code" grant type (this is where the oauth magic happens)
			$server->addGrantType(new OAuth2\GrantType\AuthorizationCode($storage));

			# Refresh token grant type
			$server->addGrantType(new OAuth2\GrantType\RefreshToken($storage, array('always_issue_new_refresh_token' => true)));

			return $server;

		}

		/**
		 * Returns User ID.
		 *
		 * Returns User ID for Email.
		 *
		 * @param	email	$user	User Email.
		 *
		 * @return	Integer	User ID.
		 *
		 */

		private function getUser($user){

			# Establish database connection
			$connect = (new dbConn)->connect('api');

			$getCode = $connect->prepare("SELECT userID FROM tblUser WHERE email = ?");
			$getCode->bind_param('s', $user);
			$getCode->execute();
			$getCode->bind_result($result);
			$getCode->fetch();
			$getCode->close();

			$connect->close();

			return $result;

		}

		/**
		 * Check Login Function.
		 *
		 * Checks sign in on selected authentication method and returns result.
		 *
		 * @param array $credentials Array containing client_id and client_secret
		 *
		 * @return	Boolean True or False.
		 *
		 */

		private function checkLogin($credentials){

			$client_id = $credentials['client_id'];
			$id_token = $credentials['id_token'];
			$access_token = $credentials['access_token'];
			$source = $credentials['source'];
			$domain = 'stmartins.edu';
			
			require_once DIR_LIB . 'google-api-php-client/Google_Client.php';
			require_once DIR_LIB . 'google-api-php-client/contrib/Google_Oauth2Service.php';
			
			$client = new Google_Client();
			$client->setApplicationName('Login to SMI');
			
			if ($source == "mobileapp") {
				$client->setClientId(GOOGLE_MOBILEAPP_API_ID);
				$client->setClientSecret(GOOGLE_MOBILEAPP_API_ID);
			}
			else {
				$client->setClientId(GOOGLE_API_ID);
				$client->setClientSecret(GOOGLE_CLIENT_SECRET);
			}
			$client->setAccessToken(htmlspecialchars_decode($access_token));
			
			// Verifies JWT Signature, AUD Claim, ISS Claim and EXP Claim
			$payload = $client->verifyIdToken($id_token); 
			
			//$test = "Payload: " . json_encode($payload->getAttributes());
			//$this->writeLog($userID = null, $function = 'checkLogin2', $message = null, $data = $test, $comment = null);
			
			
			
			$googleAcc = new Google_Oauth2Service($client);
			
			if ($source == "mobileapp") {
				$clientDetails = [];
				$clientDetails['given_name'] = $payload->getAttributes()['payload']['given_name'];
				$clientDetails['family_name'] = $payload->getAttributes()['payload']['family_name'];
				
				// log details (temporary)
				//$test = "Name: " . $clientDetails['given_name'] . ", Surname is: " . $clientDetails['family_name'];
				//$this->writeLog($userID = null, $function = 'checkLogin3', $message = null, $data = $test, $comment = null);
			
				
			}
			else {
				$clientDetails = $googleAcc->userinfo->get();
			}

			
		    if(($payload->getAttributes()['payload']) && ( $payload->getAttributes()['payload']['email'] == $client_id ) && ($payload->getAttributes()['payload']['hd'] == $domain)){
				
				$return = array( 'id' => $payload->getAttributes()['payload']['sub'], 'email' => $payload->getAttributes()['payload']['email'], 'given_name' => $clientDetails['given_name'], 'family_name' => $clientDetails['family_name'] );
				
				return $return;
				
		    } else {

		        return false;
			}			
		}

		/**
		 * Populate database with account details.
		 *
		 * Populates both tblUser and oauth_clients with relative user information as gathered from authentication methods.
		 *
		 * @param array $params Array of user details containing (Name, Surname, Email, Password, IP, Provider and Active status).
		 *
		 */

		private function newAccount($params){

			# Set Parameter Variables
			$firstName = $params['firstName'];
			$surName = $params['surName'];
			$email = $params['email'];
			$pass = $params['pass'];
			$ip = $params['ip'];
			$provider = $params['provider'];
			$active = $params['active'];
			$smNumber = $params['smNumber'];
			$scope = $params['scope'];
			
			# Other Required Variables
			$date = date("Y-m-d H:i:s");
			$activation = md5(uniqid(mt_rand(), true)) . microtime();
			$deleted = 0;
			$redirect_uri = SITE_URL;

			# Establish database connection
			$connect = (new dbConn)->connect('api');

			# Create New Local User Account
			$stmt = $connect->prepare("INSERT INTO tblUser (firstName,surName,email,pass,dateCreated,ipAddr,provider,activation,active,deleted,lastChange,smNumber)
										VALUES (?,?,?,?,?,?,?,?,?,?,?,?);");

			$stmt->bind_param('ssssssssiisi',
								$firstName,
								$surName,
								$email,
								$pass,
								$date,
								$ip,
								$provider,
								$activation,
								$active,
								$deleted,
								$date,
			                    $smNumber);

			$stmt->execute();
			$userID = $stmt->insert_id;
			$stmt->close();

			# Create New OAuth Account based on the previous user id
			$stmt = $connect->prepare("INSERT INTO oauth_clients (client_id,client_secret,redirect_uri,scope,user_id)
										VALUES (?,?,?,?,?);");

			$stmt->bind_param('ssssi',
								$email,
								$pass,
								$redirect_uri,
								$scope,
								$userID);

			$stmt->execute();
			$stmt->close();

			$connect->close();

			return $userID;

		}

		/**
		 * Checks user credentials.
		 *
		 * Used to check hash values of user credentials especially during token exchange.
		 *
		 * @param string $client_id Username (email)
		 * @param string $client_secret Password (clear text)
		 *
		 * @return	String Hash value for password.
		 *
		 */

		private function checkPassword($client_id, $client_secret){

			# Establish database connection
			$connect = (new dbConn)->connect('api');

			# Fetch Password Hash
			$stmt = $connect->prepare("SELECT client_secret
										FROM oauth_clients AS oc
										JOIN tblUser AS u
										ON oc.user_id = u.userID
										WHERE oc.client_id = ?
										AND u.active = 1
										AND u.deleted = 0;");

			$stmt->bind_param('s', $client_id);
			$stmt->execute();
			$stmt->bind_result($hash);
			$stmt->fetch();
			$stmt->close();

			$connect->close();

			return password_verify($client_secret, $hash);

		}

		
		/**
		 * Authorize Controller.
		 *
		 * Authorizes user according to authentication details and issues a code. Method: POST
		 *
		 * @api
		 *
		 * @link https://bshaffer.github.io/oauth2-server-php-docs/
		 * @link https://api.stmartins.edu/rest/user/getCode Endpoint URI
		 *
		 * @uses Method::POST
		 *
		 * (client_id = Username),
		 * (client_secret = Password),
		 * (response_type = Set to 'code'),
		 * (scope = Required scope),
		 * (state = State Token),
		 * (id_token = Google ID For Verification)
		 *
		 * @param $params Array An array of passed parameters.
		 *
		 * @return	String JSON String with authCode and state values which can be parsed.
		 *
		 */

		public function getCode($params){
			
		    //Very IMP: Endpoint Security
		    $origin = array('ALL');
		    $ip = array('ALL');
		    $this->secureEndpoint(__FUNCTION__,'POST',$origin,$ip,false);

			# Set Variables
			$ip = $this->validate($_SERVER['REMOTE_ADDR'], 'ip');
			$client_id = $this->sanitize($this->_request['client_id'], 'email');
			$id_token = $this->sanitize($this->_request['id_token'], 'string');
			$access_token = $this->sanitize($this->_request['access_token'], 'string');
			$scope = $this->sanitize($this->_request['scope'], 'string');
			$response_type = $this->sanitize($this->_request['response_type'], 'string');
			$state = $this->sanitize($this->_request['state'], 'string');
			$source = $this->sanitize($this->_request['source'], 'string');
			
			//$test = json_encode($_POST);			
			//$this->writeLog($userID = null, $function = 'getCode5', $message = null, $data = $test, $comment = null);
							
			//$test = "ClientID: " . $client_id . " ID_Token: " . $id_token . " ACCESS_Token: " . $access_token . " State: " . $state . " Scope: " . $scope . " Response Type: " . $response_type . " Provider: " . $provider . " Source: " . $source;
			//$this->writeLog($userID = null, $function = 'getCode2', $message = null, $data = $test, $comment = null);
				
			$descrepancy = false;
			if (($client_id == '') || ($id_token == '') || ($response_type == '') || ($scope == '') || ($state == '')) {
				$descrepancy = true;
			}
						
			if (!$descrepancy) {

			    //Check if Google User is Logged in and all details match.
				$credentials = array('source' => $source, 'client_id' => $client_id, 'id_token' => $id_token, 'access_token' => $access_token);
				$checkLogin = $this->checkLogin($credentials);
								
				if($checkLogin){

				    # Check if User Exists
				    $userID = $this->getUser($client_id);

				    //If Not Create User and OAuth Client
				    if(!$userID){
						
			            $smNumber = substr($checkLogin['email'], 2, 5);
			            $defaultScope = 'intranet.user.login.null intranet.user.getBookings.read intranet.user.saveBookings.write';

			            $params = array('firstName' => $checkLogin['given_name'],
            			                'surName' => $checkLogin['family_name'],
            			                'email' => $checkLogin['email'],
            			                'pass' => password_hash(OAUTH_CLIENT_SECRET, PASSWORD_DEFAULT),
            			                'provider' => 'google',
            			                'ip' => $ip,
            			                'active' => 1,
            			                'smNumber' => $smNumber,
            			                'scope' => $defaultScope);
						
			            $userID = $this->newAccount($params);

				    }

				    # Initialize Server
				    $server = $this->authServer();

				    # Set Request and Response
				    $request = OAuth2\Request::createFromGlobals();
				    $response = new OAuth2\Response();
				    $is_authorized = false;

				    if($server->validateAuthorizeRequest($request, $response)){
				        $key = APIKEY_GLOBAL;
				        $iss = $_SERVER['SERVER_NAME'];
				        $sub = $userID;
				        $aud = $client_id;
				        $iat = time();
				        $exp = time() + (60 * 60 * 24 * 14);

				        $params = array('apiKey' => $key, 'iss' => $iss, 'sub' => $sub, 'aud' => $aud, 'iat' => $iat, 'exp' => $exp);

				        $jwt = $this->jwtEncode($params, APIKEY_REQ_KEY);
							
						# Establish database connection
						$connect = (new dbConn)->connect('api');

						# Set JWT
						$stmt = $connect->prepare("DELETE FROM tblJwt WHERE client_id = ?");
						$stmt->bind_param('s', $client_id);
						$stmt->execute();
						$stmt->close();
						
						$stmt = $connect->prepare("INSERT INTO tblJwt(client_id, jwt) VALUES(?,?)");
						$stmt->bind_param('ss', $client_id, $jwt);
						$stmt->execute();
						$stmt->close();
						$connect->close();

					    $is_authorized = true;

					    if($is_authorized === true){
        					$server->handleAuthorizeRequest($request, $response, $is_authorized, $userID);

        					$authcode = substr($response->getHttpHeader('Location'), strpos($response->getHttpHeader('Location'), 'code=')+5, 40);
        					$state = substr($response->getHttpHeader('Location'), strpos($response->getHttpHeader('Location'), 'state=')+6, 40);
							
							echo $this->endpoint_response(array('authcode' => $authcode, 'state' => $state, 'jwt' => $jwt));
							
					    }

				    } else {

				        $this->endpoint_error(255);

				    }

				} else {

					$this->endpoint_error(250);

				}

			} else {

				$this->endpoint_error(351);

			}

		}

		/**
		 * Token Controller.
		 *
		 * Function to exchange codes from  authorize controller for valid tokens. Method: POST
		 *
		 * @api
		 *
		 * @link https://api.stmartins.edu/rest/user/getToken Endpoint URI
		 *
		 * @uses Method::POST
		 * (client_id = Email or Username),
		 * (client_secret = Password),
		 * (code = Authorization Code),
		 * (grant_type = 'authorization_code')
		 *
		 * @param $params Array An array of passed parameters.
		 *
		 * @return String JSON encoded string with the relevant token and refresh token.
		 */

		public function getToken($params){

		    //Very IMP: Endpoint Security
		    $origin = array('ALL');
		    $ip = array('ALL');
		    $this->secureEndpoint(__FUNCTION__,'POST',$origin,$ip,false);

			# Set Variables
			$client_id = $this->sanitize($this->_request['client_id'], 'string');

			if(isset($this->_request['client_secret'])){
			    $client_secret = $this->sanitize($this->_request['client_secret'], 'string');
			} else {
			    $client_secret = OAUTH_CLIENT_SECRET;
			}

			if (($client_id == '') || ($client_secret == '') || (($this->_request['code'] == '') && ($this->_request['refresh_token'] == '')) || ($this->_request['grant_type'] == '')) {
				$descrepancy = true;
			}

			if (!$descrepancy) {

				# Confirm Secret and Get Hash Value
				$hash = $this->checkPassword($client_id, $client_secret);

				# Verify User Password and Hash
				if($hash){

				    # Initialize Server
				    $server = $this->authServer();

				    # Set Request and Response
				    $request = OAuth2\Request::createFromGlobals();
				    $response = new OAuth2\Response();

					# Populate $request with hash
					$request->request['client_secret'] = $hash;

					# Handle a request for an OAuth2.0 Access Token and send the response to the client
					$server->handleTokenRequest($request, $response);
					$result = $response->getParameters();

					echo $this->endpoint_response($result);

				} else {

					# Show Error Page
					$this->endpoint_error(253);

				}

			} else {

				$this->endpoint_error(351);

			}

		}

		/**
		 * Resource Controller.
		 *
		 * Validates tokens for user. Method: POST
		 *
		 * @api
		 *
		 * @link https://api.stmartins.edu/rest/user/validateToken Endpoint URI
		 *
		 * @uses Method::POST
		 * (access_token = Access token to validate),
		 * (scope = Scope required to validate against),
		 *
		 * @param $params Array An array of passed parameters.
		 *
		 * @return String JSON encoded string with success or failure response.
		 *
		 */

		public function validateToken($params){

		    //Very IMP: Endpoint Security
		    $origin = array('ALL');
		    $ip = array('ALL');
		    $this->secureEndpoint(__FUNCTION__,'POST',$origin,$ip,false);

			# Set Variables
			$scope = $this->sanitize($this->_request['scope'], 'string');
			
			if (($scope == '') || ($this->_request['access_token'] == '')) {
				
			    $descrepancy = true;

			}

			if (!$descrepancy) {

				# Initialize Server
				$server = $this->authServer();

				# Set Request and Response
				$request = OAuth2\Request::createFromGlobals();
				$response = new OAuth2\Response();

				# Handle a request to a resource and authenticate the access token
				if ($server->verifyResourceRequest($request, $response, $scope)) {

					echo $this->endpoint_response('verified');

				} else {

                    $this->endpoint_error(254);

				}

			} else {

				$this->endpoint_error(351);

			}

		}
		
		/**
		  * Get Token Info
		  *
		  * Gets information about a given token.
		  *
		  * @api
		  *
		  * @link https://api.stmartins.edu/rest/user/getTokenInfo Endpoint URI
		  *
		  * @param Array $params Array of parameters if needed.
		  *
		  * @uses Method::GET
		  *
		  * @return String JSON String of token details.
		  *
		  */

		public function getTokenInfoOAuthStyle($params){

		    //Very IMP: Endpoint Security
		    $origin = array('ALL');
		    $ip = array('ALL');
		    $this->secureEndpoint(__FUNCTION__,'GET',$origin,$ip,false);

		    if ($this->_request['access_token'] == '') {

		        $descrepancy = true;

		    }

		    if (!$descrepancy) {

		        # Initialize Server
		        $server = $this->authServer();

		        # Set Request and Response
		        $request = OAuth2\Request::createFromGlobals();

		        echo $this->endpoint_response($server->getAccessTokenData($request));

		    } else {

		        $this->endpoint_error(351);

		    }

		}		
		
		public function validateGoogleLogin($params){
			
			$g_data = [];
			
			 //Very IMP: Endpoint Security
		    $origin = array('ALL');
		    $ip = array('ALL');
		    $this->secureEndpoint(__FUNCTION__,'GET',$origin,$ip,false);
			
			$g_client_id = $this->sanitize($this->_request['g_client_id'], 'email');
			$g_access_token = $this->sanitize($this->_request['g_access_token'], 'email');
			$g_id_token = $this->sanitize($this->_request['g_id_token'], 'email');
			
			$ch = curl_init();
			$headers = array(
			'Accept: application/json',
			'Content-Type: application/json',

			);
			curl_setopt($ch, CURLOPT_URL, 'https://www.googleapis.com/oauth2/v1/tokeninfo?access_token='.$g_access_token);
			curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
			curl_setopt($ch, CURLOPT_HEADER, 0);
			$body = '{}';

			curl_setopt($ch, CURLOPT_CUSTOMREQUEST, "GET"); 
			//curl_setopt($ch, CURLOPT_POSTFIELDS,$body);
			curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);

			// Timeout in seconds
			curl_setopt($ch, CURLOPT_TIMEOUT, 30);

			$accessTokenInfo = curl_exec($ch);
			$gdata['accessTokenInfo'] = $accessTokenInfo;
			
			
			curl_setopt($ch, CURLOPT_URL, 'https://oauth2.googleapis.com/tokeninfo?id_token='.$g_id_token);
			curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
			curl_setopt($ch, CURLOPT_HEADER, 0);
			$body = '{}';

			curl_setopt($ch, CURLOPT_CUSTOMREQUEST, "GET"); 
			//curl_setopt($ch, CURLOPT_POSTFIELDS,$body);
			curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);

			// Timeout in seconds
			curl_setopt($ch, CURLOPT_TIMEOUT, 30);

			$idTokenInfo = curl_exec($ch);			
			$gdata['idTokenInfo'] = $idTokenInfo;
						
			$accessTokenEmail = json_decode($gdata['accessTokenInfo'],false)->email;
			$idTokenEmail = json_decode($gdata['idTokenInfo'],false)->email;
			$domain = json_decode($gdata['idTokenInfo'],false)->hd;
	
			if (($accessTokenEmail == $idTokenEmail) && ($idTokenEmail == $g_client_id) && ($domain == 'stmartins.edu')) {
				$valid = true;
			}
			else {
				$valid = false;
			}
			//var_dump($gdata);
			
			
			
			
			if ($valid) {
								
				$params = [];
				$params['response_type'] = 'code';
				$params['client_id'] = $g_client_id;
				$params['state'] = 'PKRs90lO295AN0BrIiFRbkf1vhFrhoaL96TvPfZn';
				$params['scope'] = 'intranet.user.login.null';
				$params['provider'] = 'google';
				$params['id_token'] = $g_id_token;
				$params['access_token'] = $g_access_token;
											
				$response = $this->getCode($params);			
				
				
				echo $response;
				if (json_decode($response,true)['code'] == 255){
					header('Location: error.php');
					die();
				}
				
				if (json_decode($response,true)['code'] == 250){
					echo "Message:" . $response . ", Helptext: This indicates an error during the login process. Please ensure you are logging with the appropriate account. For example, certain services at Saint Martin's Institute require you to use the SMI email account. Click 'back' on your browser and choose a different account!";
					die();
				}
				
				# Close the connection, release resources used.
				curl_close($ch);
				
				# Do anything you want with your response or die if state does not match.
				if (json_decode($response,true)['message']['state'] != 'PKRs90lO295AN0BrIiFRbkf1vhFrhoaL96TvPfZn') {
					die();
				}
				$authCode = json_decode($response,true)['message']['authcode'];
				
				$authHeader = "Bearer " . json_decode($response,true)['message']['jwt'];		
						
				$post = array(
					'client_id'=>$g_client_id, 
					'grant_type'=>'authorization_code', 
					'code'=>$authCode
				);
				
				foreach($post as $k => $v) 
				   { 
					  $postData .= $k . '='.$v.'&'; 
				   }
				   $postData = rtrim($postData, '&');
					
				$ch = curl_init('https://api.stmartins.edu/rest/user/getToken');
				curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
				curl_setopt($ch, CURLOPT_POSTFIELDS, $postData);
				curl_setopt($ch, CURLOPT_HTTPHEADER, array(
					"Authorization: $authHeader"
				));

				# Execute!
				$response = curl_exec($ch);
				
				# Close the connection, release resources used.
				curl_close($ch);

				# Do anything you want with your response.
				$accessToken = json_decode($response,true)['message']['access_token'];
			
				echo "H".$accessToken;
			}
			else {
				
				// Invalid Google Data
				
			}
		
		}
		
		public function getTokenInfo($token) {
		
			//Very IMP: Endpoint Security
		    $origin = array('ALL');
		    $ip = array('ALL');
		    $this->secureEndpoint(__FUNCTION__,'GET',$origin,$ip,false);
			
			# Establish database connection
			$connect = (new dbConn)->connect('api');
			$token = $_GET['access_token'];
			
			# Fetch Password Hash
			$getCode = $connect->prepare("SELECT c.user_id, t.client_id, t.scope, t.expires, r.refresh_token, r.expires , j.jwt
			FROM oauth_access_tokens t JOIN oauth_clients c on c.client_id = t.client_id 
			JOIN oauth_refresh_tokens r ON c.client_id = r.client_id 
			JOIN tblJwt j ON j.client_id = c.client_id
			WHERE t.access_token = ?");
			$getCode->bind_param("s", $token);
			$getCode->execute();
			$getCode->bind_result($userID, $email, $scope, $tokenExpiry, $refreshToken, $refreshExpiry, $jwt);
			$getCode->fetch();
			$getCode->close();
			
			$this->endpoint_response(array('email' => $email, 'jwt' => $jwt, 'tokenExpiry' => $tokenExpiry, 'refreshToken' => $refreshToken, 'access_token' => $token));

		}

	}

?>

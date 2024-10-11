<?php

class SMIApp extends REST {

    # -------------------------------------------------- Rest Functions -------------------------------------------------- #

    /**
     * API Access.
     *
     * Checks if method exists and proceeds to call that particular method.
     *
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

    # -------------------------------------------------- Public Functions -------------------------------------------------- #
	
	public function writeDB($params){
       
        // Very IMP: Endpoint Security
        $origin = array('ALL');
        $ip = array('ALL');
        $this->secureEndpoint(__FUNCTION__,'GET',$origin,$ip,false);


        $_DO_ENCRYPT =false;
		
        // API Call Data
        $message = $this->sanitize($this->_request['theMessage'], 'string');
        
		// Prepare Email Debug to send (if need be)
		$emailErrorLog = "Errors:";


        // Finally, after all sanitisation, we are ready to connect to the database and save data
		$connect = (new dbConn)->connect('mobileapp');
		
		// Write to Table       
        $stmt_msg = $connect->prepare('INSERT INTO Notification(message) VALUES(?);');
        $stmt_msg->bind_param('s',$message);
        $stmt_msg->execute();
		$emailErrorLog .= "DB Statement ERROR STUDENT: ". " " . $stmt_msg->error. "\r\n";
        $emailErrorLog .= "DB Connection ERROR if any: " . $connect->error. "\r\n";
        $last_message_id = $stmt_msg->insert_id;
        $stmt_msg ->close();
	
	}
	
	public function readDB($params){

		// Very IMP: Endpoint Security	
        $origin = array('ALL');
        $ip = array('ALL');
        $this->secureEndpoint(__FUNCTION__,'GET',$origin,$ip,false);


        $_DO_ENCRYPT =false;
		
        // API Call Data
        // $message = $this->sanitize($this->_request['theMessage'], 'string');
        
		// Prepare Email Debug to send (if need be)
		$emailErrorLog = "Errors:";


        // Finally, after all sanitisation, we are ready to connect to the database and save data
		$connect = (new dbConn)->connect('mobileapp');
		
		# Read from table
		$value = 1;
		//$value = $this->sanitize($this->_request['msgid'], 'int');
		$stmtDetails = $connect->prepare('SELECT * FROM Notification n
										  WHERE n.notifyID >= ?');
						$stmtDetails->bind_param('i', $value);
						$stmtDetails->execute();
						$result = $stmtDetails->get_result();
						$stmtDetails->close();						
						
		// Create Result Array
		$emparray = array();
		while($row = $result->fetch_assoc())
		{
			$emparray[] = $row;
		}
						
		// Convert to JSON and send as response
		echo json_encode($emparray);
		
		# Template Function for Email
		//goMail($fromMail, $fromName, $toMail, $toName, $subject, $message, $replyMail=FROM_MAIL, $replyName=FROM_NAME, $attach=null, $embed=null, $cc=null){
				
    }	
	
	public function apiTest($params){
       
        //Very IMP: Endpoint Security
        $origin = array('ALL');
        $ip = array('ALL');
        $this->secureEndpoint(__FUNCTION__,'GET',$origin,$ip,false);		
		
		// $this->goMail(null, null, "smcgurk@stmartins.edu", "Silvio" . ' ' . "Mc Gurk", "Student Application", "SMI Application has been accessed", "smcgurk@stmartins.edu", "Silvio" . ' ' . "Mc Gurk", null, null, null);
		echo "API Works!";	
		
	}

    # -------------------------------------------------- Private Functions -------------------------------------------------- #

    private function saveFormDetails($file, $encrypt=true, $id=null, $fname=null){

		$saveDir = '/var/applicationFormData/uploads/';
		
		$extension = pathinfo($file['name'], PATHINFO_EXTENSION);
		
		
        if ($encrypt == true){
			$hash =  hash_file('md5', $file['tmp_name']);			
			$subDir = substr($hash, 0, 2) . '/';
			$target = $saveDir . $subDir . $hash;		
		}
		else {		
			$subDir = $id . "/";
			//$target = $saveDir . $subDir . $file['name'];
			$target = $saveDir . $subDir . $fname . "." . $extension;
			
		}
		
		if(is_dir($saveDir . $subDir) === false){
			mkdir($saveDir . $subDir, 0700);
		}

		if(file_exists($target) === false){
			move_uploaded_file($file['tmp_name'], $target);
		}		
		
		return $target;
    }
	
	private function isAuthorised($scope, $accessToken, $private, $user = null) {
		
		// Is auth cached in memcached?
		$mem_var = new Memcached();
		$mem_var->addServer("127.0.0.1", 11211);
		$response = $mem_var->get($accessToken . "," . $scope);
		
		// If available
		$authorized = false;
		if ($response) {
			
			if ($response == true) {
				$authorized = true;
			}
			else {
				$authorized = false;
			}
		} 
		
		// Otherwise get auth and add it to memcached for a few seconds
		else {
		
			// Verify Token against scope/s required
			$url = 'https://api.stmartins.edu/rest/user/validateToken';

			$fields = array(
				"scope" => $scope,
				"access_token" => $accessToken
			);

			$token = json_decode($this->curl($url, $fields, 'POST'), true);	
			
			if($token['message'] == 'verified') {
				$authorized = true;
				$mem_var->set($accessToken . "," . $scope, true, 10) or die("Keys Couldn't be Created");
			}
			else {
				$authorized = false;	
				$mem_var->set($accessToken . "," . $scope, false, 10) or die("Keys Couldn't be Created");
			}			
		}
		
		// Is this API URI public or private?
		if (strpos($scope, ".private") !== false) {
			$private = true;
		}		
		
		// Who is accessing this function? Determine user from token 					
		// $url = 'https://api.stmartins.edu/rest/user/getTokenInfoOAuthStyle?access_token=' . $accessToken;

		$fields = array(					
			"access_token" => $accessToken
		);

		// $useremail = json_decode($this->curl($url, $fields, 'GET'), false)->message->client_id;
		
		// Is token is valid, continue
		// Note: If this is a private URI, make sure data pertains to this user only
		if($authorized){
				return true;
		}
		else {
			return false;
		}
	}
	
	public function getStudentDayScheduleDev($params){
       
        //Very IMP: Endpoint Security
        $origin = array('ALL');
        $ip = array('ALL');
        $this->secureEndpoint(__FUNCTION__,'GET',$origin,$ip,false);
		
		$id = $this->sanitize($this->_request['user_id'], 'int');
		$date = $this->sanitize($this->_request['date'], 'string');
		$accessToken = $this->sanitize($this->_request['access_token'], 'string');
					
		// Scope required for this call		
		$scope = 'intranet.user.login.null';		
		
		$auth = $this->isAuthorised($scope, $accessToken, false);
				
		if ($auth) {
			// Finally, after all sanitisation, we are ready to connect to the database and save data
			$connect = (new dbConn)->connect('mobileapp');
			
			# Read from table
			$value = 1;
			//$value = $this->sanitize($this->_request['msgid'], 'int');
			$stmtDetails = $connect->prepare('SELECT tta.userid as StudentId, tt.start, tt.end, c.name, c.description, tte.ttableentryid, tt.ttableid, tte.ttabledate, l.location AS roomNumber, lect.Name as lecturerName, lect.Surname AS lecturerSurname, tta.confirmedAttendance
												FROM users u
												JOIN ttableattendance tta ON u.user_id = tta.userid              
												JOIN ttableentries tte ON tta.ttableentryid = tte.ttableentryid 
												JOIN ttable tt ON tt.ttableid = tte.ttableid                    
												JOIN ScheduledCourses sc ON sc.SchedID = tt.schedid
												JOIN users lect ON lect.user_id = sc.LectID    
												JOIN Courses c ON c.CourseID = sc.CourseID
												JOIN locations l ON l.locationid = tte.locationid
												WHERE tta.userid = ? AND Datediff(?, tte.ttabledate) = 0 -- 3727 and 2020-03-05 are parameters in the api
												Order by HOUR(tt.start)');
							$stmtDetails->bind_param('is', $id, $date);
							$stmtDetails->execute();
							$result = $stmtDetails->get_result();
							$stmtDetails->close();						
							
			// Create Result Array
			$emparray = array();
			while($row = $result->fetch_assoc())
			{
				$emparray[] = $row;
			}
							
			// Convert to JSON and send as response
			echo json_encode($emparray, JSON_NUMERIC_CHECK);
		}
		else {
			$this->endpoint_error(401);
			die();
		}		
	}
	
	public function getStudentDaySchedule($params){
       
        //Very IMP: Endpoint Security
        $origin = array('ALL');
        $ip = array('ALL');
        $this->secureEndpoint(__FUNCTION__,'GET',$origin,$ip,false);
		
		$id = $this->sanitize($this->_request['user_id'], 'int');
		$date = $this->sanitize($this->_request['date'], 'string');
		$accessToken = $this->sanitize($this->_request['access_token'], 'string');
					
		// Scope required for this call		
		$scope = 'intranet.user.login.null';		
		
		$auth = $this->isAuthorised($scope, $accessToken, false);
				
		if ($auth) {
			// Finally, after all sanitisation, we are ready to connect to the database and save data
	
			$params = array(
				'function' => 'getStudentDaySchedule',
				'userid' => $id,
				'date' => $date
			);
		
			$jwtToken = $this->jwtEncode($params, APIKEY_INTRANET_KEY);
			$array = array('jwt' => $jwtToken);
			$url = 'https://intranet.stmartins.edu/rest/smimobileapp.php';

			$emparray = json_decode($this->curl($url, $array, 'POST'));
						
			// Convert to JSON and send as response
			$response = json_encode($emparray, JSON_NUMERIC_CHECK);				
														
			// Convert to JSON and send as response
			echo $response;
		}
		else {
			$this->endpoint_error(401);
			die();
		}		
	}
	
	public function getConfirmedAttendanceDev($params){
       
        // Very IMP: Endpoint Security
        $origin = array('ALL');
        $ip = array('ALL');
        $this->secureEndpoint(__FUNCTION__,'GET',$origin,$ip,false);

        // API Call Data
        $ttableentryid = $this->sanitize($this->_request['ttableentryid'], 'int');
		$accessToken = $this->sanitize($this->_request['access_token'], 'string');
					
		// Scope required for this call		
		$scope = 'intranet.user.login.null';		
		
		$auth = $this->isAuthorised($scope, $accessToken, false);
				
		// Prepare Email Debug to send (if need be)
		$emailErrorLog = "Errors:";

		if ($auth) {
			// Finally, after all sanitisation, we are ready to connect to the database and save data
			$connect = (new dbConn)->connect('mobileapp');
			
			
			// Does an entry already exist?
			$stmt_msg = $connect->prepare('SELECT ttableattendance.userid, ttableattendance.confirmedAttendance 
											FROM ttableattendance 
											Where ttableentryid = ?
										   ');
			$stmt_msg->bind_param('i', $ttableentryid);
			$stmt_msg->execute();
			$result = $stmt_msg->get_result();
			$stmt_msg->close();	
					
			// Create Result Array		
			$emparray = array();
			while($row = $result->fetch_assoc())
			{
				$emparray[] = $row;
			}
							
			// Convert to JSON and send as response
			echo json_encode($emparray, JSON_NUMERIC_CHECK);
		}
		else {
			$this->endpoint_error(401);
			die();
		}			
	}	
	
	public function getConfirmedAttendance($params){
       
        // Very IMP: Endpoint Security
        $origin = array('ALL');
        $ip = array('ALL');
        $this->secureEndpoint(__FUNCTION__,'GET',$origin,$ip,false);

        // API Call Data
        $ttableentryid = $this->sanitize($this->_request['ttableentryid'], 'int');
		$accessToken = $this->sanitize($this->_request['access_token'], 'string');
					
		// Scope required for this call		
		$scope = 'intranet.user.login.null';		
		
		$auth = $this->isAuthorised($scope, $accessToken, false);
		$auth = true;
		
		// Prepare Email Debug to send (if need be)
		$emailErrorLog = "Errors:";

		if ($auth) {
			// Finally, after all sanitisation, we are ready to connect to the database and save data
			$params = array(
				'function' => 'getConfirmedAttendance',
				'ttableentryid' => $ttableentryid
			);
		
			$jwtToken = $this->jwtEncode($params, APIKEY_INTRANET_KEY);
			$array = array('jwt' => $jwtToken);
			$url = 'https://intranet.stmartins.edu/rest/smimobileapp.php';
			//var_dump($this->curl($url, $array, 'POST'));
			$emparray = json_decode($this->curl($url, $array, 'POST'));
						
			// Convert to JSON and send as response
			$response = json_encode($emparray, JSON_NUMERIC_CHECK);				
											
			// Filter required data before sending to client
			//$array = array();
			//$counter = 0;
			
			
			//foreach ($emparray as $row) {
				
			//	array_push($array, array(1, 0));
			//}
			
			echo json_encode($emparray, JSON_NUMERIC_CHECK);
		}
		else {
			$this->endpoint_error(401);
			die();
		}			
	}	
	
	public function saveConfirmedAttendanceDev($params){
       
        // Very IMP: Endpoint Security
        $origin = array('ALL');
        $ip = array('ALL');
        $this->secureEndpoint(__FUNCTION__,'GET',$origin,$ip,false);
		
        // API Call Data
        $userid = $this->sanitize($this->_request['userid'], 'int');
        $ttableentryid = $this->sanitize($this->_request['ttableentryid'], 'int');
		$attendanceState = $this->sanitize($this->_request['attendanceState'], 'int');
		$accessToken = $this->sanitize($this->_request['access_token'], 'string');
					
		// Scope required for this call		
		$scope = 'intranet.user.login.null';		
		
		$auth = $this->isAuthorised($scope, $accessToken, false);
				
		// Prepare Email Debug to send (if need be)
		$emailErrorLog = "Errors:";

		if ($auth) {
			// Finally, after all sanitisation, we are ready to connect to the database and save data
			$connect = (new dbConn)->connect('mobileapp');
			
			
			// Does an entry already exist?
			$stmt_msg = $connect->prepare('SELECT * 
										   FROM ttableattendance
										   WHERE userid = ?
										   AND ttableentryid = ?
										   ');
			$stmt_msg->bind_param('ii',$userid, $ttableentryid);
			$stmt_msg->execute();
			$result = $stmt_msg->get_result();
			$stmt_msg->close();	
					
			// Create Result Array
			$countRows = 0;
			while($row = $result->fetch_assoc()) {
				$countRows++;
			}
			
			
			if ($countRows > 0) {
				
				// UPDATE
				
				if (($attendanceState == 0) || ($attendanceState == 1)) {
					// Write to Table
					$stmt_msg = $connect->prepare('UPDATE ttableattendance
												   SET confirmedAttendance = ?
												   WHERE  ttableentryid = ?
												   AND userid = ?');
					$stmt_msg->bind_param('iii',$attendanceState, $ttableentryid, $userid);
					$stmt_msg->execute();
					$emailErrorLog .= "DB Statement ERROR STUDENT: ". " " . $stmt_msg->error. "\r\n";
					$emailErrorLog .= "DB Connection ERROR if any: " . $connect->error. "\r\n";			
					$stmt_msg ->close();
					
					// Create Result Array
					$emparray = array();
					$emparray['status'] = 'completed';
					$emparray['type'] = 'update';
				}
				else {
					// Create Result Array
					$emparray = array();
					$emparray['type'] = 'update';
					$emparray['status'] = 'failed';						
				}
			}
			else {
				
				// INSERT
				
				// Check whether value is 0 or 1.
				if (($attendanceState == 0) || ($attendanceState == 1)) {
					
					// Write to Table
					$stmt_msg = $connect->prepare('INSERT INTO ttableattendance(ttableentryid, userid, confirmedAttendance) VALUES(?,?,?);');
					$stmt_msg->bind_param('iii',$userid, $ttableentryid, $attendanceState);
					$stmt_msg->execute();
					$emailErrorLog .= "DB Statement ERROR STUDENT: ". " " . $stmt_msg->error. "\r\n";
					$emailErrorLog .= "DB Connection ERROR if any: " . $connect->error. "\r\n";
					$last_message_id = $stmt_msg->insert_id;
					$stmt_msg ->close();
				
				// Create Result Array
				$emparray = array();
				$emparray['status'] = 'completed';
				$emparray['type'] = 'insert';
				
				}
				else {				
					// Create Result Array
					$emparray = array();
					$emparray['type'] = 'insert';
					$emparray['status'] = 'failed';				
				}
			}				
			// Convert to JSON and send as response
			echo json_encode($emparray, JSON_NUMERIC_CHECK);
		}
		else {
		        $this->endpoint_error(401);
				die();
		}		
	}
			
	public function saveConfirmedAttendance($params){
       
        // Very IMP: Endpoint Security
        $origin = array('ALL');
        $ip = array('ALL');
        $this->secureEndpoint(__FUNCTION__,'GET',$origin,$ip,false);
		
        // API Call Data
        $userid = $this->sanitize($this->_request['userid'], 'int');
        $ttableentryid = $this->sanitize($this->_request['ttableentryid'], 'int');
		$attendanceState = $this->sanitize($this->_request['attendanceState'], 'int');
		$accessToken = $this->sanitize($this->_request['access_token'], 'string');
					
		// Scope required for this call		
		$scope = 'intranet.user.login.null';		
		
		$auth = $this->isAuthorised($scope, $accessToken, false);
		$auth = true;
		// Prepare Email Debug to send (if need be)
		$emailErrorLog = "Errors:";

		if ($auth) {
			// Finally, after all sanitisation, we are ready to connect to the database and save data
			$params = array(
				'function' => 'getStudentLessonAttendance',
				'ttableentryid' => $ttableentryid,
				'userid' => $userid
			);
		
			$jwtToken = $this->jwtEncode($params, APIKEY_INTRANET_KEY);
			$array = array('jwt' => $jwtToken);
			$url = 'https://intranet.stmartins.edu/rest/smimobileapp.php';

			$emparray = json_decode($this->curl($url, $array, 'POST'));
						
			// Convert to JSON and send as response
			$response = json_encode($emparray, JSON_NUMERIC_CHECK);				
						
			if (sizeof($emparray) > 0) {
				
				// UPDATE
				
				if (($attendanceState == 0) || ($attendanceState == 1)) {
					// Write to Table
					
					$params = array(
						'function' => 'updateStudentLessonAttendance',
						'ttableentryid' => $ttableentryid,
						'userid' => $userid,
						'attendance' => $attendanceState
					);
				
					$jwtToken = $this->jwtEncode($params, APIKEY_INTRANET_KEY);
					$array = array('jwt' => $jwtToken);
					$url = 'https://intranet.stmartins.edu/rest/smimobileapp.php';
					$emparray = json_decode($this->curl($url, $array, 'POST'));
								
					// Convert to JSON and send as response
					$response = json_encode($emparray, JSON_NUMERIC_CHECK);			
					
					// Create Result Array
					$emparray = array();
					$emparray['status'] = 'completed';
					$emparray['type'] = 'update';
				}
				else {
					// Create Result Array
					$emparray = array();
					$emparray['type'] = 'update';
					$emparray['status'] = 'failed';						
				}
			}
			else {
				
				// INSERT
				
				// Check whether value is 0 or 1.
				if (($attendanceState == 0) || ($attendanceState == 1)) {
					
					// Write to Table
					$params = array(
						'function' => 'insertStudentLessonAttendance',
						'ttableentryid' => $ttableentryid,
						'userid' => $userid,
						'attendance' => $attendanceState
					);
				
					$jwtToken = $this->jwtEncode($params, APIKEY_INTRANET_KEY);
					$array = array('jwt' => $jwtToken);
					$url = 'https://intranet.stmartins.edu/rest/smimobileapp.php';
					$emparray = json_decode($this->curl($url, $array, 'POST'));
								
					// Convert to JSON and send as response
					$response = json_encode($emparray, JSON_NUMERIC_CHECK);	
					
					// Create Result Array
					$emparray = array();
					$emparray['status'] = 'completed';
					$emparray['type'] = 'insert';
				
				}
				else {				
					// Create Result Array
					$emparray = array();
					$emparray['type'] = 'insert';
					$emparray['status'] = 'failed';				
				}
			}				
			// Convert to JSON and send as response
			echo json_encode($emparray, JSON_NUMERIC_CHECK);
		}
		else {
		        $this->endpoint_error(401);
				die();
		}		
	}
	
	public function getLecturerDayCoursesDev(){
		
		 //Very IMP: Endpoint Security
        $origin = array('ALL');
        $ip = array('ALL');
        $this->secureEndpoint(__FUNCTION__,'GET',$origin,$ip,false);
		
		// Parameters from HTTP query
		$date = $this->sanitize($this->_request['date'], 'string');
		$userid = $this->sanitize($this->_request['userid'], 'int');
		$accessToken = $this->sanitize($this->_request['access_token'], 'string');
				
		// Scope required for this call		
		$scope = 'intranet.user.login.null';		
		
		$auth = $this->isAuthorised($scope, $accessToken, false);
				
		if ($auth) {
			// Finally, after all sanitisation, we are ready to connect to the database and save data
			$connect = (new dbConn)->connect('mobileapp');
			
			# Read from table		
			$stmtDetails = $connect->prepare('SELECT sc.LectID as LecturerId, tt.start, tt.end, c.name, c.description, tte.ttableentryid, tt.ttableid, tte.ttabledate, l.location AS roomNumber, r.Description AS courseRole
												FROM ScheduledCourses sc
												JOIN Courses c ON c.CourseID = sc.CourseID   
												JOIN ttable tt ON tt.schedid = sc.SchedID
												JOIN ttableentries tte ON tte.ttableid = tt.ttableid
												JOIN locations l ON l.locationid = tte.locationid
												JOIN Roles r ON r.RoleID = sc.RoleID
												WHERE Datediff(?, tte.ttabledate) = 0 AND sc.LectID = ?
												Order by HOUR(tt.start)');	
							$stmtDetails->bind_param('si',$date, $userid);											
							$stmtDetails->execute();
							$result = $stmtDetails->get_result();
							$stmtDetails->close();						
							
			// Create Result Array
			$emparray = array();
			while($row = $result->fetch_assoc())
			{
				$emparray[] = $row;
			}
							
			// Convert to JSON and send as response
			echo json_encode($emparray, JSON_NUMERIC_CHECK);
		}
		else {
		        $this->endpoint_error(401);
				die();
		}
	}
	
	public function getLecturerDayCourses(){
		
		 //Very IMP: Endpoint Security
        $origin = array('ALL');
        $ip = array('ALL');
        $this->secureEndpoint(__FUNCTION__,'GET',$origin,$ip,false);
		
		// Parameters from HTTP query
		$date = $this->sanitize($this->_request['date'], 'string');
		$userid = $this->sanitize($this->_request['userid'], 'int');
		$accessToken = $this->sanitize($this->_request['access_token'], 'string');
					
		// Scope required for this call		
		$scope = 'intranet.user.login.null';		
		
		$auth = $this->isAuthorised($scope, $accessToken, false);
				
		if ($auth) {
			
			// Finally, after all sanitisation, we are ready to connect to the database and save data
			$params = array(
				'function' => 'getLecturerDayCourses',
				'userid' => $userid,
				'date' => $date
			);
		
			$jwtToken = $this->jwtEncode($params, APIKEY_INTRANET_KEY);
			$array = array('jwt' => $jwtToken);
			$url = 'https://intranet.stmartins.edu/rest/smimobileapp.php';

			$emparray = json_decode($this->curl($url, $array, 'POST'));
						
			// Convert to JSON and send as response
			$response = json_encode($emparray, JSON_NUMERIC_CHECK);		
							
			// Convert to JSON and send as response
			echo $response;
		}
		else {
		        $this->endpoint_error(401);
				die();
		}
	}

	public function getStudentsByCourseDev() {
		
		 //Very IMP: Endpoint Security
        $origin = array('ALL');
        $ip = array('ALL');
        $this->secureEndpoint(__FUNCTION__,'GET',$origin,$ip,false);
		
		// Parameters from HTTP query		
		$ttableentryid = $this->sanitize($this->_request['ttableentryid'], 'int');
		$accessToken = $this->sanitize($this->_request['access_token'], 'string');
					
		// Scope required for this call		
		$scope = 'intranet.user.login.null';		
		
		$auth = $this->isAuthorised($scope, $accessToken, false);
				
		if ($auth) {
			// Finally, after all sanitisation, we are ready to connect to the database and save data
			$connect = (new dbConn)->connect('mobileapp');
			
			# Read from table		
			$stmtDetails = $connect->prepare('SELECT sc.LectID as LecturerId,  tta.userid as StudentId , u.username , u.name, u.surname , tt.start, tt.end, c.name as coursename, c.description, tte.ttableentryid, tt.ttableid, tte.ttabledate
												FROM users u
												JOIN ttableattendance tta ON u.user_id = tta.userid               
												JOIN ttableentries tte ON tta.ttableentryid = tte.ttableentryid  
												JOIN ttable tt ON tt.ttableid = tte.ttableid                     
												JOIN ScheduledCourses sc ON sc.SchedID = tt.schedid              
												JOIN Courses c ON c.CourseID = sc.CourseID 
												WHERE tte.ttableentryid = ?');	
							$stmtDetails->bind_param('i',$ttableentryid);											
							$stmtDetails->execute();
							$result = $stmtDetails->get_result();
							$stmtDetails->close();						
							
			// Create Result Array
			$emparray = array();
			while($row = $result->fetch_assoc())
			{
				$emparray[] = $row;
			}
							
			// Convert to JSON and send as response
			echo json_encode($emparray, JSON_NUMERIC_CHECK);
		}
		else {
		        $this->endpoint_error(401);
				die();
		}
	}
	
	public function getStudentsByCourse() {
		
		 //Very IMP: Endpoint Security
        $origin = array('ALL');
        $ip = array('ALL');
        $this->secureEndpoint(__FUNCTION__,'GET',$origin,$ip,false);
		
		// Parameters from HTTP query		
		$ttableentryid = $this->sanitize($this->_request['ttableentryid'], 'int');
		$accessToken = $this->sanitize($this->_request['access_token'], 'string');
					
		// Scope required for this call		
		$scope = 'intranet.user.login.null';		
		
		$auth = $this->isAuthorised($scope, $accessToken, false);
				
		if ($auth) {
			
			// Finally, after all sanitisation, we are ready to connect to the database and save data
			$params = array(
				'function' => 'getStudentsByCourse',
				'ttableentryid' => $ttableentryid
			);
		
			$jwtToken = $this->jwtEncode($params, APIKEY_INTRANET_KEY);
			$array = array('jwt' => $jwtToken);
			$url = 'https://intranet.stmartins.edu/rest/smimobileapp.php';

			$emparray = json_decode($this->curl($url, $array, 'POST'));
						
			// Convert to JSON and send as response
			$response = json_encode($emparray, JSON_NUMERIC_CHECK);		
							
			// Convert to JSON and send as response
			echo $response;
		}
		else {
		        $this->endpoint_error(401);
				die();
		}
	}
	
	public function getAllStudentsAndCoursesByLecturer() {
					
		 //Very IMP: Endpoint Security
        $origin = array('ALL');
        $ip = array('ALL');
        $this->secureEndpoint(__FUNCTION__,'GET',$origin,$ip,false);
		
		// Parameters from HTTP query		
		$lectId = $this->sanitize($this->_request['lectId'], 'int');
		$startDate = $this->sanitize($this->_request['startDate'], 'string');
		$endDate = $this->sanitize($this->_request['endDate'], 'string');
		$accessToken = $this->sanitize($this->_request['access_token'], 'string');
					
		// Scope required for this call		
		$scope = 'intranet.user.login.null';		
		
		$auth = $this->isAuthorised($scope, $accessToken, false);
		
		if ($auth) {
		
			// Finally, after all sanitisation, we are ready to connect to the database and save data
			$connect = (new dbConn)->connect('mobileapp');
			
			# Read from table		
			$stmtDetails = $connect->prepare('SELECT sc.LectID as LecturerId,  tta.userid as StudentId , u.name, u.surname , c.name as coursename, c.description, tte.ttableentryid, tt.ttableid, tte.ttabledate
												FROM users u
												JOIN ttableattendance tta ON u.user_id = tta.userid              
												JOIN ttableentries tte ON tta.ttableentryid = tte.ttableentryid 
												JOIN ttable tt ON tt.ttableid = tte.ttableid                    
												JOIN ScheduledCourses sc ON sc.SchedID = tt.schedid             
												JOIN Courses c ON c.CourseID = sc.CourseID                      
												WHERE sc.LectID = ?  and tte.ttabledate between ? and ?  
												ORDER BY `tte`.`ttableid`  ASC
												
												');	
							$stmtDetails->bind_param('iss',$lectId, $startDate, $endDate);											
							$stmtDetails->execute();
							$result = $stmtDetails->get_result();
							$stmtDetails->close();						
							
			// Create Result Array
			$emparray = array();
			while($row = $result->fetch_assoc())
			{
				$emparray[] = $row;
			}
							
			// Convert to JSON and send as response
			echo json_encode($emparray, JSON_NUMERIC_CHECK);
		}
		else {
			$this->endpoint_error(401);
			die();
		}
	}
	
	public function getUserTypeDev() {
		
		//Very IMP: Endpoint Security
        $origin = array('ALL');
        $ip = array('ALL');
        $this->secureEndpoint(__FUNCTION__,'GET',$origin,$ip,false);
		
		// Scope required for this call		
		$scope = 'intranet.user.login.null';		
						
		// Parameters from HTTP query		
		$email = $this->sanitize($this->_request['email'], 'string');
		$accessToken = $this->sanitize($this->_request['access_token'], 'string');
		
		$auth = $this->isAuthorised($scope, $accessToken, false);
				
		// Is token is valid, continue
		// Note: If this is a private URI, make sure data pertains to this user only
		if($auth){				
						
			// Finally, after all sanitisation, we are ready to connect to the database and save data
			$connect = (new dbConn)->connect('mobileapp');
			
			# Read from table		
			$stmtDetails = $connect->prepare('Select users.user_id, users.Type From users where email = ?');	
							$stmtDetails->bind_param('s',$email);											
							$stmtDetails->execute();
							$result = $stmtDetails->get_result();
							$stmtDetails->close();
							
			// Create Result Array
			$emparray = array();
			while($row = $result->fetch_assoc())
			{
				$emparray[] = $row;
				
			}
							
			// Convert to JSON and send as response
			$response = json_encode($emparray, JSON_NUMERIC_CHECK);
			
			// if the User's type is not A or L, this URI should only send data pertaining to current user
			if ((json_decode($response)[0]->Type != 'A') && (json_decode($response)[0]->Type != 'L')) {
				
				// Stop!
				if (($useremail != $email) && ($private === true)) {
					
					$this->endpoint_error(401);
					
				}
				else {
					echo $response;
				}
			}
			else {
				
				echo $response;
			}
		}
		else {
		        $this->endpoint_error(401);
				die();
		}
	}
	
	public function getUserType() {
		
		//Very IMP: Endpoint Security
        $origin = array('ALL');
        $ip = array('ALL');
        $this->secureEndpoint(__FUNCTION__,'GET',$origin,$ip,false);
		
		// Scope required for this call		
		$scope = 'intranet.user.login.null';		
						
		// Parameters from HTTP query		
		$email = $this->sanitize($this->_request['email'], 'string');
		$accessToken = $this->sanitize($this->_request['access_token'], 'string');
		
		$auth = $this->isAuthorised($scope, $accessToken, false);
		
		// Is token is valid, continue
		// Note: If this is a private URI, make sure data pertains to this user only
		if($auth){				
			
			$params = array(
				'function' => 'getUserType',
				'email' => $email
			);
		
			$jwtToken = $this->jwtEncode($params, APIKEY_INTRANET_KEY);
			$array = array('jwt' => $jwtToken);
			$url = 'https://intranet.stmartins.edu/rest/smimobileapp.php';

			$emparray = json_decode($this->curl($url, $array, 'POST'));
						
			// Convert to JSON and send as response
			$response = json_encode($emparray, JSON_NUMERIC_CHECK);
			
			// if the User's type is not A or L, this URI should only send data pertaining to current user
			if ((json_decode($response)[0]->Type != 'A') && (json_decode($response)[0]->Type != 'L')) {
				
				// Stop!
				if (($useremail != $email) && ($private === true)) {
					
					$this->endpoint_error(401);
					
				}
				else {
					echo $response;
				}
			}
			else {
				
				echo $response;
			}
		}
		else {
		        $this->endpoint_error(401);
				die();
		}
	}

	public function getTargetBeacons($params) {
		$this->secureEndpoint(__FUNCTION__, 'GET', ['ALL'], ['ALL'], false);
		
		$scope = 'intranet.user.login.null';
		$accessToken = $this->sanitize($this->_request['access_token'], 'string');
		$auth = $this->isAuthorised($scope, $accessToken, false);
		
		if ($auth) {
			$connect = (new dbConn)->connect('mobileapp');
			
			$sql = $connect->prepare('SELECT * FROM view_target_beacon');
			$sql->execute();
			$result = $sql->get_result();
			$sql->close();
			
			$data = [];
			while ($row = $result->fetch_assoc())
			{
				$data[] = $row;
			}
			
			echo json_encode($data, JSON_NUMERIC_CHECK);
		}
		else {
			$this->endpoint_error(401);
			exit();
		}
	}

	public function getTargetBeaconByMac($params) {
		$this->secureEndpoint(__FUNCTION__, 'GET', ['ALL'], ['ALL'], false);
		
		$scope = 'intranet.user.login.null';
		$mac = $this->sanitize($this->_request['mac'], 'string');
		$accessToken = $this->sanitize($this->_request['access_token'], 'string');
		$auth = $this->isAuthorised($scope, $accessToken, false);
		
		if ($auth) {
			$connect = (new dbConn)->connect('mobileapp');
			
			$sql = $connect->prepare('SELECT * FROM view_target_beacon WHERE mac = ?');
			$sql->bind_param('s', $mac);
			$sql->execute();
			$result = $sql->get_result();
			$sql->close();

			$data = [];
			while ($row = $result->fetch_assoc())
			{
				$data[] = $row;
			}
			
			echo json_encode($data, JSON_NUMERIC_CHECK);
		}
		else {
			$this->endpoint_error(401);
			exit();
		}
	}

	public function getClassroomByTargetBeaconId($params) {
		$this->secureEndpoint(__FUNCTION__, 'GET', ['ALL'], ['ALL'], false);
		
		$scope = 'intranet.user.login.null';
		$targetBeaconId = $this->sanitize($this->_request['target_beacon_id'], 'string');
		$accessToken = $this->sanitize($this->_request['access_token'], 'string');
		$auth = $this->isAuthorised($scope, $accessToken, false);
		
		if ($auth) {
			$connect = (new dbConn)->connect('mobileapp');
			
			$sql = $connect->prepare('SELECT * FROM view_target_beacon_to_classroom WHERE target_beacon_id = ?');
			$sql->bind_param('i', $targetBeaconId);
			$sql->execute();
			$result = $sql->get_result();
			$sql->close();

			$data = [];
			while ($row = $result->fetch_assoc())
			{
				$data[] = $row;
			}
			
			echo json_encode($data, JSON_NUMERIC_CHECK);
		}
		else {
			$this->endpoint_error(401);
			exit();
		}
	}

	public function postAttendance($params) {
		$this->secureEndpoint(__FUNCTION__, 'GET', ['ALL'], ['ALL'], false);
		
		$scope = 'intranet.user.login.null';
		$studentId = $this->sanitize($this->_request['student_id'], 'string');
		$classroomId = $this->sanitize($this->_request['classroom_id'], 'string');
		$dateTime = $this->sanitize($this->_request['date_time'], 'string');
		$accessToken = $this->sanitize($this->_request['access_token'], 'string');
		$auth = $this->isAuthorised($scope, $accessToken, false);
		
		if ($auth) {
			$connect = (new dbConn)->connect('mobileapp');
			
			$sql = $connect->prepare('INSERT INTO smi_attendance(id, student_id, classroom_id, date_time) VALUES(NULL, ?, ?, ?)');
			$sql->bind_param('iis', $studentId, $classroomId, $dateTime);
			$sql->execute();
			$sql->close();
		}
		else {
			$this->endpoint_error(401);
			exit();
		}
	}
}

?>

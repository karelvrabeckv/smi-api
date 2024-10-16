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
        $stmt_msg = $connect->prepare('INSERT INTO smi_notification(message) VALUES(?)');
        $stmt_msg->bind_param('s',$message);
        $stmt_msg->execute();
		$emailErrorLog .= "DB Statement ERROR STUDENT: ". " " . $stmt_msg->error. "\r\n";
        $emailErrorLog .= "DB Connection ERROR if any: " . $connect->error. "\r\n";
        $stmt_msg ->close();
	}
	
	public function readDB($params){
		// Very IMP: Endpoint Security	
        $origin = array('ALL');
        $ip = array('ALL');
        $this->secureEndpoint(__FUNCTION__,'GET',$origin,$ip,false);

        // Finally, after all sanitisation, we are ready to connect to the database and save data
		$connect = (new dbConn)->connect('mobileapp');
		
		// Read from table
		$value = 1;
		$stmtDetails = $connect->prepare('SELECT * FROM smi_notification n WHERE n.notifyID >= ?');
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
		
		$fields = array(					
			"access_token" => $accessToken
		);

		return $authorized;
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
			$stmtDetails = $connect->prepare('SELECT tta.userid as StudentId, tt.start, tt.end, c.name, c.description, tte.ttableentryid, tt.ttableid, tte.ttabledate, l.location AS roomNumber, lect.Name as lecturerName, lect.Surname AS lecturerSurname, tta.confirmedAttendance
												FROM smi_user u
												JOIN smi_t_table_attendance tta ON u.id = tta.userid              
												JOIN smi_t_table_entry tte ON tta.ttableentryid = tte.ttableentryid 
												JOIN smi_t_table tt ON tt.ttableid = tte.ttableid                    
												JOIN smi_scheduled_course sc ON sc.SchedID = tt.schedid
												JOIN smi_user lect ON lect.id = sc.LectID    
												JOIN smi_course c ON c.CourseID = sc.CourseID
												JOIN smi_location l ON l.locationid = tte.locationid
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
	
	public function getAttendanceByIdLegacyDev($params){
       
        // Very IMP: Endpoint Security
        $origin = array('ALL');
        $ip = array('ALL');
        $this->secureEndpoint(__FUNCTION__,'GET',$origin,$ip,false);

        // API Call Data
        $ttableentryid = $this->sanitize($this->_request['t_table_entry_id'], 'int');
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
			$stmt_msg = $connect->prepare('SELECT tta.userid, tta.confirmedAttendance FROM smi_t_table_attendance tta WHERE ttableentryid = ?');
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
	
	public function getAttendanceByIdLegacy($params){
       
        // Very IMP: Endpoint Security
        $origin = array('ALL');
        $ip = array('ALL');
        $this->secureEndpoint(__FUNCTION__,'GET',$origin,$ip,false);

        // API Call Data
        $ttableentryid = $this->sanitize($this->_request['t_table_entry_id'], 'int');
		$accessToken = $this->sanitize($this->_request['access_token'], 'string');
					
		// Scope required for this call		
		$scope = 'intranet.user.login.null';		
		
		$auth = $this->isAuthorised($scope, $accessToken, false);
		$auth = true;

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
			
			echo json_encode($emparray, JSON_NUMERIC_CHECK);
		}
		else {
			$this->endpoint_error(401);
			die();
		}			
	}	
	
	public function postAttendanceLegacyDev($params){
        // Very IMP: Endpoint Security
        $origin = array('ALL');
        $ip = array('ALL');
        $this->secureEndpoint(__FUNCTION__,'GET',$origin,$ip,false);
		
        // API Call Data
        $ttableentryid = $this->sanitize($this->_request['t_table_entry_id'], 'int');
        $userid = $this->sanitize($this->_request['user_id'], 'int');
		$attendanceState = $this->sanitize($this->_request['attendance_state'], 'int');
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
			$stmt_msg = $connect->prepare('SELECT * FROM smi_t_table_attendance WHERE userid = ? AND ttableentryid = ?');
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
					$stmt_msg = $connect->prepare('UPDATE smi_t_table_attendance SET confirmedAttendance = ? WHERE  ttableentryid = ? AND userid = ?');
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
					$stmt_msg = $connect->prepare('INSERT INTO smi_t_table_attendance(ttableentryid, userid, confirmedAttendance) VALUES (?, ?, ?)');
					$stmt_msg->bind_param('iii',$userid, $ttableentryid, $attendanceState);
					$stmt_msg->execute();
					$emailErrorLog .= "DB Statement ERROR STUDENT: ". " " . $stmt_msg->error. "\r\n";
					$emailErrorLog .= "DB Connection ERROR if any: " . $connect->error. "\r\n";
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
			
	public function postAttendanceLegacy($params){
        // Very IMP: Endpoint Security
        $origin = array('ALL');
        $ip = array('ALL');
        $this->secureEndpoint(__FUNCTION__,'GET',$origin,$ip,false);
		
        // API Call Data
        $ttableentryid = $this->sanitize($this->_request['t_table_entry_id'], 'int');
        $userid = $this->sanitize($this->_request['user_id'], 'int');
		$attendanceState = $this->sanitize($this->_request['attendance_state'], 'int');
		$accessToken = $this->sanitize($this->_request['access_token'], 'string');
		
		// Scope required for this call		
		$scope = 'intranet.user.login.null';		
		
		$auth = $this->isAuthorised($scope, $accessToken, false);
		$auth = true;

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
		$userid = $this->sanitize($this->_request['user_id'], 'int');
		$date = $this->sanitize($this->_request['date'], 'string');
		$accessToken = $this->sanitize($this->_request['access_token'], 'string');
				
		// Scope required for this call		
		$scope = 'intranet.user.login.null';		
		
		$auth = $this->isAuthorised($scope, $accessToken, false);
				
		if ($auth) {
			// Finally, after all sanitisation, we are ready to connect to the database and save data
			$connect = (new dbConn)->connect('mobileapp');
			
			# Read from table		
			$stmtDetails = $connect->prepare('SELECT sc.LectID as LecturerId, tt.start, tt.end, c.name, c.description, tte.ttableentryid, tt.ttableid, tte.ttabledate, l.location AS roomNumber, r.Description AS courseRole
												FROM smi_scheduled_course sc
												JOIN smi_course c ON c.CourseID = sc.CourseID   
												JOIN smi_t_table tt ON tt.schedid = sc.SchedID
												JOIN smi_t_table_entry tte ON tte.ttableid = tt.ttableid
												JOIN smi_location l ON l.locationid = tte.locationid
												JOIN smi_role r ON r.RoleID = sc.RoleID
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
		$userid = $this->sanitize($this->_request['user_id'], 'int');
		$date = $this->sanitize($this->_request['date'], 'string');
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
		$ttableentryid = $this->sanitize($this->_request['t_table_entry_id'], 'int');
		$accessToken = $this->sanitize($this->_request['access_token'], 'string');
		
		// Scope required for this call		
		$scope = 'intranet.user.login.null';		
		
		$auth = $this->isAuthorised($scope, $accessToken, false);
				
		if ($auth) {
			// Finally, after all sanitisation, we are ready to connect to the database and save data
			$connect = (new dbConn)->connect('mobileapp');
			
			# Read from table		
			$stmtDetails = $connect->prepare('SELECT sc.LectID as LecturerId,  tta.userid as StudentId , u.username , u.name, u.surname , tt.start, tt.end, c.name as coursename, c.description, tte.ttableentryid, tt.ttableid, tte.ttabledate
												FROM smi_user u
												JOIN smi_t_table_attendance tta ON u.id = tta.userid               
												JOIN smi_t_table_entry tte ON tta.ttableentryid = tte.ttableentryid  
												JOIN smi_t_table tt ON tt.ttableid = tte.ttableid                     
												JOIN smi_scheduled_course sc ON sc.SchedID = tt.schedid              
												JOIN smi_course c ON c.CourseID = sc.CourseID 
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
		$ttableentryid = $this->sanitize($this->_request['t_table_entry_id'], 'int');
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
		$lectId = $this->sanitize($this->_request['lect_id'], 'int');
		$startDate = $this->sanitize($this->_request['start_date'], 'string');
		$endDate = $this->sanitize($this->_request['end_date'], 'string');
		$accessToken = $this->sanitize($this->_request['access_token'], 'string');

		// Scope required for this call		
		$scope = 'intranet.user.login.null';		
		
		$auth = $this->isAuthorised($scope, $accessToken, false);
		
		if ($auth) {
		
			// Finally, after all sanitisation, we are ready to connect to the database and save data
			$connect = (new dbConn)->connect('mobileapp');
			
			# Read from table		
			$stmtDetails = $connect->prepare('SELECT sc.LectID as LecturerId,  tta.userid as StudentId , u.name, u.surname , c.name as coursename, c.description, tte.ttableentryid, tt.ttableid, tte.ttabledate
												FROM smi_user u
												JOIN smi_t_table_attendance tta ON u.id = tta.userid              
												JOIN smi_t_table_entry tte ON tta.ttableentryid = tte.ttableentryid 
												JOIN smi_t_table tt ON tt.ttableid = tte.ttableid                    
												JOIN smi_scheduled_course sc ON sc.SchedID = tt.schedid             
												JOIN smi_course c ON c.CourseID = sc.CourseID                      
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
	
	public function getUserByEmailDev() {
		
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
			$stmtDetails = $connect->prepare('SELECT u.id, u.type FROM smi_user u WHERE email = ?');	
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
			if ((json_decode($response)[0]->type != 'A') && (json_decode($response)[0]->type != 'L')) {
				
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
	
	public function getUserByEmail() {
		
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
			if ((json_decode($response)[0]->type != 'A') && (json_decode($response)[0]->type != 'L')) {
				
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
			
			$sql = $connect->prepare('CALL getTargetBeacons()');
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
			
			$sql = $connect->prepare('CALL getTargetBeaconByMac(?)');
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
			
			$sql = $connect->prepare('CALL getClassroomByTargetBeaconId(?)');
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
			
			$sql = $connect->prepare('CALL postAttendance(?, ?, ?)');
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

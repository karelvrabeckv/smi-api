<?php
	
	//Set Code and Status
	function getCode($array){
		
		if(is_array($array)){
			$data = array('code' => '200', 'status' => 'success', 'message' => $array);
			return str_replace('\/','/',json_encode($data));	
		} else {
			return json_encode(array('code' => 500, 'status' => 'failed', 'message' => $array));
		}
	
	}

	
	function getUserType($email){
				
		//Database Connection
		require ('includes/dbConnectSMIMobileApp.php');

		$sql = "SELECT userid, Type FROM [SMIIT_Intranet].[dbo].[Users] WHERE email = ?";
		$params = array($email);
		
		$stmt = sqlsrv_query($conn,$sql,$params);
		
		if($stmt === false){
		    die(print_r(sqlsrv_errors(), true));
		} else {
			$rows = array();	

			while($row = sqlsrv_fetch_array($stmt, SQLSRV_FETCH_ASSOC) ) {
				
				array_push($rows, $row);
				
			}
		}
		
		sqlsrv_free_stmt($stmt);
		sqlsrv_close($conn);
		
		return json_encode($rows);
	}


	function getStudentDaySchedule($userid, $date){
				
		//Database Connection
		require ('includes/dbConnectSMIMobileApp.php');

		$sql = "SELECT tta.userid as StudentId, tt.start, tt.[end], c.name, c.description, tte.ttableentryid, tt.ttableid, tte.ttabledate, l.location AS roomNumber, lect.Name as lecturerName, lect.Surname AS lecturerSurname, tta.confirmedAttendance
		FROM Users u
		JOIN ttableattendance tta ON u.userid = tta.userid              
		JOIN ttableentries tte ON tta.ttableentryid = tte.ttableentryid 
		JOIN ttable tt ON tt.ttableid = tte.ttableid                    
		JOIN ScheduledCourses sc ON sc.SchedID = tt.schedid
		JOIN Users lect ON lect.userid = sc.LectID    
		JOIN Courses c ON c.CourseID = sc.CourseID
		JOIN locations l ON l.locationid = tte.locationid
		WHERE tta.userid = ? AND Datediff(day, ?, tte.ttabledate) = 0 -- 3727 and 2020-03-05 are parameters in the api
		Order by datepart(hh, tt.start)";
		
		$params = array($userid, $date);
		
		$stmt = sqlsrv_query($conn,$sql,$params);
		
		if($stmt === false){
		    die(print_r(sqlsrv_errors(), true));
		} else {
			$rows = array();	

			while($row = sqlsrv_fetch_array($stmt, SQLSRV_FETCH_ASSOC) ) {
				
				array_push($rows, $row);
				
			}
		}
		
		sqlsrv_free_stmt($stmt);
		sqlsrv_close($conn);
		
		return json_encode($rows);
	}

	
	function getLecturerDayCourses($userid, $date){
				
		//Database Connection
		require ('includes/dbConnectSMIMobileApp.php');

		$sql = "SELECT sc.LectID as LecturerId, tt.start, tt.[end], c.name, c.description, tte.ttableentryid, tt.ttableid, tte.ttabledate, l.location AS roomNumber, r.Description AS courseRole
		FROM ScheduledCourses sc
		JOIN Courses c ON c.CourseID = sc.CourseID   
		JOIN ttable tt ON tt.schedid = sc.SchedID
		JOIN ttableentries tte ON tte.ttableid = tt.ttableid
		JOIN locations l ON l.locationid = tte.locationid
		JOIN Roles r ON r.RoleID = sc.RoleID
		WHERE Datediff(day, ?, tte.ttabledate) = 0 AND sc.LectID = ?
		Order by datepart(hh, tt.start)";
		
		$params = array($date, $userid);
		
		$stmt = sqlsrv_query($conn,$sql,$params);
		
		if($stmt === false){
		    die(print_r(sqlsrv_errors(), true));
		} else {
			$rows = array();	

			while($row = sqlsrv_fetch_array($stmt, SQLSRV_FETCH_ASSOC) ) {
				
				array_push($rows, $row);
				
			}
		}
		
		sqlsrv_free_stmt($stmt);
		sqlsrv_close($conn);
		
		return json_encode($rows);
	}


	function getStudentsByCourse($ttableentryid){
				
		//Database Connection
		require ('includes/dbConnectSMIMobileApp.php');

		$sql = "SELECT sc.LectID as LecturerId,  tta.userid as StudentId , u.username , u.name, u.surname , tt.start, tt.[end], c.name as coursename, c.description, tte.ttableentryid, tt.ttableid, tte.ttabledate
		FROM Users u
		JOIN ttableattendance tta ON u.userid = tta.userid               
		JOIN ttableentries tte ON tta.ttableentryid = tte.ttableentryid  
		JOIN ttable tt ON tt.ttableid = tte.ttableid                     
		JOIN ScheduledCourses sc ON sc.SchedID = tt.schedid              
		JOIN Courses c ON c.CourseID = sc.CourseID 
		WHERE tte.ttableentryid = ?;
		-- 482773 should be replaced by a parameter in the api";
		
		$params = array($ttableentryid);
		
		$stmt = sqlsrv_query($conn,$sql,$params);
		
		if($stmt === false){
		    die(print_r(sqlsrv_errors(), true));
		} else {
			$rows = array();	

			while($row = sqlsrv_fetch_array($stmt, SQLSRV_FETCH_ASSOC) ) {
				
				array_push($rows, $row);
				
			}
		}
		
		sqlsrv_free_stmt($stmt);
		sqlsrv_close($conn);
		
		return json_encode($rows);
	}


	function getStudentLessonAttendance($ttableentryid, $userid){
				
		//Database Connection
		require ('includes/dbConnectSMIMobileApp.php');

		$sql = "SELECT * 
			FROM ttableattendance
			WHERE userid = ?
			AND ttableentryid = ?";
		
		$params = array($userid, $ttableentryid);
		
		$stmt = sqlsrv_query($conn,$sql,$params);
		
		if($stmt === false){
		    die(print_r(sqlsrv_errors(), true));
		} else {
			$rows = array();	

			while($row = sqlsrv_fetch_array($stmt, SQLSRV_FETCH_ASSOC) ) {
				
				array_push($rows, $row);
				
			}
		}
		
		sqlsrv_free_stmt($stmt);
		sqlsrv_close($conn);
		
		return json_encode($rows);
	}


	function getAutoAttendance($ttableentryid){
				
		//Database Connection
		require ('includes/dbConnectSMIMobileApp.php');

		$sql = "SELECT ttableattendance.userid, ttableattendance.automaticAttendance 
		FROM ttableattendance 
		WHERE ttableentryid = ?";
		
		$params = array($ttableentryid);
		
		$stmt = sqlsrv_query($conn,$sql,$params);
		
		if($stmt === false){
		    die(print_r(sqlsrv_errors(), true));
		} else {
			$rows = array();	

			while($row = sqlsrv_fetch_array($stmt, SQLSRV_FETCH_ASSOC) ) {
				
				array_push($rows, $row);
				
			}
		}
		
		sqlsrv_free_stmt($stmt);
		sqlsrv_close($conn);
		
		return json_encode($rows);
	}

	function getConfirmedAttendance($ttableentryid){
				
		//Database Connection
		require ('includes/dbConnectSMIMobileApp.php');

		$out = 0;
		$params = array( 
			array(&$out, SQLSRV_PARAM_OUT),
			array($ttableentryid, SQLSRV_PARAM_IN)			
		);
		
		$sql = "SET NOCOUNT ON; EXEC ? = [SMIIT_Intranet].[dbo].[getattendanceMobileApp] @ttableentryid = ?";
		$stmt = sqlsrv_query($conn,$sql, $params);
		

		if($stmt === false){
		    die(print_r(sqlsrv_errors(), true));
		} else {

			$rows = array();
			
			do {
				
				// throw away first result set of the proc
				sqlsrv_next_result($stmt);

				
				while($row = sqlsrv_fetch_array($stmt)) {
					
					
					//$rows[] = $row;
					array_push($rows, $row);
				}
				
			} while (sqlsrv_next_result($stmt));
			
		}
		
		sqlsrv_free_stmt($stmt);
		sqlsrv_close($conn);
		
		return json_encode($rows);
	}

	function updateStudentLessonAttendance($attendance, $ttableentryid, $userid){
		
		//Database Connection
		require ('includes/dbConnectSMIMobileApp.php');

		$sql = "UPDATE ttableattendance
		SET confirmedAttendance = ?
		WHERE  ttableentryid = ?
		AND userid = ?";
		
		$params = array($attendance, $ttableentryid, $userid);
		
		$stmt = sqlsrv_query($conn,$sql,$params);
		
		if($stmt === false){
		    die(print_r(sqlsrv_errors(), true));
		} else {
			$rows = array();	

			while($row = sqlsrv_fetch_array($stmt, SQLSRV_FETCH_ASSOC) ) {
				
				array_push($rows, $row);
				
			}
		}
		
		sqlsrv_free_stmt($stmt);
		sqlsrv_close($conn);
		
		return json_encode($rows);
	}



	function insertStudentLessonAttendance($attendance, $ttableentryid, $userid){
		
		//Database Connection
		require ('includes/dbConnectSMIMobileApp.php');

		$sql = "INSERT INTO ttableattendance(ttableentryid, userid, confirmedAttendance, state) VALUES(?,?,?,?);";
		$state = "N";

		$params = array($ttableentryid, $userid, $attendance, $state);
		
		$stmt = sqlsrv_query($conn,$sql,$params);
		
		if($stmt === false){
		    die(print_r(sqlsrv_errors(), true));
		} else {
			$rows = array();	

			while($row = sqlsrv_fetch_array($stmt, SQLSRV_FETCH_ASSOC) ) {
				
				array_push($rows, $row);
				
			}
		}
		
		sqlsrv_free_stmt($stmt);
		sqlsrv_close($conn);
		
		return json_encode($rows);
	}

	//Start of Router
	if(isset($_REQUEST['jwt'])){$jwt = filter_var(trim($_REQUEST['jwt']), FILTER_SANITIZE_STRING);}
	//$jwt = 'true';
	if($jwt){
		
		$data = explode('.',$jwt);
		$base64URLHeader = $data[0];
		$base64URLPayload = $data[1];
		$base64URLSignature = $data[2];
		
		$salt = '%^;v~+*~A9.3vG*|3*|=:~^K*^|c=*Kx';
		$signature = hash_hmac('sha256', $base64URLHeader . "." . $base64URLPayload, $salt, true);
		$encodedSignature = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($signature));
		
		$check = hash_equals($encodedSignature, $base64URLSignature);
		//$check = true;
		
		if($check){
			$params = base64_decode(str_replace(['-', '_', ''],['+', '/', '='], $base64URLPayload));
			$function = json_decode($params);
			$selectedFunc = $function->function;
			
			//Run Query and Send Formatted Data
			if($selectedFunc == 'getUserType') { 
				$response = getUserType($function->email);
			} 
			else if ($selectedFunc == 'getStudentDaySchedule') {
				$response = getStudentDaySchedule($function->userid, $function->date);				
			}
			else if ($selectedFunc == 'getLecturerDayCourses') {
				$response = getLecturerDayCourses($function->userid, $function->date);				
			}
			else if ($selectedFunc == 'getStudentsByCourse') {
				$response = getStudentsByCourse($function->ttableentryid);				
			}
			else if ($selectedFunc == 'getAutoAttendance') {
				$response = getAutoAttendance($function->ttableentryid);				
			}
			else if ($selectedFunc == 'getConfirmedAttendance') {
				$response = getConfirmedAttendance($function->ttableentryid);				
			}
			else if ($selectedFunc == 'getStudentLessonAttendance') {
				$response = getStudentLessonAttendance($function->ttableentryid, $function->userid);				
			}
			else if ($selectedFunc == 'updateStudentLessonAttendance') {
				$response = updateStudentLessonAttendance($function->attendance, $function->ttableentryid, $function->userid);				
			}
			else if ($selectedFunc == 'insertStudentLessonAttendance') {
				$response = insertStudentLessonAttendance($function->attendance, $function->ttableentryid, $function->userid);				
			}
			else {
				$response = getCode('Invalid Function');
			}
			
			header('Content-Type: application/json');
			echo $response;
		}
	} else {
		$response = getCode('Invalid JWT Token');
		
		header('Content-Type: application/json');
		echo $response;
	}
	
?>
<?php

	/**
	 * File for database connections.
	 */

	/** 
	 * API DB Connection Functions.
	 *
	 * @author 	Silvio McGurk (smcgurk@stmartins.edu)
	 * @author 	Reuben Debattista (rdebattista@stmartins.edu)
	 * @date	January 2019
	 *
	 * @package REST\dbConn
	 * @version Stable-8.0
	 *
	 */
	
	class dbConn {		

		/**
		 * Connect Function.
		 *
		 * Connects to database for the given site.
		 *
		 * @param string $site Sitename.
		 *
		 * @return Object Returns database connection object.
		 *
		 */
	
		public function connect($site) {

			# Require credentials and parameters file
			require('credentials.php');
			
			# Attempting connection with selected database
			$connect = new mysqli($hostname[$site], $username[$site], $password[$site], $database[$site]);

			# Check status of connection; fail on error
			if ($connect->connect_error) { 
				$this->writeLog(__FUNCTION__,"Connection to [$site] failed",'DB Connection Error' . $connect->connect_errno . ': ' . $connect->connect_error,null);
				
				die("Connection Failed " . $connect->connect_error);
			}
		
			# Return the mysqli connection
			return $connect;
			
		}		
	}
?>
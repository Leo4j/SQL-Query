function SQL-Query {
	param (
		[string]$Server,
		[string]$Database = "master",
        [string]$Username = $null,
        [string]$Password = $null,
        [string]$Domain = $null
	)
	
	$access = $null
	$loggedInUser = $null
	$dbUser = $null
	$rolesResults = $null
	$impersonationResults = $null
	$xpCmdShellStatus = "N/A"
	$oleAutomationStatus = "N/A"
	$clrStatus = "N/A"
	$rpcOutStatus = "N/A"
	$serviceAccount = "N/A"
	
	# Build the connection string
    if ($Username -and $Password -and $Domain) {
        if ($Domain -eq ".") {
            $connectionString = "Server=$Server;Database=$Database;User ID=$Username;Password=$Password;Connection Timeout=2;"
        } else {
            # Domain account authentication
            try {
                # Create a temporary PowerShell script with a .ps1 extension
                $tempScript = [System.IO.Path]::Combine("C:\Users\Public\Documents", [System.IO.Path]::GetRandomFileName() + ".ps1")
                $scriptContent = @'
function Execute-SQLQuery {
	param (
		[string]$Server,
		[string]$Database = "master"
	)
	
	$access = $null
	$loggedInUser = $null
	$dbUser = $null
	$rolesResults = $null
	$impersonationResults = $null
	$xpCmdShellStatus = "N/A"
	$oleAutomationStatus = "N/A"
	$clrStatus = "N/A"
	$rpcOutStatus = "N/A"
	$serviceAccount = "N/A"

	# Connection string
	$connectionString = "Server=$Server;Database=$Database;Integrated Security=True;Connection Timeout=2;"
	$connection = New-Object System.Data.SqlClient.SqlConnection $connectionString

	try {
		$connection.Open()
		$access = $true
	} catch {
		$access = $false
	}
	
	if ($access) {
		# Function to execute a query and fetch a single result
		function ExecuteQuery {
			param ($query)
			$command = $connection.CreateCommand()
			$command.CommandText = $query
			$reader = $command.ExecuteReader()
			$result = $null
			if ($reader.Read()) {
				$result = $reader[0]
			}
			$reader.Close()
			return $result
		}

		# Fetch the SQL login
		$loggedInUser = ExecuteQuery "SELECT SYSTEM_USER;"

		# Fetch the username (database user)
		$dbUser = ExecuteQuery "SELECT USER_NAME();"

		# Check if user is part of various server roles
		$roles = @("public", "sysadmin", "securityadmin", "serveradmin", "dbcreator", "diskadmin", "processadmin", "setupadmin", "bulkadmin")
		$rolesResults = @()
		foreach ($role in $roles) {
			$isMember = ExecuteQuery "SELECT IS_SRVROLEMEMBER('$role');"
			if ($isMember -eq 1) {
				$rolesResults += $role
			}
		}
		
		if ($rolesResults.count -gt 0) {
			$rolesResults = $rolesResults -join ", "
		} else {
			$rolesResults = "None"
		}

		# Logins that can be impersonated
		$impersonateQuery = "SELECT DISTINCT b.name FROM sys.server_permissions a " +
							"INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id " +
							"WHERE a.permission_name = 'IMPERSONATE';"

		$command = $connection.CreateCommand()
		$command.CommandText = $impersonateQuery
		$reader = $command.ExecuteReader()
		
		$impersonationResults = @()
		
		while ($reader.Read()) {
			$impersonationResults += $($reader[0])
		}
		$reader.Close()
		
		if ($impersonationResults.count -gt 0) {
			$impersonationResults = $impersonationResults -join ", "
		} else {
			$impersonationResults = "none"
		}
		
		# Linked Servers
		$execCmd = "EXEC sp_linkedservers;"
		$command = $connection.CreateCommand()
		$command.CommandText = $execCmd
		$reader = $command.ExecuteReader()

		# Array to store linked server names
		$linkedServers = @()

		# Retrieve linked servers and store them in the array
		while ($reader.Read()) {
			$linkedServers += $reader[0]
		}
		$reader.Close()
		
		if ($linkedServers.Count -gt 0) {
			$linkedServers = $linkedServers -join ", "
		} else {
			$linkedServers = "none"
		}

		# Check xp_cmdshell status
		$xpCmdShellStatus = ExecuteQuery "SELECT value FROM sys.configurations WHERE name = 'xp_cmdshell';"
		if ($xpCmdShellStatus -eq 1) {
			$xpCmdShellStatus = "Enabled"
		} else {
			$xpCmdShellStatus = "Disabled"
		}

		# Check OLE Automation Procedures status
		$oleAutomationStatus = ExecuteQuery "SELECT value FROM sys.configurations WHERE name = 'Ole Automation Procedures';"
		if ($oleAutomationStatus -eq 1) {
			$oleAutomationStatus = "Enabled"
		} else {
			$oleAutomationStatus = "Disabled"
		}

		# Check CLR status
		$clrStatus = ExecuteQuery "SELECT value FROM sys.configurations WHERE name = 'clr enabled';"
		if ($clrStatus -eq 1) {
			$clrStatus = "Enabled"
		} else {
			$clrStatus = "Disabled"
		}

		# Check RPC Out status
		$rpcOutStatus = ExecuteQuery "SELECT is_rpc_out_enabled FROM sys.servers WHERE name = @@SERVERNAME;"
		if ($rpcOutStatus -eq 1) {
			$rpcOutStatus = "Enabled"
		} else {
			$rpcOutStatus = "Disabled"
		}
		
		# Fetch the service account using xp_instance_regread
        $serviceAccountQuery = @"
DECLARE @SQLServerInstance NVARCHAR(255)
DECLARE @ServiceAccountName NVARCHAR(255)

IF @@SERVICENAME = 'MSSQLSERVER'
    SET @SQLServerInstance = 'SYSTEM\CurrentControlSet\Services\MSSQLSERVER'
ELSE
    SET @SQLServerInstance = 'SYSTEM\CurrentControlSet\Services\MSSQL$' + CAST(@@SERVICENAME AS NVARCHAR(255))

EXEC master.dbo.xp_instance_regread
    N'HKEY_LOCAL_MACHINE',
    @SQLServerInstance,
    N'ObjectName',
    @ServiceAccountName OUTPUT

SELECT @ServiceAccountName AS [ServiceAccount]
"@
        try {
            $serviceAccounts = ExecuteQuery $serviceAccountQuery
            if ($serviceAccounts.Count -gt 0) {
                $serviceAccount = $serviceAccounts -join ", "
            } else {
                $serviceAccount = "Not available"
            }
        } catch {
            $serviceAccount = "Error retrieving service account"
        }

		# Close connection
		$connection.Close()
		
		$MSSQLResults = [PSCustomObject]@{
			"Access"        = $access
			"Identity"      = $loggedInUser
			"Mapped to"     = $dbUser
			"Roles"         = $rolesResults
			"Impersonate"   = $impersonationResults
			"Links"         = $linkedServers
			"xp_cmdshell"   = $xpCmdShellStatus
			"OLE Automation"= $oleAutomationStatus
			"CLR Enabled"   = $clrStatus
			"RPC Out"       = $rpcOutStatus
			"Service Account"= $serviceAccount
		}
		
		$MSSQLResults
	}
	else {
		# Return default values when access is not available
		$MSSQLResults = [PSCustomObject]@{
			"Access"        = $access
			"Identity"      = "N/A"
			"Mapped to"     = "N/A"
			"Roles"         = "N/A"
			"Impersonate"   = "N/A"
			"Links"         = "N/A"
			"xp_cmdshell"   = "N/A"
			"OLE Automation"= "N/A"
			"CLR Enabled"   = "N/A"
			"RPC Out"       = "N/A"
			"Service Account"= "N/A"
		}
		
		$MSSQLResults
	}
};
'@
                $scriptContent = $scriptContent + "Execute-SQLQuery -Server ""$Server"" -Database ""$Database"""
				
				Set-Content -Path $tempScript -Value $scriptContent

                # Prepare credentials
                $securePassword = ConvertTo-SecureString $Password -AsPlainText -Force

                # Configure process start info
                $startInfo = New-Object System.Diagnostics.ProcessStartInfo
                $startInfo.FileName = "powershell.exe"
                $startInfo.Arguments = "-NoProfile -Windows Hidden -ExecutionPolicy Bypass -File `"$tempScript`""
                $startInfo.UserName = $Username         # Only the username
                $startInfo.Domain = $Domain            # Set the domain separately
                $startInfo.Password = $securePassword  # Use SecureString for the password
                $startInfo.UseShellExecute = $false
                $startInfo.RedirectStandardOutput = $true
                $startInfo.RedirectStandardError = $true

                $process = New-Object System.Diagnostics.Process
                $process.StartInfo = $startInfo

                # Start the process and wait for completion
                if ($process.Start()) {
                    $process.WaitForExit()

                    # Capture and display output
                    $output = $process.StandardOutput.ReadToEnd()
                    $errorOutput = $process.StandardError.ReadToEnd()
                    if ($output) { Write-Output $output }
                    if ($errorOutput) { Write-Error $errorOutput }
                } else {
                    Write-Error "Failed to start process with the provided credentials."
                }
            } catch {
                Write-Error "Error starting process: $_"
            } finally {
                # Clean up the temporary script file
                if (Test-Path $tempScript) {
                    Remove-Item -Path $tempScript -Force
                }
            }

            return
        }
    } else {
        $connectionString = "Server=$Server;Database=$Database;Integrated Security=True;Connection Timeout=2;"
    }

    $connection = New-Object System.Data.SqlClient.SqlConnection $connectionString

	try {
		$connection.Open()
		$access = $true
	} catch {
		$access = $false
	}
	
	if ($access) {
		# Function to execute a query and fetch a single result
		function ExecuteQuery {
			param ($query)
			$command = $connection.CreateCommand()
			$command.CommandText = $query
			$reader = $command.ExecuteReader()
			$result = $null
			if ($reader.Read()) {
				$result = $reader[0]
			}
			$reader.Close()
			return $result
		}

		# Fetch the SQL login
		$loggedInUser = ExecuteQuery "SELECT SYSTEM_USER;"

		# Fetch the username (database user)
		$dbUser = ExecuteQuery "SELECT USER_NAME();"

		# Check if user is part of various server roles
		$roles = @("public", "sysadmin", "securityadmin", "serveradmin", "dbcreator", "diskadmin", "processadmin", "setupadmin", "bulkadmin")
		$rolesResults = @()
		foreach ($role in $roles) {
			$isMember = ExecuteQuery "SELECT IS_SRVROLEMEMBER('$role');"
			if ($isMember -eq 1) {
				$rolesResults += $role
			}
		}
		
		if ($rolesResults.count -gt 0) {
			$rolesResults = $rolesResults -join ", "
		} else {
			$rolesResults = "None"
		}

		# Logins that can be impersonated
		$impersonateQuery = "SELECT DISTINCT b.name FROM sys.server_permissions a " +
							"INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id " +
							"WHERE a.permission_name = 'IMPERSONATE';"

		$command = $connection.CreateCommand()
		$command.CommandText = $impersonateQuery
		$reader = $command.ExecuteReader()
		
		$impersonationResults = @()
		
		while ($reader.Read()) {
			$impersonationResults += $($reader[0])
		}
		$reader.Close()
		
		if ($impersonationResults.count -gt 0) {
			$impersonationResults = $impersonationResults -join ", "
		} else {
			$impersonationResults = "none"
		}
		
		# Linked Servers
		$execCmd = "EXEC sp_linkedservers;"
		$command = $connection.CreateCommand()
		$command.CommandText = $execCmd
		$reader = $command.ExecuteReader()

		# Array to store linked server names
		$linkedServers = @()

		# Retrieve linked servers and store them in the array
		while ($reader.Read()) {
			$linkedServers += $reader[0]
		}
		$reader.Close()
		
		if ($linkedServers.Count -gt 0) {
			$linkedServers = $linkedServers -join ", "
		} else {
			$linkedServers = "none"
		}

		# Check xp_cmdshell status
		$xpCmdShellStatus = ExecuteQuery "SELECT value FROM sys.configurations WHERE name = 'xp_cmdshell';"
		if ($xpCmdShellStatus -eq 1) {
			$xpCmdShellStatus = "Enabled"
		} else {
			$xpCmdShellStatus = "Disabled"
		}

		# Check OLE Automation Procedures status
		$oleAutomationStatus = ExecuteQuery "SELECT value FROM sys.configurations WHERE name = 'Ole Automation Procedures';"
		if ($oleAutomationStatus -eq 1) {
			$oleAutomationStatus = "Enabled"
		} else {
			$oleAutomationStatus = "Disabled"
		}

		# Check CLR status
		$clrStatus = ExecuteQuery "SELECT value FROM sys.configurations WHERE name = 'clr enabled';"
		if ($clrStatus -eq 1) {
			$clrStatus = "Enabled"
		} else {
			$clrStatus = "Disabled"
		}

		# Check RPC Out status
		$rpcOutStatus = ExecuteQuery "SELECT is_rpc_out_enabled FROM sys.servers WHERE name = @@SERVERNAME;"
		if ($rpcOutStatus -eq 1) {
			$rpcOutStatus = "Enabled"
		} else {
			$rpcOutStatus = "Disabled"
		}
		
		# Fetch the service account using xp_instance_regread
        $serviceAccountQuery = @"
DECLARE @SQLServerInstance NVARCHAR(255)
DECLARE @ServiceAccountName NVARCHAR(255)

IF @@SERVICENAME = 'MSSQLSERVER'
    SET @SQLServerInstance = 'SYSTEM\CurrentControlSet\Services\MSSQLSERVER'
ELSE
    SET @SQLServerInstance = 'SYSTEM\CurrentControlSet\Services\MSSQL$' + CAST(@@SERVICENAME AS NVARCHAR(255))

EXEC master.dbo.xp_instance_regread
    N'HKEY_LOCAL_MACHINE',
    @SQLServerInstance,
    N'ObjectName',
    @ServiceAccountName OUTPUT

SELECT @ServiceAccountName AS [ServiceAccount]
"@
        try {
            $serviceAccounts = ExecuteQuery $serviceAccountQuery
            if ($serviceAccounts.Count -gt 0) {
                $serviceAccount = $serviceAccounts -join ", "
            } else {
                $serviceAccount = "Not available"
            }
        } catch {
            $serviceAccount = "Error retrieving service account"
        }

		# Close connection
		$connection.Close()
		
		$MSSQLResults = [PSCustomObject]@{
			"Access"        = $access
			"Identity"      = $loggedInUser
			"Mapped to"     = $dbUser
			"Roles"         = $rolesResults
			"Impersonate"   = $impersonationResults
			"Links"         = $linkedServers
			"xp_cmdshell"   = $xpCmdShellStatus
			"OLE Automation"= $oleAutomationStatus
			"CLR Enabled"   = $clrStatus
			"RPC Out"       = $rpcOutStatus
			"Service Account"= $serviceAccount
		}
		
		$MSSQLResults
	}
	else {
		# Return default values when access is not available
		$MSSQLResults = [PSCustomObject]@{
			"Access"        = $access
			"Identity"      = "N/A"
			"Mapped to"     = "N/A"
			"Roles"         = "N/A"
			"Impersonate"   = "N/A"
			"Links"         = "N/A"
			"xp_cmdshell"   = "N/A"
			"OLE Automation"= "N/A"
			"CLR Enabled"   = "N/A"
			"RPC Out"       = "N/A"
			"Service Account"= "N/A"
		}
		
		$MSSQLResults
	}
}

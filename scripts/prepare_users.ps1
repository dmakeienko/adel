#Requires -Modules ActiveDirectory
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Creates 1000 random users and 500 random groups in Active Directory
    
.DESCRIPTION
    This script generates random users with proper naming conventions and email addresses,
    along with random security groups. Includes comprehensive logging and error handling.
    
.PARAMETER Domain
    The domain suffix for email addresses (default: "company.local")
    
.PARAMETER UserOU
    Organizational Unit for users (default: "CN=Users")
    
.PARAMETER GroupOU
    Organizational Unit for groups (default: "CN=Users")
    
.PARAMETER LogPath
    Path for log file (default: current directory)
    
.EXAMPLE
    .\Create-ADUsersAndGroups.ps1 -Domain "contoso.com" -UserOU "OU=TestUsers,DC=contoso,DC=com"
#>

param(
    [string]$Domain = "company.local",
    [string]$UserOU = "CN=Users",
    [string]$GroupOU = "CN=Users",
    [string]$LogPath = ".\ADCreation_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
)

# Import Active Directory module
try {
    Import-Module ActiveDirectory -ErrorAction Stop
    Write-Host "Active Directory module loaded successfully" -ForegroundColor Green
} catch {
    Write-Error "Failed to import Active Directory module. Ensure RSAT-AD-PowerShell feature is installed."
    exit 1
}

# Initialize logging
function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    Add-Content -Path $LogPath -Value $logMessage
    
    switch ($Level) {
        "ERROR" { Write-Host $logMessage -ForegroundColor Red }
        "WARNING" { Write-Host $logMessage -ForegroundColor Yellow }
        "SUCCESS" { Write-Host $logMessage -ForegroundColor Green }
        default { Write-Host $logMessage }
    }
}

Write-Log "Starting AD bulk creation script"
Write-Log "Target Domain: $Domain"
Write-Log "User OU: $UserOU"
Write-Log "Group OU: $GroupOU"

# Arrays for generating random names
$FirstNames = @(
    "James", "Mary", "John", "Patricia", "Robert", "Jennifer", "Michael", "Linda", "William", "Elizabeth",
    "David", "Barbara", "Richard", "Susan", "Joseph", "Jessica", "Thomas", "Sarah", "Christopher", "Karen",
    "Charles", "Nancy", "Daniel", "Lisa", "Matthew", "Betty", "Anthony", "Helen", "Mark", "Sandra",
    "Donald", "Donna", "Steven", "Carol", "Paul", "Ruth", "Andrew", "Sharon", "Joshua", "Michelle",
    "Kenneth", "Laura", "Kevin", "Sarah", "Brian", "Kimberly", "George", "Deborah", "Timothy", "Dorothy",
    "Ronald", "Lisa", "Jason", "Nancy", "Edward", "Karen", "Jeffrey", "Betty", "Ryan", "Helen",
    "Jacob", "Sandra", "Gary", "Donna", "Nicholas", "Carol", "Eric", "Ruth", "Jonathan", "Sharon",
    "Stephen", "Michelle", "Larry", "Laura", "Justin", "Sarah", "Scott", "Kimberly", "Brandon", "Deborah",
    "Benjamin", "Dorothy", "Samuel", "Lisa", "Gregory", "Nancy", "Alexander", "Karen", "Patrick", "Betty",
    "Frank", "Helen", "Raymond", "Sandra", "Jack", "Donna", "Dennis", "Carol", "Jerry", "Ruth"
)

$LastNames = @(
    "Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller", "Davis", "Rodriguez", "Martinez",
    "Hernandez", "Lopez", "Gonzalez", "Wilson", "Anderson", "Thomas", "Taylor", "Moore", "Jackson", "Martin",
    "Lee", "Perez", "Thompson", "White", "Harris", "Sanchez", "Clark", "Ramirez", "Lewis", "Robinson",
    "Walker", "Young", "Allen", "King", "Wright", "Scott", "Torres", "Nguyen", "Hill", "Flores",
    "Green", "Adams", "Nelson", "Baker", "Hall", "Rivera", "Campbell", "Mitchell", "Carter", "Roberts",
    "Gomez", "Phillips", "Evans", "Turner", "Diaz", "Parker", "Cruz", "Edwards", "Collins", "Reyes",
    "Stewart", "Morris", "Morales", "Murphy", "Cook", "Rogers", "Gutierrez", "Ortiz", "Morgan", "Cooper",
    "Peterson", "Bailey", "Reed", "Kelly", "Howard", "Ramos", "Kim", "Cox", "Ward", "Richardson",
    "Watson", "Brooks", "Chavez", "Wood", "James", "Bennett", "Gray", "Mendoza", "Ruiz", "Hughes",
    "Price", "Alvarez", "Castillo", "Sanders", "Patel", "Myers", "Long", "Ross", "Foster", "Jimenez"
)

$GroupPrefixes = @(
    "Department", "Team", "Project", "Access", "Security", "Resource", "Application", "Service",
    "Region", "Division", "Unit", "Committee", "Task", "Special", "Admin", "Support",
    "Development", "Testing", "Production", "Finance", "Marketing", "Sales", "HR", "IT",
    "Operations", "Management", "Executive", "Temporary", "Contractor", "External"
)

$GroupSuffixes = @(
    "Users", "Admins", "Managers", "Staff", "Members", "Group", "Team", "Access", "Rights",
    "Committee", "Board", "Council", "Alliance", "Association", "Society", "Union", "Guild",
    "Network", "Community", "Organization", "Department", "Division", "Unit", "Section", "Branch"
)

# Validate OUs and Containers exist
function Test-OUExists {
    param([string]$OU)
    try {
        # Try as OU first
        Get-ADOrganizationalUnit -Identity $OU -ErrorAction Stop | Out-Null
        return $true
    } catch {
        # Try as generic AD object (handles containers like CN=Users)
        try {
            Get-ADObject -Identity $OU -ErrorAction Stop | Out-Null
            return $true
        } catch {
            return $false
        }
    }
}

# Auto-detect domain DN if using default CN=Users
if ($UserOU -eq "CN=Users") {
    try {
        $domainDN = (Get-ADDomain).DistinguishedName
        $UserOU = "CN=Users,$domainDN"
        Write-Log "Auto-detected User container: $UserOU"
    } catch {
        Write-Log "Failed to auto-detect domain DN" "ERROR"
        exit 1
    }
}

if ($GroupOU -eq "CN=Users") {
    try {
        $domainDN = (Get-ADDomain).DistinguishedName
        $GroupOU = "CN=Users,$domainDN"
        Write-Log "Auto-detected Group container: $GroupOU"
    } catch {
        Write-Log "Failed to auto-detect domain DN" "ERROR"
        exit 1
    }
}

if (-not (Test-OUExists $UserOU)) {
    Write-Log "User OU/Container '$UserOU' does not exist" "ERROR"
    exit 1
}

if (-not (Test-OUExists $GroupOU)) {
    Write-Log "Group OU/Container '$GroupOU' does not exist" "ERROR"
    exit 1
}

# Function to generate secure random password
function New-RandomPassword {
    param([int]$Length = 12)
    
    $chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*"
    $password = ""
    
    for ($i = 0; $i -lt $Length; $i++) {
        $password += $chars[(Get-Random -Maximum $chars.Length)]
    }
    
    # Ensure password meets complexity requirements
    if ($password -notmatch "[a-z]" -or $password -notmatch "[A-Z]" -or 
        $password -notmatch "\d" -or $password -notmatch "[!@#$%^&*]") {
        return New-RandomPassword -Length $Length
    }
    
    return $password
}

# Cache existing usernames and groups to avoid repeated AD queries
Write-Log "Loading existing AD users and groups into cache..."
$existingUsers = @{}
$existingGroups = @{}

try {
    Get-ADUser -Filter * -Properties SamAccountName | ForEach-Object {
        $existingUsers[$_.SamAccountName.ToLower()] = $true
    }
    Write-Log "Cached $($existingUsers.Count) existing users" "SUCCESS"
} catch {
    Write-Log "Warning: Could not cache existing users. Performance may be impacted." "WARNING"
}

try {
    Get-ADGroup -Filter * -Properties SamAccountName | ForEach-Object {
        $existingGroups[$_.Name.ToLower()] = $true
    }
    Write-Log "Cached $($existingGroups.Count) existing groups" "SUCCESS"
} catch {
    Write-Log "Warning: Could not cache existing groups. Performance may be impacted." "WARNING"
}

# Track newly created objects in this session
$createdUsersCache = @{}
$createdGroupsCache = @{}

# Function to check if username exists (using cache)
function Test-UsernameExists {
    param([string]$Username)
    $userLower = $Username.ToLower()
    return ($existingUsers.ContainsKey($userLower) -or $createdUsersCache.ContainsKey($userLower))
}

# Function to check if group exists (using cache)
function Test-GroupExists {
    param([string]$GroupName)
    $groupLower = $GroupName.ToLower()
    return ($existingGroups.ContainsKey($groupLower) -or $createdGroupsCache.ContainsKey($groupLower))
}

# Generate unique username
function New-UniqueUsername {
    param([string]$FirstName, [string]$LastName)
    
    $baseUsername = ($FirstName.Substring(0,1) + $LastName).ToLower()
    $username = $baseUsername
    $counter = 1
    
    while (Test-UsernameExists $username) {
        $username = "$baseUsername$counter"
        $counter++
        
        # Prevent infinite loop
        if ($counter -gt 999) {
            $username = "$baseUsername$(Get-Random -Maximum 9999)"
            break
        }
    }
    
    return $username
}

# Create users
Write-Log "Checking existing bulk-created users..."
$existingBulkUsers = (Get-ADUser -Filter "Description -like '*Bulk created user*'").Count
Write-Log "Found $existingBulkUsers bulk-created users already in AD"

$startTime = Get-Date  # Initialize start time for total execution

if ($existingBulkUsers -ge 1000) {
    Write-Log "Target of 1000 users already met or exceeded. Skipping user creation." "SUCCESS"
    $createdUsers = 0
    $failedUsers = 0
    $usersToCreate = 0
} else {
    $usersToCreate = 1000 - $existingBulkUsers
    Write-Log "Will create $usersToCreate additional users to reach 1000 total" "SUCCESS"
    $createdUsers = 0
    $failedUsers = 0

    for ($i = 1; $i -le $usersToCreate; $i++) {
    try {
        $firstName = $FirstNames | Get-Random
        $lastName = $LastNames | Get-Random
        $username = New-UniqueUsername -FirstName $firstName -LastName $lastName
        $email = "$username@$Domain"
        $displayName = "$firstName $lastName"
        $password = New-RandomPassword
        
        $userParams = @{
            Name = $username
            SamAccountName = $username
            UserPrincipalName = "$username@$Domain"
            GivenName = $firstName
            Surname = $lastName
            DisplayName = $displayName
            EmailAddress = $email
            AccountPassword = (ConvertTo-SecureString $password -AsPlainText -Force)
            Enabled = $true
            Path = $UserOU
            ChangePasswordAtLogon = $true
            Description = "Bulk created user - $(Get-Date -Format 'yyyy-MM-dd')"
        }
        
        New-ADUser @userParams
        $createdUsers++
        
        # Add to cache to prevent duplicates
        $createdUsersCache[$username.ToLower()] = $true
        
        if ($i % 100 -eq 0) {
            $elapsed = (Get-Date) - $startTime
            $rate = $i / $elapsed.TotalSeconds
            Write-Log "Created $i users so far... (Rate: $([math]::Round($rate, 2)) users/sec)" "SUCCESS"
        }
        
    } catch {
        $failedUsers++
        Write-Log "Failed to create user $i`: $($_.Exception.Message)" "ERROR"
    }
}
}

Write-Log "User creation completed. Success: $createdUsers, Failed: $failedUsers, Already existed: $existingBulkUsers" "SUCCESS"

# Create groups
Write-Log "Checking existing bulk-created groups..."
$existingBulkGroups = (Get-ADGroup -Filter "Description -like '*Bulk created security group*'").Count
Write-Log "Found $existingBulkGroups bulk-created groups already in AD"

if ($existingBulkGroups -ge 500) {
    Write-Log "Target of 500 groups already met or exceeded. Skipping group creation." "SUCCESS"
    $createdGroups = 0
    $failedGroups = 0
    $groupsToCreate = 0
} else {
    $groupsToCreate = 500 - $existingBulkGroups
    Write-Log "Will create $groupsToCreate additional groups to reach 500 total" "SUCCESS"
    $createdGroups = 0
    $failedGroups = 0
    $groupStartTime = Get-Date

    for ($i = 1; $i -le $groupsToCreate; $i++) {
    try {
        $prefix = $GroupPrefixes | Get-Random
        $suffix = $GroupSuffixes | Get-Random
        # Use larger random range and include timestamp component to ensure uniqueness
        $randomPart = Get-Random -Minimum 1000 -Maximum 9999
        $groupName = "$prefix-$suffix-$randomPart"
        
        # Ensure unique group name using cache with escape valve
        $counter = 1
        $originalGroupName = $groupName
        $maxAttempts = 50
        
        while (Test-GroupExists $groupName -and $counter -le $maxAttempts) {
            $groupName = "$prefix-$suffix-$(Get-Random -Minimum 10000 -Maximum 99999)"
            $counter++
        }
        
        # If still not unique after max attempts, use timestamp
        if (Test-GroupExists $groupName) {
            $timestamp = (Get-Date).ToString("HHmmssffff")
            $groupName = "$prefix-$suffix-$timestamp"
        }
        
        $groupParams = @{
            Name = $groupName
            SamAccountName = $groupName
            GroupCategory = 'Security'
            GroupScope = 'Global'
            Path = $GroupOU
            Description = "Bulk created security group - $(Get-Date -Format 'yyyy-MM-dd')"
        }
        
        New-ADGroup @groupParams
        $createdGroups++
        
        # Add to cache to prevent duplicates
        $createdGroupsCache[$groupName.ToLower()] = $true
        
        if ($i % 50 -eq 0) {
            $elapsed = (Get-Date) - $groupStartTime
            $rate = $i / $elapsed.TotalSeconds
            Write-Log "Created $i groups so far... (Rate: $([math]::Round($rate, 2)) groups/sec, Attempts for last: $counter)" "SUCCESS"
        }
        
    } catch {
        $failedGroups++
        Write-Log "Failed to create group $i ($groupName): $($_.Exception.Message)" "ERROR"
        
        # Add delay on error to prevent AD throttling
        Start-Sleep -Milliseconds 100
    }
}
}

Write-Log "Group creation completed. Success: $createdGroups, Failed: $failedGroups, Already existed: $existingBulkGroups" "SUCCESS"

# Summary
$endTime = Get-Date
Write-Log "=== CREATION SUMMARY ===" "SUCCESS"
Write-Log "Total bulk users in AD: $($existingBulkUsers + $createdUsers)" "SUCCESS"
Write-Log "Users created this run: $createdUsers" "SUCCESS"
Write-Log "Users failed: $failedUsers" "SUCCESS"
Write-Log "Total bulk groups in AD: $($existingBulkGroups + $createdGroups)" "SUCCESS"
Write-Log "Groups created this run: $createdGroups" "SUCCESS"
Write-Log "Groups failed: $failedGroups" "SUCCESS"
Write-Log "Total execution time: $($endTime - $startTime)" "SUCCESS"
Write-Log "Log file saved to: $LogPath" "SUCCESS"

Write-Host "`nScript completed! Check the log file for detailed results: $LogPath" -ForegroundColor Green

# Optional: Export created objects to CSV for reference
if ($createdUsers -gt 0) {
    try {
        $userExportPath = ".\CreatedUsers_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
        Get-ADUser -Filter "Description -like '*Bulk created user*'" -Properties EmailAddress, Description |
            Select-Object Name, SamAccountName, EmailAddress, GivenName, Surname, Enabled, Description |
            Export-Csv -Path $userExportPath -NoTypeInformation
        Write-Log "User export saved to: $userExportPath" "SUCCESS"
    } catch {
        Write-Log "Failed to export user list: $($_.Exception.Message)" "WARNING"
    }
}

if ($createdGroups -gt 0) {
    try {
        $groupExportPath = ".\CreatedGroups_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
        Get-ADGroup -Filter "Description -like '*Bulk created security group*'" -Properties Description |
            Select-Object Name, SamAccountName, GroupCategory, GroupScope, Description |
            Export-Csv -Path $groupExportPath -NoTypeInformation
        Write-Log "Group export saved to: $groupExportPath" "SUCCESS"
    } catch {
        Write-Log "Failed to export group list: $($_.Exception.Message)" "WARNING"
    }
}
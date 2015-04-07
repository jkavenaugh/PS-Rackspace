<#

	Generate User Key and Secret Key from E-Mail Admin controll panel at Rackspace.
	
	ARW Specific code:
		Path variables for arwplans.com and americanrw.com
		Function - Build Headers
		
#>

$agent = "Rackspace Management Interface"
$ukey = "User Key"
$skey = "Secret Key"
$timestamp = Get-Date -Format yyyyMMddHHmmss

<# 

    Server and URL Path variables
#>

$arwplans = "https://api.emailsrvr.com/v1/domains/arwplans.com"
$americanrw = "https://api.emailsrvr.com/v1/domains/americanrw.com"
$mailbox_url = "rs/mailboxes"
$alias_url = "rs/aliases"

function hash{

<#

    .SYNOPSIS
        Builds a SHA1 Hash from a string.
#>

[CmdletBinding()]
Param(
    [Parameter(Mandatory=$True)]
    [string]$string
    )

    $sha1 = New-Object System.Security.Cryptography.SHA1CryptoServiceProvider
    $bytes = [Text.Encoding]::ASCII.GetBytes($string)
    $hash = [Convert]::ToBase64String($sha1.ComputeHash($bytes))
    
    return $hash

}

function build_headers(){

<#

    .SYNOPSIS
        Builds a list of headers to authenticate the connection to Rackspace.

#>

    $hash = hash($ukey+$agent+$timestamp+$skey)
    $signature = "$ukey`:$timestamp`:$hash"
    $headers = @{"Accept" = "application/json"
                 "X-Api-Signature"="$signature"}
    
    return $headers
}


function build_domainURL{

<#

    .SYNOPSIS
        Builds URLs for each domain.

#>

[CmdletBinding()]
Param(
    [Parameter(Mandatory=$True)]
    [string]$Domain
    )

Switch($domain){
    arwplans.com {$domain = $arwplans}
    americanrw.com {$domain = $americanrw}
    }

return $domain
}




function Get-RSDomain{

<#

    .SYNOPSIS
        Retrieves information on a RackSpace Domain.
    .EXAMPLE
        Get-RSDomain -Domain arwplans.com

#>

[CmdletBinding()]
Param(
    [Parameter(Mandatory=$True)]
    [string]$Domain
    )

$domain_url = build_domainURL($domain)
$headers = build_headers

 try {

      $response = Invoke-RestMethod $domain_url -Headers $headers -Method Get -UserAgent $agent
      return $response

     }
catch {

      $response = $_
      Write-Error $response
      return $false > $null
     }

}

function Get-RSDomainAvailableMailboxes{

<#

    .SYNOPSIS
        Returns the number of available mailboxes on a RackSpace Domain
    .EXAMPLE
        Get-RSDomainAvaiableMaiboxes -Domain arwplans.com

#>

[CmdletBinding()]
Param(
    [Parameter(Mandatory=$True)]
    [string]$Domain
    )

$domain_url = build_domainURL($domain)
$headers = build_headers

try {

      $response = Invoke-RestMethod $domain_url -Headers $headers -Method Get -UserAgent $agent
      $free = ($response.rsEmailMaxNumberMailboxes - $response.rsEmailUsedStorage)
      return $free 
     }
catch {

    $response = $_
    Write-Error $response
    return $false > $null

     }

}


function Get-RSAliases{

<#

    .SYNOPSIS
        Displays a list of Aliases on a Domain and the number of alias members.
    .EXAMPLE
        Get-RSAlias -Domain arwplans.com
#>

[CmdletBinding()]
Param(
    [Parameter(Mandatory=$True)]
    [string]$Domain
    )

$domain_url = build_domainURL($domain)
$headers = build_headers

 try {

      $response = Invoke-RestMethod "$domain_url/$alias_url" -Headers $headers -Method Get -UserAgent $agent
      return $response.aliases

     }
catch {

    $response = $_
    Write-Error $response
    return $false > $null

     }

}

function Get-RSAlias{

<#

    .SYNOPSIS
        Displays a list of e-mail addresses associated with an alias.
    .EXAMPLE
        Get-RSAlias -Domain arwplans.com -Name orders

#> 

[CmdletBinding()]
Param(
    [Parameter(Mandatory=$True, Position=1)]
    [string]$Domain,
    [Parameter(Mandatory=$True, Position=2)]
    [string]$Name
    )

$domain_url = build_domainURL($domain)
$headers = build_headers


 try {
      $response = Invoke-RestMethod "$domain_url/$alias_url/$Name" -Headers $headers -Method Get -UserAgent $agent
      return $response.emailAddressList.emailAddress
     }
catch {

    $response = $_
    Write-Error $response
    return $false > $null
     }

}



function Add-RSAlias{

<#
   .SYNOPSIS
       Creates a new e-mail alias and assigns an e-mail address or multiple e-mail addresses to the alias.
   .DESCRIPTION
       Creates a new e-mail alias and assigns an e-mail address or multiple e-mail addresses to the alias.
       Multiple e-mail addresses should be comma sepperated. There is a maximum of 50 domain e-mails and
       4 non-domain e-mails.
   .EXAMPLE
       Add-RSAlias -Domain arwplans.com -Name myalias -EmailAddress bsmith@arwplans.com
   .Example
       Add-RSAlias -Domain arwplans.com -Name myalias -EmailAddress "bsmith@arwplans.com, jsmith@arwplans.com

#>

[CmdletBinding()]
Param(
    [Parameter(Mandatory=$True, Position=1)]
    [string]$Domain,
    [Parameter(Mandatory=$True, Position=2)]
    [string]$Name,
    [Parameter(Mandatory=$True, Position=3)]
    [string]$EmailAddress
    )

If (Get-RSAlias $Domain $Name){
    Write-Host "Cannot create Alias, the alias $Name already exists in Domain."
    return $false > $null
}
ElseIf(Get-RSMailbox $Domain $Name){
    Write-Host "Cannot create Alias, this alias already exists as a mailbox in the Domain."
    return $false > $null
}

$domain_url = build_domainURL($domain)
$headers = build_headers

$body = @{aliasEmails=$EmailAddress}

 try {
      $response = Invoke-RestMethod "$domain_url/$alias_url/$Name" -Headers $headers -Method Post -Body $body -UserAgent $agent
      return $response
     }
catch {

    $response = $_
    Write-Error $response
    return $false > $null

     }

}



function Add-RSAliasMember{

<#

    .SYNOPSIS
        Adds a new e-mail address to the specified alias.
    .DESCRIPTION
        Adds a new e-mail address to the specified alias. The e-mail address
        must be valid. If the e-mail address is already a member of the alias
        the command will return an error.
    .EXAMPLE
        Add-RSAliasMember -Domain arwplans.com -Name arwalias -EmailAddress bob@arwplans.com

#>
[CmdletBinding()]
Param(
    [Parameter(Mandatory=$True, Position=1)]
    [string]$Domain,
    [Parameter(Mandatory=$True, Position=2)]
    [string]$Name,
    [Parameter(Mandatory=$True, Position=3)]
    [string]$EmailAddress
    )


$domain_url = build_domainURL($domain)
$headers = build_headers

if((Get-RSAlias $Domain $Name) -contains $EmailAddress){

    Write-Host "E-Mail address already a member of the $Name alias."
    return $False > $null
}

 try {
      $response = Invoke-RestMethod "$domain_url/$alias_url/$Name/$EmailAddress" -Headers $headers -Method Post -Body $body -UserAgent $agent
      return $response
     }
catch {

    $response = $_
    Write-Error $response
    return $false > $null

     }

}

function Remove-RSAlias{

<#

   .SYNOPSIS
       Removes an Alias from the RackSpace domain.
   .EXAMPLE
       Remove-RSAlias -Domain arwplans.com -Name myalias
#>
[CmdletBinding()]
Param(
    [Parameter(Mandatory=$True, Position=1)]
    [string]$Domain,
    [Parameter(Mandatory=$True, Position=2)]
    [string]$Name
    )


$domain_url = build_domainURL($domain)
$headers = build_headers

if ((Get-RSAlias $Domain $Name) -eq $False){

    Write-Host "Alias $Name does not exist in the $Domain Domain"
    return $Fales > $null
}

 try {
      $response = Invoke-RestMethod "$domain_url/$alias_url/$Name" -Headers $headers -Method Delete -UserAgent $agent
      return $response
     }
catch {

    $response = $_
    Write-Error $response
    return $false > $null

     }

}


function Remove-RSAliasMember{

<#

    .SYNOPSIS
        Removes an e-mail address from an alias
    .Example
        Remove-RSAliasMember -Domain arwplans.com -Name myalias -EmailAddress bsmith@americanrw.com

#>
[CmdletBinding()]
Param(
    [Parameter(Mandatory=$True, Position=1)]
    [string]$Domain,
    [Parameter(Mandatory=$True, Position=2)]
    [string]$Name,
    [Parameter(Mandatory=$True, Position=2)]
    [string]$EmailAddress
    )

$domain_url = build_domainURL($domain)
$headers = build_headers

 try {
      $response = Invoke-RestMethod "$domain_url/$alias_url/$Name/$EmailAddress" -Headers $headers -Method Delete -UserAgent $agent
      return $response
     }
catch {

    $response = $_
    Write-Error $response
    return $false > $null

     }

}



function Get-RSMailboxes{

<#

    .SYNOPSIS
        Retrieves a list of domian mailboxes from RackSpace
    .EXAMPLE
        Get-RSMailBoxes -Domain arwplans.com
#>
[CmdletBinding()]
Param(
    [Parameter(Mandatory=$True, Position=1)]
    [string]$Domain
    )

$domain_url = build_domainURL($domain)
$headers = build_headers

try {
      $response = Invoke-RestMethod "$domain_url/$mailbox_url" -Headers $headers -Method Get -UserAgent $agent
      return $response
     }
catch {

    $response = $_
    Write-Error $response
    return $false > $null

     }

}

function Get-RSMailbox([string]$Domain, [string]$Name){

<#

    .SYNOPSIS
        Gets information about a specific mailbox
    .EXAMPLE
        Get-RSMailbox -Domain arwplans.com -Name bsmith
#>
[CmdletBinding()]
$domain_url = build_domainURL($domain)
$headers = build_headers

try{

    $response = Invoke-RestMethod "$domain_url/$mailbox_url/$Name" -Headers $headers -Method Get -UserAgent $agent
    return $response
    }
catch{

    $response = $_
    Write-Error $response
    return $false > $null

    }
}

function Add-RSMailbox{

<#

    .SYNOPSIS
        Adds a new Mailbox to a domain. Must provide Password, First Name and Last Name
    .EXAMPLE
        Add_RSMailbox -Domain arwplans.com -Name bsmith -Password Secret! -FirstName Bob -LastName Smith

#>
[CmdletBinding()]
Param(
    [Parameter(Mandatory=$True, Position=1)]
    [string]$Domain,
    [Parameter(Mandatory=$True, Position=2)]
    [string]$Name,
    [Parameter(Mandatory=$True, Position=3)]
    [string]$Password,
    [Parameter(Mandatory=$True, Position=4)]
    [string]$FirstName,
    [Parameter(Mandatory=$True, Position=5)]
    [string]$LastName
    )


$domain_url = build_domainURL($Domain)
$headers = build_headers


$body = @{password = $password;size = '25600'}
if ($LastName) {$body.Add('lastName', $LastName)}
if ($FirstName) {$body.Add('firstName', $FirstName)}

try{

    $response = Invoke-RestMethod "$domain_url/$mailbox_url/$Name" -Body $body -Headers $headers -Method Post -UserAgent $agent
    return $response

    }
catch{

    $response = $_
    Write-Error $response
    return $false > $null

    }
}


function Set-RSMailboxForwarder{

<#

  .SYNOPSIS
      Sets a Mailbox to foward to an e-mail address.
  .DESCRIPTION
      Multiple E-Mail addresses may be specified with a comma sepperated list. A Maximum
      of 15 addresses 4 of which may be outside of the domain. SaveForwarded Email is a
      boolean which may be set to True to keep forwarded e-mail on the mailbox. The command
      can be used with a blank EmailAddress string to clear forwarding addresses.
  .EXAMPLE
      Set-RSMailboxForwarder -Domain arwplans.com -Name bsmith -EmailAddresses jrodger@arwplans.com -SaveForwardEmail 0

      Sends e-mail to bsmith@arwplans.com to jrodger@arwplans.com. Deletes forwarded mail from the bsmith mailbox.
  .Example
      Set-RSMailboxForwarder -Domain arwplans.com -Name bsmith -EmailAddresses
       
      Removes all forwarding addresses from the bsmith mailbox.
#>
[CmdletBinding()]
Param(
    [Parameter(Mandatory=$True, Position=1)]
    [string]$Domain,
    [Parameter(Mandatory=$True, Position=2)]
    [string]$Name,
    [Parameter(Mandatory=$True, Position=3)]
    [string]$EmailAddress,
    [Parameter(Position=4)]
    [bool]$SaveForwardedEmail
    )

$domain_url = build_domainURL($Domain)
$headers = build_headers

$body = @{emailForwardingAddresses = $EmailAddress}
if ($SaveForwardedEmail) {$body.Add('saveForwardedEmail', 'true')}

try{

    $response = Invoke-RestMethod "$domain_url/$mailbox_url/$Name" -Body $body -Headers $headers -Method Put -UserAgent $agent -ContentType "application/x-www-form-urlencoded"
    return $response

    }
catch{

    $response = $_
    Write-Error $response
    return $false > $null

    }
}


function Remove-RSMailbox{

<#

    .SYNOPSIS
        Removes a mailbox from a domain
    .EXAMPLE
        Remove-RSMailbox -Domain arwplans.com -Name bsmith

        Removes the bsmith mailbox from arwplans.com

#>
[CmdletBinding()]
Param(
    [Parameter(Mandatory=$True, Position=1)]
    [string]$Domain,
    [Parameter(Mandatory=$True, Position=1)]
    [string]$Name
    )

$domain_url = build_domainURL($Domain)
$headers = build_headers

try{

    $response = Invoke-RestMethod "$domain_url/$mailbox_url/$Name" -Headers $headers -Method Delete -UserAgent $agent
    return $response

    }
catch{

    $response = $_
    Write-Error $response
    return $false > $null

    }
}

Export-Modulemember *-*
